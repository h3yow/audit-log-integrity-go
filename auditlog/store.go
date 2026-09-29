package auditlog

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Clock 为可注入时钟，便于测试保留与重启语义。
type Clock func() time.Time

// Option 配置 Store。
type Option func(*config)

type config struct {
	clock Clock
}

// WithClock 注入自定义时钟。
func WithClock(c Clock) Option {
	return func(cfg *config) { cfg.clock = c }
}

// Store 是一个可追加、可校验、可清理的本地审计日志句柄。
// 同一时刻每个路径只允许一个写句柄（进程内句柄互斥 + flock 跨进程互斥）。
type Store struct {
	path      string
	statePath string
	f         *os.File
	lock      *fileLock
	mu        sync.Mutex
	cfg       config
	closed    bool

	lastSeq  int64
	lastHash [32]byte
	lastTime time.Time
}

const (
	tempLogSuffix  = ".new"
	tempArchSuffix = ".arc"
)

// Open 打开（或首次创建）审计日志，并在续写前完成重启核对。
//
// 结论分类（可 errors.Is 区分）：
//   - 全新文件：写入 genesis 后立即可用；
//   - 收尾干净：文件长度/末帧与侧车锚点完全一致，可安全续写；
//   - ErrTailTruncated：文件末帧结构完整但与锚点对不上（被截断/回卷）；
//   - ErrUncleanShutdown：锚点之后还有字节（未提交帧或半帧）；
//   - ErrChainBroken/ErrInvalidFormat：中段被改写/删除/插入，不可续写。
func Open(path string, opts ...Option) (*Store, error) {
	cfg := config{clock: func() time.Time { return time.Now().UTC() }}
	for _, o := range opts {
		o(&cfg)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	lock, err := acquireLock(abs)
	if err != nil {
		return nil, err
	}
	s := &Store{
		path:      abs,
		statePath: abs + ".state",
		lock:      lock,
		cfg:       cfg,
	}

	f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("auditlog: open log: %w", err)
	}
	s.f = f

	fi, err := f.Stat()
	if err != nil {
		_ = s.closeFiles()
		return nil, err
	}
	size := fi.Size()
	cp, _, cpErr := readCheckpoint(s.statePath)
	if cpErr != nil && cp == nil {
		// 锚点文件存在但无法解析（magic 不符等）：锚点不可信，拒绝续写。
		_ = s.closeFiles()
		return nil, cpErr
	}

	if size == 0 {
		// 全新段：无锚点（或锚点是更早历史遗留，忽略）→ 建链。
		if err := s.initGenesis(0, zeroHash, 0); err != nil {
			_ = s.closeFiles()
			return nil, err
		}
		return s, nil
	}

	rep, prob := verifyChain(f, size)
	if prob != nil {
		_ = s.closeFiles()
		return nil, prob
	}

	if cp == nil {
		// 有内容但没有任何“上次正常收尾”的凭据：无法证明它安全，拒绝续写。
		_ = s.closeFiles()
		return nil, &IntegrityProblem{
			Kind:   ErrNotRepairable,
			Offset: 0,
			Index:  -1,
			Reason: "existing log has no checkpoint proving a clean shutdown; refusing to append to an unproven base",
		}
	}

	switch {
	case rep.LastOffset == cp.Size && rep.LastHash == cp.LastHash && rep.LastSeq == cp.LastSeq:
		// 收尾干净：可以安全续写。
	case rep.LastOffset < cp.Size:
		_ = s.closeFiles()
		return nil, &IntegrityProblem{
			Kind:   ErrTailTruncated,
			Offset: rep.LastOffset,
			Index:  -1,
			Reason: fmt.Sprintf("log ends at %d but checkpoint records a clean size of %d: bytes were removed", rep.LastOffset, cp.Size),
		}
	case rep.LastOffset == cp.Size && (rep.LastHash != cp.LastHash || rep.LastSeq != cp.LastSeq):
		_ = s.closeFiles()
		return nil, &IntegrityProblem{
			Kind:   ErrTailTruncated,
			Offset: rep.LastOffset,
			Index:  -1,
			Reason: "final frame does not match the cleanly committed checkpoint: tail was rewritten",
		}
	default:
		// rep.LastOffset > cp.Size：锚点之后存在未提交字节。
		_ = s.closeFiles()
		return nil, &IntegrityProblem{
			Kind:   ErrUncleanShutdown,
			Offset: cp.Size,
			Index:  -1,
			Reason: fmt.Sprintf("%d uncommitted byte(s) follow the clean checkpoint at %d", rep.LastOffset-cp.Size, cp.Size),
		}
	}

	s.lastSeq = rep.LastSeq
	s.lastHash = rep.LastHash
	if nr := newestRecord(rep.Frames); nr != nil {
		s.lastTime = nr.Time
	}
	return s, nil
}

// initGenesis 在空文件写入建链帧并落第一个干净锚点。
func (s *Store) initGenesis(removed int64, prev [32]byte, upToTime int64) error {
	var raw []byte
	var err error
	var firstHash [32]byte
	var upToSeq int64
	if removed == 0 {
		raw, err = encodeGenesisFrame()
		if err != nil {
			return err
		}
	} else {
		upToSeq = removed
		raw, err = encodeAnchorFrame(anchorHeader{Removed: removed, UpToSeq: upToSeq, UpToTime: upToTime, Prev: prev})
		if err != nil {
			return err
		}
	}
	if err := s.writeRaw(raw); err != nil {
		return err
	}
	firstHash = frameHash(raw[offHeader:offHeader+frameHeaderLen(raw)], nil)
	s.lastSeq = upToSeq
	s.lastHash = firstHash
	return s.commitCheckpoint(int64(len(raw)), true)
}

// writeRaw 向文件尾部写入一帧并 fsync 数据（不更新锚点）。
func (s *Store) writeRaw(raw []byte) error {
	if _, err := s.f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	if _, err := s.f.Write(raw); err != nil {
		return fmt.Errorf("auditlog: write frame: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("auditlog: fsync log: %w", err)
	}
	return nil
}

// commitCheckpoint 更新内存链状态并原子落下干净侧车锚点。
func (s *Store) commitCheckpoint(size int64, clean bool) error {
	cp := &checkpoint{LastSeq: s.lastSeq, LastHash: s.lastHash, Size: size, Clean: clean}
	return writeCheckpoint(s.statePath, cp)
}

// Append 顺序追加一条审计记录；并发调用按获得锁的先后次序落盘。
func (s *Store) Append(rec Record) (seq int64, offset int64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if rec.Action == "" {
		return 0, 0, fmt.Errorf("%w: empty action", ErrInvalidRecord)
	}
	ts := rec.Timestamp
	if ts.IsZero() {
		ts = s.cfg.clock()
	}
	ts = ts.UTC()
	if ts.Before(s.lastTime) {
		return 0, 0, fmt.Errorf("%w: record time %s is earlier than last committed %s (monotonic timeline required)",
			ErrInvalidRecord, ts.Format(time.RFC3339Nano), s.lastTime.Format(time.RFC3339Nano))
	}

	where, err := s.f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, 0, err
	}
	newSeq := s.lastSeq + 1
	hdr := recordHeader{
		Seq:    newSeq,
		Time:   ts.UnixNano(),
		Actor:  rec.Actor,
		Action: rec.Action,
		Res:    rec.Resource,
		Prev:   s.lastHash,
	}
	body := []byte(rec.Detail)
	raw, err := encodeRecordFrame(hdr, body)
	if err != nil {
		return 0, 0, err
	}
	if err := s.writeRaw(raw); err != nil {
		return 0, 0, err
	}
	// 帧已 fsync：此刻崩溃会留下“未提交的完整帧” → 重启判定为 unclean，可 Repair。
	s.lastSeq = newSeq
	s.lastHash = frameHash(raw[offHeader:offHeader+frameHeaderLen(raw)], body)
	s.lastTime = ts
	size := where + int64(len(raw))
	if err := s.commitCheckpoint(size, true); err != nil {
		return 0, 0, err
	}
	return newSeq, where, nil
}

// frameHeaderLen 从已编码帧中取出 header JSON 长度。
func frameHeaderLen(raw []byte) int {
	return int(uint32(raw[offHeaderLen])<<24 | uint32(raw[offHeaderLen+1])<<16 |
		uint32(raw[offHeaderLen+2])<<8 | uint32(raw[offHeaderLen+3]))
}

// Verify 对当前段做全量完整性校验，返回确定性结论。
func (s *Store) Verify() (*ChainReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fi, err := s.f.Stat()
	if err != nil {
		return nil, err
	}
	rep, prob := verifyChain(s.f, fi.Size())
	if prob != nil {
		return nil, prob
	}
	return rep, nil
}

// Purge 按保留策略清理历史前缀（原子重写，新首帧为清理锚点）。
func (s *Store) Purge(pol RetentionPolicy, req PurgeRequest) (*PurgeResult, error) {
	return s.purgeOrArchive("", pol, req)
}

// Archive 按保留策略把可清理前缀写入归档文件，随后执行与 Purge 相同的前缀清理。
func (s *Store) Archive(archivePath string, pol RetentionPolicy, req PurgeRequest) (*PurgeResult, error) {
	if archivePath == "" {
		return nil, fmt.Errorf("%w: empty archive path", ErrInvalidRetention)
	}
	return s.purgeOrArchive(archivePath, pol, req)
}

func (s *Store) purgeOrArchive(archivePath string, pol RetentionPolicy, req PurgeRequest) (*PurgeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := pol.validate(); err != nil {
		return nil, err
	}
	fi, err := s.f.Stat()
	if err != nil {
		return nil, err
	}
	rep, prob := verifyChain(s.f, fi.Size())
	if prob != nil {
		return nil, prob
	}
	if !rep.OK {
		return nil, &IntegrityProblem{Kind: ErrChainBroken, Offset: 0, Index: -1, Reason: "refusing to purge a log that does not verify"}
	}

	n, err := eligiblePrefix(rep.Frames, rep.Count, pol, req)
	if err != nil {
		return nil, err
	}
	// frames[1..n] 为可清理 record；frames[n+1..] 保留。
	purged := rep.Frames[1 : 1+n]
	kept := rep.Frames[1+n:]
	lastPurged := purged[len(purged)-1]
	newBase := rep.TotalRemoved + int64(n)

	anchorRaw, err := encodeAnchorFrame(anchorHeader{
		Removed:  newBase,
		UpToSeq:  newBase,
		UpToTime: lastPurged.Time.UnixNano(),
		Prev:     lastPurged.Hash,
		Link:     lastPurged.Hash,
	})
	if err != nil {
		return nil, err
	}

	// 归档：被删前缀原文帧 + 同样的边界锚点，归档自包含、可独立校验。
	if archivePath != "" {
		if err := s.writeArchive(archivePath, purged, anchorRaw, newBase); err != nil {
			return nil, err
		}
	}

	// 原子重写活动日志：anchor + 保留帧原文。
	if err := s.rewriteActive(anchorRaw, kept); err != nil {
		return nil, err
	}

	res := &PurgeResult{
		Removed:       n,
		NewStartIndex: kept[0].Seq,
		AnchorOffset:  int64(len(anchorRaw)),
		Archived:      archivePath != "",
	}
	return res, nil
}

// writeArchive 将被清理帧原文与边界锚点写入归档文件（O_EXCL 拒绝覆盖）。
func (s *Store) writeArchive(archivePath string, purged []*Frame, anchorRaw []byte, newBase int64) error {
	af, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrArchiveExists, archivePath)
		}
		return fmt.Errorf("auditlog: create archive: %w", err)
	}
	copyFrame := func(fr *Frame) error {
		raw, err := readFrameBytes(s.f, fr.Offset, fr.End)
		if err != nil {
			return err
		}
		_, err = af.Write(raw)
		return err
	}
	for _, fr := range purged {
		if err := copyFrame(fr); err != nil {
			_ = af.Close()
			_ = os.Remove(archivePath)
			return err
		}
	}
	if _, err := af.Write(anchorRaw); err != nil {
		_ = af.Close()
		_ = os.Remove(archivePath)
		return err
	}
	if err := af.Sync(); err != nil {
		_ = af.Close()
		_ = os.Remove(archivePath)
		return err
	}
	if err := af.Close(); err != nil {
		_ = os.Remove(archivePath)
		return err
	}
	if err := fsyncDir(filepath.Dir(filepath.Clean(archivePath))); err != nil {
		return err
	}
	_ = newBase
	return nil
}

// readFrameBytes 从日志文件中读取 [start,end) 的一帧原始字节。
func readFrameBytes(f *os.File, start, end int64) ([]byte, error) {
	buf := make([]byte, end-start)
	if _, err := f.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf, nil
}

// rewriteActive 用“新锚点 + 保留帧原文”原子替换活动日志文件。
func (s *Store) rewriteActive(anchorRaw []byte, kept []*Frame) error {
	tmpPath := s.path + tempLogSuffix
	nf, err := os.OpenFile(tmpPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("auditlog: create temp log: %w", err)
	}
	abort := func(e error) error {
		_ = nf.Close()
		_ = os.Remove(tmpPath)
		return e
	}
	if _, err := nf.Write(anchorRaw); err != nil {
		return abort(err)
	}
	for _, fr := range kept {
		raw, err := readFrameBytes(s.f, fr.Offset, fr.End)
		if err != nil {
			return abort(err)
		}
		if _, err := nf.Write(raw); err != nil {
			return abort(err)
		}
	}
	if err := nf.Sync(); err != nil {
		return abort(fmt.Errorf("auditlog: fsync temp log: %w", err))
	}
	if err := nf.Close(); err != nil {
		return abort(err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return abort(fmt.Errorf("auditlog: replace log: %w", err))
	}
	if err := fsyncDir(filepath.Dir(s.path)); err != nil {
		return err
	}

	// 重新打开替换后的文件，并核对其自洽性后再更新锚点。
	nf2, err := os.OpenFile(s.path, os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	fi, err := nf2.Stat()
	if err != nil {
		_ = nf2.Close()
		return err
	}
	rep, prob := verifyChain(nf2, fi.Size())
	if prob != nil {
		_ = nf2.Close()
		return prob
	}
	_ = s.f.Close()
	s.f = nf2
	s.lastSeq = rep.LastSeq
	s.lastHash = rep.LastHash
	if nr := newestRecord(rep.Frames); nr != nil {
		s.lastTime = nr.Time
	} else {
		s.lastTime = time.Time{}
	}
	return s.commitCheckpoint(rep.LastOffset, true)
}

// Close 正常收尾：锚点在每次 Append/Purge 后均已落盘，这里释放句柄与锁。
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.closeFiles()
}

func (s *Store) closeFiles() error {
	var firstErr error
	if s.f != nil {
		if err := s.f.Close(); err != nil {
			firstErr = err
		}
		s.f = nil
	}
	if s.lock != nil {
		if err := s.lock.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.lock = nil
	}
	return firstErr
}
