package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	logFileName    = "audit.log"
	archiveDirName = "archive"
)

// Store 是以本地文件承载的审计日志存储。
//
// 并发模型：进程内所有 Append/Purge/Archive/Close 由 mu 串行化；
// 进程间由数据目录上的 flock 互斥。因此每条记录的序号与链条全局一致，
// 不会出现两个写入方占用同一位置。
type Store struct {
	dir   string
	clock func() time.Time
	lock  *fileLock

	mu       sync.Mutex
	log      *os.File
	cp       *checkpoint
	healthy  bool // 已确认收尾正常、允许追加
	closed   bool
	lastDiag Diagnostic
}

func logPath(dir string) string { return filepath.Join(dir, logFileName) }

// Append 追加一条审计记录。
//
// 崩溃安全协议（在持锁状态下完成）：
//  1. 依据检查点的 LastSeq/LastHash 计算新序号与 prev_hash；
//  2. 以 O_APPEND 写入“一行 JSON + '\n'”，'\n' 即提交标记；
//  3. fsync 日志文件，使提交落盘；
//  4. 原子更新检查点并 fsync 目录。
//
// 进程在 2 的 '\n' 之前死亡 => 重启看到悬空字节，拒绝续写；
// 在 2 与 4 之间死亡 => 记录已提交、检查点滞后，诊断为“可恢复”，
// 不会出现重复序号或断链。
func (s *Store) Append(actor, action, resource, detail string, at time.Time) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrNotOpen
	}
	if !s.healthy {
		return nil, fmt.Errorf("%w: store is not in a verified clean state; run Diagnose/Recover before appending", ErrUncleanTail)
	}
	if at.IsZero() {
		at = s.clock()
	}
	r := &Record{
		Seq:      s.cp.LastSeq + 1,
		Time:     at.Unix(),
		Actor:    actor,
		Action:   action,
		Resource: resource,
		Detail:   detail,
		PrevHash: s.cp.LastHash,
	}
	// 空日志（全新，或此前全部被清理/归档）时，前驱回退到检查点锚点。
	if r.PrevHash == "" {
		r.PrevHash = s.cp.HeadAnchor
	}
	if s.cp.LastSeq == 0 && s.cp.HeadSeq == 1 {
		// 全新链条：前驱指向固定创世哈希。
		r.PrevHash = genesisPrevHash()
	}
	if err := r.validateFields(); err != nil {
		return nil, err
	}
	r.SelfHash = hashRecord(r)

	line, err := marshalLine(r)
	if err != nil {
		return nil, fmt.Errorf("encode record: %w", err)
	}
	line = append(line, '\n')
	if _, err := s.log.Write(line); err != nil {
		return nil, fmt.Errorf("write record: %w", err)
	}
	if err := s.log.Sync(); err != nil {
		return nil, fmt.Errorf("sync record: %w", err)
	}

	newCP := *s.cp
	newCP.LastSeq = r.Seq
	newCP.LastHash = r.SelfHash
	if newCP.LastSeq == 1 {
		newCP.HeadSeq = 1
	}
	newCP.UpdatedAt = s.clock().Unix()
	if err := saveCheckpoint(s.dir, &newCP); err != nil {
		// 记录已提交而检查点未更新：不假装成功，下一次重启会走“检查点滞后”恢复路径。
		return nil, fmt.Errorf("record seq=%d is committed but checkpoint update failed: %w", r.Seq, err)
	}
	s.cp = &newCP
	return r, nil
}

// Verify 在当前锁保护下重放全部现存记录并给出完整性结论。
func (s *Store) Verify() (VerifyReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return VerifyReport{}, ErrNotOpen
	}
	rep, _, err := verifyLogFile(s.dir, s.cp)
	if err != nil {
		return rep, err
	}
	return rep, nil
}

// Diagnose 报告日志文件与检查点的收尾状态，不做任何修改。
// 状态可疑时同时返回非 nil 错误（可用 errors.Is 分类），但 Diagnostic 仍可用于解释原因。
func (s *Store) Diagnose() (Diagnostic, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Diagnostic{}, ErrNotOpen
	}
	diag := diagnose(s.dir, s.cp)
	s.lastDiag = diag
	if diag.Clean {
		return diag, nil
	}
	return diag, diagError(diag)
}

// HeadSeq / LastSeq 返回检查点确认的链条边界。
func (s *Store) HeadSeq() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cp == nil {
		return 0
	}
	return s.cp.HeadSeq
}

func (s *Store) LastSeq() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cp == nil {
		return 0
	}
	return s.cp.LastSeq
}

// Close 刷新日志并释放目录锁。
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.healthy = false
	var err error
	if s.log != nil {
		err = s.log.Close()
	}
	if lerr := s.lock.release(); lerr != nil && err == nil {
		err = lerr
	}
	return err
}

// verifyLogFile 依据检查点扫描并校验活动日志，生成报告与解析后的记录。
func verifyLogFile(dir string, cp *checkpoint) (VerifyReport, []*Record, error) {
	rep := VerifyReport{VerifiedAt: time.Time{}}
	path := logPath(dir)
	lines, dangling, size, err := scanFile(path)
	if err != nil && !os.IsNotExist(err) {
		return rep, nil, fmt.Errorf("read log: %w", err)
	}
	rep.VerifiedAt = time.Now()
	_ = size

	if len(dangling) > 0 {
		rep.OK = false
		rep.Reason = fmt.Sprintf("%d dangling byte(s) after last newline: last append was not finalized", len(dangling))
		return rep, nil, &integrityFailure{0, rep.Reason}
	}
	if cp == nil {
		rep.OK = false
		rep.Reason = "no checkpoint available"
		return rep, nil, &integrityFailure{0, rep.Reason}
	}
	records, fail := verifyChain(lines, cp.HeadSeq, cp.HeadAnchor)
	fillReportFromRecords(&rep, cp.HeadSeq, records)
	if fail != nil {
		rep.OK = false
		rep.ProblemSeq = fail.problemSeq
		rep.Reason = fail.reason
		return rep, records, fmt.Errorf("%w: %s", ErrLogTampered, fail.reason)
	}
	// 空日志：现存边界停在 head 之前（全新日志 head=1 时为 0）。
	fileLast := rep.LastSeq
	if rep.Records == 0 {
		fileLast = cp.HeadSeq - 1
	}
	switch {
	case fileLast < cp.LastSeq:
		rep.OK = false
		rep.Reason = fmt.Sprintf(
			"records were deleted after last verified checkpoint: file ends at seq=%d lastHash=%s, checkpoint proves seq=%d lastHash=%s",
			fileLast, rep.LastHash, cp.LastSeq, cp.LastHash)
		return rep, records, fmt.Errorf("%w: %s", ErrCheckpointMismatch, rep.Reason)
	case fileLast > cp.LastSeq:
		rep.OK = false
		rep.Reason = fmt.Sprintf("committed records reach seq=%d but checkpoint only acknowledges seq=%d (unfinalized append)",
			fileLast, cp.LastSeq)
		return rep, records, fmt.Errorf("%w: %s", ErrCheckpointMismatch, rep.Reason)
	case rep.Records > 0 && rep.LastHash != cp.LastHash:
		rep.OK = false
		rep.Reason = fmt.Sprintf("last hash mismatch: file=%s checkpoint=%s", rep.LastHash, cp.LastHash)
		return rep, records, fmt.Errorf("%w: %s", ErrCheckpointMismatch, rep.Reason)
	}
	rep.OK = true
	if rep.Records == 0 {
		rep.Reason = fmt.Sprintf("empty log, next seq=%d", cp.HeadSeq)
	} else {
		rep.Reason = fmt.Sprintf("chain intact: %d record(s) seq %d..%d verified against checkpoint",
			rep.Records, rep.HeadSeq, rep.LastSeq)
	}
	return rep, records, nil
}

func fillReportFromRecords(rep *VerifyReport, expectHeadSeq int64, records []*Record) {
	rep.Records = int64(len(records))
	if len(records) == 0 {
		rep.HeadSeq = expectHeadSeq
		return
	}
	rep.FirstSeq = records[0].Seq
	rep.HeadSeq = records[0].Seq
	rep.LastSeq = records[len(records)-1].Seq
	rep.FirstPrevHash = records[0].PrevHash
	rep.LastHash = records[len(records)-1].SelfHash
	rep.LastTime = records[len(records)-1].Time
}
