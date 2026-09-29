package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PurgeResult 是一次清理操作的结论。
type PurgeResult struct {
	// Removed 被删除的记录条数。
	Removed int64
	// FirstSeq / LastSeq 被删除记录的序号范围。
	FirstSeq int64
	LastSeq  int64
	// NewHeadSeq 清理后现存第一条记录的序号（可能是“下一条未使用序号”）。
	NewHeadSeq int64
}

// PurgeOptions 控制清理行为。
type PurgeOptions struct {
	// Now 判定保留资格所用的当前时间；零值取存储时钟。
	Now time.Time
}

// ArchiveOptions 控制归档行为。
type ArchiveOptions struct {
	// Dir 归档输出目录；为空时使用数据目录下的 archive 子目录。
	Dir string
	// Now 判定保留资格所用的当前时间；零值取存储时钟。
	Now time.Time
}

// Purge 按保留策略删除过期记录。
//
// 只允许删除“日志前缀中连续符合资格”的记录；中途遇到任何一条不符合资格
// 的记录即停止。这样剩余链条的起点明确，锚点可随之迁移，校验不会被破坏。
func (s *Store) Purge(policy RetentionPolicy, opts PurgeOptions) (PurgeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guardWritable(); err != nil {
		return PurgeResult{}, err
	}
	if err := policy.Validate(); err != nil {
		return PurgeResult{}, err
	}
	now := opts.Now
	if now.IsZero() {
		now = s.clock()
	}
	records, err := s.currentRecords()
	if err != nil {
		return PurgeResult{}, err
	}
	cutoff := findEligiblePrefix(records, policy, s.cp.LastSeq, now)
	if cutoff == 0 {
		return PurgeResult{}, classifyNoRemoval(records, policy, s.cp.LastSeq, now)
	}
	return s.rewriteAfterRemoval(records, cutoff, "purge", now, "", "")
}

// PurgeBefore 显式请求清理序号 <= uptoSeq 且业务时间 < before 的前缀。
//
// 它必须同时满足保留策略，否则给出可区分的拒绝原因：
//   - ErrInvalidRetention：策略本身非法；
//   - ErrPurgeConflict：请求范围越过了尾部保护区（KeepLatest）；
//   - ErrRecordsNotEligible：范围内存在 MinAge 尚未到期的记录；
//   - ErrNothingToPurge：请求范围内没有任何现存记录。
func (s *Store) PurgeBefore(policy RetentionPolicy, uptoSeq int64, before time.Time) (PurgeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guardWritable(); err != nil {
		return PurgeResult{}, err
	}
	if err := policy.Validate(); err != nil {
		return PurgeResult{}, err
	}
	records, err := s.currentRecords()
	if err != nil {
		return PurgeResult{}, err
	}
	if len(records) == 0 {
		return PurgeResult{}, fmt.Errorf("%w: log is empty", ErrNothingToPurge)
	}
	if uptoSeq < records[0].Seq {
		return PurgeResult{}, fmt.Errorf("%w: requested uptoSeq=%d but head seq=%d",
			ErrNothingToPurge, uptoSeq, records[0].Seq)
	}
	// 请求命中的现存记录区间。
	end := -1
	for i, r := range records {
		if r.Seq <= uptoSeq && r.Time < before.Unix() {
			end = i
		}
		if r.Seq > uptoSeq {
			break
		}
	}
	if end < 0 {
		return PurgeResult{}, fmt.Errorf("%w: no record with seq<=%d and time<%s",
			ErrNothingToPurge, uptoSeq, before.Format(time.RFC3339))
	}
	// 范围内若存在不满足策略资格的记录，必须明确拒绝（不得悄悄跳过）。
	for i := 0; i <= end; i++ {
		r := records[i]
		if policy.KeepLatest > 0 && r.Seq > s.cp.LastSeq-policy.KeepLatest {
			return PurgeResult{}, fmt.Errorf("%w: seq=%d is inside KeepLatest=%d protection zone",
				ErrPurgeConflict, r.Seq, policy.KeepLatest)
		}
		if r.Time > before.Add(-policy.MinAge).Unix() {
			return PurgeResult{}, fmt.Errorf(
				"%w: seq=%d time=%s is younger than MinAge=%s relative to requested before=%s",
				ErrRecordsNotEligible, r.Seq,
				time.Unix(r.Time, 0).UTC().Format(time.RFC3339), policy.MinAge,
				before.Format(time.RFC3339))
		}
	}
	// 紧接请求区间的下一条记录如果仍显式落在 uptoSeq/before 范围内却没被选中，
	// 说明删除会在中间留洞——拒绝。
	if end+1 < len(records) {
		nxt := records[end+1]
		if nxt.Seq <= uptoSeq {
			return PurgeResult{}, fmt.Errorf(
				"%w: seq=%d falls within requested range but is not eligible; refusing to leave a gap",
				ErrRecordsNotEligible, nxt.Seq)
		}
	}
	return s.rewriteAfterRemoval(records, end+1, "purge-before", before, "", "")
}

// Archive 按保留策略把过期前缀移动到归档文件，并让剩余日志仍可独立校验。
func (s *Store) Archive(policy RetentionPolicy, opts ArchiveOptions) (ArchiveReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guardWritable(); err != nil {
		return ArchiveReport{}, err
	}
	if err := policy.Validate(); err != nil {
		return ArchiveReport{}, err
	}
	now := opts.Now
	if now.IsZero() {
		now = s.clock()
	}
	records, err := s.currentRecords()
	if err != nil {
		return ArchiveReport{}, err
	}
	cutoff := findEligiblePrefix(records, policy, s.cp.LastSeq, now)
	if cutoff == 0 {
		err := classifyNoRemoval(records, policy, s.cp.LastSeq, now)
		return ArchiveReport{}, err
	}

	archDir := opts.Dir
	if archDir == "" {
		archDir = filepath.Join(s.dir, archiveDirName)
	}
	if err := os.MkdirAll(archDir, 0o700); err != nil {
		return ArchiveReport{}, fmt.Errorf("create archive dir: %w", err)
	}
	archived := records[:cutoff]
	first := archived[0]
	last := archived[len(archived)-1]
	name := fmt.Sprintf("audit-%010d-%010d.log", first.Seq, last.Seq)
	archPath := filepath.Join(archDir, name)
	if _, err := os.Stat(archPath); err == nil {
		return ArchiveReport{}, fmt.Errorf("archive file already exists: %s", archPath)
	}

	if err := writeArchiveFile(archPath, archived, first.PrevHash); err != nil {
		return ArchiveReport{}, err
	}
	// 写一份随附清单：记录归档区间与首尾哈希，便于独立核对衔接关系。
	manifest := map[string]any{
		"version":     1,
		"path":        filepath.Base(archPath),
		"first_seq":   first.Seq,
		"last_seq":    last.Seq,
		"count":       len(archived),
		"head_anchor": first.PrevHash,
		"last_hash":   last.SelfHash,
		"archived_at": now.Unix(),
	}
	mb, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(archPath+".manifest.json", mb, 0o600); err != nil {
		return ArchiveReport{}, fmt.Errorf("write archive manifest: %w", err)
	}
	if _, err := VerifyArchive(archPath); err != nil {
		return ArchiveReport{}, fmt.Errorf("freshly written archive failed self-verification: %w", err)
	}

	res, err := s.rewriteAfterRemoval(records, cutoff, "archive", now,
		archPath, last.SelfHash)
	if err != nil {
		return ArchiveReport{}, err
	}
	return ArchiveReport{
		Archived:   res.Removed,
		FirstSeq:   res.FirstSeq,
		LastSeq:    res.LastSeq,
		Path:       archPath,
		NewHeadSeq: res.NewHeadSeq,
		Created:    true,
	}, nil
}

// VerifyArchive 独立校验归档文件：序号必须连续、哈希链完整。
//
// 归档段可能不是整条链的第一段（此前已经清理/归档过更早的记录），
// 因此链首锚点优先取同目录下的 .manifest.json；没有清单时退化为
// “必须从 seq=1、创世哈希开始”，避免在无凭据时给出虚假结论。
func VerifyArchive(path string) (VerifyReport, error) {
	lines, dangling, _, err := scanFile(path)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("read archive: %w", err)
	}
	if len(dangling) > 0 {
		return VerifyReport{}, fmt.Errorf("%w: archive has %d dangling bytes", ErrLogTampered, len(dangling))
	}
	if len(lines) == 0 {
		return VerifyReport{}, fmt.Errorf("%w: archive is empty", ErrLogTampered)
	}
	headSeq, headAnchor, err := archiveProvenance(path, lines)
	if err != nil {
		return VerifyReport{}, err
	}
	records, fail := verifyChain(lines, headSeq, headAnchor)
	rep := VerifyReport{VerifiedAt: time.Now()}
	fillReportFromRecords(&rep, headSeq, records)
	if fail != nil {
		rep.OK = false
		rep.ProblemSeq = fail.problemSeq
		rep.Reason = fail.reason
		return rep, fmt.Errorf("%w: %s", ErrLogTampered, fail.reason)
	}
	rep.OK = true
	rep.Reason = fmt.Sprintf("archive intact: %d record(s) seq %d..%d anchored at %s",
		rep.Records, headSeq, rep.LastSeq, shortHash(headAnchor))
	return rep, nil
}

// archiveProvenance 决定归档段的链首锚点。
func archiveProvenance(path string, firstLines [][]byte) (int64, string, error) {
	first, err := unmarshalLine(firstLines[0])
	if err != nil {
		return 0, "", fmt.Errorf("%w: archive first line invalid: %v", ErrLogTampered, err)
	}
	mb, mErr := os.ReadFile(path + ".manifest.json")
	if mErr == nil {
		var m struct {
			FirstSeq   int64  `json:"first_seq"`
			HeadAnchor string `json:"head_anchor"`
		}
		if err := json.Unmarshal(mb, &m); err != nil {
			return 0, "", fmt.Errorf("%w: archive manifest invalid: %v", ErrLogTampered, err)
		}
		if m.FirstSeq != first.Seq {
			return 0, "", fmt.Errorf("%w: manifest first_seq=%d but file starts at %d",
				ErrLogTampered, m.FirstSeq, first.Seq)
		}
		return m.FirstSeq, m.HeadAnchor, nil
	}
	if !os.IsNotExist(mErr) {
		return 0, "", fmt.Errorf("read archive manifest: %w", mErr)
	}
	// 无清单：仅接受真正的链首。
	if first.Seq != 1 || first.PrevHash != genesisPrevHash() {
		return 0, "", fmt.Errorf(
			"%w: archive starts at seq=%d without manifest; cannot prove its predecessor",
			ErrLogTampered, first.Seq)
	}
	return 1, genesisPrevHash(), nil
}

func shortHash(h string) string {
	if len(h) <= 16 {
		return h
	}
	return h[:16] + "..."
}

// ---- 内部实现 ----

func (s *Store) guardWritable() error {
	if s.closed {
		return ErrNotOpen
	}
	if !s.healthy {
		return fmt.Errorf("%w: store is not in a verified clean state", ErrUncleanTail)
	}
	return nil
}

// currentRecords 读取并校验活动日志，返回现存记录（必须与检查点一致）。
func (s *Store) currentRecords() ([]*Record, error) {
	_, records, err := verifyLogFile(s.dir, s.cp)
	if err != nil {
		return nil, err
	}
	return records, nil
}

// findEligiblePrefix 返回前缀中连续符合资格的记录条数。
func findEligiblePrefix(records []*Record, p RetentionPolicy, lastSeq int64, now time.Time) int {
	cutoff := 0
	for _, r := range records {
		if !p.Eligible(r, lastSeq, now) {
			break
		}
		cutoff++
	}
	return cutoff
}

// classifyNoRemoval 在没有可删前缀时，区分“被什么规则挡住”。
func classifyNoRemoval(records []*Record, p RetentionPolicy, lastSeq int64, now time.Time) error {
	if len(records) == 0 {
		return fmt.Errorf("%w: log is empty", ErrNothingToPurge)
	}
	head := records[0]
	if p.KeepLatest > 0 && head.Seq > lastSeq-p.KeepLatest {
		return fmt.Errorf("%w: head seq=%d is inside KeepLatest=%d protection zone",
			ErrPurgeConflict, head.Seq, p.KeepLatest)
	}
	return fmt.Errorf("%w: head seq=%d time=%s has not reached MinAge=%s (now=%s)",
		ErrRecordsNotEligible, head.Seq,
		time.Unix(head.Time, 0).UTC().Format(time.RFC3339), p.MinAge,
		now.UTC().Format(time.RFC3339))
}

// rewriteAfterRemoval 把 records[cutoff:] 原子地替换为新的活动日志，
// 并把检查点的 head 锚点迁移到被删前缀最后一条记录的自身哈希。
func (s *Store) rewriteAfterRemoval(records []*Record, cutoff int, kind string, now time.Time,
	archivePath string, archiveLastHash string) (PurgeResult, error) {
	if cutoff <= 0 || cutoff > len(records) {
		return PurgeResult{}, fmt.Errorf("internal error: bad cutoff %d", cutoff)
	}
	removed := records[:cutoff]
	kept := records[cutoff:]
	lastRemoved := removed[len(removed)-1]

	var newHeadSeq int64
	if len(kept) > 0 {
		newHeadSeq = kept[0].Seq
	} else {
		newHeadSeq = lastRemoved.Seq + 1
	}

	// 1) 组装新日志内容并自校验剩余链条（其 prev_hash 天然指向被删前缀尾部）。
	var buf []byte
	for _, r := range kept {
		line, err := marshalLine(r)
		if err != nil {
			return PurgeResult{}, err
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	checkLines, dangling, _ := splitForCheck(buf)
	if len(dangling) > 0 {
		return PurgeResult{}, fmt.Errorf("internal error: rebuilt log has dangling bytes")
	}
	if _, fail := verifyChain(checkLines, newHeadSeq, lastRemoved.SelfHash); fail != nil {
		return PurgeResult{}, fmt.Errorf("%w: rebuilt log failed self-verification: %s",
			ErrLogTampered, fail.reason)
	}

	// 2) 两阶段提交：临时文件 -> pending 标记 -> rename -> 检查点 -> 删标记。
	tmp := logPath(s.dir) + ".rewrite.tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return PurgeResult{}, fmt.Errorf("create rewrite temp: %w", err)
	}
	if _, err := f.Write(buf); err != nil {
		f.Close()
		return PurgeResult{}, fmt.Errorf("write rewrite temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return PurgeResult{}, err
	}
	if err := f.Close(); err != nil {
		return PurgeResult{}, err
	}

	newCP := &checkpoint{
		HeadSeq:    newHeadSeq,
		HeadAnchor: lastRemoved.SelfHash,
		LastSeq:    s.cp.LastSeq,
		LastHash:   s.cp.LastHash,
		UpdatedAt:  now.Unix(),
	}
	if len(kept) == 0 {
		newCP.LastSeq = newHeadSeq - 1
		newCP.LastHash = ""
	}
	pending := &rewritePending{
		TempPath:   tmp,
		Old:        *s.cp,
		New:        *newCP,
		Kind:       kind,
		Archive:    archivePath,
		ArchLastH:  archiveLastHash,
		RemovedN:   int64(len(removed)),
		RemovedFst: removed[0].Seq,
		RemovedLst: lastRemoved.Seq,
		At:         now.Unix(),
	}
	if err := pending.save(s.dir); err != nil {
		return PurgeResult{}, fmt.Errorf("write rewrite marker: %w", err)
	}

	// 3) 自此 rename 之后事务只能前滚：切换日志文件。
	if s.log != nil {
		_ = s.log.Close()
		s.log = nil
	}
	if err := os.Rename(tmp, logPath(s.dir)); err != nil {
		// rename 失败：日志仍是旧的，下次打开按标记回滚；本次返回错误。
		return PurgeResult{}, fmt.Errorf("install rewritten log: %w", err)
	}
	if err := syncDir(s.dir); err != nil {
		return PurgeResult{}, err
	}
	nf, err := os.OpenFile(logPath(s.dir), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return PurgeResult{}, fmt.Errorf("reopen rewritten log: %w", err)
	}
	s.log = nf

	// 4) 切换检查点到新边界。
	if err := saveCheckpoint(s.dir, newCP); err != nil {
		return PurgeResult{}, err
	}
	s.cp = newCP

	// 5) 事务完成：删标记并落盘目录。
	if err := os.Remove(pendingPath(s.dir)); err != nil {
		return PurgeResult{}, err
	}
	if err := syncDir(s.dir); err != nil {
		return PurgeResult{}, err
	}

	// 6) 记录一条清理/归档事件（仅用于可追溯，不参与哈希链校验）。
	ev := map[string]any{
		"event":             kind,
		"at":                now.Unix(),
		"removed_first_seq": removed[0].Seq,
		"removed_last_seq":  lastRemoved.Seq,
		"removed_count":     len(removed),
		"new_head_seq":      newHeadSeq,
		"new_head_anchor":   lastRemoved.SelfHash,
	}
	if archivePath != "" {
		ev["archive_path"] = archivePath
		ev["archive_last_hash"] = archiveLastHash
	}
	_ = appendEventLog(s.dir, ev)

	res := PurgeResult{
		Removed:    int64(len(removed)),
		FirstSeq:   removed[0].Seq,
		LastSeq:    lastRemoved.Seq,
		NewHeadSeq: newHeadSeq,
	}

	// 5) 替换后立刻全量校验，给出确定结论。
	diag := diagnose(s.dir, s.cp)
	if !diag.Clean {
		return res, fmt.Errorf("%w: post-%s verification failed: %s", ErrLogTampered, kind, diag.Reason)
	}
	return res, nil
}

func splitForCheck(b []byte) ([][]byte, []byte, int64) {
	return scanBytes(b)
}
