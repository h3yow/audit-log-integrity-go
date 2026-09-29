package audit

import (
	"os"
	"testing"
	"time"
)

// crashBeforeRename 手工构造“临时文件 + pending 标记已写、rename 尚未发生”的崩溃现场。
func crashBeforeRename(t *testing.T, dir string, p *rewritePending) {
	t.Helper()
	// 临时文件内容必须与 p.New 一致（协议第一步保证）。
	_, records, err := verifyLogFile(dir, &p.Old)
	if err != nil {
		t.Fatal(err)
	}
	var buf []byte
	for _, r := range records {
		if r.Seq >= p.New.HeadSeq && r.Seq <= p.New.LastSeq {
			b, _ := marshalLine(r)
			buf = append(buf, b...)
			buf = append(buf, '\n')
		}
	}
	if err := os.WriteFile(p.TempPath, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.save(dir); err != nil {
		t.Fatal(err)
	}
}

// crashAfterRename 构造“audit.log 已替换、检查点仍旧、标记仍在”的崩溃现场。
func crashAfterRename(t *testing.T, dir string, p *rewritePending) {
	t.Helper()
	crashBeforeRename(t, dir, p)
	if err := os.Rename(p.TempPath, logPath(dir)); err != nil {
		t.Fatal(err)
	}
	if err := syncDir(dir); err != nil {
		t.Fatal(err)
	}
}

// buildPending 构造一次“删除前 cutoff 条”的 pending 计划（不实际执行）。
func buildPending(t *testing.T, dir string, oldCP *checkpoint, records []*Record, cutoff int, kind string, at time.Time) *rewritePending {
	t.Helper()
	removed := records[:cutoff]
	kept := records[cutoff:]
	lastRemoved := removed[len(removed)-1]
	newHead := lastRemoved.Seq + 1
	if len(kept) > 0 {
		newHead = kept[0].Seq
	}
	newCP := checkpoint{
		HeadSeq:    newHead,
		HeadAnchor: lastRemoved.SelfHash,
		LastSeq:    oldCP.LastSeq,
		LastHash:   oldCP.LastHash,
		UpdatedAt:  at.Unix(),
	}
	if len(kept) == 0 {
		newCP.LastSeq = newHead - 1
		newCP.LastHash = ""
	}
	return &rewritePending{
		Version:    1,
		TempPath:   logPath(dir) + ".rewrite.tmp",
		Old:        *oldCP,
		New:        newCP,
		Kind:       kind,
		RemovedN:   int64(len(removed)),
		RemovedFst: removed[0].Seq,
		RemovedLst: lastRemoved.Seq,
		At:         at.Unix(),
	}
}

// TestCrashBeforeRenameRollback rename 前崩溃：重开必须回滚到旧日志，数据一条不丢。
func TestCrashBeforeRenameRollback(t *testing.T) {
	s, dir := openFresh(t, 6)
	oldCP := *readCheckpoint(t, dir)
	_, records, err := verifyLogFile(dir, &oldCP)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	p := buildPending(t, dir, &oldCP, records, 3, "purge", t0.Add(48*time.Hour))
	crashBeforeRename(t, dir, p)
	t.Log("input: crash after temp file + marker written, before rename; audit.log still has seq 1..6")

	s2, diag, err := Open(dir, Options{Clock: func() time.Time { return t0.Add(48 * time.Hour) }})
	if err != nil {
		t.Fatalf("rollback should make open clean: %v (%s)", err, diag.Reason)
	}
	defer s2.Close()
	if s2.LastSeq() != 6 || s2.HeadSeq() != 1 {
		t.Fatalf("rollback must restore full log, got head=%d last=%d", s2.HeadSeq(), s2.LastSeq())
	}
	if _, statErr := os.Stat(pendingPath(dir)); !os.IsNotExist(statErr) {
		t.Fatal("pending marker must be removed after rollback")
	}
	mustVerify(t, s2, true)
	t.Logf("conclusion: rolled back to pre-purge state; %s", diag.Reason)
}

// TestCrashAfterRenameRollForward rename 后、检查点切换前崩溃：重开必须前滚到新边界。
func TestCrashAfterRenameRollForward(t *testing.T) {
	s, dir := openFresh(t, 6)
	oldCP := *readCheckpoint(t, dir)
	_, records, err := verifyLogFile(dir, &oldCP)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	p := buildPending(t, dir, &oldCP, records, 3, "purge", t0.Add(48*time.Hour))
	crashAfterRename(t, dir, p)
	t.Log("input: crash after rename, before checkpoint swap; audit.log now has only seq 4..6")

	s2, diag, err := Open(dir, Options{Clock: func() time.Time { return t0.Add(48 * time.Hour) }})
	if err != nil {
		t.Fatalf("roll-forward should make open clean: %v (%s)", err, diag.Reason)
	}
	defer s2.Close()
	if s2.HeadSeq() != 4 || s2.LastSeq() != 6 {
		t.Fatalf("roll-forward must land on new bounds head=4 last=6, got head=%d last=%d",
			s2.HeadSeq(), s2.LastSeq())
	}
	if _, statErr := os.Stat(pendingPath(dir)); !os.IsNotExist(statErr) {
		t.Fatal("pending marker must be removed after roll-forward")
	}
	mustVerify(t, s2, true)
	// 前滚后可继续追加，序号单调。
	r, err := s2.Append("grace", "post-2pc-crash", "r", "d", t0.Add(49*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if r.Seq != 7 {
		t.Fatalf("want seq=7 after roll-forward, got %d", r.Seq)
	}
	t.Logf("conclusion: rolled forward to post-purge state and resumed at seq=%d; %s", r.Seq, diag.Reason)
}

// TestInterruptedRewriteAmbiguous 日志既不匹配旧边界也不匹配新边界：必须拒绝猜测。
func TestInterruptedRewriteAmbiguous(t *testing.T) {
	s, dir := openFresh(t, 6)
	oldCP := *readCheckpoint(t, dir)
	_, records, err := verifyLogFile(dir, &oldCP)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	p := buildPending(t, dir, &oldCP, records, 3, "purge", t0.Add(48*time.Hour))
	crashBeforeRename(t, dir, p)
	// 再把旧日志的中间一条破坏掉 => 与旧、新边界都不匹配。
	lines := rawLines(t, dir)
	lines[4] = []byte(`{"seq":5,"broken`)
	rewriteLog(t, dir, lines)

	s2, _, err := Open(dir, Options{})
	if err == nil {
		s2.Close()
		t.Fatal("ambiguous interrupted rewrite must be rejected")
	}
	t.Logf("conclusion: ambiguous interrupted rewrite rejected: %v", err)
	s2.Close()
}
