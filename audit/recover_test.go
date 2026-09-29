package audit

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestCleanRestartContinue 正常收尾后重启：诊断干净、可安全续写、序号连续。
func TestCleanRestartContinue(t *testing.T) {
	s, dir := openFresh(t, 3)
	s2, diag, err := reopenStore(t, s, dir)
	if err != nil {
		t.Fatalf("clean reopen failed: %v (%s)", err, diag.Reason)
	}
	defer s2.Close()
	t.Logf("basis after restart: clean=%v reason=%s", diag.Clean, diag.Reason)
	if !diag.Clean {
		t.Fatal("want clean diagnosis")
	}
	r, err := s2.Append("eve", "resume", "sys", "clean restart", t0.Add(time.Hour))
	if err != nil {
		t.Fatalf("append after clean restart: %v", err)
	}
	if r.Seq != 4 {
		t.Fatalf("want seq=4, got %d", r.Seq)
	}
	t.Logf("conclusion: safely continued at seq=%d", r.Seq)
	mustVerify(t, s2, true)
}

// TestRestartDanglingBytes 模拟写入在换行符落盘前崩溃：
// 重启必须识别为未收尾并拒绝追加；Recover 截断悬空字节后可继续。
func TestRestartDanglingBytes(t *testing.T) {
	s, dir := openFresh(t, 3)
	sizeBefore := fileSize(t, dir)

	// 构造一条完整 JSON 记录，但故意不写换行：等于崩溃在提交点之前。
	var partial Record
	last, _ := unmarshalLine(rawLines(t, dir)[2])
	partial = Record{
		Seq: 4, Time: (t0.Add(time.Hour)).Unix(),
		Actor: "crash", Action: "half-written", Resource: "r", Detail: "d",
		PrevHash: last.SelfHash,
	}
	partial.SelfHash = hashRecord(&partial)
	b, _ := json.Marshal(partial)

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	appendRaw(t, dir, b, false)
	t.Logf("input: simulate crash mid-append: %d bytes without trailing newline (file grew %d -> %d)",
		len(b), sizeBefore, fileSize(t, dir))

	s2, diag, err := Open(dir, Options{})
	if err == nil {
		s2.Close()
		t.Fatal("Open must reject a dangling-tail log")
	}
	t.Logf("basis on reopen: problem=%q dangling=%d reason=%s",
		diag.Problem, diag.DanglingBytes, diag.Reason)
	if diag.DanglingBytes != int64(len(b)) {
		t.Fatalf("want %d dangling bytes, got %d", len(b), diag.DanglingBytes)
	}
	if _, aerr := s2.Append("x", "y", "z", "", t0); aerr == nil {
		t.Fatal("Append must be refused on a suspicious base")
	} else {
		t.Logf("conclusion: append refused before recovery: %v", aerr)
	}

	// Recover：截断到最后一个已提交换行，检查点不动（仍停在 seq=3）。
	post, rerr := s2.Recover()
	if rerr != nil {
		s2.Close()
		t.Fatalf("Recover of dangling tail failed: %v (%s)", rerr, post.Reason)
	}
	t.Logf("basis after recover: %s", post.Reason)
	if fileSize(t, dir) != sizeBefore {
		t.Fatalf("file must be truncated back to %d, got %d", sizeBefore, fileSize(t, dir))
	}
	r, err := s2.Append("eve", "after-recover", "sys", "ok", t0.Add(time.Hour))
	if err != nil {
		t.Fatalf("append after recover: %v", err)
	}
	if r.Seq != 4 {
		t.Fatalf("want resumed seq=4, got %d", r.Seq)
	}
	t.Logf("conclusion: dangling bytes truncated, safely resumed at seq=%d", r.Seq)
	mustVerify(t, s2, true)
	s2.Close()
}

// TestRestartCheckpointLag 记录已完整提交（含换行+fsync），但检查点更新前崩溃：
// 不得丢失数据，Recover 推进检查点，而不是重写出一条重复/断裂记录。
func TestRestartCheckpointLag(t *testing.T) {
	s, dir := openFresh(t, 3)
	cp := readCheckpoint(t, dir)
	t.Logf("input: checkpoint acknowledges lastSeq=%d; append a full committed line bypassing checkpoint",
		cp.LastSeq)

	lines := rawLines(t, dir)
	last, _ := unmarshalLine(lines[2])
	r4 := Record{
		Seq: 4, Time: t0.Add(time.Hour).Unix(),
		Actor: "crash", Action: "committed", Resource: "r", Detail: "d",
		PrevHash: last.SelfHash,
	}
	r4.SelfHash = hashRecord(&r4)
	line4, _ := json.Marshal(r4)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	appendRaw(t, dir, line4, true) // 带换行：视为已提交

	s2, diag, err := Open(dir, Options{})
	if err == nil {
		t.Fatal("Open must flag the unfinalized state (checkpoint lag)")
	}
	t.Logf("basis on reopen: problem=%q reason=%s", diag.Problem, diag.Reason)
	if diag.LastSeq != 4 {
		t.Fatalf("file physically contains seq=4, diag lastSeq=%d", diag.LastSeq)
	}

	post, rerr := s2.Recover()
	if rerr != nil {
		t.Fatalf("Recover should advance checkpoint without data loss: %v (%s)", rerr, post.Reason)
	}
	if s2.LastSeq() != 4 {
		t.Fatalf("after recover lastSeq must be 4 (no lost record), got %d", s2.LastSeq())
	}
	t.Logf("conclusion: %s", post.Reason)

	// 关键：续写必须是 seq=5，而不是重新占用 4 或断链。
	r5, err := s2.Append("frank", "post-crash", "sys", "ok", t0.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("append after checkpoint-lag recovery: %v", err)
	}
	if r5.Seq != 5 {
		t.Fatalf("want seq=5, got %d (duplicate position or broken chain)", r5.Seq)
	}
	if r5.PrevHash != r4.SelfHash {
		t.Fatal("new record must chain onto the recovered seq=4")
	}
	t.Logf("conclusion: resumed at seq=%d chained to recovered seq=4, no duplicate slot", r5.Seq)
	mustVerify(t, s2, true)
	s2.Close()
}

// TestRestartChainBreakIsNotAutoRecoverable 历史中被改写时，Recover 不允许“截断修复”
// 来掩盖问题——必须明确拒绝。
func TestRestartChainBreakIsNotAutoRecoverable(t *testing.T) {
	s, dir := openFresh(t, 4)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	lines := rawLines(t, dir)
	lines[1] = []byte(`{"seq":2,"time":1700000001,"actor":"x","action":"TAMPERED","resource":"r","detail":"d","prev_hash":"sha256:dead","self_hash":"sha256:beef"}`)
	rewriteLog(t, dir, lines)
	t.Log("input: rewrite seq=2 with bogus hashes, then restart + attempt Recover")

	s2, diag, err := Open(dir, Options{})
	if err == nil {
		t.Fatal("tampered log must not open cleanly")
	}
	t.Logf("basis on open: problem=%q reason=%s", diag.Problem, diag.Reason)
	if _, rerr := s2.Recover(); rerr == nil {
		t.Fatal("Recover must refuse to silently repair a broken hash chain")
	} else {
		t.Logf("conclusion: automatic recovery refused for broken chain: %v", rerr)
	}
	if _, aerr := s2.Append("x", "y", "z", "", t0); aerr == nil {
		t.Fatal("Append must stay disabled after failed recovery")
	}
	s2.Close()
}

// TestRestartCheckpointAhead 检查点声称的尾部超出文件（检查点被破坏或文件被换）：
// 无法区分是数据丢失还是检查点伪造，必须拒绝。
func TestRestartCheckpointAhead(t *testing.T) {
	s, dir := openFresh(t, 4)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// 只改检查点的 lastSeq，使其声称存在 seq=99。
	cp := readCheckpoint(t, dir)
	cp.LastSeq = 99
	if err := saveCheckpoint(dir, cp); err != nil {
		t.Fatal(err)
	}
	t.Log("input: forge checkpoint lastSeq=99 while file only has seq 1..4")

	s2, diag, err := Open(dir, Options{})
	if err == nil {
		t.Fatal("checkpoint-ahead inconsistency must be rejected at open")
	}
	t.Logf("basis: problem=%q reason=%s", diag.Problem, diag.Reason)
	s2.Close()
}

// TestRestartNoCheckpointWithLog 日志存在但检查点缺失：无凭据续写必须拒绝。
func TestRestartNoCheckpointWithLog(t *testing.T) {
	s, dir := openFresh(t, 3)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeCheckpoint(t, dir); err != nil {
		t.Fatal(err)
	}
	t.Log("input: delete checkpoint.json while audit.log retains 3 records")
	s2, diag, err := Open(dir, Options{})
	if err == nil {
		t.Fatal("must refuse to continue without checkpoint provenance")
	}
	t.Logf("basis: problem=%q reason=%s", diag.Problem, diag.Reason)
	s2.Close()
}

// TestRestartLogFileDeleted 检查点证明有记录但日志文件整体被删：必须拒绝新建空日志续写。
func TestRestartLogFileDeleted(t *testing.T) {
	s, dir := openFresh(t, 3)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(logPath(dir)); err != nil {
		t.Fatal(err)
	}
	t.Log("input: delete audit.log entirely while checkpoint proves seq 1..3")
	s2, diag, err := Open(dir, Options{})
	if err == nil {
		s2.Close()
		t.Fatal("missing log file with non-empty checkpoint must be rejected")
	}
	t.Logf("basis: problem=%q reason=%s", diag.Problem, diag.Reason)
	s2.Close()
}
