package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestVerifyHealthyChain 正常写入与校验路径（回归基线）。
func TestVerifyHealthyChain(t *testing.T) {
	s, _ := openFresh(t, 5)
	rep := mustVerify(t, s, true)
	if rep.HeadSeq != 1 || rep.LastSeq != 5 || rep.Records != 5 {
		t.Fatalf("unexpected bounds: %+v", rep)
	}
	if rep.FirstPrevHash != genesisPrevHash() {
		t.Fatalf("head anchor must be genesis, got %s", rep.FirstPrevHash)
	}
	t.Logf("conclusion: healthy chain seq %d..%d, head anchor=%s, last=%s",
		rep.HeadSeq, rep.LastSeq, rep.FirstPrevHash[:14], rep.LastHash[:14])
}

// TestTamperModifyMiddle 改写中间一条记录的内容，self_hash 未变 => 内容哈希不符。
func TestTamperModifyMiddle(t *testing.T) {
	s, dir := openFresh(t, 5)

	lines := rawLines(t, dir)
	var rec Record
	if err := json.Unmarshal(lines[2], &rec); err != nil {
		t.Fatal(err)
	}
	t.Logf("input: tamper seq=%d field action %q -> %q (hash fields untouched)",
		rec.Seq, rec.Action, "HACKED")
	rec.Action = "HACKED"
	bad, _ := json.Marshal(rec)
	lines[2] = bad
	rewriteLog(t, dir, lines)

	rep, err := s.Verify()
	if err == nil || rep.OK {
		t.Fatalf("conclusion: modification undetected! rep=%+v", rep)
	}
	t.Logf("basis: %s", rep.Reason)
	if rep.ProblemSeq != 3 {
		t.Fatalf("want problem located at seq=3, got %d", rep.ProblemSeq)
	}
	if !strings.Contains(rep.Reason, "content hash mismatch") {
		t.Fatalf("want content hash mismatch, got %s", rep.Reason)
	}
	t.Logf("conclusion: tamper detected and located at seq=%d", rep.ProblemSeq)
}

// TestTamperRehashMiddle 改写中间记录并伪造 self_hash => 下一条的 prev 对不上，
// 问题必须定位到被插入/改写位置之后的第一条记录（链条断裂点）。
func TestTamperRehashMiddle(t *testing.T) {
	s, dir := openFresh(t, 5)
	lines := rawLines(t, dir)

	var rec Record
	json.Unmarshal(lines[1], &rec)
	rec.Action = "ELEVATED"
	rec.SelfHash = hashRecord(&rec) // 伪造自洽的 self_hash
	lines[1], _ = json.Marshal(rec)
	rewriteLog(t, dir, lines)

	t.Logf("input: rewrite seq=%d and forge its self_hash=%s", rec.Seq, rec.SelfHash[:14])
	rep, err := s.Verify()
	if err == nil || rep.OK {
		t.Fatal("forged record undetected")
	}
	if rep.ProblemSeq != 3 {
		t.Fatalf("broken link must surface at seq=3 (first record trusting the forged one), got %d", rep.ProblemSeq)
	}
	t.Logf("basis: %s", rep.Reason)
	t.Logf("conclusion: forged-hash tamper detected at chain break seq=%d", rep.ProblemSeq)
}

// TestTamperDeleteMiddle 删除中间一条 => 后续 prev_hash 与前一条 self_hash 对不上。
func TestTamperDeleteMiddle(t *testing.T) {
	s, dir := openFresh(t, 5)
	lines := rawLines(t, dir)
	t.Logf("input: physically delete seq=3 line (file now has 4 lines)")
	lines = append(lines[:2], lines[3:]...)
	rewriteLog(t, dir, lines)

	rep, err := s.Verify()
	if err == nil || rep.OK {
		t.Fatal("deletion undetected")
	}
	t.Logf("basis: %s", rep.Reason)
	// 删除位置是 3：第 3 行原来是 seq=4，其 prev_hash 指向旧 seq=2 => 在 seq=4 处断链。
	if rep.ProblemSeq != 4 {
		t.Fatalf("want problem seq=4, got %d", rep.ProblemSeq)
	}
	t.Logf("conclusion: deletion detected at seq=%d", rep.ProblemSeq)
}

// TestTamperInsert 插入一条伪造记录 => 序号冲突/断链。
func TestTamperInsert(t *testing.T) {
	s, dir := openFresh(t, 5)
	lines := rawLines(t, dir)

	var r2 Record
	json.Unmarshal(lines[1], &r2)
	fake := r2
	fake.Action = "INJECTED"
	fake.SelfHash = hashRecord(&fake)
	fakeLine, _ := json.Marshal(fake)
	newLines := make([][]byte, 0, len(lines)+1)
	newLines = append(newLines, lines[0], fakeLine)
	newLines = append(newLines, lines[1:]...)
	rewriteLog(t, dir, newLines)

	t.Logf("input: insert forged record (copied seq=%d with different action) at position 2", fake.Seq)
	rep, err := s.Verify()
	if err == nil || rep.OK {
		t.Fatal("insertion undetected")
	}
	t.Logf("basis: %s", rep.Reason)
	t.Logf("conclusion: insertion detected at problem seq=%d", rep.ProblemSeq)
}

// TestTamperTruncateTail 仅删除尾部记录（链前缀仍然自洽）=> 必须靠检查点发现。
func TestTamperTruncateTail(t *testing.T) {
	s, dir := openFresh(t, 5)
	lines := rawLines(t, dir)
	rewriteLog(t, dir, lines[:3]) // 物理删掉 seq=4,5

	t.Logf("input: truncate tail, keep seq 1..3 (checkpoint still says lastSeq=5)")
	rep, err := s.Verify()
	if err == nil || rep.OK {
		t.Fatal("tail truncation undetected")
	}
	t.Logf("basis: %s", rep.Reason)
	if !strings.Contains(rep.Reason, "records were deleted") {
		t.Fatalf("want checkpoint-based deletion detection, got %s", rep.Reason)
	}
	t.Log("conclusion: suffix deletion detected via checkpoint boundary")
}

// TestTamperCorruptJSON 破坏一行 JSON => 定位到具体序号。
func TestTamperCorruptJSON(t *testing.T) {
	s, dir := openFresh(t, 5)
	lines := rawLines(t, dir)
	lines[3] = []byte(`{"seq":4,broken`)
	rewriteLog(t, dir, lines)
	t.Log("input: corrupt JSON on seq=4 line")
	rep, err := s.Verify()
	if err == nil || rep.OK {
		t.Fatal("corruption undetected")
	}
	if rep.ProblemSeq != 4 {
		t.Fatalf("want problem seq=4, got %d", rep.ProblemSeq)
	}
	t.Logf("basis: %s; conclusion: corruption located at seq=%d", rep.Reason, rep.ProblemSeq)
}

// TestReopenRejectsTamperedLog 重启后必须拒绝在被篡改的日志上续写。
func TestReopenRejectsTamperedLog(t *testing.T) {
	s, dir := openFresh(t, 5)
	s.Close()
	s = nil

	lines := rawLines(t, dir)
	lines[0] = []byte(strings.Replace(string(lines[0]), "login", "root", 1))
	rewriteLog(t, dir, lines)
	t.Log("input: tamper seq=1 while store is closed, then reopen")

	s2, diag, err := Open(dir, Options{})
	if err == nil {
		s2.Close()
		t.Fatal("Open accepted tampered log")
	}
	t.Logf("basis on open: clean=%v problem=%q reason=%s", diag.Clean, diag.Problem, diag.Reason)
	if _, err := s2.Append("x", "y", "z", "", t0); err == nil {
		s2.Close()
		t.Fatal("Append succeeded on a store that failed open-time verification")
	} else {
		t.Logf("conclusion: append rejected on suspicious base: %v", err)
	}
	s2.Close()
}
