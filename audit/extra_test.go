package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPurgeBeforeSuccess 显式范围请求在完全满足策略时成功，且只删前缀。
func TestPurgeBeforeSuccess(t *testing.T) {
	s, _ := openFresh(t, 5)
	before := t0.Add(10 * time.Second)
	res, err := s.PurgeBefore(RetentionPolicy{MinAge: time.Second, KeepLatest: 2}, 3, before)
	if err != nil {
		t.Fatalf("eligible purge-before: %v", err)
	}
	if res.Removed != 3 || res.FirstSeq != 1 || res.LastSeq != 3 || res.NewHeadSeq != 4 {
		t.Fatalf("bad result: %+v", res)
	}
	t.Logf("conclusion: explicit range removed seq %d..%d, new head=%d",
		res.FirstSeq, res.LastSeq, res.NewHeadSeq)
	mustVerify(t, s, true)
}

// TestArchiveNonGenesisSegment 先归档一次（移走 1..2），再归档一次（移走 3..4），
// 第二个归档文件不从 seq=1 开始，必须依赖清单锚点通过校验。
func TestArchiveNonGenesisSegment(t *testing.T) {
	s, _ := openFresh(t, 6)
	now := t0.Add(48 * time.Hour)

	r1, err := s.Archive(RetentionPolicy{MinAge: time.Hour, KeepLatest: 4}, ArchiveOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if r1.Archived != 2 {
		t.Fatalf("first archive want 2, got %d", r1.Archived)
	}
	r2, err := s.Archive(RetentionPolicy{MinAge: time.Hour, KeepLatest: 2}, ArchiveOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if r2.Archived != 2 || r2.FirstSeq != 3 || r2.LastSeq != 4 {
		t.Fatalf("second archive want seq 3..4, got %+v", r2)
	}
	t.Logf("input: second archive covers non-genesis segment seq %d..%d", r2.FirstSeq, r2.LastSeq)

	arep, err := VerifyArchive(r2.Path)
	if err != nil || !arep.OK {
		t.Fatalf("non-genesis archive must verify via manifest anchor: %v %s", err, arep.Reason)
	}
	t.Logf("basis: %s", arep.Reason)

	// 清单缺失时，非链首归档必须被拒绝（无法证明前驱）。
	if err := os.Remove(r2.Path + ".manifest.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyArchive(r2.Path); err == nil {
		t.Fatal("archive without manifest and not starting at seq=1 must be rejected")
	} else {
		t.Logf("conclusion: manifest-less non-genesis archive rejected: %v", err)
	}
	mustVerify(t, s, true)
}

// TestCorruptCheckpointJSON 检查点 JSON 被破坏：打开失败，错误可分类。
func TestCorruptCheckpointJSON(t *testing.T) {
	s, dir := openFresh(t, 3)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Log("input: corrupt checkpoint.json contents")
	s2, _, err := Open(dir, Options{})
	if err == nil {
		s2.Close()
		t.Fatal("corrupt checkpoint must fail open")
	}
	t.Logf("conclusion: %v", err)
	s2.Close()
}

// TestDiagnoseMethod 公开的 Diagnose 在健康与异常两种状态下的结论。
func TestDiagnoseMethod(t *testing.T) {
	s, dir := openFresh(t, 2)
	d, err := s.Diagnose()
	if err != nil || !d.Clean {
		t.Fatalf("want clean diagnose, got %v %s", err, d.Reason)
	}
	t.Logf("healthy diagnose: %s", d.Reason)

	lines := rawLines(t, dir)
	rewriteLog(t, dir, lines[:1]) // 尾部物理删除，检查点仍声称 2 条
	d, err = s.Diagnose()
	if err == nil || d.Clean {
		t.Fatal("diagnose must flag tail deletion")
	}
	t.Logf("tampered diagnose: problem=%q %s", d.Problem, d.Reason)
}
