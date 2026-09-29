package audit

import (
	"testing"
	"time"
)

func TestSmokeAppendVerify(t *testing.T) {
	dir := t.TempDir()
	base := time.Unix(1_700_000_000, 0)
	s, diag, err := Open(dir, Options{Clock: func() time.Time { return base }})
	if err != nil {
		t.Fatalf("open: %v (diag=%+v)", err, diag)
	}
	for i := 0; i < 3; i++ {
		r, err := s.Append("alice", "login", "console", "ok", base.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		t.Logf("appended seq=%d self=%s prev=%s", r.Seq, r.SelfHash[:14], r.PrevHash[:14])
	}
	rep, err := s.Verify()
	if err != nil || !rep.OK {
		t.Fatalf("verify: %v ok=%v reason=%s", err, rep.OK, rep.Reason)
	}
	t.Logf("verify: %s", rep.Reason)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// 重开：应诊断为干净并可续写。
	s2, diag2, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("reopen: %v diag=%s", err, diag2.Reason)
	}
	r, err := s2.Append("bob", "logout", "console", "", time.Now())
	if err != nil {
		t.Fatalf("append after reopen: %v", err)
	}
	t.Logf("after reopen appended seq=%d", r.Seq)
	s2.Close()
}
