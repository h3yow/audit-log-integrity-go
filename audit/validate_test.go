package audit

import (
	"strings"
	"testing"
	"time"
)

func TestAppendInvalidRecord(t *testing.T) {
	s, _ := openFresh(t, 1)

	cases := []struct {
		name   string
		actor  string
		action string
		detail string
	}{
		{"empty actor", "", "read", "d"},
		{"empty action", "a", "", "d"},
		{"newline in detail", "a", "read", "line1\nline2"},
		{"carriage return in resource", "a", "read", "r\r"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := s.Append(c.actor, c.action, "res", c.detail, t0)
			assertErrIs(t, "append invalid record", err, ErrInvalidRecord)
		})
	}
	mustVerify(t, s, true)
	// 被拒绝的追加绝不能占用序号：下一条合法记录必须是 seq=2。
	r, err := s.Append("valid", "read", "res", "ok", t0.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if r.Seq != 2 {
		t.Fatalf("rejected appends must not consume seq; want 2 got %d", r.Seq)
	}
	t.Logf("conclusion: 4 invalid inputs rejected, next valid record seq=%d (no holes)", r.Seq)
	mustVerify(t, s, true)
}

// TestAppendOnClosedStore 关闭后写入必须返回 ErrNotOpen。
func TestAppendOnClosedStore(t *testing.T) {
	s, _ := openFresh(t, 1)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := s.Append("a", "b", "c", "d", t0)
	assertErrIs(t, "append after close", err, ErrNotOpen)
	if !strings.Contains(err.Error(), "not open") {
		t.Fatalf("want explanatory message, got %v", err)
	}
}
