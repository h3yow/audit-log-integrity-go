package auditlog

import (
	"testing"
	"time"
)

// TestFileLockExclusivity 同一路径同时只允许一个写句柄。
func TestFileLockExclusivity(t *testing.T) {
	s, path, _ := newTestStore(t, time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC))
	defer s.Close()

	t.Log("输入: 已持有一个写句柄时，再次 Open 同一路径")
	_, err := Open(path)
	expectErrIs(t, err, ErrLocked, "同路径第二个写句柄")

	// 释放后应能重新获取。
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("释放锁后重新 Open 失败: %v", err)
	}
	t.Log("结论: flock 互斥生效，关闭后锁释放可重新打开")
	s2.Close()
}
