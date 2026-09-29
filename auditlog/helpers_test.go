package auditlog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// testLogger 在单测日志中打印【输入 / 判定依据 / 结论】三段信息。
type testLogger struct{ t *testing.T }

func (l testLogger) logf(stage, format string, args ...any) {
	l.t.Helper()
	l.t.Logf("[%s] %s", stage, fmt.Sprintf(format, args...))
}

func newTestStore(t *testing.T, start time.Time) (*Store, string, Clock) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	cur := start
	var mu sync.Mutex
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		cur = cur.Add(time.Millisecond)
		return cur
	}
	s, err := Open(path, WithClock(clock))
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	return s, path, clock
}

func mustAppend(t *testing.T, s *Store, r Record, wantSeq int64) {
	t.Helper()
	seq, off, err := s.Append(r)
	if err != nil {
		t.Fatalf("Append(action=%q) 意外失败: %v", r.Action, err)
	}
	if seq != wantSeq {
		t.Fatalf("Append 返回 seq=%d, 期望 %d", seq, wantSeq)
	}
	t.Logf("  -> 已落盘 seq=%d offset=%d action=%q time=%s", seq, off, r.Action, r.Timestamp.Format(time.RFC3339Nano))
}

// reopen 关闭后以正常路径重新打开。
func reopen(t *testing.T, path string, opts ...Option) *Store {
	t.Helper()
	s, err := Open(path, opts...)
	if err != nil {
		t.Fatalf("重启 Open 失败: %v", err)
	}
	return s
}

// corruptFileBytes 直接改写磁盘文件中指定偏移的字节（绕过 Store）。
func corruptFileBytes(t *testing.T, path string, pos int64, b ...byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("打开待篡改文件失败: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteAt(b, pos); err != nil {
		t.Fatalf("篡改写入失败: %v", err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("篡改 fsync 失败: %v", err)
	}
}

func truncateFile(t *testing.T, path string, size int64) {
	t.Helper()
	if err := os.Truncate(path, size); err != nil {
		t.Fatalf("截断文件失败: %v", err)
	}
}

func expectErrIs(t *testing.T, err error, target error, context string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: 期望错误 %v，实际为 nil", context, target)
	}
	if !errors.Is(err, target) {
		t.Fatalf("%s: 期望 errors.Is(err, %v)，实际 err=%v", context, target, err)
	}
	t.Logf("  -> 结论符合预期 [%s]: %v", context, err)
}

func frameOffsets(rep *ChainReport) []int64 {
	var out []int64
	for _, fr := range rep.Frames {
		out = append(out, fr.Offset)
	}
	return out
}

func writeFileAll(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
