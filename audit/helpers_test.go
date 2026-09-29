package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// t0 是测试使用的固定业务时间起点，保证保留期判定确定可解释。
var t0 = time.Unix(1_700_000_000, 0)

// openFresh 在临时目录打开一个干净存储，并写入 n 条时间相差 1s 的记录。
func openFresh(t *testing.T, n int) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, diag, err := Open(dir, Options{Clock: func() time.Time { return t0 }})
	if err != nil {
		t.Fatalf("input: open fresh dir; want clean; got err=%v reason=%s", err, diag.Reason)
	}
	t.Cleanup(func() { s.Close() })
	for i := 0; i < n; i++ {
		r, err := s.Append(
			fmt.Sprintf("actor-%d", i%3),
			[]string{"login", "read", "write", "logout"}[i%4],
			fmt.Sprintf("resource/%d", i),
			fmt.Sprintf("detail-%d", i),
			t0.Add(time.Duration(i)*time.Second),
		)
		if err != nil {
			t.Fatalf("input: append #%d; want success; got err=%v", i+1, err)
		}
		t.Logf("input: seq=%d time=%s actor=%s action=%s", r.Seq,
			time.Unix(r.Time, 0).UTC().Format(time.RFC3339), r.Actor, r.Action)
	}
	return s, dir
}

// reopenStore 关闭后重新打开同一目录（模拟进程重启）。
func reopenStore(t *testing.T, s *Store, dir string) (*Store, Diagnostic, error) {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatalf("close before reopen: %v", err)
	}
	s2, diag, err := Open(dir, Options{Clock: func() time.Time { return t0.Add(time.Hour) }})
	return s2, diag, err
}

// rawLines 读取日志文件并按行切分（测试内篡改用）。
func rawLines(t *testing.T, dir string) [][]byte {
	t.Helper()
	b, err := os.ReadFile(logPath(dir))
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	trimmed := strings.TrimSuffix(string(b), "\n")
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, "\n")
	out := make([][]byte, len(parts))
	for i := range parts {
		out[i] = []byte(parts[i])
	}
	return out
}

// rewriteLog 用给定行重写日志文件（直接物理覆写，模拟外部篡改/截断）。
func rewriteLog(t *testing.T, dir string, lines [][]byte) {
	t.Helper()
	path := logPath(dir)
	var b []byte
	for _, l := range lines {
		b = append(b, l...)
		b = append(b, '\n')
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("rewrite log: %v", err)
	}
}

// appendRaw 在日志末尾直接追加原始字节（模拟半截写入，绕过正常 Append）。
func appendRaw(t *testing.T, dir string, raw []byte, newline bool) {
	t.Helper()
	path := logPath(dir)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open for raw append: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(raw); err != nil {
		t.Fatalf("raw append: %v", err)
	}
	if newline {
		if _, err := f.Write([]byte{'\n'}); err != nil {
			t.Fatalf("raw append newline: %v", err)
		}
	}
}

// readCheckpoint 供测试读取检查点。
func readCheckpoint(t *testing.T, dir string) *checkpoint {
	t.Helper()
	cp, err := loadCheckpoint(dir)
	if err != nil {
		t.Fatalf("load checkpoint: %v", err)
	}
	return cp
}

// mustVerify 执行 Verify 并打印判定依据与结论。
func mustVerify(t *testing.T, s *Store, wantOK bool) VerifyReport {
	t.Helper()
	rep, err := s.Verify()
	decision := "PASS"
	if rep.OK != wantOK {
		decision = "FAIL"
	}
	t.Logf("[%s] verify input: head=%d last=%d records=%d; basis: %s; conclusion: ok=%v err=%v",
		decision, rep.HeadSeq, rep.LastSeq, rep.Records, rep.Reason, rep.OK, err)
	if rep.OK != wantOK {
		t.Fatalf("verify: want ok=%v got ok=%v (problemSeq=%d): %s", wantOK, rep.OK, rep.ProblemSeq, rep.Reason)
	}
	return rep
}

// assertErrIs 判定 err 非空且可分类为 target，打印输入与结论。
func assertErrIs(t *testing.T, context string, err error, target error) {
	t.Helper()
	if err == nil {
		t.Fatalf("input: %s; want error %v; got nil (silent acceptance is forbidden)", context, target)
	}
	if !errors.Is(err, target) {
		t.Fatalf("input: %s; want error %v; got %v", context, target, err)
	}
	t.Logf("input: %s; basis: matched sentinel %v; conclusion: rejected with %q",
		context, target, err.Error())
}

func fileSize(t *testing.T, dir string) int64 {
	t.Helper()
	st, err := os.Stat(logPath(dir))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	return st.Size()
}

var _ = filepath.Join
