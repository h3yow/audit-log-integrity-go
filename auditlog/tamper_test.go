package auditlog

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func seedLog(t *testing.T, n int) (*Store, string) {
	t.Helper()
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	s, path, _ := newTestStore(t, base)
	for i := 1; i <= n; i++ {
		// 显式时间戳；间隔一天，便于保留策略判定
		mustAppend(t, s, Record{
			Timestamp: base.AddDate(0, 0, i),
			Actor:     "admin",
			Action:    fmt.Sprintf("op-%d", i),
			Resource:  fmt.Sprintf("res-%d", i),
			Detail:    fmt.Sprintf("payload-%d", i),
		}, int64(i))
	}
	return s, path
}

// TestTamperMiddleRewrite 改写中段某条记录的一个字节。
func TestTamperMiddleRewrite(t *testing.T) {
	s, path := seedLog(t, 5)
	rep, err := s.Verify()
	if err != nil {
		t.Fatalf("基线校验失败: %v", err)
	}
	// 第 3 条 record 的帧（frames[0]=genesis, frames[3]=op-3）
	target := rep.Frames[3]
	t.Logf("输入: 将 op-3 帧内 body 的某一字节翻转（offset=%d, seq=%d）", target.Offset, target.Seq)
	s.Close()

	// 找到 body 区域一个字节（帧尾 hash 前倒数第 3 个字节属于 body）
	pos := target.End - hashSize - 3
	corruptFileBytes(t, path, pos, 0xFF)

	_, err = Open(path)
	expectErrIs(t, err, ErrChainBroken, "中段改写")
	var prob *IntegrityProblem
	if !errors.As(err, &prob) {
		t.Fatalf("错误未携带定位信息: %v", err)
	}
	t.Logf("判定依据: 重算帧自哈希与帧尾 32 字节不一致；定位 offset=%d index=%d", prob.Offset, prob.Index)
	if prob.Offset != target.Offset {
		t.Fatalf("定位 offset=%d，期望 %d", prob.Offset, target.Offset)
	}
	t.Log("结论: 中段改写在重启时即被发现并拒绝续写，位置精确定位")
}

// TestTamperDeleteMiddle 删除中段一整帧：前帧哈希不变、后帧 prev 对不上。
func TestTamperDeleteMiddle(t *testing.T) {
	s, path := seedLog(t, 5)
	rep, _ := s.Verify()
	victim := rep.Frames[3] // op-3
	after := rep.Frames[4]  // op-4
	t.Logf("输入: 物理删除 op-3 整帧 [%d,%d)，让 op-3 前后帧直接相邻", victim.Offset, victim.End)
	s.Close()

	// 用“前移”方式删除一帧：把 victim.End 之后的内容拷到 victim.Offset
	f, _ := os.OpenFile(path, os.O_RDWR, 0)
	fi, _ := f.Stat()
	tail := make([]byte, fi.Size()-victim.End)
	if _, err := f.ReadAt(tail, victim.End); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(tail, victim.Offset); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Truncate(path, fi.Size()-(victim.End-victim.Offset)); err != nil {
		t.Fatal(err)
	}

	_, err := Open(path)
	expectErrIs(t, err, ErrChainBroken, "中段删除")
	var prob *IntegrityProblem
	if !errors.As(err, &prob) {
		t.Fatalf("错误未携带定位信息: %v", err)
	}
	t.Logf("判定依据: op-4 头部 prev 仍指向被删的 op-3，与实际前帧 op-2 不符；定位 ordinal=%d", prob.Index)
	if prob.Index != 3 {
		t.Fatalf("定位 ordinal=%d，期望 3（被删位置之后的第一帧）", prob.Index)
	}
	_ = after
	t.Logf("结论: 删除一帧在重启 Open 时即被链校验发现，拒绝续写，位置=%d", prob.Offset)
}

// TestTamperInsert 在中段插入一条伪造帧，必须与前后任一侧对不上。
func TestTamperInsert(t *testing.T) {
	s, path := seedLog(t, 5)
	rep, _ := s.Verify()
	// 取 op-1 的整帧原文，插入到 op-3 之前：它的 prev 指向 genesis，会与新前帧不符
	dup := rep.Frames[1]
	insertAt := rep.Frames[3].Offset
	t.Logf("输入: 在 offset=%d 处插入一帧 op-1 的副本（其 prev 指向 genesis）", insertAt)
	s.Close()

	raw, err := readFrameBytes(mustOpenRO(t, path), dup.Offset, dup.End)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(path, os.O_RDWR, 0)
	fi, _ := f.Stat()
	tail := make([]byte, fi.Size()-insertAt)
	_, _ = f.ReadAt(tail, insertAt)
	if err := f.Truncate(insertAt); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(raw, insertAt); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(tail, insertAt+int64(len(raw))); err != nil {
		t.Fatal(err)
	}
	_ = f.Sync()
	f.Close()

	_, oerr := Open(path)
	expectErrIs(t, oerr, ErrChainBroken, "中段插入")
	var oprob *IntegrityProblem
	if !errors.As(oerr, &oprob) {
		t.Fatalf("错误未携带定位信息: %v", oerr)
	}
	t.Logf("判定依据: 插入位置 ordinal=%d 的帧 prev 与实际前帧哈希不符", oprob.Index)
	if oprob.Index != 3 {
		t.Fatalf("定位 ordinal=%d，期望 3", oprob.Index)
	}
	t.Log("结论: 插入被明确发现并定位，拒绝把可疑历史当作正常链继续追加")
}

func mustOpenRO(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
