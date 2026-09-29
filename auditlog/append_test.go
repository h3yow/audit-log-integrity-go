package auditlog

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestAppendVerifyHappyPath 正常写入与校验路径不回归。
func TestAppendVerifyHappyPath(t *testing.T) {
	base := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	s, path, _ := newTestStore(t, base)
	defer s.Close()

	t.Log("输入: 顺序追加 5 条审计记录")
	for i := 1; i <= 5; i++ {
		mustAppend(t, s, Record{
			Timestamp: base.Add(time.Duration(i) * time.Minute),
			Actor:     fmt.Sprintf("user-%d", i%2),
			Action:    fmt.Sprintf("action-%d", i),
			Resource:  "resource-x",
			Detail:    fmt.Sprintf(`{"k":%d}`, i),
		}, int64(i))
	}

	rep, err := s.Verify()
	if err != nil {
		t.Fatalf("Verify 失败: %v", err)
	}
	t.Logf("判定依据: Verify 逐帧比对自哈希与 prev 链，Count=%d LastSeq=%d LastOffset=%d", rep.Count, rep.LastSeq, rep.LastOffset)
	if !rep.OK || rep.Count != 5 || rep.LastSeq != 5 {
		t.Fatalf("结论异常: %+v", rep)
	}
	t.Log("结论: 5 条记录链完整，校验通过")

	// 重启后应判定为收尾干净并可继续追加。
	s.Close()
	s = reopen(t, path)
	defer s.Close()
	seq, _, err := s.Append(Record{Timestamp: base.Add(10 * time.Minute), Action: "after-restart"})
	if err != nil {
		t.Fatalf("重启后续写失败: %v", err)
	}
	t.Logf("判定依据: 重启后文件长度/末帧哈希与侧车锚点一致；结论: 安全续写 seq=%d", seq)
	if seq != 6 {
		t.Fatalf("续写 seq=%d，期望 6", seq)
	}
}

// TestAppendInvalidRecord 非法输入必须被明确拒绝。
func TestAppendInvalidRecord(t *testing.T) {
	base := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	s, _, _ := newTestStore(t, base)
	defer s.Close()
	_, _, err := s.Append(Record{Timestamp: base, Action: ""})
	expectErrIs(t, err, ErrInvalidRecord, "空 action")

	// 首条记录前没有时间基准，先正常写入一条，再验证时间单调性。
	mustAppend(t, s, Record{Timestamp: base, Action: "first"}, 1)
	_, _, err = s.Append(Record{Timestamp: base.Add(-time.Hour), Action: "back-in-time"})
	expectErrIs(t, err, ErrInvalidRecord, "时间倒流")
}

// TestConcurrentAppend 多方并发追加：位置不重复、链条不断裂、总数确定。
func TestConcurrentAppend(t *testing.T) {
	base := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	s, _, _ := newTestStore(t, base)
	defer s.Close()

	const writers = 8
	const perWriter = 25
	t.Logf("输入: %d 个 goroutine 各追加 %d 条（共 %d 条），时间戳在锁内单调生成", writers, perWriter, writers*perWriter)

	var wg sync.WaitGroup
	errCh := make(chan error, writers)
	seqCh := make(chan int64, writers*perWriter)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				// Timestamp 留空 => Store 在持锁状态下用注入时钟取点，保证先后次序确定
				seq, _, err := s.Append(Record{
					Actor:  fmt.Sprintf("writer-%d", w),
					Action: fmt.Sprintf("w%d-op%d", w, i),
				})
				if err != nil {
					errCh <- err
					return
				}
				seqCh <- seq
			}
		}(w)
	}
	wg.Wait()
	close(seqCh)
	close(errCh)
	for err := range errCh {
		t.Fatalf("并发追加出现错误: %v", err)
	}

	// 判定 1：序号集合恰为 1..N，无重复占位、无断号。
	seen := make(map[int64]bool)
	for seq := range seqCh {
		if seen[seq] {
			t.Fatalf("位置 %d 被重复占用", seq)
		}
		seen[seq] = true
	}
	if len(seen) != writers*perWriter {
		t.Fatalf("占用位置数=%d，期望 %d", len(seen), writers*perWriter)
	}
	for seq := int64(1); seq <= int64(writers*perWriter); seq++ {
		if !seen[seq] {
			t.Fatalf("位置 %d 缺失（链条断裂）", seq)
		}
	}
	t.Logf("判定依据: 收集到 %d 个序号，恰好覆盖 1..%d，无重复无缺失", len(seen), writers*perWriter)

	// 判定 2：全链哈希校验通过。
	rep, err := s.Verify()
	if err != nil {
		var p *IntegrityProblem
		errors.As(err, &p)
		t.Fatalf("并发后校验失败: %v", err)
	}
	if !rep.OK || rep.Count != writers*perWriter {
		t.Fatalf("结论异常: %+v", rep)
	}
	t.Logf("结论: 并发追加后 Count=%d，prev 链与序号全部连续，校验通过", rep.Count)
}
