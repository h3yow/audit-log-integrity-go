package audit

import (
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"
)

// TestConcurrentAppend 多个写入方并发追加：
// 序号必须 1..N 连续唯一、链条必须完整、关闭重开后结论一致。
func TestConcurrentAppend(t *testing.T) {
	s, dir := openFresh(t, 0)

	const writers = 8
	const perWriter = 25
	t.Logf("input: %d goroutines x %d appends = %d records, sharing one Store",
		writers, perWriter, writers*perWriter)

	var wg sync.WaitGroup
	errCh := make(chan error, writers*perWriter)
	var mu sync.Mutex
	got := make(map[int64]string) // seq -> 写入方标记

	start := make(chan struct{})
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < perWriter; i++ {
				at := t0.Add(time.Duration(w*100+i) * time.Second)
				r, err := s.Append(fmt.Sprintf("writer-%d", w), "act",
					fmt.Sprintf("res-%d-%d", w, i), "concurrent", at)
				if err != nil {
					errCh <- fmt.Errorf("writer %d: %w", w, err)
					return
				}
				mu.Lock()
				if _, dup := got[r.Seq]; dup {
					errCh <- fmt.Errorf("duplicate seq=%d occupied by two writers", r.Seq)
				}
				got[r.Seq] = fmt.Sprintf("writer-%d#%d", w, i)
				mu.Unlock()
			}
		}(w)
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("conclusion: concurrent append inconsistency: %v", err)
	}

	if len(got) != writers*perWriter {
		t.Fatalf("conclusion: lost or duplicated positions: got %d unique seqs, want %d",
			len(got), writers*perWriter)
	}
	seqs := make([]int64, 0, len(got))
	for k := range got {
		seqs = append(seqs, k)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for i, seq := range seqs {
		if seq != int64(i)+1 {
			t.Fatalf("conclusion: seq gap/hole at position %d: got %d", i, seq)
		}
	}
	t.Logf("basis: all seqs 1..%d occupied exactly once across writers; sample owners: %v",
		len(seqs), []string{got[1], got[2], got[3]})

	mustVerify(t, s, true)

	// 重启后再校验：并发写入的最终顺序必须与落盘顺序一致。
	s2, diag, err := reopenStore(t, s, dir)
	if err != nil {
		t.Fatalf("reopen after concurrent writes: %v (%s)", err, diag.Reason)
	}
	defer s2.Close()
	mustVerify(t, s2, true)
	if s2.LastSeq() != int64(writers*perWriter) {
		t.Fatalf("want lastSeq=%d got %d", writers*perWriter, s2.LastSeq())
	}
	t.Logf("conclusion: %d concurrent appends produced one continuous chain; survives restart",
		writers*perWriter)
}

// TestProcessLock 同一目录不允许第二个进程（第二个 Store）同时打开。
func TestProcessLock(t *testing.T) {
	s, dir := openFresh(t, 1)
	t.Log("input: open same directory twice without closing the first store")
	_, _, err := Open(dir, Options{})
	assertErrIs(t, "second concurrent Open of same dir", err, ErrLogLocked)
	s.Close()

	// 关闭后锁必须释放。
	s3, _, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("conclusion: lock not released after close: %v", err)
	}
	t.Log("conclusion: lock blocks concurrent holders and is released on close")
	s3.Close()
}
