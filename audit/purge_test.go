package audit

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRetentionValidate 非法保留策略必须被拒绝并给出原因。
func TestRetentionValidate(t *testing.T) {
	cases := []struct {
		name string
		p    RetentionPolicy
		want error
	}{
		{"zero minage", RetentionPolicy{MinAge: 0}, ErrInvalidRetention},
		{"negative minage", RetentionPolicy{MinAge: -1}, ErrInvalidRetention},
		{"negative keeplatest", RetentionPolicy{MinAge: time.Hour, KeepLatest: -1}, ErrInvalidRetention},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.p.Validate()
			t.Logf("input: policy MinAge=%s KeepLatest=%d; conclusion err=%v", c.p.MinAge, c.p.KeepLatest, err)
			assertErrIs(t, "retention validate", err, c.want)
		})
	}
}

// TestPurgeRejectsWhenTooYoung 记录还不满足 MinAge 时必须拒绝，不得悄悄跳过。
func TestPurgeRejectsWhenTooYoung(t *testing.T) {
	s, _ := openFresh(t, 5)
	now := t0.Add(10 * time.Second) // 最老记录才 10 秒
	p := RetentionPolicy{MinAge: time.Hour, KeepLatest: 0}
	t.Logf("input: purge with MinAge=%s at now=%s while oldest record age=10s", p.MinAge, now)
	_, err := s.Purge(p, PurgeOptions{Now: now})
	assertErrIs(t, "purge too-young records", err, ErrRecordsNotEligible)
	mustVerify(t, s, true) // 拒绝后日志不受影响
	t.Log("conclusion: purge refused, log intact")
}

// TestPurgeRespectsKeepLatest 尾部保护区：即使全部过期也必须保留最近 N 条。
func TestPurgeRespectsKeepLatest(t *testing.T) {
	s, _ := openFresh(t, 5)
	now := t0.Add(48 * time.Hour)
	p := RetentionPolicy{MinAge: time.Hour, KeepLatest: 2}
	t.Logf("input: all records old, but KeepLatest=%d", p.KeepLatest)
	res, err := s.Purge(p, PurgeOptions{Now: now})
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if res.Removed != 3 || res.NewHeadSeq != 4 {
		t.Fatalf("want remove seq 1..3 keep tail 2, got %+v", res)
	}
	t.Logf("basis: removed seq %d..%d (%d records); new head seq=%d anchored to seq=3 hash",
		res.FirstSeq, res.LastSeq, res.Removed, res.NewHeadSeq)
	mustVerify(t, s, true)
	rep, _ := s.Verify()
	if rep.FirstPrevHash == genesisPrevHash() {
		t.Fatal("after purge head anchor must no longer be genesis")
	}
	t.Logf("conclusion: tail protected; remaining chain verifies; new head anchor=%s", rep.FirstPrevHash[:14])
}

// TestPurgeStopsAtFirstIneligible 前缀中遇到第一条不符合资格的记录即停止：
// 只删连续前缀，绝不挖洞。
func TestPurgeStopsAtFirstIneligible(t *testing.T) {
	s, _ := openFresh(t, 6)
	now := t0.Add(48 * time.Hour)
	// 保留 2 条 => 只有 seq 1..4 符合；删除 seq1..4，保留 5..6。
	p := RetentionPolicy{MinAge: time.Hour, KeepLatest: 2}
	res, err := s.Purge(p, PurgeOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed != 4 || res.NewHeadSeq != 5 {
		t.Fatalf("want 4 removed new head 5, got %+v", res)
	}
	t.Logf("conclusion: removed prefix %d..%d, remaining starts at %d", res.FirstSeq, res.LastSeq, res.NewHeadSeq)
	mustVerify(t, s, true)

	// 续写：新 seq 必须接着旧序号，链不断。
	r, err := s.Append("carol", "write", "r", "post-purge", now)
	if err != nil {
		t.Fatalf("append after purge: %v", err)
	}
	if r.Seq != 7 {
		t.Fatalf("want seq=7 (monotonic across purge), got %d", r.Seq)
	}
	t.Logf("conclusion: append after purge continues at seq=%d with prev=%s", r.Seq, r.PrevHash[:14])
	mustVerify(t, s, true)
}

// TestPurgeRestartConsistency 清理后重启仍校验通过。
func TestPurgeRestartConsistency(t *testing.T) {
	s, dir := openFresh(t, 6)
	now := t0.Add(48 * time.Hour)
	if _, err := s.Purge(RetentionPolicy{MinAge: time.Hour, KeepLatest: 2}, PurgeOptions{Now: now}); err != nil {
		t.Fatal(err)
	}
	s2, diag, err := reopenStore(t, s, dir)
	if err != nil {
		t.Fatalf("reopen after purge: %v reason=%s", err, diag.Reason)
	}
	defer s2.Close()
	t.Logf("basis on reopen: %s", diag.Reason)
	mustVerify(t, s2, true)
	if s2.HeadSeq() != 5 || s2.LastSeq() != 6 {
		t.Fatalf("bounds after restart: head=%d last=%d", s2.HeadSeq(), s2.LastSeq())
	}
	t.Log("conclusion: remaining history verifies after restart")
}

// TestPurgeEverythingRemovesAll 全部符合条件时可清空；清空后仍可安全续写。
func TestPurgeEverythingRemovesAll(t *testing.T) {
	s, _ := openFresh(t, 3)
	now := t0.Add(48 * time.Hour)
	res, err := s.Purge(RetentionPolicy{MinAge: time.Hour, KeepLatest: 0}, PurgeOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed != 3 {
		t.Fatalf("want 3 removed, got %d", res.Removed)
	}
	t.Logf("basis: removed all %d..%d, new head seq=%d", res.FirstSeq, res.LastSeq, res.NewHeadSeq)
	mustVerify(t, s, true)
	r, err := s.Append("dave", "login", "x", "after full purge", now.Add(time.Second))
	if err != nil {
		t.Fatalf("append after full purge: %v", err)
	}
	if r.Seq != 4 {
		t.Fatalf("seq must be monotonic, want 4 got %d", r.Seq)
	}
	t.Logf("conclusion: new record seq=%d prev anchored to purged tail hash %s", r.Seq, r.PrevHash[:14])
	mustVerify(t, s, true)
}

// TestPurgeEmpty 空日志清理必须明确报“无可清理”，不允许静默成功。
func TestPurgeEmpty(t *testing.T) {
	s, _ := openFresh(t, 0)
	_, err := s.Purge(RetentionPolicy{MinAge: time.Hour}, PurgeOptions{Now: t0.Add(time.Hour * 48)})
	assertErrIs(t, "purge empty log", err, ErrNothingToPurge)
}

// TestPurgeBeforeConflicts 显式范围请求的各类拒绝原因必须可区分。
func TestPurgeBeforeConflicts(t *testing.T) {
	now := t0.Add(48 * time.Hour)

	t.Run("too_young", func(t *testing.T) {
		s, _ := openFresh(t, 4)
		// before=t0+1m, MinAge=1h：记录年龄不满足。
		_, err := s.PurgeBefore(RetentionPolicy{MinAge: time.Hour, KeepLatest: 0}, 4, t0.Add(time.Minute))
		assertErrIs(t, "purge-before too young", err, ErrRecordsNotEligible)
		mustVerify(t, s, true)
	})
	t.Run("keep_latest_conflict", func(t *testing.T) {
		s, _ := openFresh(t, 4)
		// 时间足够老，但 uptoSeq=4 撞上 KeepLatest=2 保护区。
		_, err := s.PurgeBefore(RetentionPolicy{MinAge: time.Hour, KeepLatest: 2}, 4, now.Add(time.Hour))
		assertErrIs(t, "purge-before protection zone", err, ErrPurgeConflict)
		mustVerify(t, s, true)
	})
	t.Run("range_ahead_of_head", func(t *testing.T) {
		s, _ := openFresh(t, 4)
		// 先正常清掉前 2 条，再请求 uptoSeq=1 => 范围已不存在。
		if _, err := s.Purge(RetentionPolicy{MinAge: time.Hour, KeepLatest: 2}, PurgeOptions{Now: now}); err != nil {
			t.Fatal(err)
		}
		_, err := s.PurgeBefore(RetentionPolicy{MinAge: time.Hour, KeepLatest: 0}, 1, now.Add(time.Hour))
		assertErrIs(t, "purge-before nonexistent range", err, ErrNothingToPurge)
		mustVerify(t, s, true)
	})
	t.Run("gap_forbidden", func(t *testing.T) {
		s, _ := openFresh(t, 4)
		// uptoSeq=3、before=t0+1h：seq1(t0..t0+1h 恰好满足 MinAge) 之后，
		// seq2 相对 before 只有 3599s => 选入会留下“删 1、跳过 2、再删 3”的洞，拒绝。
		_, err := s.PurgeBefore(RetentionPolicy{MinAge: time.Hour, KeepLatest: 0}, 3, t0.Add(time.Hour))
		assertErrIs(t, "purge-before leaves gap", err, ErrRecordsNotEligible)
		mustVerify(t, s, true)
	})
}

// TestArchiveMovesRecords 归档：归档文件自成链、活动日志剩余部分仍可校验，
// 且活动日志新 head 的锚点 == 归档文件最后一条哈希。
func TestArchiveMovesRecords(t *testing.T) {
	s, dir := openFresh(t, 6)
	now := t0.Add(48 * time.Hour)
	archDir := filepath.Join(t.TempDir(), "archives")

	rep, err := s.Archive(RetentionPolicy{MinAge: time.Hour, KeepLatest: 2}, ArchiveOptions{
		Dir: archDir, Now: now,
	})
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	if rep.Archived != 4 || rep.FirstSeq != 1 || rep.LastSeq != 4 || !rep.Created {
		t.Fatalf("bad archive report: %+v", rep)
	}
	t.Logf("basis: archived seq %d..%d to %s; active log new head=%d",
		rep.FirstSeq, rep.LastSeq, rep.Path, rep.NewHeadSeq)

	// 活动日志剩余链必须完整。
	mustVerify(t, s, true)

	// 归档文件必须独立校验通过。
	arep, err := VerifyArchive(rep.Path)
	if err != nil || !arep.OK {
		t.Fatalf("verify archive: %v %s", err, arep.Reason)
	}
	t.Logf("conclusion: archive self-verifies: %s", arep.Reason)

	// 衔接关系：活动日志 head 的 prev_hash 必须等于归档尾部哈希。
	cp := readCheckpoint(t, dir)
	mb, err := os.ReadFile(rep.Path + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("manifest: %s", string(mb))
	if cp.HeadAnchor == "" || cp.HeadAnchor != arep.LastHash {
		t.Fatalf("active head anchor %s must equal archive last hash %s", cp.HeadAnchor, arep.LastHash)
	}
	t.Logf("conclusion: active head anchor == archive tail hash (%s); full timeline is explainable",
		cp.HeadAnchor[:14])

	// 归档文件被篡改也必须被发现。
	lines := rawLines(t, dir) // 活动日志（seq 5..6）
	_ = lines
	archLines := rawLinesOf(t, rep.Path)
	archLines[0] = []byte(`{"broken`)
	rewriteLogGeneric(t, rep.Path, archLines)
	if _, verr := VerifyArchive(rep.Path); verr == nil {
		t.Fatal("tampered archive was accepted")
	} else if !errors.Is(verr, ErrLogTampered) {
		t.Fatalf("want ErrLogTampered, got %v", verr)
	} else {
		t.Logf("conclusion: tampering inside archive is detected: %v", verr)
	}
}

// rawLinesOf / rewriteLogGeneric 对任意路径操作（归档文件复用）。
func rawLinesOf(t *testing.T, path string) [][]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return splitTestLines(b)
}

func rewriteLogGeneric(t *testing.T, path string, lines [][]byte) {
	t.Helper()
	var b []byte
	for _, l := range lines {
		b = append(b, l...)
		b = append(b, '\n')
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
