package auditlog

import (
	"path/filepath"
	"testing"
	"time"
)

// TestPurgePolicyRejections 非法策略/范围冲突/还不够老，必须分别给出可区分原因。
func TestPurgePolicyRejections(t *testing.T) {
	s, _ := seedLog(t, 4)
	defer s.Close()
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)

	t.Log("输入1: MaxAge=0（非法保留期）")
	_, err := s.Purge(RetentionPolicy{MaxAge: 0}, PurgeRequest{Now: now})
	expectErrIs(t, err, ErrInvalidRetention, "MaxAge=0")

	t.Log("输入2: MaxAge=-1*time.Hour（非法保留期）")
	_, err = s.Purge(RetentionPolicy{MaxAge: -time.Hour}, PurgeRequest{Now: now})
	expectErrIs(t, err, ErrInvalidRetention, "MaxAge 为负")

	t.Log("输入3: MaxAge=100*24h，所有记录都年轻（4 条记录最老为 9-2）")
	_, err = s.Purge(RetentionPolicy{MaxAge: 100 * 24 * time.Hour}, PurgeRequest{Now: now})
	expectErrIs(t, err, ErrNotYetDeletable, "记录还不够老")

	t.Log("输入4: MaxAge=24h 但 MinKeep=4（最少保留 4 条，全部受保护）")
	_, err = s.Purge(RetentionPolicy{MaxAge: 24 * time.Hour, MinKeep: 4}, PurgeRequest{Now: now})
	expectErrIs(t, err, ErrNotYetDeletable, "MinKeep 保护全部记录")

	rep, _ := s.Verify()
	op2End := rep.Frames[2].End // frames: genesis,1,2,3,4；UpToOffset 落在 op-2 与 op-3 之间
	t.Logf("输入5: MaxAge=24h 允许删 op-1..op-3，但 UpToOffset=%d 只允许删 op-1..op-2（范围与策略冲突）", op2End)
	_, err = s.Purge(RetentionPolicy{MaxAge: 24 * time.Hour}, PurgeRequest{Now: now, UpToOffset: op2End})
	expectErrIs(t, err, ErrRangeConflict, "清理范围切穿可清理前缀")

	t.Log("输入6: UpToOffset 小到连最老一条都没覆盖")
	_, err = s.Purge(RetentionPolicy{MaxAge: 24 * time.Hour}, PurgeRequest{Now: now, UpToOffset: rep.Frames[1].Offset})
	expectErrIs(t, err, ErrNothingEligible, "范围内没有可删记录")
	t.Log("结论: 五类拒绝原因彼此可区分，且没有任何记录被静默跳过")
}

// TestPurgeHappyPath 清理后剩余历史必须仍校验通过、序号从锚点后续接。
func TestPurgeHappyPath(t *testing.T) {
	s, path := seedLog(t, 5)
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)

	t.Log("输入: 5 条记录(9-2..9-6)，MaxAge=3*24h，now=9-10；老于 9-7 的 op-1..op-5 都足够老，")
	t.Log("      但活动段至少保留 1 条 => 期望清理 op-1..op-4，保留 op-5")
	res, err := s.Purge(RetentionPolicy{MaxAge: 3 * 24 * time.Hour}, PurgeRequest{Now: now})
	if err != nil {
		t.Fatalf("Purge 失败: %v", err)
	}
	if res.Removed != 4 {
		t.Fatalf("Removed=%d，期望 4", res.Removed)
	}
	t.Logf("判定依据: eligiblePrefix 从最老端连续计数，受“至少留一条”约束停止；Removed=%d", res.Removed)

	rep, err := s.Verify()
	if err != nil {
		t.Fatalf("清理后校验失败: %v", err)
	}
	if !rep.OK || rep.Count != 1 || !rep.FirstIsAnchor || rep.TotalRemoved != 4 {
		t.Fatalf("清理后段异常: %+v", rep)
	}
	if rep.Frames[1].Seq != 5 {
		t.Fatalf("剩余首条 seq=%d，期望 5（跨锚点序号连续）", rep.Frames[1].Seq)
	}
	t.Logf("结论: 新首帧 anchor(removed=4,prev=op-4哈希) + op-5；Count=%d FirstIsAnchor=%v 校验通过", rep.Count, rep.FirstIsAnchor)

	// 重启后仍然干净、可续写，且新记录序号为 6。
	s.Close()
	s2 := reopen(t, path)
	defer s2.Close()
	mustAppend(t, s2, Record{Timestamp: now.Add(time.Hour), Action: "post-purge"}, 6)
	t.Log("结论: 清理并重启后，新记录以 seq=6 正确挂接在清理锚点之后")
}

// TestPurgeRefusesAcrossYoungRecord 不得跨过年轻记录清理更老的记录。
func TestPurgeRefusesAcrossYoungRecord(t *testing.T) {
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	// 手工插入：op-1 老，op-2 年轻（不可能由正常 Append 产生，这里直接构造前缀判定单元）
	frames := []*Frame{
		{Kind: kindGenesis, Offset: 0, End: 58},
		{Kind: kindRecord, Offset: 58, End: 100, Seq: 1, Time: now.Add(-30 * 24 * time.Hour)},
		{Kind: kindRecord, Offset: 100, End: 200, Seq: 2, Time: now.Add(-time.Hour)}, // 年轻
		{Kind: kindRecord, Offset: 200, End: 300, Seq: 3, Time: now.Add(-40 * 24 * time.Hour)},
		{Kind: kindRecord, Offset: 300, End: 400, Seq: 4, Time: now.Add(-50 * 24 * time.Hour)},
	}
	t.Log("输入: 帧序时间为 老/年轻/老/老，MaxAge=7*24h；只允许前缀式清理，不得跨过年轻的第 2 条")
	n, err := eligiblePrefix(frames, 4, RetentionPolicy{MaxAge: 7 * 24 * time.Hour}, PurgeRequest{Now: now})
	if err != nil {
		t.Fatalf("判定异常: %v", err)
	}
	if n != 1 {
		t.Fatalf("可清理数 n=%d，期望 1（年轻记录之后更老的记录不得被跨过清理）", n)
	}
	t.Logf("判定依据: 第 2 条时间在 cutoff 之后，前缀计数立即停止；结论 n=%d", n)
}

// TestArchiveHappyPath 归档：归档文件自包含可独立校验，活动段剩余链也通过。
func TestArchiveHappyPath(t *testing.T) {
	s, path := seedLog(t, 4)
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	arcPath := filepath.Join(filepath.Dir(path), "archive-1.log")

	t.Log("输入: 4 条记录，MaxAge=4*24h；至少留 1 条 => 归档 op-1..op-3，保留 op-4")
	res, err := s.Archive(arcPath, RetentionPolicy{MaxAge: 4 * 24 * time.Hour}, PurgeRequest{Now: now})
	if err != nil {
		t.Fatalf("Archive 失败: %v", err)
	}
	if !res.Archived || res.Removed != 3 {
		t.Fatalf("归档结果异常: %+v", res)
	}

	arcRep, err := VerifyArchive(arcPath)
	if err != nil {
		t.Fatalf("归档文件独立校验失败: %v", err)
	}
	if !arcRep.OK || arcRep.Count != 3 || arcRep.LastSeq != 3 {
		t.Fatalf("归档结论异常: %+v", arcRep)
	}
	t.Logf("判定依据: 归档内含 op-1..op-3 原文帧 + 收尾 anchor(prev=op-3哈希,uptoseq=3)；Count=%d", arcRep.Count)

	rep, err := s.Verify()
	if err != nil || !rep.OK || rep.Count != 1 || rep.TotalRemoved != 3 {
		t.Fatalf("归档后活动段异常: err=%v rep=%+v", err, rep)
	}
	t.Log("结论: 归档自校验通过；活动段 anchor(removed=3)+op-4 校验通过；两段在锚点处可对应")

	// 归档目标已存在时拒绝覆盖：先补足记录使新的清理有资格，再撞同名归档。
	for i, ts := range []time.Time{
		now.AddDate(0, 0, 2), now.AddDate(0, 0, 3), now.AddDate(0, 0, 4),
	} {
		mustAppend(t, s, Record{Timestamp: ts, Action: "more"}, int64(5+i))
	}
	later := now.AddDate(1, 0, 0)
	_, err = s.Archive(arcPath, RetentionPolicy{MaxAge: 24 * time.Hour}, PurgeRequest{Now: later})
	expectErrIs(t, err, ErrArchiveExists, "归档目标已存在")
}

// TestSecondPurgeChainAnchors 连续两次清理：累计 removed 正确，序号仍连续。
func TestSecondPurgeChainAnchors(t *testing.T) {
	s, path := seedLog(t, 6)
	now1 := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	t.Log("输入: 6 条(9-2..9-7)；第一次清理 MaxAge=17.5*24h @9-20 => cutoff=9-2 12:00，仅删 op-1")
	res, err := s.Purge(RetentionPolicy{MaxAge: 17*24*time.Hour + 12*time.Hour}, PurgeRequest{Now: now1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed != 1 {
		t.Fatalf("第一次 Removed=%d 期望 1", res.Removed)
	}
	now2 := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	t.Log("输入: 追加 seq7@9-21、seq8@9-22 后第二次清理 MaxAge=14*24h @9-25 => cutoff=9-11，删 op-2..op-6 共 5 条")
	mustAppend(t, s, Record{Timestamp: time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC), Action: "new-7"}, 7)
	mustAppend(t, s, Record{Timestamp: time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC), Action: "new-8"}, 8)
	res, err = s.Purge(RetentionPolicy{MaxAge: 14 * 24 * time.Hour}, PurgeRequest{Now: now2})
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed != 5 {
		t.Fatalf("第二次 Removed=%d 期望 5", res.Removed)
	}
	rep, err := s.Verify()
	if err != nil {
		t.Fatalf("第二次清理后校验失败: %v", err)
	}
	if !rep.OK || rep.TotalRemoved != 6 || rep.Count != 2 || rep.Frames[1].Seq != 7 {
		t.Fatalf("二次清理后段异常: %+v", rep)
	}
	s.Close()
	s2 := reopen(t, path)
	defer s2.Close()
	mustAppend(t, s2, Record{Timestamp: now2.Add(time.Hour), Action: "new-9"}, 9)
	t.Logf("结论: 两次清理后累计 removed=%d，剩余段以 seq=7 起，重启续写 seq=9，全链可校验", rep.TotalRemoved)
}
