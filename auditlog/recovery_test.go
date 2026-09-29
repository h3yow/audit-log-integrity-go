package auditlog

import (
	"os"
	"testing"
	"time"
)

// TestRestartCleanShutdown 正常收尾：重启可安全续写。
func TestRestartCleanShutdown(t *testing.T) {
	s, path := seedLog(t, 3)
	s.Close()
	t.Log("输入: 写入 3 条后正常 Close（每次 append 已原子落下干净锚点）")
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("干净收尾后重启应成功: %v", err)
	}
	defer s2.Close()
	rep, _ := s2.Verify()
	t.Logf("判定依据: 文件 size/末帧哈希/序号与侧车锚点三者一致；LastSeq=%d Count=%d", rep.LastSeq, rep.Count)
	mustAppend(t, s2, Record{Timestamp: time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC), Action: "post-restart"}, 4)
	t.Log("结论: 收尾正常 → 安全续写 seq=4")
}

// TestRestartTornTail 尾部被截断成半个帧：识别为未正常收尾，Repair 后可续写。
func TestRestartTornTail(t *testing.T) {
	s, path := seedLog(t, 3)
	rep, _ := s.Verify()
	cpSize := rep.LastOffset
	s.Close()

	t.Logf("输入: 在干净文件末尾追加 13 个垃圾字节（模拟写帧写到一半崩溃），锚点 size=%d", cpSize)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("AUDLOG1\x02gar")); err != nil {
		t.Fatal(err)
	}
	_ = f.Sync()
	f.Close()

	_, err = Open(path)
	expectErrIs(t, err, ErrUncleanShutdown, "半帧脏尾")

	t.Log("判定依据: 已提交前缀校验通过，脏尾无法构成完整帧且完全位于锚点之后 => 可安全 Repair")
	s2, err := Repair(path)
	if err != nil {
		t.Fatalf("Repair 应成功: %v", err)
	}
	defer s2.Close()
	fi, _ := s2.f.Stat()
	if fi.Size() != cpSize {
		t.Fatalf("Repair 后 size=%d，期望 %d", fi.Size(), cpSize)
	}
	rep2, err := s2.Verify()
	if err != nil || !rep2.OK || rep2.Count != 3 {
		t.Fatalf("Repair 后校验异常: %v %+v", err, rep2)
	}
	mustAppend(t, s2, Record{Timestamp: time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC), Action: "after-repair"}, 4)
	t.Log("结论: 半个帧被精确截断到锚点，3 条历史无损，续写 seq=4")
}

// TestRestartUncommittedFullFrame 帧已完整 fsync 但锚点尚未更新（提交窗口内崩溃）。
func TestRestartUncommittedFullFrame(t *testing.T) {
	s, path := seedLog(t, 2)
	rep, _ := s.Verify()
	committed := rep.LastOffset

	// 手工构造一条“已写盘但未提交锚点”的完整帧：直接通过底层文件写入，
	// 但不更新 checkpoint（模拟 write+fsync 之后、rename 锚点之前崩溃）。
	raw, err := encodeRecordFrame(recordHeader{
		Seq: 3, Time: time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC).UnixNano(),
		Actor: "admin", Action: "ghost", Res: "r", Prev: s.lastHash,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.f.Seek(0, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.f.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := s.f.Sync(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	t.Logf("输入: 第 3 条完整帧已 fsync 在 offset=%d，但侧车锚点仍停在 %d（提交窗口内崩溃）", committed, committed)

	_, err = Open(path)
	expectErrIs(t, err, ErrUncleanShutdown, "完整但未提交的帧")

	s2, err := Repair(path)
	if err != nil {
		t.Fatalf("Repair 失败: %v", err)
	}
	defer s2.Close()
	rep2, _ := s2.Verify()
	if rep2.Count != 2 {
		t.Fatalf("Repair 必须丢弃未提交帧，剩余 %d 条", rep2.Count)
	}
	t.Logf("判定依据: 锚点之后 %d 字节恰好是一个完整帧，但没有任何提交凭据；Repair 回退到锚点", len(raw))
	mustAppend(t, s2, Record{Timestamp: time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC), Action: "redone"}, 3)
	t.Log("结论: 未提交帧不被当作事实，回退后重新落盘 seq=3，历史与锚点重新一致")
}

// TestRestartTruncatedBehindCheckpoint 已提交的尾部被物理删除。
func TestRestartTruncatedBehindCheckpoint(t *testing.T) {
	s, path := seedLog(t, 3)
	rep, _ := s.Verify()
	// 删掉最后一条记录帧
	last := rep.Frames[len(rep.Frames)-1]
	s.Close()
	t.Logf("输入: 把文件截断到最后一条记录之前 size=%d（锚点声明 size=%d）", last.Offset, rep.LastOffset)
	truncateFile(t, path, last.Offset)

	_, err := Open(path)
	expectErrIs(t, err, ErrTailTruncated, "提交点之后被截断")

	_, err = Repair(path)
	expectErrIs(t, err, ErrTailTruncated, "Repair 拒绝补齐凭空的字节")
	t.Log("结论: 文件短于锚点，无法在不伪造数据的前提下恢复，拒绝续写与修复")
}

// TestRestartCheckpointCorrupt 锚点本身被改坏：不可信，拒绝一切续写。
func TestRestartCheckpointCorrupt(t *testing.T) {
	s, path := seedLog(t, 2)
	s.Close()
	t.Log("输入: 向侧车锚点文件写入无法解析的内容")
	if err := writeFileAll(path+".state", []byte("{not-json")); err != nil {
		t.Fatal(err)
	}
	_, err := Open(path)
	expectErrIs(t, err, ErrNotRepairable, "锚点损坏")
	t.Log("结论: 缺少可信收尾凭据 → 不在不可信基础上继续追加")
}

// TestRestartMiddleCorruptNotRepairable 中段破坏时 Repair 也必须拒绝。
func TestRestartMiddleCorruptNotRepairable(t *testing.T) {
	s, path := seedLog(t, 4)
	rep, _ := s.Verify()
	s.Close()
	pos := rep.Frames[2].End - hashSize - 2
	t.Logf("输入: 翻转中段帧字节 offset=%d，再制造一个脏尾", pos)
	corruptFileBytes(t, path, pos, 0x7F)
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	_, _ = f.Write([]byte("X"))
	_ = f.Sync()
	f.Close()

	_, err := Open(path)
	expectErrIs(t, err, ErrChainBroken, "Open 首先报中段断裂")
	_, err = Repair(path)
	expectErrIs(t, err, ErrNotRepairable, "Repair 拒绝带中段伤的日志")
	t.Log("结论: 修复只允许处理锚点之后的脏尾；已提交前缀有伤 → ErrNotRepairable")
}
