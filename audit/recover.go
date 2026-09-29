package audit

import (
	"fmt"
)

// Recover 在诊断为异常的日志上执行处置。处置规则是确定、可解释的：
//
//   - 哈希链断裂 / 内容被改写 / 检查点之后记录被删：不可自动恢复，返回
//     ErrLogTampered 或 ErrCheckpointMismatch，绝不续写；
//   - 末尾存在未以换行收尾的悬空字节（写到一半崩溃）：在“完整前缀链校验通过”
//     的前提下，截断悬空字节，把日志恢复到最后一个已提交边界；
//   - 存在带换行的完整记录、但检查点停在更早位置（记录已 fsync、检查点未更新）：
//     不删除任何数据，仅把检查点推进到文件真实尾部；
//   - 干净状态：原样返回。
func (s *Store) Recover() (Diagnostic, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Diagnostic{}, ErrNotOpen
	}

	diag := diagnose(s.dir, s.cp)
	s.lastDiag = diag

	switch diag.Problem {
	case problemNone:
		s.healthy = true
		return diag, nil
	case problemTampered:
		return diag, fmt.Errorf("%w: %s", ErrLogTampered, diag.Reason)
	case problemCheckpoint:
		return diag, fmt.Errorf("%w: %s", ErrCheckpointMismatch, diag.Reason)
	case problemDangling:
		// 继续细分：悬空字节 vs 检查点滞后。
	default:
		return diag, fmt.Errorf("%w: %s", ErrUncleanTail, diag.Reason)
	}

	path := logPath(s.dir)
	lines, dangling, _, err := scanFile(path)
	if err != nil {
		return diag, err
	}
	records, fail := verifyChain(lines, expectHead(s.cp), expectAnchor(s.cp))
	if fail != nil {
		// 完整前缀自身都对不上：不是崩溃，是篡改。拒绝。
		return diag, fmt.Errorf("%w: cannot truncate because committed prefix is invalid: %s",
			ErrLogTampered, fail.reason)
	}

	// 1) 截断未提交的悬空字节，使文件恰好在最后一个换行处结束。
	if len(dangling) > 0 {
		if err := s.log.Sync(); err != nil {
			return diag, fmt.Errorf("sync before truncate: %w", err)
		}
		keep := int64(0)
		for _, ln := range lines {
			keep += int64(len(ln)) + 1
		}
		if err := s.log.Truncate(keep); err != nil {
			return diag, fmt.Errorf("truncate dangling bytes: %w", err)
		}
		if err := s.log.Sync(); err != nil {
			return diag, fmt.Errorf("sync after truncate: %w", err)
		}
	}

	// 2) 推进检查点到文件真实尾部（覆盖“记录已提交、检查点滞后”场景）。
	var lastSeq int64
	var lastHash string
	if len(records) > 0 {
		lastSeq = records[len(records)-1].Seq
		lastHash = records[len(records)-1].SelfHash
	} else {
		lastSeq = s.cp.HeadSeq - 1
	}
	newCP := *s.cp
	newCP.LastSeq = lastSeq
	newCP.LastHash = lastHash
	newCP.UpdatedAt = s.clock().Unix()
	if err := saveCheckpoint(s.dir, &newCP); err != nil {
		return diag, err
	}
	s.cp = &newCP

	post := diagnose(s.dir, s.cp)
	s.lastDiag = post
	if !post.Clean {
		return post, fmt.Errorf("%w: post-recovery diagnosis still not clean: %s", ErrUncleanTail, post.Reason)
	}
	s.healthy = true
	return post, nil
}
