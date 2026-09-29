package auditlog

import (
	"fmt"
	"time"
)

// RetentionPolicy 描述历史保留规则。
type RetentionPolicy struct {
	// MaxAge 保留时长：事件时间早于 now-MaxAge 的记录才允许被清理。
	// 必须为正；零值或负值非法。
	MaxAge time.Duration
	// MinKeep 即使记录很老，链上也至少保留多少条 record。0 表示不限制。
	MinKeep int
}

// PurgeRequest 是调用方对一次清理范围的约束。
type PurgeRequest struct {
	Now        time.Time // 判定“老/年轻”的基准时刻
	UpToOffset int64     // 仅允许清理起始偏移 < 该值的帧；0 表示不限制（只受策略约束）
}

// PurgeResult 是一次清理/归档的确定性结论。
type PurgeResult struct {
	Removed       int   // 实际清理的 record 帧数
	NewStartIndex int64 // 清理后首条剩余记录的全链序号
	AnchorOffset  int64 // 新锚点帧写入后的文件偏移（即新的日志起点）
	Archived      bool
}

// validate 检查保留策略本身是否合法。
func (p RetentionPolicy) validate() error {
	if p.MaxAge <= 0 {
		return fmt.Errorf("%w: MaxAge must be positive, got %v", ErrInvalidRetention, p.MaxAge)
	}
	if p.MinKeep < 0 {
		return fmt.Errorf("%w: MinKeep must be >= 0, got %d", ErrInvalidRetention, p.MinKeep)
	}
	return nil
}

// eligiblePrefix 在校验通过的帧序列中，找出满足策略与请求约束的
// 最长可清理 record 前缀，返回可清理的 record 帧数 n（frames[1..n]）。
//
// 规则（任一不满足都明确拒绝，绝不悄悄跳过）：
//   - 必须保留至少一条 record 在当前段（不能把活动段清空）；
//   - 只有“从最老一端开始的连续前缀”可清理，不得跨过年轻记录；
//   - 最老一条都还年轻 => ErrNotYetDeletable；
//   - 受 MinKeep 约束导致一条都不能删 => ErrNotYetDeletable；
//   - 调用方 UpToOffset 早于最早可清理边界（一条都没被它允许）=> ErrNothingEligible；
//   - UpToOffset 落在可清理范围内部（与策略允许范围冲突）=> ErrRangeConflict。
func eligiblePrefix(frames []*Frame, totalRecords int, pol RetentionPolicy, req PurgeRequest) (int, error) {
	if err := pol.validate(); err != nil {
		return 0, err
	}
	now := req.Now.UTC()
	cutoff := now.Add(-pol.MaxAge)

	// 从安全角度：最终至少留一条 record。
	limitByKeep := totalRecords - 1
	if pol.MinKeep > limitByKeep {
		limitByKeep = 0
	} else if pol.MinKeep > 0 {
		limitByKeep = totalRecords - pol.MinKeep
		if limitByKeep < 0 {
			limitByKeep = 0
		}
	}

	// frames[0] 是 genesis/anchor；record 从 frames[1] 起。
	n := 0
	for i := 1; i < len(frames) && frames[i].Kind == kindRecord; i++ {
		if n >= limitByKeep {
			break
		}
		fr := frames[i]
		if req.UpToOffset > 0 && fr.Offset >= req.UpToOffset {
			break
		}
		if fr.Time.After(cutoff) {
			break // 年轻记录：前缀到此为止，绝不能跨过它
		}
		n++
	}

	if n == 0 {
		// 区分原因：到底是“还不够老/保留数约束”，还是“请求范围没覆盖到”。
		oldest := oldestRecord(frames)
		if req.UpToOffset > 0 && (oldest == nil || oldest.Offset >= req.UpToOffset) {
			return 0, fmt.Errorf("%w: requested UpToOffset=%d does not cover any deletable record", ErrNothingEligible, req.UpToOffset)
		}
		if totalRecords > 0 && limitByKeep <= 0 {
			return 0, fmt.Errorf("%w: MinKeep=%d protects all %d record(s)", ErrNotYetDeletable, pol.MinKeep, totalRecords)
		}
		if oldest != nil && oldest.Time.After(cutoff) {
			return 0, fmt.Errorf("%w: oldest record at %s is younger than cutoff %s (maxage=%v)",
				ErrNotYetDeletable, oldest.Time.Format(time.RFC3339Nano), cutoff.Format(time.RFC3339Nano), pol.MaxAge)
		}
		return 0, fmt.Errorf("%w: no record is old enough", ErrNotYetDeletable)
	}

	// n > 0：若调用方给了 UpToOffset，而其允许范围比策略允许范围更窄，
	// 属于“清理范围与策略冲突”——拒绝，而不是静默按较小范围执行。
	if req.UpToOffset > 0 {
		lastAllowed := frames[n] // 第 n 条可清理 record（索引 n）
		if lastAllowed.Offset < req.UpToOffset {
			// 调用方范围在策略允许范围之前终止
			next := frames[n+1]
			return 0, fmt.Errorf("%w: UpToOffset=%d cuts through the policy-eligible prefix ending at offset %d; next record offset=%d is already old enough",
				ErrRangeConflict, req.UpToOffset, lastAllowed.End, next.Offset)
		}
	}
	return n, nil
}

// oldestRecord 返回 frames 中第一个 record 帧（链上最老记录）。
func oldestRecord(frames []*Frame) *Frame {
	for _, fr := range frames {
		if fr.Kind == kindRecord {
			return fr
		}
	}
	return nil
}

// newestRecord 返回 frames 中最后一个 record 帧（链上最新记录）。
func newestRecord(frames []*Frame) *Frame {
	var last *Frame
	for _, fr := range frames {
		if fr.Kind == kindRecord {
			last = fr
		}
	}
	return last
}
