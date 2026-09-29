package audit

import (
	"fmt"
	"time"
)

// RetentionPolicy 描述历史记录的保留规则。
//
// 一条记录只有同时满足下面两个条件，才“符合清理/归档资格”：
//  1. 记录业务时间距今至少 MinAge；
//  2. 它不属于序号最大的 KeepLatest 条记录（尾部保护区）。
//
// 两个条件是“与”关系：KeepLatest 保证无论时间多旧，最近 N 条永远保留，
// 避免在时钟异常或批量导入时把仍在尾部的记录误删。
type RetentionPolicy struct {
	// MinAge 记录从其业务时间起必须至少经过多久才允许被清理 / 归档；必须 > 0。
	MinAge time.Duration
	// KeepLatest 无论多旧都必须保留的最近记录条数（按 seq 从尾部计）；必须 >= 0。
	KeepLatest int64
}

// Validate 检查保留策略是否合法，并返回可区分的原因。
func (p RetentionPolicy) Validate() error {
	if p.MinAge <= 0 {
		return fmt.Errorf("%w: MinAge must be positive, got %s", ErrInvalidRetention, p.MinAge)
	}
	if p.KeepLatest < 0 {
		return fmt.Errorf("%w: KeepLatest must be >= 0, got %d", ErrInvalidRetention, p.KeepLatest)
	}
	return nil
}

// Eligible 判断一条记录是否满足清理 / 归档条件。
//   - lastSeq 为当前日志尾部序号，用于计算尾部保护区；
//   - now 为判定时刻，用记录业务时间与它比较。
func (p RetentionPolicy) Eligible(r *Record, lastSeq int64, now time.Time) bool {
	if r == nil {
		return false
	}
	if p.KeepLatest > 0 && r.Seq > lastSeq-p.KeepLatest {
		return false
	}
	cutoff := now.Add(-p.MinAge).Unix()
	return r.Time <= cutoff
}
