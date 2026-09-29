// Package auditlog 提供以本地文件承载、可自证完整性的审计日志存储。
package auditlog

import (
	"errors"
	"fmt"
)

// 可区分的哨兵错误：调用方可用 errors.Is 判断失败原因。
var (
	// ErrChainBroken 历史中任意位置的记录与前后记录对不上
	// （被改写、插入、删除），或侧车锚点指向位置不一致。
	ErrChainBroken = errors.New("auditlog: hash chain broken")
	// ErrTailTruncated 既有内容以一个结构完整的帧结尾，
	// 但与上次正常收尾时记录的锚点不一致（被截断/回卷）。
	ErrTailTruncated = errors.New("auditlog: tail truncated behind checkpoint")
	// ErrUncleanShutdown 上次写入没有正常收尾，尾部存在半个帧
	// 或已提交之后的可疑字节，拒绝在可疑基础上续写。
	ErrUncleanShutdown = errors.New("auditlog: unclean shutdown detected")
	// ErrNotRepairable 中段被破坏、锚点本身不可信等，修复无法保证安全，拒绝修复。
	ErrNotRepairable = errors.New("auditlog: log not safely repairable")
	// ErrInvalidRetention 保留期设置非法（为零、为负等）。
	ErrInvalidRetention = errors.New("auditlog: invalid retention policy")
	// ErrNothingEligible 没有任何记录满足删除条件。
	ErrNothingEligible = errors.New("auditlog: no record eligible for purge yet")
	// ErrNotYetDeletable 待清理记录还不满足删除条件（年轻于保留期）。
	ErrNotYetDeletable = errors.New("auditlog: requested records not yet deletable")
	// ErrRangeConflict 调用方要求的清理范围与保留策略允许的范围冲突。
	ErrRangeConflict = errors.New("auditlog: purge range conflicts with retention policy")
	// ErrArchiveExists 归档目标已存在，拒绝覆盖。
	ErrArchiveExists = errors.New("auditlog: archive destination already exists")
	// ErrLocked 日志已被另一个进程/句柄以写方式打开。
	ErrLocked = errors.New("auditlog: log is locked by another writer")
	// ErrInvalidRecord 记录内容非法（为空、字段不合法等）。
	ErrInvalidRecord = errors.New("auditlog: invalid record")
	// ErrInvalidFormat 文件魔数/格式版本无法识别。
	ErrInvalidFormat = errors.New("auditlog: unrecognized file format")
)

// IntegrityProblem 描述一次完整性判定的结论与定位信息。
type IntegrityProblem struct {
	Kind   error  // 上述哨兵错误之一
	Offset int64  // 出问题的帧在日志文件中的起始字节偏移；-1 表示无法定位
	Index  int    // 出问题的帧在链上的序号；-1 表示无法定位
	Reason string // 判定依据的人类可读说明
}

func (p *IntegrityProblem) Error() string {
	return fmt.Sprintf("%s: %s (offset=%d index=%d)", p.Kind, p.Reason, p.Offset, p.Index)
}

func (p *IntegrityProblem) Unwrap() error { return p.Kind }
