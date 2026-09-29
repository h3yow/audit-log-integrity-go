package audit

import "errors"

// 打开 / 重启续写阶段的错误。
var (
	// ErrLogTampered 历史记录的哈希链被破坏（改写 / 删除 / 插入）。
	ErrLogTampered = errors.New("audit: log integrity check failed")
	// ErrUncleanTail 上次写入没有正常收尾（尾部截断 / 落盘不完整）。
	ErrUncleanTail = errors.New("audit: last append was not finalized cleanly")
	// ErrCheckpointMismatch 检查点与日志内容不一致。
	ErrCheckpointMismatch = errors.New("audit: checkpoint does not match log content")
	// ErrLogLocked 数据目录已被另一个进程占用。
	ErrLogLocked = errors.New("audit: data directory is locked by another process")
)

// 追加写入阶段的错误。
var (
	// ErrNotOpen 存储尚未打开或已关闭。
	ErrNotOpen = errors.New("audit: store is not open")
	// ErrInvalidRecord 记录字段不合法。
	ErrInvalidRecord = errors.New("audit: invalid record")
)

// 保留 / 清理 / 归档阶段的错误。
var (
	// ErrInvalidRetention 保留策略参数非法。
	ErrInvalidRetention = errors.New("audit: invalid retention policy")
	// ErrPurgeConflict 请求清理的范围与保留策略冲突。
	ErrPurgeConflict = errors.New("audit: purge range conflicts with retention policy")
	// ErrRecordsNotEligible 待清理记录尚未满足删除条件。
	ErrRecordsNotEligible = errors.New("audit: records are not yet eligible for deletion")
	// ErrNothingToPurge 没有满足条件、可被清理的记录。
	ErrNothingToPurge = errors.New("audit: no eligible records to purge")
)
