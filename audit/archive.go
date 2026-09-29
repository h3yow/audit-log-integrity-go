package audit

// ArchiveReport 是一次归档操作的结论。
type ArchiveReport struct {
	// Archived 被归档的记录条数。
	Archived int64
	// FirstSeq / LastSeq 被归档记录的序号范围；无归档时为零值。
	FirstSeq int64
	LastSeq  int64
	// Path 归档文件路径（无归档时为空）。
	Path string
	// NewHeadSeq 归档后日志现存第一条记录的序号。
	NewHeadSeq int64
	// Created 是否真正生成了归档文件。
	Created bool
}
