package audit

import "time"

// VerifyReport 是一次全量校验的结论。
type VerifyReport struct {
	// OK 链条是否完整一致。
	OK bool
	// Records 参与校验的记录条数。
	Records int64
	// FirstSeq / LastSeq 校验覆盖的序号范围。
	FirstSeq int64
	LastSeq  int64
	// HeadSeq 磁盘现存第一条记录的序号（清理 / 归档后可能 > 1）。
	HeadSeq int64
	// FirstPrevHash 现存第一条记录保存的前驱哈希。
	FirstPrevHash string
	// LastHash 现存最后一条记录的自身哈希。
	LastHash string
	// LastTime 最后一条记录的业务时间。
	LastTime int64
	// VerifiedAt 校验时刻。
	VerifiedAt time.Time
	// ProblemSeq 发现问题的位置（序号）；无问题时为 0。
	ProblemSeq int64
	// Reason 人类可解释的判定依据。
	Reason string
}

// Diagnostic 是打开存储时对文件状态的诊断结论。
type Diagnostic struct {
	// Clean 上次写入是否确认正常收尾、当前文件是否可直接续写。
	Clean bool
	// TotalLines 日志中完整的行数。
	TotalLines int64
	// HeadSeq / LastSeq 现存记录序号范围。
	HeadSeq int64
	LastSeq int64
	// LastHash 最后一条记录哈希。
	LastHash string
	// DanglingBytes 最后一个换行符之后的悬空字节数（截断写）。
	DanglingBytes int64
	// Report 全量哈希链校验报告。
	Report VerifyReport
	// Reason 判定依据。
	Reason string
	// Problem 诊断出的问题类别（problemDangling/problemTampered/problemCheckpoint）。
	Problem string
}
