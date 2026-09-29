package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Record 是一条审计记录的内存表示。
// 落盘时以单行 JSON 写入日志文件，并通过 PrevHash / SelfHash 与相邻记录构成哈希链：
//
//	record[n].prev_hash == record[n-1].self_hash
//	record[n].self_hash == sha256(固定字段顺序的 record[n] 内容)
//
// 链首记录（seq=1，或清理/归档后现存的新 head）的 prev_hash 指向一个
// 固定的创世哈希，使“从哪里开始链”本身也是显式、可校验的。
type Record struct {
	Seq      int64  `json:"seq"`
	Time     int64  `json:"time"` // 业务时间，Unix 秒
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Detail   string `json:"detail"`
	PrevHash string `json:"prev_hash"`
	SelfHash string `json:"self_hash"`
}

// validateFields 检查用户可控字段是否合法（哈希字段由内部计算，不在此列）。
func (r *Record) validateFields() error {
	if r.Seq < 1 {
		return fmt.Errorf("%w: seq must be >= 1, got %d", ErrInvalidRecord, r.Seq)
	}
	if r.Time < 0 {
		return fmt.Errorf("%w: time must be a non-negative unix timestamp", ErrInvalidRecord)
	}
	if r.Actor == "" {
		return fmt.Errorf("%w: actor is empty", ErrInvalidRecord)
	}
	if r.Action == "" {
		return fmt.Errorf("%w: action is empty", ErrInvalidRecord)
	}
	// resource/detail 允许为空，但所有字符串字段都不允许包含换行或回车，
	// 保证“一条记录一行”的物理格式不被破坏。
	for name, v := range map[string]string{
		"actor": r.Actor, "action": r.Action,
		"resource": r.Resource, "detail": r.Detail,
	} {
		if bytes.ContainsAny([]byte(v), "\n\r") {
			return fmt.Errorf("%w: %s contains newline", ErrInvalidRecord, name)
		}
	}
	return nil
}

// marshalLine 把记录编码为一行 JSON（不含行尾换行）。
func marshalLine(r *Record) ([]byte, error) {
	return json.Marshal(r)
}

// unmarshalLine 解析一行 JSON 为记录。
func unmarshalLine(bytesLine []byte) (*Record, error) {
	var r Record
	dec := json.NewDecoder(bytes.NewReader(bytesLine))
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("decode record line: %w", err)
	}
	// 一行里只允许恰好一条 JSON 对象，拒绝尾随垃圾。
	if dec.More() {
		return nil, fmt.Errorf("decode record line: trailing data")
	}
	return &r, nil
}
