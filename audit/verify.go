package audit

import (
	"bytes"
	"fmt"
	"os"
)

// integrityFailure 携带问题位置与可解释原因。
type integrityFailure struct {
	problemSeq int64
	reason     string
}

func (e *integrityFailure) Error() string {
	if e.problemSeq > 0 {
		return fmt.Sprintf("integrity failure at seq=%d: %s", e.problemSeq, e.reason)
	}
	return "integrity failure: " + e.reason
}

// scanFile 读取日志文件并切分为：以 '\n' 正常收尾的完整行 + 末尾悬空字节。
func scanFile(path string) (lines [][]byte, dangling []byte, size int64, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, 0, err
	}
	size = int64(len(b))
	if len(b) == 0 {
		return nil, nil, 0, nil
	}
	if b[len(b)-1] != '\n' {
		// 最后一条记录没有行尾换行：属于未收尾的写入。
		idx := bytes.LastIndexByte(b, '\n')
		var head []byte
		if idx < 0 {
			dangling = b
		} else {
			head, dangling = b[:idx+1], b[idx+1:]
		}
		b = head
	}
	if len(b) > 0 {
		lines = bytes.Split(b[:len(b)-1], []byte{'\n'})
	}
	return lines, dangling, size, nil
}

// verifyChain 重放完整行构成的哈希链。
//
// expectHeadSeq/expectHeadAnchor 描述链条必须从哪里开始：
//   - 活动日志：来自检查点（HeadSeq/HeadAnchor）；
//   - 全新日志或归档文件：seq 必须从 1 开始，锚点为创世哈希。
//
// 返回解析后的记录与失败详情（成功时 fail 为 nil）。
func verifyChain(lines [][]byte, expectHeadSeq int64, expectHeadAnchor string) (records []*Record, fail *integrityFailure) {
	var prevHash string
	for i, line := range lines {
		r, err := unmarshalLine(line)
		if err != nil {
			seq := int64(i) + expectHeadSeq
			return records, &integrityFailure{seq, "record line is not valid JSON: " + err.Error()}
		}
		position := int64(i) + 1
		// 1) 序号必须严格连续。
		wantSeq := expectHeadSeq + int64(i)
		if r.Seq != wantSeq {
			return records, &integrityFailure{r.Seq,
				fmt.Sprintf("seq mismatch at position %d: want %d, got %d (insert/delete/reorder detected)",
					position, wantSeq, r.Seq)}
		}
		// 2) 链首锚点 / 前驱哈希必须衔接。
		if i == 0 {
			if expectHeadSeq == 0 {
				return records, &integrityFailure{r.Seq, "chain is empty but a line exists"}
			}
			if r.PrevHash != expectHeadAnchor {
				return records, &integrityFailure{r.Seq, fmt.Sprintf(
					"head anchor mismatch: prev_hash=%q want %q", r.PrevHash, expectHeadAnchor)}
			}
			prevHash = expectHeadAnchor
		}
		if r.PrevHash != prevHash {
			return records, &integrityFailure{r.Seq, fmt.Sprintf(
				"broken link: prev_hash=%q does not match previous self_hash=%q", r.PrevHash, prevHash)}
		}
		// 3) 自身哈希必须与内容一致（字段被改写立即暴露）。
		got := hashRecord(r)
		if r.SelfHash != got {
			return records, &integrityFailure{r.Seq, fmt.Sprintf(
				"content hash mismatch: stored self_hash=%q recomputed=%q (tampered content)", r.SelfHash, got)}
		}
		if r.SelfHash == "" || r.PrevHash == "" {
			return records, &integrityFailure{r.Seq, "hash field is empty"}
		}
		prevHash = r.SelfHash
		records = append(records, r)
	}
	return records, nil
}
