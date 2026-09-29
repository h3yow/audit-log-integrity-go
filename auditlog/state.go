package auditlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// stateMagic 标识侧车检查点文件。
const stateMagic = "AUDSTATE1"

// checkpoint 是“上次正常收尾”时落下的侧车锚点。
//
// 重启时用它与日志文件实际内容比对：
//   - 日志长度 == Size，且末帧哈希/序号与锚点一致 => 收尾正常，可续写；
//   - 日志短于 Size，或末帧与锚点对不上 => 疑似截断/回卷（ErrTailTruncated）；
//   - 日志长于 Size => 上次 append 未正常收尾（ErrUncleanShutdown），
//     多出的字节必须被证明是“结构完整但未提交”的一帧，或半个帧，方可 Repair。
type checkpoint struct {
	Magic    string   `json:"magic"`
	LastSeq  int64    `json:"last_seq"`
	LastHash [32]byte `json:"last_hash"` // 末帧（record 或 anchor）的链哈希
	Size     int64    `json:"size"`      // 正常收尾时日志文件长度
	Clean    bool     `json:"clean"`     // 是否为 append 完成后落的锚点
}

// readCheckpoint 读取并校验侧车锚点；文件不存在时返回 (nil, nil, nil)。
// 返回的第二值是文件原始字节（供上层需要时使用）。
func readCheckpoint(path string) (*checkpoint, []byte, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("auditlog: read checkpoint: %w", err)
	}
	var cp checkpoint
	if err := json.Unmarshal(raw, &cp); err != nil {
		return nil, raw, fmt.Errorf("%w: checkpoint unparseable: %v", ErrNotRepairable, err)
	}
	if cp.Magic != stateMagic {
		return nil, raw, fmt.Errorf("%w: checkpoint magic mismatch", ErrNotRepairable)
	}
	return &cp, raw, nil
}

// writeCheckpoint 将锚点原子地（temp + fsync + rename + fsync dir）写到 path。
func writeCheckpoint(path string, cp *checkpoint) error {
	cp.Magic = stateMagic
	raw, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("auditlog: encode checkpoint: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return fmt.Errorf("auditlog: create temp checkpoint: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("auditlog: write checkpoint: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("auditlog: fsync checkpoint: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("auditlog: close checkpoint: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("auditlog: install checkpoint: %w", err)
	}
	if err := fsyncDir(dir); err != nil {
		return err
	}
	return nil
}

// removeCheckpoint 删除侧车锚点（保留路径不存在的容错）。
func removeCheckpoint(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// fsyncDir fsync 一个目录，保证其中的 rename/create 元数据落盘。
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("auditlog: open dir for fsync: %w", err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("auditlog: fsync dir: %w", err)
	}
	return d.Close()
}
