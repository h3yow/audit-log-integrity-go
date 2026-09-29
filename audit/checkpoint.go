package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// checkpoint 是续写与重启判定的依据，与日志文件分离存放。
//
// 它记录“已确认落盘的链条边界”：
//   - HeadSeq/HeadAnchor：现存第一条记录的序号，以及它 prev_hash 必须指向的锚点
//     （全新日志锚点为创世哈希；清理/归档后锚点为被删前缀最后一条记录的自身哈希）；
//   - LastSeq/LastHash：现存最后一条记录的序号与自身哈希。
//
// 后缀删除类篡改（只删尾部记录时哈希链本身仍然自洽）正是通过
// checkpoint 的 LastSeq/LastHash 与文件内容比对发现的。
type checkpoint struct {
	Version    int    `json:"version"`
	HeadSeq    int64  `json:"head_seq"`
	HeadAnchor string `json:"head_anchor"`
	LastSeq    int64  `json:"last_seq"`
	LastHash   string `json:"last_hash"`
	UpdatedAt  int64  `json:"updated_at"`
}

const checkpointVersion = 1

func checkpointPath(dir string) string { return filepath.Join(dir, "checkpoint.json") }

// loadCheckpoint 读取检查点；文件不存在时返回 (nil, nil)。
func loadCheckpoint(dir string) (*checkpoint, error) {
	b, err := os.ReadFile(checkpointPath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read checkpoint: %w", err)
	}
	var cp checkpoint
	if err := json.Unmarshal(b, &cp); err != nil {
		return nil, fmt.Errorf("%w: parse checkpoint: %v", ErrCheckpointMismatch, err)
	}
	if cp.Version != checkpointVersion {
		return nil, fmt.Errorf("%w: unsupported checkpoint version %d", ErrCheckpointMismatch, cp.Version)
	}
	return &cp, nil
}

// saveCheckpoint 在同目录下“写临时文件 + fsync + 原子改名 + fsync 目录”，
// 保证检查点本身要么是旧版、要么是新版，不会出现半截 JSON。
func saveCheckpoint(dir string, cp *checkpoint) error {
	cp.Version = checkpointVersion
	b, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("encode checkpoint: %w", err)
	}
	tmp := checkpointPath(dir) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("write checkpoint: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return fmt.Errorf("write checkpoint: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync checkpoint: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close checkpoint: %w", err)
	}
	if err := os.Rename(tmp, checkpointPath(dir)); err != nil {
		return fmt.Errorf("rename checkpoint: %w", err)
	}
	return syncDir(dir)
}

// syncDir 对目录执行 fsync，使 rename / 新建条目落盘。
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir for sync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync dir: %w", err)
	}
	return nil
}
