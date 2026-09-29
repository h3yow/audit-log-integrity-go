package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// rewritePending 是日志重写（purge / archive）的两阶段提交标记。
//
// 协议：
//  1. 把新日志写入 audit.log.rewrite.tmp 并 fsync；
//  2. 写本标记（含旧/新边界与临时文件路径）并原子落盘；
//  3. rename 临时文件为 audit.log，fsync 目录（此后只能前滚）；
//  4. 切换检查点到新边界；
//  5. 删除标记。
//
// 任何一步崩溃后重开，resumePendingRewrite 都能给出确定结论：
//   - audit.log 仍是旧日志且临时文件还在 => 回滚（丢弃临时文件与标记）；
//   - audit.log 已是新日志（与新边界校验一致）=> 前滚（补齐检查点、删标记）；
//   - 两者都对不上 => ErrLogTampered，拒绝猜测。
type rewritePending struct {
	Version    int        `json:"version"`
	TempPath   string     `json:"temp_path"`
	Old        checkpoint `json:"old"`
	New        checkpoint `json:"new"`
	Kind       string     `json:"kind"`
	Archive    string     `json:"archive_path,omitempty"`
	ArchLastH  string     `json:"archive_last_hash,omitempty"`
	RemovedN   int64      `json:"removed_count"`
	RemovedFst int64      `json:"removed_first_seq"`
	RemovedLst int64      `json:"removed_last_seq"`
	At         int64      `json:"at"`
}

func pendingPath(dir string) string { return filepath.Join(dir, "rewrite.pending.json") }

func (p *rewritePending) save(dir string) error {
	p.Version = 1
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := pendingPath(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := syncPath(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, pendingPath(dir)); err != nil {
		return err
	}
	return syncDir(dir)
}

func loadPending(dir string) (*rewritePending, error) {
	b, err := os.ReadFile(pendingPath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var p rewritePending
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%w: invalid rewrite pending marker: %v", ErrCheckpointMismatch, err)
	}
	return &p, nil
}

func syncPath(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// logMatchesCheckpoint 判断当前 audit.log 是否恰好与给定检查点描述的边界一致。
func logMatchesCheckpoint(dir string, cp *checkpoint) ([]*Record, bool) {
	lines, dangling, _, err := scanFile(logPath(dir))
	if err != nil || len(dangling) > 0 {
		return nil, false
	}
	records, fail := verifyChain(lines, cp.HeadSeq, cp.HeadAnchor)
	if fail != nil {
		return nil, false
	}
	var lastSeq int64 = cp.HeadSeq - 1
	var lastHash string
	if len(records) > 0 {
		lastSeq = records[len(records)-1].Seq
		lastHash = records[len(records)-1].SelfHash
	}
	if lastSeq != cp.LastSeq {
		return nil, false
	}
	if len(records) > 0 && lastHash != cp.LastHash {
		return nil, false
	}
	return records, true
}

// resumePendingRewrite 在打开阶段消解可能残留的重写事务。
// 返回消解后应采用的检查点；无待处理事务时返回入参 cp。
func resumePendingRewrite(dir string, cp *checkpoint) (*checkpoint, error) {
	p, err := loadPending(dir)
	if err != nil {
		return cp, err
	}
	if p == nil {
		return cp, nil
	}

	// 前滚：audit.log 已经是新版本。
	if _, ok := logMatchesCheckpoint(dir, &p.New); ok {
		if err := saveCheckpoint(dir, &p.New); err != nil {
			return cp, err
		}
		_ = os.Remove(p.TempPath)
		if err := os.Remove(pendingPath(dir)); err != nil {
			return cp, err
		}
		if err := syncDir(dir); err != nil {
			return cp, err
		}
		// 管理事件落账（归档崩溃也照记，因为归档文件在 rename 之前已 fsync）。
		ev := map[string]any{
			"event":             p.Kind + "-recovered",
			"at":                p.At,
			"removed_first_seq": p.RemovedFst,
			"removed_last_seq":  p.RemovedLst,
			"removed_count":     p.RemovedN,
			"new_head_seq":      p.New.HeadSeq,
			"new_head_anchor":   p.New.HeadAnchor,
		}
		if p.Archive != "" {
			ev["archive_path"] = p.Archive
			ev["archive_last_hash"] = p.ArchLastH
		}
		_ = appendEventLog(dir, ev)
		return &p.New, nil
	}

	// 回滚：audit.log 仍是旧版本，且临时文件还在（rename 尚未发生）。
	if _, ok := logMatchesCheckpoint(dir, &p.Old); ok {
		if _, statErr := os.Stat(p.TempPath); statErr != nil {
			return cp, fmt.Errorf(
				"%w: rewrite marker exists, log is old but temp file is missing: cannot decide intent",
				ErrLogTampered)
		}
		if err := os.Remove(p.TempPath); err != nil {
			return cp, err
		}
		if err := os.Remove(pendingPath(dir)); err != nil {
			return cp, err
		}
		if err := syncDir(dir); err != nil {
			return cp, err
		}
		return &p.Old, nil
	}

	return cp, fmt.Errorf(
		"%w: interrupted rewrite marker found but audit.log matches neither old nor new boundary",
		ErrLogTampered)
}
