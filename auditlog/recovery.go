package auditlog

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Repair 在重启发现“脏尾/未正常收尾”时使用。
//
// 可安全修复的唯一情形：
//  1. 锚点之前的全部内容校验通过（中段绝不能有问题）；
//  2. 问题完全位于最后一次已提交锚点之后——无论是半个帧，
//     还是一个结构完整但从未提交（落锚点）的帧。
//
// 修复动作是把文件物理截断到锚点记录的 Size，并重新核对后打开。
// 中段破坏、锚点不可信、文件比锚点更短等情况一律 ErrNotRepairable，
// 绝不“丢数据式”修复。
func Repair(path string, opts ...Option) (*Store, error) {
	cfg := config{clock: func() time.Time { return time.Now().UTC() }}
	for _, o := range opts {
		o(&cfg)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	lock, err := acquireLock(abs)
	if err != nil {
		return nil, err
	}
	logF, err := os.OpenFile(abs, os.O_RDWR, 0o600)
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("auditlog: open for repair: %w", err)
	}
	defer func() { _ = logF.Close() }()

	cp, _, err := readCheckpoint(abs + ".state")
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	if cp == nil {
		_ = lock.Close()
		return nil, fmt.Errorf("%w: no checkpoint available as repair anchor", ErrNotRepairable)
	}
	fi, err := logF.Stat()
	if err != nil {
		_ = lock.Close()
		return nil, err
	}

	// 情形一：文件比锚点更短 —— 已提交字节被删除，无法在不伪造数据的前提下恢复。
	if fi.Size() < cp.Size {
		_ = logF.Close()
		_ = lock.Close()
		return nil, &IntegrityProblem{
			Kind:   ErrTailTruncated,
			Offset: fi.Size(),
			Index:  -1,
			Reason: fmt.Sprintf("repair refused: file size %d is shorter than checkpoint size %d", fi.Size(), cp.Size),
		}
	}

	// 情形二：已提交前缀必须在锚点长度处干净校验通过。
	// 先于“长度相等即转交 Open”处理：即使长度恰好相等，中段有伤也必须明确拒绝修复。
	prefix, prob := verifyChain(logF, cp.Size)
	if prob != nil {
		_ = lock.Close()
		// 只要已提交前缀有任何问题（链断裂、格式非法、半帧等），一律不可修复。
		prob.Kind = ErrNotRepairable
		prob.Reason = "repair refused: committed prefix is itself corrupt — " + prob.Reason
		return nil, prob
	}
	if prefix.LastHash != cp.LastHash || prefix.LastSeq != cp.LastSeq {
		_ = lock.Close()
		return nil, &IntegrityProblem{
			Kind:   ErrNotRepairable,
			Offset: cp.Size,
			Index:  -1,
			Reason: "repair refused: committed prefix does not match its checkpoint anchor",
		}
	}

	if fi.Size() == cp.Size {
		// 没有脏尾且前缀完全干净：无需修复，走正常打开路径。
		_ = logF.Close()
		_ = lock.Close()
		return Open(abs, opts...)
	}

	// 情形三：锚点之后存在脏尾。脏尾必须可解析为若干完整帧或最后一个半帧
	// ——无论哪种都丢弃，
	// 但先确认它们没有破坏“已提交前缀”（上面已保证），此处仅做结构勘察并记录。
	sc := newFrameScanner(logF, cp.Size, fi.Size())
	for {
		_, scanErr := sc.next()
		if errors.Is(scanErr, io.EOF) {
			break
		}
		if errors.Is(scanErr, errTornTail) {
			break // 半帧：正是 unclean 的典型形态
		}
		if scanErr != nil {
			// 脏尾中出现无法识别的字节：仍然拒绝，宁可人工介入。
			_ = lock.Close()
			return nil, fmt.Errorf("%w: unparseable bytes beyond checkpoint: %v", ErrNotRepairable, scanErr)
		}
	}

	if err := logF.Truncate(cp.Size); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("auditlog: truncate torn tail: %w", err)
	}
	if err := logF.Sync(); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("auditlog: fsync after truncate: %w", err)
	}
	_ = logF.Close()
	if err := fsyncDir(filepath.Dir(abs)); err != nil {
		_ = lock.Close()
		return nil, err
	}
	_ = lock.Close()
	return Open(abs, opts...)
}
