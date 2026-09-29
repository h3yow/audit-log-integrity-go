package audit

import (
	"fmt"
	"os"
	"time"
)

// Open 打开（必要时初始化）数据目录，并在允许续写前完成完整性诊断。
//
// 返回值约定：
//   - 目录为全新或日志确认收尾正常：store 可直接追加，diag.Clean=true，err=nil；
//   - 发现可疑状态（截断、链断裂、检查点不一致）：返回 err（可 errors.Is 判定类别），
//     同时仍返回非 nil 的 store 供只读检查（Diagnose/Verify）或调用 Recover；
//     此时 Append 一律被拒绝，直到 Recover 成功或 Close。
func Open(dir string, opts Options) (*Store, Diagnostic, error) {
	if dir == "" {
		return nil, Diagnostic{}, fmt.Errorf("%w: empty data directory", ErrInvalidRecord)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, Diagnostic{}, fmt.Errorf("create data directory: %w", err)
	}
	lock, err := acquireLock(dir)
	if err != nil {
		return nil, Diagnostic{}, err
	}

	s := &Store{
		dir:   dir,
		clock: opts.now,
		lock:  lock,
	}

	cp, err := loadCheckpoint(dir)
	if err != nil {
		s.cp = cp
		return s, s.DiagnoseOrErr(), err
	}
	// 消解上一次可能崩溃在中途的清理 / 归档重写事务（回滚或前滚）。
	cp, err = resumePendingRewrite(dir, cp)
	if err != nil {
		s.cp = cp
		diag := diagnose(dir, cp)
		return s, diag, err
	}
	path := logPath(dir)
	existed := true
	if _, statErr := os.Stat(path); statErr != nil {
		if !os.IsNotExist(statErr) {
			return s, Diagnostic{}, fmt.Errorf("stat log: %w", statErr)
		}
		existed = false
	}

	// 全新目录：无日志、无检查点 => 初始化空检查点（head=1，锚点为创世哈希）。
	if cp == nil && !existed {
		cp = &checkpoint{
			HeadSeq:    1,
			HeadAnchor: genesisPrevHash(),
			LastSeq:    0,
			LastHash:   "",
			UpdatedAt:  s.clock().Unix(),
		}
		if err := saveCheckpoint(dir, cp); err != nil {
			return s, Diagnostic{}, err
		}
		if err := syncDir(dir); err != nil {
			return s, Diagnostic{}, err
		}
	}
	s.cp = cp

	// 没有检查点却已有日志：拒绝在无凭据状态下续写。
	if cp == nil && existed {
		diag := diagnose(dir, nil)
		diag.Clean = false
		return s, diag, fmt.Errorf("%w: %s", ErrCheckpointMismatch, diag.Reason)
	}
	// 检查点证明曾有记录，但日志文件整体缺失：不得静默新建空日志继续写。
	if cp != nil && !existed && cp.LastSeq > 0 {
		diag := Diagnostic{
			Problem: problemCheckpoint,
			HeadSeq: cp.HeadSeq,
			LastSeq: cp.LastSeq,
			Reason: fmt.Sprintf(
				"audit.log is missing but checkpoint proves %d record(s) (head=%d last=%d) existed",
				cp.LastSeq-cp.HeadSeq+1, cp.HeadSeq, cp.LastSeq),
		}
		return s, diag, fmt.Errorf("%w: %s", ErrCheckpointMismatch, diag.Reason)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return s, Diagnostic{}, fmt.Errorf("open log file: %w", err)
	}
	s.log = f

	diag := diagnose(dir, cp)
	s.lastDiag = diag
	if diag.Clean {
		s.healthy = true
		return s, diag, nil
	}
	return s, diag, diagError(diag)
}

// DiagnoseOrErr 供加载检查点本身失败时使用：尽力给出诊断。
func (s *Store) DiagnoseOrErr() Diagnostic {
	return diagnose(s.dir, s.cp)
}

func diagError(d Diagnostic) error {
	switch d.Problem {
	case problemTampered:
		return fmt.Errorf("%w: %s", ErrLogTampered, d.Reason)
	case problemCheckpoint:
		return fmt.Errorf("%w: %s", ErrCheckpointMismatch, d.Reason)
	default:
		return fmt.Errorf("%w: %s", ErrUncleanTail, d.Reason)
	}
}

// 诊断问题类别。
const (
	problemNone       = ""
	problemDangling   = "dangling"
	problemTampered   = "tampered"
	problemCheckpoint = "checkpoint"
)

// diagnose 只读地比较“磁盘文件 / 哈希链 / 检查点”三者，给出可解释结论。
func diagnose(dir string, cp *checkpoint) Diagnostic {
	d := Diagnostic{}
	path := logPath(dir)
	lines, dangling, _, err := scanFile(path)
	if err != nil && !os.IsNotExist(err) {
		d.Reason = "cannot read log file: " + err.Error()
		d.Problem = problemTampered
		return d
	}
	d.DanglingBytes = int64(len(dangling))
	d.TotalLines = int64(len(lines))

	if len(dangling) > 0 {
		// 悬空内容若是一条完整 JSON，也一律视为未提交：我们无法证明其检查点已更新，
		// 宁可拒绝，由 Recover 明确截断。
		d.Problem = problemDangling
		d.Reason = fmt.Sprintf(
			"last %d byte(s) are not terminated by newline -> last append was not finalized cleanly",
			len(dangling))
	}

	records, fail := verifyChain(lines, expectHead(cp), expectAnchor(cp))
	if len(records) > 0 {
		d.HeadSeq = records[0].Seq
		d.LastSeq = records[len(records)-1].Seq
		d.LastHash = records[len(records)-1].SelfHash
	} else if cp != nil {
		d.HeadSeq = cp.HeadSeq
	}
	d.Report = buildReport(cp, records, fail)

	if fail != nil {
		d.Problem = problemTampered
		if d.Reason != "" {
			d.Reason += "; "
		}
		d.Reason += "hash chain verification failed: " + fail.reason
		return d
	}

	if cp == nil {
		if len(lines) > 0 {
			d.Problem = problemCheckpoint
			d.Reason = "log has records but checkpoint is missing; refusing to continue without provenance"
		} else {
			d.Reason = "empty log, no checkpoint"
		}
		return d
	}

	// 链条自洽，再与检查点比较边界。
	fileLast := d.LastSeq
	if len(records) == 0 {
		fileLast = cp.HeadSeq - 1 // 空日志：边界应停在 head 之前
	}
	switch {
	case fileLast < cp.LastSeq:
		d.Problem = problemCheckpoint
		d.Reason = fmt.Sprintf(
			"file ends at seq=%d but checkpoint proves seq=%d was committed -> records were deleted after last verified checkpoint",
			fileLast, cp.LastSeq)
	case fileLast > cp.LastSeq:
		// 记录已完整提交（含换行）、只是检查点更新前崩溃 => 可恢复。
		d.Problem = problemDangling
		if d.Reason != "" {
			d.Reason += "; "
		}
		d.Reason += fmt.Sprintf(
			"committed records reach seq=%d but checkpoint only acknowledges seq=%d -> last write was not fully finalized (recoverable)",
			fileLast, cp.LastSeq)
	case len(records) > 0 && d.LastHash != cp.LastHash:
		d.Problem = problemCheckpoint
		d.Reason = fmt.Sprintf("last hash mismatch: file=%s checkpoint=%s", d.LastHash, cp.LastHash)
	default:
		if d.Problem == problemNone {
			d.Clean = true
			d.Reason = fmt.Sprintf("clean: %d complete line(s), seq %d..%d match checkpoint",
				len(lines), safeHead(records, cp), fileLast)
		}
	}
	return d
}

func expectHead(cp *checkpoint) int64 {
	if cp == nil {
		return 1
	}
	return cp.HeadSeq
}

func expectAnchor(cp *checkpoint) string {
	if cp == nil {
		return genesisPrevHash()
	}
	return cp.HeadAnchor
}

func safeHead(records []*Record, cp *checkpoint) int64 {
	if len(records) > 0 {
		return records[0].Seq
	}
	if cp != nil {
		return cp.HeadSeq
	}
	return 1
}

func buildReport(cp *checkpoint, records []*Record, fail *integrityFailure) VerifyReport {
	rep := VerifyReport{VerifiedAt: time.Now()}
	fillReportFromRecords(&rep, expectHead(cp), records)
	if fail != nil {
		rep.OK = false
		rep.ProblemSeq = fail.problemSeq
		rep.Reason = fail.reason
	}
	return rep
}
