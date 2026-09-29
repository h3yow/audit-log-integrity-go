// audit-demo 是审计日志库的本地自证入口：
//
//	append  <path> <actor> <action> <resource> [detail]
//	verify  <path>
//	purge   <path> <maxage-duration> [minkeep]
//	archive <path> <archivePath> <maxage-duration> [minkeep]
//	repair  <path>
//
// 所有命令都会打印“输入 / 判定依据 / 结论”。
package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/h3yow/audit-log-integrity-go/auditlog"
)

func main() {
	if len(os.Args) < 3 {
		usage()
	}
	cmd, path := os.Args[1], os.Args[2]
	var err error
	switch cmd {
	case "append":
		err = doAppend(path, os.Args[3:])
	case "verify":
		err = doVerify(path)
	case "purge":
		err = doPurge(path, "", os.Args[3:])
	case "archive":
		if len(os.Args) < 4 {
			usage()
		}
		err = doPurge(path, os.Args[3], os.Args[4:])
	case "repair":
		err = doRepair(path)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "结论: 失败 (%v)\n", classify(err))
		os.Exit(1)
	}
}

func classify(err error) string {
	for _, target := range []error{
		auditlog.ErrChainBroken, auditlog.ErrTailTruncated, auditlog.ErrUncleanShutdown,
		auditlog.ErrNotRepairable, auditlog.ErrInvalidRetention, auditlog.ErrNothingEligible,
		auditlog.ErrNotYetDeletable, auditlog.ErrRangeConflict, auditlog.ErrArchiveExists,
		auditlog.ErrLocked, auditlog.ErrInvalidRecord, auditlog.ErrInvalidFormat,
	} {
		if errors.Is(err, target) {
			return target.Error()
		}
	}
	return err.Error()
}

func doAppend(path string, args []string) error {
	if len(args) < 3 {
		usage()
	}
	detail := ""
	if len(args) > 3 {
		detail = args[3]
	}
	s, err := auditlog.Open(path)
	if err != nil {
		return err
	}
	defer s.Close()
	seq, off, err := s.Append(auditlog.Record{
		Timestamp: time.Now().UTC(),
		Actor:     args[0], Action: args[1], Resource: args[2], Detail: detail,
	})
	if err != nil {
		return err
	}
	fmt.Printf("输入: actor=%s action=%s resource=%s\n", args[0], args[1], args[2])
	fmt.Printf("判定依据: 全锁串行编码帧(seq/prev/自哈希)并 fsync 数据+原子侧车锚点\n")
	fmt.Printf("结论: 成功 seq=%d offset=%d\n", seq, off)
	return nil
}

func doVerify(path string) error {
	s, err := auditlog.Open(path)
	if err != nil {
		return err
	}
	defer s.Close()
	rep, err := s.Verify()
	if err != nil {
		return err
	}
	fmt.Printf("判定依据: 从首字节逐帧重算自哈希并比对 prev 链/序号连续性\n")
	fmt.Printf("结论: OK records=%d lastSeq=%d size=%d firstIsAnchor=%v totalRemoved=%d\n",
		rep.Count, rep.LastSeq, rep.LastOffset, rep.FirstIsAnchor, rep.TotalRemoved)
	return nil
}

func doPurge(path, archive string, args []string) error {
	if len(args) < 1 {
		usage()
	}
	maxAge, err := time.ParseDuration(args[0])
	if err != nil {
		return fmt.Errorf("解析 maxage: %w", err)
	}
	minKeep := 0
	if len(args) > 1 {
		minKeep, err = strconv.Atoi(args[1])
		if err != nil {
			return err
		}
	}
	s, err := auditlog.Open(path)
	if err != nil {
		return err
	}
	defer s.Close()
	pol := auditlog.RetentionPolicy{MaxAge: maxAge, MinKeep: minKeep}
	req := auditlog.PurgeRequest{Now: time.Now().UTC()}
	fmt.Printf("输入: maxage=%s minkeep=%d now=%s\n", maxAge, minKeep, req.Now.Format(time.RFC3339))
	var res *auditlog.PurgeResult
	if archive != "" {
		res, err = s.Archive(archive, pol, req)
	} else {
		res, err = s.Purge(pol, req)
	}
	if err != nil {
		return err
	}
	fmt.Printf("判定依据: 仅删最老端连续且早于 now-maxage 的前缀，活动段至少保留 1 条；新首帧为清理锚点\n")
	fmt.Printf("结论: removed=%d newStartSeq=%d archived=%v\n", res.Removed, res.NewStartIndex, res.Archived)
	return nil
}

func doRepair(path string) error {
	s, err := auditlog.Repair(path)
	if err != nil {
		return err
	}
	defer s.Close()
	rep, err := s.Verify()
	if err != nil {
		return err
	}
	fmt.Printf("判定依据: 已提交前缀与锚点一致，脏尾全部位于锚点之后并已物理截断\n")
	fmt.Printf("结论: 修复完成 records=%d lastSeq=%d\n", rep.Count, rep.LastSeq)
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, `用法:
  audit-demo append  <path> <actor> <action> <resource> [detail]
  audit-demo verify  <path>
  audit-demo purge   <path> <maxage> [minkeep]
  audit-demo archive <path> <archivePath> <maxage> [minkeep]
  audit-demo repair  <path>`)
	os.Exit(2)
}
