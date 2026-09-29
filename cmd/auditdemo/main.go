// Command auditdemo 是一个本地可运行的端到端演示：
// 顺序追加 -> 全量校验 -> 重启续写 -> 归档 -> 清理，并打印每一步的判定依据与结论。
//
// 用法：
//
//	go run ./cmd/auditdemo [数据目录]
//
// 不传目录时使用 ./audit-demo-data。
package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/h3yow/audit-log-integrity-go/audit"
)

func main() {
	dir := "./audit-demo-data"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	base := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return base.Add(24 * time.Hour) }

	fmt.Printf("== open %s ==\n", dir)
	s, diag, err := audit.Open(dir, audit.Options{Clock: clock})
	if err != nil {
		fmt.Printf("open rejected: %v\n  reason: %s\n", err, diag.Reason)
		os.Exit(1)
	}
	fmt.Printf("diagnosis: clean=%v %s\n\n", diag.Clean, diag.Reason)

	if s.LastSeq() == 0 {
		fmt.Println("== append 5 sequential records (timestamps t0..t0+4s) ==")
		for i := 0; i < 5; i++ {
			r, err := s.Append(fmt.Sprintf("user-%d", i),
				[]string{"login", "read", "write", "export", "logout"}[i],
				fmt.Sprintf("doc/%d", i), "demo", base.Add(time.Duration(i)*time.Second))
			must(err)
			fmt.Printf("append seq=%d self=%s prev=%s\n", r.Seq, r.SelfHash[:20], r.PrevHash[:20])
		}
	}

	fmt.Println("\n== verify ==")
	rep, err := s.Verify()
	must(err)
	fmt.Printf("ok=%v records=%d range=%d..%d\n  %s\n", rep.OK, rep.Records, rep.HeadSeq, rep.LastSeq, rep.Reason)

	fmt.Println("\n== simulate restart (close + reopen) ==")
	must(s.Close())
	s, diag, err = audit.Open(dir, audit.Options{Clock: clock})
	if err != nil {
		panic(err)
	}
	fmt.Printf("reopened: clean=%v head=%d last=%d\n", diag.Clean, s.HeadSeq(), s.LastSeq())

	fmt.Println("\n== archive records older than 1h, keep latest 2 ==")
	ar, err := s.Archive(audit.RetentionPolicy{MinAge: time.Hour, KeepLatest: 2},
		audit.ArchiveOptions{Now: base.Add(24 * time.Hour)})
	switch {
	case err == nil:
		fmt.Printf("archived %d records seq %d..%d -> %s; active head now %d\n",
			ar.Archived, ar.FirstSeq, ar.LastSeq, ar.Path, ar.NewHeadSeq)
		arep, aerr := audit.VerifyArchive(ar.Path)
		must(aerr)
		fmt.Printf("archive verify: ok=%v %s\n", arep.OK, arep.Reason)
	case errors.Is(err, audit.ErrNothingToPurge),
		errors.Is(err, audit.ErrPurgeConflict),
		errors.Is(err, audit.ErrRecordsNotEligible):
		fmt.Printf("archive explicitly refused (no silent skip): %v\n", err)
	default:
		must(err)
	}

	fmt.Println("\n== verify active log after archive ==")
	rep, err = s.Verify()
	must(err)
	fmt.Printf("ok=%v %s\n", rep.OK, rep.Reason)
	must(s.Close())
	fmt.Println("\nDEMO OK")
}

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
}
