# audit-log-integrity-go

本地文件承载、可自证完整性的审计日志存储。无需数据库或外部服务，
在**并发追加、进程重启 / 崩溃、历史清理 / 归档**之后仍能给出确定、可解释的结论。

详细设计见 [`docs/DESIGN.md`](docs/DESIGN.md)。

## 能力概览

- **顺序追加 + 哈希链**：每条记录含 `prev_hash` / `self_hash`（SHA-256），
  任意位置的改写、删除、插入都会在校验时暴露并定位到具体 `seq`。
- **并发安全**：进程内互斥锁 + 数据目录 `flock` 进程间互斥；
  序号严格连续、不重复占位，重启后追加次序与落盘一致。
- **保留 / 清理 / 归档**：`MinAge + KeepLatest` 策略；只删连续合格前缀；
  非法策略、范围冲突、记录未到期分别返回可区分错误，绝不静默跳过；
  归档文件可独立校验，并与活动日志在哈希上衔接。
- **重启续写**：打开时三方比对（文件 / 哈希链 / 检查点）；
  悬空尾、检查点矛盾、链断裂时拒绝续写；崩溃后可 `Recover()`
  截断半截写或推进滞后检查点，然后安全续写。

## 快速上手

```go
s, diag, err := audit.Open("./data", audit.Options{}) // diag.Clean=true 才可写
if err != nil {
    log.Fatalf("log not trustworthy: %v (%s)", err, diag.Reason)
}
defer s.Close()

r, err := s.Append("alice", "login", "console", "ok", time.Now())
// r.Seq, r.PrevHash, r.SelfHash

rep, err := s.Verify()   // rep.OK / rep.Reason / rep.ProblemSeq
```

崩溃恢复：

```go
s, diag, err := audit.Open("./data", audit.Options{})
if errors.Is(err, audit.ErrUncleanTail) {
    if diag, err = s.Recover(); err != nil { /* 链断裂，必须人工介入 */ }
}
// 恢复干净后才允许 Append
```

清理 / 归档：

```go
s.Purge(audit.RetentionPolicy{MinAge: 24 * time.Hour, KeepLatest: 100}, audit.PurgeOptions{})
report, _ := s.Archive(audit.RetentionPolicy{MinAge: 90 * 24 * time.Hour, KeepLatest: 0},
    audit.ArchiveOptions{})
arep, err := audit.VerifyArchive(report.Path)
```

错误哨兵：`ErrLogTampered`、`ErrUncleanTail`、`ErrCheckpointMismatch`、
`ErrLogLocked`、`ErrInvalidRetention`、`ErrPurgeConflict`、
`ErrRecordsNotEligible`、`ErrNothingToPurge`。

## 本地验证

### 1. 运行全部单测（带竞态检测）

```bash
go test -race -count=1 -v ./...
```

测试覆盖以下场景，且每个用例都会打印**输入、判定依据、最终结论**：

| 测试 | 场景 |
| --- | --- |
| `TestVerifyHealthyChain` | 正常写入 / 校验不回归 |
| `TestTamperModifyMiddle` / `TestTamperRehashMiddle` | 改写内容、伪造 self_hash |
| `TestTamperDeleteMiddle` / `TestTamperInsert` | 删除 / 插入记录并定位 |
| `TestTamperTruncateTail` | 只删尾部（靠检查点发现） |
| `TestTamperCorruptJSON` / `TestReopenRejectsTamperedLog` | 坏行、重启拒写 |
| `TestConcurrentAppend` | 8×25 并发追加：序号唯一连续、重启一致 |
| `TestProcessLock` | 同目录第二个进程被拒，关闭后释放 |
| `TestPurge*` / `TestArchive*` | 保留策略、连续前缀删除、全删续写、重启一致、四类拒绝原因、归档自校验与衔接、非链首归档凭清单验证 |
| `TestCleanRestartContinue` | 正常收尾后续写 |
| `TestRestartDanglingBytes` | 半截写：拒写 → Recover 截断 → seq 不重复地续写 |
| `TestRestartCheckpointLag` | 记录已提交、检查点滞后：Recover 不丢数据、不重占位 |
| `TestRestartChainBreakIsNotAutoRecoverable` | 链断裂：Recover 拒绝掩盖问题 |
| `TestRestartCheckpointAhead` / `TestRestartNoCheckpointWithLog` / `TestRestartLogFileDeleted` | 检查点矛盾 / 缺失凭据 / 日志文件整体丢失 |
| `TestCrashBeforeRenameRollback` / `TestCrashAfterRenameRollForward` / `TestInterruptedRewriteAmbiguous` | 清理重写两阶段提交在各崩溃窗口的回滚 / 前滚 / 拒绝猜测 |
| `TestAppendInvalidRecord` / `TestHashDeterminismAndLink` | 非法输入不占位、哈希确定性 |

### 2. 运行端到端演示

```bash
go run ./cmd/auditdemo /tmp/audit-demo
go run ./cmd/auditdemo /tmp/audit-demo   # 再跑一次：模拟重启 + 再次归档被策略拒绝
ls /tmp/audit-demo /tmp/audit-demo/archive
```

### 3. 手工制造篡改观察结论

```bash
go run ./cmd/auditdemo /tmp/audit-tamper
# 用编辑器把 audit.log 第二行里某个字段改掉，再运行：
go run ./cmd/auditdemo /tmp/audit-tamper
# 输出 open rejected ... reason: ... content hash mismatch / broken link，问题序号一并给出
```
