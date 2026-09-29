# audit-log-integrity-go

以**本地文件**承载、可自证完整性的审计日志存储。写入、保留清理、归档与
进程重启后的续写，在并发与崩溃之后都能给出**确定、可解释**的结论：
要么明确“通过 / 已安全续写”，要么明确指出问题类型与字节位置，绝不静默跳过。

## 它保证什么

- **顺序追加与完整性校验**
  - 每条记录帧带全链单调序号 `seq` 与前一帧哈希 `prev`，帧尾带自身内容的 SHA-256。
  - 历史中任意位置被**改写、删除、插入**，`Open`/`Verify` 都会失败，
    并返回问题类型、字节偏移 `Offset` 与链上序号 `Index`。
  - 多个 goroutine / 多个进程并发追加时，进程内互斥锁 + `flock` 双重串行化，
    序号集合恒为连续的 `1..N`，不会重复占位或断链。
- **按保留策略清理 / 归档**
  - 只允许清理“从最老一端开始的连续前缀”，不得跨过年轻记录清理更老的记录。
  - 清理后文件以**清理锚点帧**开头，保留记录的序号与哈希关系不变，剩余历史仍可校验。
  - 非法保留期、清理范围与策略冲突、记录还不满足删除条件等情况，
    分别返回可 `errors.Is` 区分的错误（见下表），不悄悄跳过。
- **重启与异常中断后的续写**
  - 每次成功追加都 fsync 数据帧，并原子替换一个“侧车检查点”
    （`<log>.state`：上次正常收尾时的文件长度、末帧哈希、末序号）。
  - 重启时以检查点为凭据分类处理；**只有能确认收尾正常时才续写**，
    可疑情况一律拒绝，可安全丢弃脏尾时由显式 `Repair` 处理。

## 文件布局

```
<dir>/audit.log        活动日志（帧序列，见下）
<dir>/audit.log.state  侧车检查点（JSON，temp+fsync+rename+fsync(dir) 原子落盘）
<dir>/audit.log.lock   flock 锁文件（跨进程单写者）
<dir>/<archive>.log    归档文件（可选；被清理前缀原文帧 + 收尾锚点，自包含可校验）
```

## 记录格式（线格式 v1）

所有整数大端。一个帧：

```
+----------+------+------------+--------------+----------+---------+----------+
| magic 7B | kind | headerLen  | header JSON  | bodyLen  |  body   | hash 32B |
|"AUDLOG1" |  1B  |    4B      |  headerLen B |   4B     | bodyLen | SHA-256  |
+----------+------+------------+--------------+----------+---------+----------+
```

- `hash = SHA256(headerJSON || body)`。
- `kind`：`1` = genesis（建链锚点，文件首帧）；`2` = record；`3` = anchor（清理边界）。
- record 的 header JSON 字段：`kind, seq, time(unix-nano), actor, action, resource, nbody, prev`。
- record 帧关系：`prev = 前一帧的 hash`；首条 record 的 `prev = genesis.hash`。
- anchor 帧字段：`removed`（累计清理条数）、`uptoseq`（被删末帧序号，=removed）、
  `uptotime`、`prev`（被删末帧哈希，同时作为归档咬合证据）、
  `link`（锚点后第一条 record 的 `prev` 必须等于它；实现上与 `prev` 相同）。

**链的形态：**

```
正常段:   genesis -> r1 -> r2 -> ... -> rN
清理后段: anchor(removed=k, link=rK.hash) -> r(k+1) -> ...
归档文件: r(a) -> ... -> r(k) -> anchor(prev=rK.hash, removed=k)
```

校验规则（`auditlog/verify.go`）：

1. 首帧必须是 genesis 或 anchor；帧 magic / 长度 / kind 合法；
2. 每帧重算 `SHA256(headerJSON||body)` 必须等于帧尾 hash（任一比特被改即失败）；
3. record 的 `prev`：正常段等于前一帧 hash；anchor 后的第一条等于 anchor.link；
4. record 的 `seq` 必须连续：genesis 段从 1 起，anchor 段从 `removed+1` 起。

删除会让其后第一帧的 `prev` 对不上；插入的伪造帧与新前帧对不上；改写则自哈希不符。
三者都会定位到具体的帧偏移与链上序号。

## 保留与清理规则

`RetentionPolicy{ MaxAge time.Duration; MinKeep int }`：

- `MaxAge` 必须为正，否则 `ErrInvalidRetention`；`MinKeep` 必须 ≥ 0。
- 事件时间 `t < now-MaxAge` 的记录才算“足够老”。
- 可清理集合必须是**最老端的连续 record 前缀**；遇到第一条年轻记录立即停止，
  其后即使还有更老的记录也不清理（不跨年轻记录）。
- 受 `MinKeep` 与“活动段至少保留 1 条”双重约束。
- `PurgeRequest.UpToOffset` 可限定允许清理的偏移上界；
  若它落在策略允许的前缀**内部**（切穿可清理前缀），返回 `ErrRangeConflict`；
  若它一条可删记录都没覆盖，返回 `ErrNothingEligible`。

清理动作为**原子重写**：写临时文件 `anchor + 保留帧原文` → fsync → rename 覆盖 →
fsync 目录 → 重新校验新文件 → 更新检查点。中途崩溃只会留下旧文件或未生效的临时文件。

`Archive(dst, …)` 先把被删前缀**原文帧 + 同一个锚点**写入 `dst`（`O_EXCL`，
不覆盖已有文件），归档文件可用 `VerifyArchive` 独立校验；随后执行同样的前缀清理。

| 场景 | 哨兵错误（`errors.Is`） |
|---|---|
| 保留期为零/负、MinKeep 为负 | `ErrInvalidRetention` |
| 记录还年轻 / MinKeep 保护了全部记录 | `ErrNotYetDeletable` |
| 请求范围内没有任何可删记录 | `ErrNothingEligible` |
| 清理范围切穿策略允许的前缀 | `ErrRangeConflict` |
| 归档目标已存在 | `ErrArchiveExists` |

## 重启与异常中断的处理

追加一帧的顺序是：① 取锁 ② 编码并 `write` 帧 ③ `fsync` 日志
④ 更新内存链状态 ⑤ 原子替换检查点。据此，重启时的判定：

| 磁盘现状 | 结论 | 行为 |
|---|---|---|
| 文件长度/末帧哈希/末序号 与检查点一致 | 收尾正常 | `Open` 成功，可直接追加 |
| 中段任一帧自哈希或 prev/seq 不符 | `ErrChainBroken`（带偏移/序号） | 拒绝打开与修复 |
| 文件比检查点更短（提交点之后被删） | `ErrTailTruncated` | 拒绝打开；`Repair` 也拒绝（不能凭空补字节） |
| 检查点之后有完整但未提交的帧 | `ErrUncleanShutdown` | 拒绝续写；`Repair` 截断到检查点 |
| 检查点之后是半个帧（写到一半崩溃） | `ErrUncleanShutdown` | 同上，截断到检查点 |
| 检查点文件缺失/损坏 | `ErrNotRepairable` | 没有可信收尾凭据，拒绝在不可信基础上续写 |
| 文件为全新空文件 | 建链 | 写入 genesis 并落首个检查点 |

`Repair` 的唯一允许动作：**已提交前缀（到检查点 size 为止）逐帧校验通过且与锚点一致**
时，把检查点之后的脏尾物理截断并 fsync；其它情况一律返回错误，不做“丢数据式”修复。

另：同一日志路径同时只允许一个写句柄——进程内互斥 + `audit.log.lock` 上的
非阻塞 `flock(LOCK_EX)`，第二个打开者得到 `ErrLocked`。

## 本地验证

无需外部依赖（仅用标准库；Go ≥ 1.25）。

```bash
# 1) 全部单测（含篡改 / 并发追加 / 清理归档 / 重启续写），-v 可看到每个用例
#    打印的【输入 / 判定依据 / 结论】
go test -race -v ./...

# 2) 编译演示 CLI
go build -o /tmp/audit-demo ./cmd/audit-demo

D=$(mktemp -d)
/tmp/audit-demo append  $D/a.log alice login host-1 '{"ip":"10.0.0.1"}'
/tmp/audit-demo append  $D/a.log bob   grant host-2
/tmp/audit-demo verify  $D/a.log
/tmp/audit-demo purge   $D/a.log 168h   # 不足够老 => ErrNotYetDeletable（明确拒绝）
```

篡改演示（翻转中段一个字节后必须被发现并拒绝）：

```bash
python3 - "$D/a.log" <<'PY'
import sys
p=sys.argv[1]; b=bytearray(open(p,'rb').read()); b[300]^=0xFF; open(p,'wb').write(b)
PY
/tmp/audit-demo verify $D/a.log   # => hash chain broken，并带 offset/index
/tmp/audit-demo repair $D/a.log   # => not safely repairable（中段伤不可修复）
```

模拟写到一半崩溃后修复：

```bash
printf 'AUDLOG1\x02garbage' >> "$D/a.log"   # 末尾制造半个帧
/tmp/audit-demo verify $D/a.log             # => unclean shutdown detected
/tmp/audit-demo repair $D/a.log             # 截断脏尾后恢复
/tmp/audit-demo append $D/a.log carl resume host-3
```

## 包 API 速览

```go
s, _ := auditlog.Open("data/audit.log")
seq, off, err := s.Append(auditlog.Record{Actor: "alice", Action: "login", Resource: "host-1"})
rep, err := s.Verify()
res, err := s.Purge(auditlog.RetentionPolicy{MaxAge: 90*24*time.Hour, MinKeep: 1000},
                    auditlog.PurgeRequest{Now: time.Now()})
res, err = s.Archive("data/2026Q3.log", pol, req)
arcRep, err := auditlog.VerifyArchive("data/2026Q3.log")
s.Close()

s, err = auditlog.Repair("data/audit.log") // 仅在“脏尾且前缀干净”时成功
```
