# 审计日志完整性设计说明

本方案只用本地文件承载审计记录，不依赖任何外部服务，目标是让**写入、保留、历史校验**在
并发追加和进程重启之后都给出确定、可解释的结论：

- 历史中任意位置被改写、删除、插入都能被发现，并定位到出问题的序号；
- 多个写入方并发追加时次序一致，不重复占位、不断链；
- 超过保留期的记录可以清理或归档，处理之后剩余历史仍然校验通过；
- 非法保留策略、范围与策略冲突、记录尚未满足删除条件时明确拒绝并给出可区分原因；
- 重启 / 崩溃后，尾部截断、内容与检查点对不上、上次写入未正常收尾时拒绝续写；
  能确认收尾正常时安全续写。

## 1. 数据目录布局

```
<data-dir>/
├── audit.log              # 审计记录主体，每条一行 JSON（JSONL），仅追加
├── checkpoint.json        # “已确认提交的链条边界”，原子替换
├── events.log             # 清理/归档等管理事件流水（可追溯，不参与链校验）
├── lock                   # 进程间互斥锁（类 Unix 为 flock）
└── archive/
    ├── audit-0000000001-0000000003.log             # 归档出的记录前缀
    └── audit-0000000001-0000000003.log.manifest.json
```

## 2. 记录格式

`audit.log` 是只追加的文本文件，每条记录恰好占一行（字段中禁止出现 `\n` / `\r`）：

```json
{"seq":1,"time":1700000000,"actor":"alice","action":"login","resource":"console","detail":"ok","prev_hash":"sha256:9d0a...","self_hash":"sha256:208c..."}
```

| 字段 | 含义 |
| --- | --- |
| `seq` | 单调递增的位置序号，从 1 开始；清理/归档**不复用序号** |
| `time` | 业务时间（Unix 秒），由调用方提供，保留期据此判定 |
| `actor` / `action` / `resource` / `detail` | 用户可控内容，不能为空（actor/action），不含换行 |
| `prev_hash` | 前一条记录的 `self_hash`；链首为固定创世哈希 |
| `self_hash` | 本条记录内容的 SHA-256 |

哈希输入字段顺序固定，用 `\x1f`（单元分隔符）连接，避免字段内字符造成歧义：

```
sha256( seq \x1f time \x1f actor \x1f action \x1f resource \x1f detail \x1f prev_hash )
```

注意哈希输入**不含 `self_hash` 自身**，因此校验时可以直接重放。

**创世哈希**：链首（seq=1）记录的 `prev_hash` 是固定常量
`sha256("audit-log-genesis-v1")` =
`sha256:9d0a5ec411cd8aa94b8e51def2d69e650770099ebdc4d716bc826bf55f1428f8`。
它让“链从哪里开始”本身也是显式、可校验的，而不是隐式约定。

### 2.1 校验时检查什么

按行重放，对每个位置检查三件事：

1. **序号连续**：位置 *i*（从 head 起）的 `seq` 必须等于 `headSeq+i`；
   任何插入 / 删除 / 重排立刻表现为序号不匹配，并给出期望与实际序号。
2. **前后衔接**：`record[i].prev_hash == record[i-1].self_hash`；链首必须等于锚点。
   即使攻击者改写一条记录后又重新伪造了它的 `self_hash`，下一条的 `prev_hash`
   仍然对不上，断链点即问题定位处。
3. **内容与自身哈希一致**：重新计算 `self_hash` 并与落盘值比较。
   只改内容不改哈希会在这里暴露，报告中直接给出“落盘值 vs 重算值”。

## 3. 检查点：提交边界与崩溃恢复的依据

`checkpoint.json` 记录已确认提交的链条边界：

```json
{
  "version": 1,
  "head_seq": 1,
  "head_anchor": "sha256:9d0a...",
  "last_seq": 5,
  "last_hash": "sha256:7b9a...",
  "updated_at": 1700086400
}
```

- `head_seq` / `head_anchor`：现存第一条记录的序号与其 `prev_hash` 必须指向的锚点；
- `last_seq` / `last_hash`：现存最后一条记录的序号与自身哈希。

检查点用“临时文件 + fsync + rename + fsync 目录”原子替换，自身不会出现半截 JSON。

**为什么需要检查点**：只删日志尾部记录时，剩余前缀的哈希链本身仍然自洽；
是检查点的 `last_seq/last_hash` 让“检查点之后记录被删”无处遁形。

> 威胁模型边界：检查点与日志处于同一目录，能同时原子地改写这两个文件的攻击者
> 不在本方案的防御范围内（这是纯本地、无外部信任锚方案的固有边界）。
> 本方案防御的是：意外截断、写到一半的崩溃、单文件/部分文件被改写或删除。

## 4. 追加协议（崩溃安全）

所有写操作都在进程内互斥锁（`sync.Mutex`）与进程间目录锁（`flock`）保护下进行：

1. 依据检查点计算 `seq = last_seq + 1` 与 `prev_hash = last_hash`
   （空日志回退到 `head_anchor` / 创世哈希）；
2. 校验字段，计算 `self_hash`；
3. 以 `O_APPEND` 写入 `一行 JSON + '\n'` —— **换行符即提交标记**；
4. `fsync(audit.log)`；
5. 原子更新检查点并 `fsync` 目录。

崩溃窗口对应的重启结论：

| 崩溃时机 | 重启看到的现象 | 结论 |
| --- | --- | --- |
| 写完 `\n` 之前 | 末尾存在不以换行收尾的悬空字节 | `ErrUncleanTail`，拒绝续写；`Recover` 截断悬空字节 |
| 日志已 fsync、检查点更新前 | 行完整且链自洽，但文件尾晚于检查点 | 标记为“可恢复的未收尾”；`Recover` 推进检查点，**不丢数据、不重占位** |
| 检查点更新之后 | 文件与检查点一致 | 干净，直接续写 |

## 5. 重启 / 打开时的诊断

`Open` 会比较“磁盘文件 / 哈希链 / 检查点”三者，返回 `Diagnostic{Clean, Problem, Reason,...}`：

- **干净**：所有行以换行收尾、链校验通过、边界与检查点一致；允许追加。
- **悬空尾（dangling）**：最后一次写入没有正常收尾（含“行完整但检查点滞后”）；
  `Open` 返回错误，`Append` 被拒绝，直到显式 `Recover()`。
- **哈希链被破坏（tampered）**：改写 / 删除 / 插入 / 坏 JSON；
  `Recover` 也拒绝自动“修复”，绝不允许在可疑基础上再写出一条看似正常的记录。
- **检查点矛盾（checkpoint）**：检查点尾部超出文件（记录被删/文件被换）、
  有日志无检查点、首尾哈希不一致；拒绝续写。

`Recover()` 只做两种确定性处置：截断“已验证完整前缀”之后的悬空字节；
把检查点推进到文件真实尾部。链断裂一律返回 `ErrLogTampered` /
`ErrCheckpointMismatch`，由人工处理。

## 6. 保留、清理与归档

### 6.1 保留策略

```go
RetentionPolicy{ MinAge time.Duration; KeepLatest int64 }
```

一条记录**同时**满足以下条件才具备清理 / 归档资格：

1. 业务时间距今至少 `MinAge`（必须 > 0，否则 `ErrInvalidRetention`）；
2. 不属于序号最大的 `KeepLatest` 条（尾部保护区，防止时钟异常时误删尾部）。

### 6.2 清理规则

- 只允许删除**日志前缀中连续符合资格**的记录，遇到第一条不符合资格的记录立即停止，
  绝不留下中间空洞；
- 删除后剩余记录的字段与哈希完全不动；检查点的 head 锚点迁移为
  “被删前缀最后一条记录的 `self_hash`”，因此剩余链仍可独立校验；
- 全部删除时 `head_seq = lastRemoved.seq + 1`、`last_seq` 回退；再次追加序号继续单调，
  其 `prev_hash` 指向被删尾部的锚点哈希；
- 管理动作（删了哪个区间、新锚点是什么）追加记录到 `events.log`。

重写采用两阶段提交（`rewrite.pending.json` 标记，全程 fsync）：

1. 新日志写入 `audit.log.rewrite.tmp` 并 fsync；
2. 写入 pending 标记（含旧/新双方边界）并原子落盘；
3. `rename` 临时文件为 `audit.log`、fsync 目录——**rename 之后事务只能前滚**；
4. 切换检查点到新边界；
5. 删除 pending 标记。

任意一步崩溃后重新 `Open`，`resumePendingRewrite` 给出确定结论：

- `audit.log` 仍匹配旧边界（rename 未发生）：丢弃临时文件与标记，**回滚**，数据不丢；
- `audit.log` 已匹配新边界（rename 已发生）：补齐检查点、删标记，**前滚**到清理后状态；
- 两者都不匹配：返回 `ErrLogTampered`，拒绝靠猜测继续。

### 6.3 可区分的拒绝原因

| 场景 | 返回错误 |
| --- | --- |
| `MinAge <= 0` 或 `KeepLatest < 0` | `ErrInvalidRetention` |
| 请求范围落入尾部保护区 | `ErrPurgeConflict` |
| 范围内有记录未达到 `MinAge`（含会留下空洞的 `PurgeBefore`） | `ErrRecordsNotEligible` |
| 没有任何命中的现存记录 / 空日志 | `ErrNothingToPurge` |
| 存储未处于已验证干净状态 | `ErrUncleanTail` |

任何拒绝都不会改动文件，拒绝后立即 `Verify` 仍应通过（测试覆盖）。

### 6.4 归档

`Archive` 把同样的“连续合格前缀”原样移动到
`archive/audit-<firstSeq>-<lastSeq>.log`（记录的 seq / 哈希不变），
并写一份 `.manifest.json` 记录区间、首锚点与尾哈希，随后按 6.2 的原子协议重写活动日志。

- `VerifyArchive(path)` 独立重放归档文件：无清单时只接受“从 seq=1、创世哈希开始”的
  完整链首；有清单时按清单锚点验证，并核对清单的 `first_seq` 与文件一致；
- 活动日志的新 `head_anchor` 等于归档文件最后一条记录的 `self_hash`，
  因此“归档段 + 活动段”的完整时间线在哈希上是可拼接、可解释的。
