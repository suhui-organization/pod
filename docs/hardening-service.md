# 加固服务 — 交付物与订阅通道（方向 A + B）

> 状态：2026-09-12 落地。对应 `business-gtm.md` 的「一次性审计服务 $500-5,000/次」与
> 「按需深度服务」，以及 90 天计划里被搁置的「托管监控（非目标）」。
> 本文只写**服务边界**与**信任设计**，定价与验证实验见 `opc-security-pod/business-gtm.md`。

---

## 0. 一句话

**A 是入口（一次性加固审计），B 是复购（规则订阅）**——两者都不需要你持有客户的数据，
所以它们不破坏 D3「本地优先」这条最值钱的信任资产。

```
客户机器                                    你这边
─────────                                   ──────
pod harden  ──▶ report.md + manifest ──▶  交付 / 讲解 / 复核
pod rules pull ──▶ 验签 ──▶ 放宽守卫 ──▶  rules.json     ◀── 签发规则包（每周）
                                            （只签发，不接触客户机器）
```

---

## 1. A：一次性加固审计（`pod harden`）

### 1.1 为什么是一条命令而不是一份 checklist

审计服务卖的是**一份可复核、可自证的报告**，不是"你自己跑四条命令再把输出拼起来"。
交付物的边界就是产品。`pod harden` 把已有四个部件编排出一次交付：

| 部件 | 回答的问题 |
|------|-----------|
| `pod scan` | 你的机器上有什么、暴露了什么（T2/T4/T6） |
| `pod posture` | 控制平面有没有被改过（钩子/冻结项/记忆/包来源/身份/委托） |
| `pod policy draft` | 你实际用到的权限面有多大、最小权限长什么样 |
| `pod export-evidence` + `verify-audit` | 上面这些结论可不可验证 |

### 1.2 产物

```bash
pod harden --out ~/audit-<客户>-<日期>
```

| 文件 | 给谁看 |
|------|--------|
| `report.md` | 客户：摘要 → 待办（按严重级别排序）→ 建议执行顺序 → 四份子报告 → 产物清单 |
| `findings.json` | 客户的自查工具 / 下次审计做 diff |
| `policy-draft.json` | 直接可以 `pod lint` + `pod serve` 的最小权限草稿 |
| `evidence.json` | 审计链证据包（含自校验哈希） |
| `manifest.json` | 每份产物的 sha256——**交付物本身可自证没被改过** |

### 1.3 服务流程（谁做什么）

1. **客户侧**（数据不出机器）：`pod init` → 日常跑 `pod record` 攒 1-2 周语料 → `pod harden`
2. **交付**：客户把 `report.md` + `manifest.json` 给你（**不含 evidence.json** 也行）
3. **你侧**：读报告 → 讲解 + 复核 → 调整 `policy-draft.json` → 客户 `pod serve` 接管
4. **交接**：`pod posture freeze` 建立基线，此后任何变更都会被 `pod posture --strict` 报出来

> 第 2 步是卖点而不是限制：客户能验证你没顺手拿走他的审计原文（manifest 里只有哈希）。
> 如果客户连报告都不想出门，改成远程讲解 + 客户自己执行，服务照做，只是交付形态不同。

### 1.4 明确不承诺的

- 不承诺"零风险"——威胁模型 §5 的不防御清单（机器被完全攻陷、agent 平台后门、LLM 提供商侧泄露）依然成立；
- 不做渗透测试（v1 非目标）；
- 报告定位是**审计证据整理辅助**，不构成合规结论（GDPR/SOC 2 的法律责任在客户，见风险登记册 R9）。

---

## 2. B：订阅式加固（`pod rules`）

### 2.1 卖的是什么

不是功能，是**对抗知识的持续更新**：新的注入词表、新的钩子风险模式、新的供应链指纹、
新出现的破坏性工具名。这些是你在客户现场和公开事件里持续积累的东西，也是竞争对手抄不走的。

### 2.2 为什么这个架构天生适合订阅

判定规则全部外置在 `~/.pod/rules.json`（`control-plane-hardening.md` §2.3），所以
"规则"本身就是一份可以独立交付、独立订阅、可读可改可删的资产。客户订阅后：

- rules.json 仍然完整在他手里（不是被锁在 SaaS 里的黑盒）；
- 停订不会让任何已有防护失效，只是不再收到新规则；
- 这个"可退出"性质本身就是安全产品的信任来源。

### 2.3 规则包格式

```jsonc
{
  "schema": "pod-rules-pack/v1",
  "packVersion": "2026.09.12",
  "issuedBy": "podsec",
  "issuedAt": "2026-09-12T00:00:00.000Z",
  "note": "新增 1 条钩子风险模式 + 1 条注入词",
  "rules": { /* 增量规则：对象深合并、数组整体替换，与 rules.json 同语义 */ },
  "signature": "…"  // Ed25519 detached，对除本字段外的全部内容签名
}
```

### 2.4 四层防线（对应"订阅通道本身被投毒"这个新威胁）

订阅模式引入了一个新的攻击面：**更新通道**。让订阅者以为在升级、实际把 deny 列表清空，
是成本最低的攻击。所以：

1. **schema 校验**：结构不对直接抛错，不静默退回默认值（fail-closed）；
2. **Ed25519 验签**：`pod rules pull`（网络来源）**强制** `--key`，不给跳过验签的口子；
   `pod rules apply`（本地文件）可以不验签——因为能改这个文件的人本来就能直接改 rules.json，
   签名在那里只增加摩擦、不增加安全；
3. **放宽守卫**：`apply` 前后做结构化 diff，任何**放宽**已有规则的改动都会被拒绝，
   除非显式 `--allow-relax`。
4. **收紧守卫**：放宽守卫是**单向的**，只防"削弱"。反方向同样成立——推一条文本长度为 1
   的信号（或一批会把正常输出也命中的模式），就能让**所有**机器的工具输出被大面积拦下。
   这是可用性攻击，而且签名验签会**正常通过**（签名只证明来源，不证明这份规则合理）。
   更常见的来源其实是自己发错包：词表里手滑写个 `.`，效果与攻击一样。
   因此客户端还拒绝：会匹配一切的过短信号（< 3 字符），以及单次新增阻断级信号超过
   `tighteningBudget()` 上限的包（除非显式 `--allow-expansion`）。

   这个上限是**产品判断**，留在 `packages/policy/src/rules-pack.ts` 的
   `tighteningBudget()` 里给维护者调：定太小会拒掉正常的批量更新（用户开始用
   `--allow-expansion` 绕过，守卫名存实亡）；定太大则一次误发就能打穿所有客户。

### 2.5 放宽守卫现在能判定什么、不能判定什么

| 变化 | 判定 |
|------|------|
| 数组少了一条（模式表、路径表、注入词、期望活跃度…） | 🔴 relax，拦 |
| `severity` 从 high 降到 low | 🔴 relax，拦 |
| 布尔检查 true → false（`requireVersionPin`、`requireSigned`、`requireApprovalToChange`…） | 🔴 relax，拦 |
| 数组多了一条 / 布尔 false → true | 🟢 tighten，放行 |
| 数值阈值变化（`maxIdleHours`、`maxDepth`…） | ⚪ unknown，**不拦**，列出来交给人看 |

最后一行是刻意的：数值阈值的"松紧方向"因字段而异（`maxIdleHours` 变大是放宽，
`maxDepth` 变大也是放宽，但 `anomaly.capabilitiesPerWindow` 变大的方向含义又要看上下文），
猜错就等于给真正的放宽开门。要精确覆盖时，在
`packages/policy/src/rules-pack.ts` 的 `classifyChange` 里补一张
"路径 → 方向"的表（那里有 `ponytail:` 注释标了位置）。

### 2.6 签发方（你）的操作

```bash
# 一次性：生成签发密钥（私钥离线保管，公钥随产品分发）
openssl genpkey -algorithm ed25519 -out podsec-rules.key
openssl pkey -in podsec-rules.key -pubout -out podsec-rules.pub

# 每周：写增量规则 → 签发 → 发布
pod rules pack --key podsec-rules.key --in delta.json --out pack-2026.09.12.json \
  --version 2026.09.12 --issued-by podsec --note "新增 1 条钩子风险模式"
```

**纪律**：`delta.json` 必须是当前默认表的**超集**。漏掉一条默认规则会被客户侧的放宽守卫
拦下来（亲测：第一版测试包就漏了一条注入词，被自己写的守卫拦住）——这既是保护，也是
签发前的自检：**守卫拦住了客户，就说明你的包写错了。**

同理，一次补的阻断级信号别超过客户侧预算（默认是现有阻断级信号的 20%、下限 3 条）。
批量更新被拒不是客户苛刻，而是"一次推送的影响面要可控"。

### 2.7 客户侧的操作

```bash
pod rules show                                  # 当前生效的规则摘要
pod rules verify --in pack.json --key podsec-rules.pub   # 只验签，不应用
pod rules apply  --in pack.json --key podsec-rules.pub   # 本地包
pod rules pull   --url https://…/pack.json --key podsec-rules.pub  # 订阅更新
```

每次应用都会往控制平面审计链写一条 `config-change`（含包版本、签发者、收紧/放宽计数），
所以"这条规则是谁、什么时候换上的"永远可查——这是把规则包纳入 T7 证据链的部分。

---

## 3. A → B 的转化逻辑

审计是入口，订阅是复购，中间的桥是**基线**：

1. 审计交付后客户会 `pod posture freeze` 建立基线；
2. 基线一建立，"什么变了"就成了每周都会发生的事（新钩子、新包、新目录）；
3. 检测能力免费（`pod posture --strict`），**对抗知识**付费——这正是订阅的位置。

如果客户不订阅，他仍然拥有全部检测与执法能力，只是漏报会随时间累积。
这不是"锁住功能"，是"持续对抗需要持续投入"，两者可以同时为真。

---

## 4. 代码落点

| 关注点 | 位置 |
|--------|------|
| A 的编排与报告渲染 | `apps/cli/src/harden.ts` |
| B 的包格式 / 签名 / 放宽守卫 | `packages/policy/src/rules-pack.ts` |
| 共用 Ed25519 实现（策略与规则包同一口径） | `packages/policy/src/sign.ts` |
| CLI 接线 | `apps/cli/src/index.ts`（`pod harden`、`pod rules`） |
| 测试 | `packages/policy/src/rules-pack.test.ts`、`apps/cli/test/harden.test.ts` |
