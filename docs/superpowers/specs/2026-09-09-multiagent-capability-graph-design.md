# 多智能体能力图与最小权限策略设计（Phase A1）

> 状态：设计已逐节确认（2026-09-09），等待用户 review。
> 范围：pod 在"单机异构多 agent"场景下的第一个交付物。
> 决策链：A1 权限收敛 → B2 能力图 + 毒性组合 / B4 每 agent 最小权限策略 → C3 静态 + 观测双图 → D2 安全语义标签 → E2 建议策略 diff（人工确认）→ G1 dogfood → H1 + H3 门槛、H4 留存。

---

## 1. 背景与问题

单 agent 的安全问题是"这个 agent 能碰什么"。多 agent 的安全问题多了一层：**每个 agent 单独看都合规，合起来却构成一条完整攻击链**。

具体地，pod 的目标用户（先 dogfood，后 2-10 人微型工作室）在一台机器上同时运行 Claude Code、Codex、Cursor、OpenClaw 等 agent，它们共享同一批 MCP server、文件、凭据和网络出口。当前没有任何工具能回答：

1. 这些 agent **合起来**能碰到哪些敏感资源、哪些外发通道？
2. 哪些组合构成数据外泄、注入→执行、凭据滥用等**毒性路径**？
3. 要断掉这条路径，**最小、最不打扰**的策略改动是什么？
4. 哪些权限是"授权了但从未使用"（可削），哪些行为是"用了但没登记"（可疑）？

现有 pod 能力可以回答单 agent 的一部分问题：`policy draft` 从语料编译工具级策略，`scan`/`coverage` 发现暴露面，审计哈希链提供证据。缺的是**跨 agent 的能力建模**与**组合风险判定**。

---

## 2. 目标与非目标

### 2.1 目标

- 在单机异构多 agent 环境中构建**跨 agent 能力图**。
- 识别 source→sink 的**毒性组合**，包含同一 agent 内部与跨 agent 两种形态。
- 为每条毒性路径给出**定点策略 diff**（E2：人工确认后应用，不自动阻断）。
- 通过"潜在图 − 观测图"差集，输出**权限过载**与**影子能力**两类结论。
- 为 B4（每 agent 最小权限基线）提供输入，但不要求本期一次性完成 B4。
- dogfood 验收：H3（≤10 分钟出第一条路径）+ H1（≥1 条用户此前未意识到、且确认真实的毒性路径）；H4（连续 2 周主动使用）作为留存信号。

### 2.2 非目标（v1 明确不做）

- 不做运行时阻断（E4）；`pod graph toxic` 只产出 diff，执行仍走现有 `pod serve`。
- 不做 agent 身份与凭据治理（A4）。
- 不做 A2A 通信安全与委托授权（Phase B）。
- 不做 ML 分类；v1 用规则表 + 人工覆盖。
- 不引入图数据库；v1 用 JSON 文件。
- 不做 daemon / 自动刷新 / 云端上传。
- 不做 agent 编排、模型网关、通用 SIEM。

---

## 3. 架构

新增一个**只读分析层**，不进入运行时请求路径，复用 pod 已有的发现器、语料加载器与策略 diff 格式。

```text
┌─ pod graph（新增） ────────────────────────────────────────────┐
│                                                                │
│  graph-core（纯函数，无 IO）                                    │
│    · D2 能力分类器                                              │
│    · 图模型：节点 / 边 / 置信度 / 证据                           │
│    · 毒性规则表：source→sink 路径                               │
│    · 差集引擎：potential − observed / observed − potential      │
│    · 策略 diff 建议器                                           │
│                                                                │
│  graph-static（潜在图）        graph-observe（观测图）           │
│    · 读 agent 配置             · 读 ~/.pod/audit 语料            │
│    · 取 MCP server 工具 schema · 从真实调用 + 参数推断能力       │
│    · 复用 onboard/scan 发现器  · 复用 loadAllAuditFiles          │
│                                                                │
│  graph-cli：build / observe / diff / toxic / explain / mark     │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
     ~/.pod/graph/potential.json · observed.json · paths.json
     ~/.pod/graph/report.md · policy-diff.json · feedback.json
                              │
                              ▼
     报告（Markdown）+ policy-diff.json（复用 pod policy draft --diff 格式）
```

### 3.1 组件边界

| 组件 | 职责 | 依赖 | 不做什么 |
|---|---|---|---|
| `graph-core` | 分类、建模、规则、差集、diff 建议 | 无 IO、无网络 | 不读文件、不起进程 |
| `graph-static` | 发现 agent/server/tool，取 schema，生成潜在图 | `onboard` 发现器、MCP `tools/list`、schema 缓存 | 不调用 `tools/call` |
| `graph-observe` | 从审计语料推断能力，生成观测图 | `loadAllAuditFiles`、`packages/audit` | 不修改语料、不联网 |
| `graph-cli` | 命令编排、报告渲染、退出码 | 上述三者 | 不执行策略、不改 agent 配置 |

### 3.2 数据流

1. `pod graph build`：发现本机 agent/server → 获取工具清单 → D2 分类 → 写 `potential.json`。
2. `pod graph observe`：读取 `~/.pod/audit` 语料 → 从真实调用与参数推断能力 → 写 `observed.json`。
3. `pod graph diff`：两图相减 → 权限过载 / 影子能力。
4. `pod graph toxic`：在选定图上跑 source→sink 规则（含跨 agent）→ `paths.json` + 报告 + `policy-diff.json`。
5. `pod graph explain <path-id>`：把某条路径追溯到具体 agent/tool/调用/语料证据。

### 3.3 关键取舍

- `graph-core` 保持纯函数，所有 IO 在 `graph-static` / `graph-observe`，与现有 `policy`/`audit` 风格一致，便于 100% 单测。
- 复用 `discoverTargets`、`checkBypass`、`loadAllAuditFiles`，不重写扫描与语料加载逻辑。
- 策略 diff 直接复用 `policy draft --diff` 的输出格式与 `lintPolicy` 校验，不另造体系。
- v1 不进入运行时：分析失败不会影响 agent 正常工作。

---

## 4. 数据模型

### 4.1 图文件

v1 使用三个 JSON 文件，位于 `~/.pod/graph/`：

| 文件 | 内容 | 写入者 |
|---|---|---|
| `potential.json` | 潜在能力图（静态配置 + schema） | `pod graph build` |
| `observed.json` | 观测能力图（审计语料） | `pod graph observe` |
| `paths.json` | 毒性路径与建议 diff | `pod graph toxic` |
| `report.md` | 人类可读报告 | `pod graph toxic` |
| `policy-diff.json` | 定点策略 diff | `pod graph toxic --diff` |
| `feedback.json` | confirmed / false-positive 标记 | `pod graph mark` |

写入采用 **tmp + 原子 rename**，避免半截图文件。

### 4.2 图结构

```json
{
  "schema_version": "0.1.0",
  "source": "static",
  "generated_at": "2026-09-09T15:00:00Z",
  "meta": {
    "tool_version": "0.1.0",
    "config_fingerprint": "sha256:...",
    "warnings": []
  },
  "nodes": [
    { "id": "agent:claude-code", "type": "agent" },
    { "id": "server:filesystem", "type": "server", "command": "mcp-server-filesystem" },
    { "id": "tool:filesystem.read_file", "type": "tool", "server": "filesystem" },
    { "id": "capability:read-secret", "type": "capability" }
  ],
  "edges": [
    { "from": "agent:claude-code", "to": "server:filesystem", "type": "connects" },
    { "from": "server:filesystem", "to": "tool:filesystem.read_file", "type": "exposes" },
    {
      "from": "tool:filesystem.read_file",
      "to": "capability:read-secret",
      "type": "has_capability",
      "confidence": 0.7,
      "origin": "name",
      "evidence": ["tool name matches /read|cat|get/", "schema arg 'path' can point at .env"]
    }
  ]
}
```

**设计约束**：

- 每条 `has_capability` 边必须带 `confidence`（0..1）、`origin`、`evidence`；没有证据的能力边不允许写入。
- 同一 `(tool, capability)` 允许多条边（不同 origin/置信度），由 `graph-core` 合并为最终置信度并保留全部证据。
- `config_fingerprint` 用于检测图是否过期。

### 4.3 D2 能力标签

| 标签 | 定义 | 典型工具 | 角色 |
|---|---|---|---|
| `read-secret` | 读凭据/密钥/token（`.env`、`.ssh`、keychain、云凭据） | `read_file`、`get_env`、`aws_secret` | source |
| `read-private-data` | 读私有数据（源码、客户数据、私有仓库、数据库） | `read_file`、`query_db`、`get_issue` | source |
| `read-untrusted-input` | 读外部不可信内容（网页、邮件、issue/PR 评论、RSS） | `fetch_url`、`read_email`、`get_pr_comments` | source |
| `external-communication` | 把数据发到信任边界外（邮件、IM、webhook、公开 PR/issue、外部 API POST） | `send_email`、`post_message`、`http_post` | sink |
| `exec` | 执行命令/代码 | `shell`、`exec`、`run`、`eval` | sink |
| `destructive-write` | 不可逆破坏 | `delete_file`、`drop_table`、`force_push`、`revoke` | sink |
| `credential-access` | 获取/使用凭据 | `assume_role`、`mint_token`、`oauth_*`、`keychain_get` | amplifier |

普通 `write` 是**上下文标签**，不是 D2 毒性能力：分类器把它记在 tool 节点上（由工具名含 `write`/`edit`/`create` 等识别），只用于 `destruction` 规则的辅助判定，不单独产生 source/sink 边。

### 4.4 分类流水线

按置信度从高到低四层：

1. **显式标注**：工具名 / schema 关键词命中规则表（`origin: name|schema`）。
2. **策略覆盖**：用户在策略中显式声明能力（`origin: policy`），例如把自研工具标为 `external-communication`。
3. **参数推断**（仅观测图）：`http_request` 带外域 URL + body → `external-communication`；GET 外域 → `read-untrusted-input`；无法区分则两个都记、置信度降低（`origin: observed`）。
4. **未分类**：标为 `unclassified` 并在报告中显式列出，不静默丢弃。

分类器是纯函数：`classifyTool(input, overrides) -> CapabilityAssertion[]`，对任意输入不得抛异常。

### 4.5 毒性路径

```json
{
  "id": "path-001",
  "kind": "cross-agent",
  "rule": "read-secret + external-communication",
  "severity": "high",
  "confidence": 0.82,
  "source": {
    "agent": "claude-code",
    "server": "filesystem",
    "tool": "read_file",
    "capability": "read-secret",
    "confidence": 0.7
  },
  "sink": {
    "agent": "openclaw",
    "server": "email",
    "tool": "send_email",
    "capability": "external-communication",
    "confidence": 0.9
  },
  "amplifier": null,
  "evidence": [
    "audit#42 read_file .env blocked",
    "audit#77 send_email ok"
  ],
  "explain": "claude-code 可读密钥，openclaw 可外发；两者组合构成数据外泄链。",
  "suggested_diff": {
    "target": "openclaw/email.send_email",
    "from": "allow",
    "to": "approve",
    "rationale": "sink 是链路末端；改为审批可保留可用性，同时阻断自动外发。"
  }
}
```

### 4.6 毒性规则 v1

| 规则 | source | sink | 严重度 | 说明 |
|---|---|---|---|---|
| `exfiltration` | `read-secret` 或 `read-private-data` | `external-communication` | high | 数据外泄链 |
| `injection-exec` | `read-untrusted-input` | `exec` | high | 注入→命令执行 |
| `injection-exfil` | `read-untrusted-input` | `external-communication` | medium | 注入→外发 |
| `credential-abuse` | `credential-access` | `exec` 或 `external-communication` | high | 凭据滥用 |
| `destruction` | 同一 agent 同时具备 `write` 上下文标签与 `destructive-write` 能力 | — | medium | 不可逆破坏 |

跨 agent 组合：source 属于 agent A、sink 属于 agent B 时，`kind: cross-agent`，并在 `explain` 中说明两端。规则表是 `graph-core` 中的常量，v1 不支持用户自定义规则；用户可通过策略覆盖调整能力标签来间接影响判定。

### 4.7 策略 diff 建议器

输入一条毒性路径，输出一个最小改动建议：

1. 优先改 **sink**：`allow → approve`（保留可用性，阻断自动执行）。
2. 若 sink 已是 `approve`，改 **source**：`allow → approve`。
3. 若两端都已是 `approve`，建议对 source 加 `deny`，并在报告中标注"这会改变工作流，需人工确认"。
4. 建议必须包含 `rationale` 与路径 id，便于 `pod graph explain` 追溯。

---

## 5. 命令与输出

### 5.1 命令面

全部只读，统一支持 `--json`；每条发现都有可 `explain` 的 id。

| 命令 | 作用 | 关键参数 |
|---|---|---|
| `pod graph build` | 生成潜在图 | `--config`、`--no-exec`、`--timeout`、`--out` |
| `pod graph observe` | 生成观测图 | `--audit-dir`、`--since 7d`、`--agent`、`--out` |
| `pod graph diff` | 两图相减 | `--potential`、`--observed`、`--min-confidence`、`--json` |
| `pod graph toxic` | 毒性路径 + 定点策略 diff | `--graph potential\|observed\|both`（默认 `both`，无观测图时自动降级为 `potential`）、`--cross-agent`、`--diff <baseline.json>`（省略则只出报告）、`--min-confidence`、`--max-paths` |
| `pod graph explain <path-id>` | 追溯证据 | `--json` |
| `pod graph mark <path-id> confirmed\|false-positive` | 记录反馈 | `--note` |

### 5.2 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 分析成功，无高危发现 |
| `1` | 分析成功，存在高危毒性路径（适合 CI 失败） |
| `2` | 分析失败或数据不可信（配置不可读、语料链断裂、图版本不符等） |

### 5.3 人类可读输出

```text
# pod graph toxic — 跨 agent 毒性路径

## 高危（2）

### path-001  读密钥 + 外发通信（跨 agent，置信度 0.82）
  claude-code.filesystem.read_file   [read-secret 0.7]
    └─▶ openclaw.email.send_email    [external-communication 0.9]

  证据：audit#42  read_file .env → blocked
        audit#77  send_email → ok
  建议：将 openclaw.email.send_email 从 allow 改为 approve
        （见 policy-diff.json，人工确认后 pod serve 生效）

## 权限过载（潜在 − 实际）
  github.create_pull_request：3 个 agent 有权限，过去 30 天 0 次使用

## 影子能力（实际 − 潜在）
  cursor.shell.execute_command：观测到 12 次调用，但未在任何配置/策略中登记

## 未分类（需人工看一眼）
  custom.acme_sync [unclassified] — schema 无法判断 source/sink
```

### 5.4 机器可读输出

- 每个命令 `--json` 输出同一份 schema。
- `policy-diff.json` 复用 `pod policy draft --diff` 格式，产物可直接喂给 `pod lint`。
- 报告按稳定顺序输出（agent / tool / path id 排序），保证 git diff 可追踪变化。

### 5.5 与现有命令的衔接

- `pod scan` 保持获客入口定位；`pod graph build` 复用其发现器。
- `pod graph toxic --diff` → `pod lint` → 人工复核 → `pod serve`。
- `pod doctor` 在 `~/.pod/graph/` 缺失时提示 `pod graph build`。
- v1 不接入 `pod digest` 自动摘要；Phase 3 再评估。

### 5.6 H3 验收路径

`pod graph build && pod graph toxic` 在 dogfood 机器上、schema 缓存建立后 ≤10 分钟产出报告与至少一条路径（或明确"无路径 + 原因"）。

---

## 6. 错误处理与降级

核心原则：分析器不能被分析对象打垮，也不能假装知道。

| 失败模式 | 行为 | 退出码 |
|---|---|---|
| agent 配置不存在 / 解析失败 | 跳过该配置，报告标 `config_unreadable`，继续其他 agent | 0 |
| MCP server 启动失败 / `tools/list` 超时 | 标 `server_unintrospectable`，回退缓存 schema 或名称启发式，降置信度 | 0 |
| 工具 schema 缺失 / 不完整 | 名称启发式分类，低置信度；无法判断则 `unclassified` | 0 |
| 分类歧义（如 `http_request`） | 记录多个能力标签 + 降置信度，不静默选一个 | 0 |
| 审计语料为空 | 观测图为空；`diff` 提示"尚无观测数据，先跑 pod record"，不编造 | 0 |
| 审计哈希链断裂 | 拒绝使用该语料，标 `corpus_untrusted` | 2 |
| 图文件损坏 / `schema_version` 不符 | 不静默使用旧图，提示重新 `pod graph build` | 2 |
| 图过期（配置变更 / 超过 N 天） | 报告顶部 `STALE` 警告；`toxic` 降级为"仅供参考" | 0 |
| 毒性路径过多 | 默认按 severity × confidence 取 Top N，其余汇总计数；`--max-paths`、`--min-confidence` 可调 | 0 |
| agent 身份自述（当前限制） | 跨 agent 路径标 `attribution: weak` 并解释原因 | 0 |
| 分析器内部错误 | 结构化错误输出；tmp + 原子 rename，不产生半截图文件 | 2 |

### 6.1 降级阶梯

```text
完整：静态图 + 观测图 + 毒性路径
  ↓ 无语料
静态图 + 静态毒性路径（低置信，标注"仅基于配置"）
  ↓ server 起不来
名称启发式 + 缓存 schema（更低置信，标注"schema 缺失"）
  ↓ 图不存在
提示 pod graph build（不猜）
```

### 6.2 分析器自身的安全边界

- 静态 introspection **只调用 `tools/list`，绝不 `tools/call`**。
- 不继承调用者的全量环境变量。
- 强制超时 + 输出大小上限 + 临时目录，不在用户目录留下非预期文件。
- 产品化默认 `--no-exec`（只读缓存 schema）；dogfood 阶段允许实际启动用户自己的 server。
- 报告只输出工具名/路径/能力标签，**不输出密钥原文**；敏感路径可按需相对化或掩码。
- 全程本地，不联网、不上传。

---

## 7. 测试与验收

### 7.1 测试矩阵

| 层级 | 测什么 | 关键用例 |
|---|---|---|
| 单元（graph-core） | 分类器、毒性规则、差集、路径排序、diff 建议 | 纯函数；安全核心逻辑 100% 覆盖 |
| 黄金样本 | fixture 配置 + 语料 → 期望图/路径/报告 | 输出稳定排序；报告快照测试 |
| 集成 | `build → observe → diff → toxic → explain` | 复用 `demo-server.ts` 与 fixture 审计语料；`--diff` 产物能被 `pod lint` 接受 |
| 失败模式 | 第 6 节每一种失败 | 断言退出码 0/1/2；断言无半截图文件 |
| 安全 | 分析器自身 | 不调用 `tools/call`、不继承全量 env、不越界写、报告不含密钥、超时生效 |
| 属性/模糊 | 分类器与规则引擎 | 任意工具名/schema 不抛异常；规则单调；diff 确定性 |

测试数据位于 `test/fixtures/graph/`，覆盖 3 个 agent（claude-code / openclaw / cursor）、5 个 server（filesystem / github / shell / email / http），以及"跨 agent 数据外泄链"和"权限过载"两个正例。

### 7.2 验收标准（dogfood 门槛）

- **H3 首次价值**：在自己的机器上，`pod graph build && pod graph toxic` ≤10 分钟，产出报告 + 至少一条路径（或明确"无路径 + 原因"）。
- **H1 发现力**：跑出 ≥1 条此前未意识到、且确认真实的毒性路径。
- **质量底线**：首次 dogfood 不出现无法解释的高危路径；每条路径可 `explain` 到证据；误报可标记、可覆盖。
- **可靠性**：所有失败模式退出码符合第 6 节；不产生半截图文件。
- **隐私**：报告不含密钥原文；全程不联网。
- **回归**：现有 175 个测试保持全绿；新增 graph 核心测试。

### 7.3 反馈机制

`pod graph mark <path-id> confirmed|false-positive` 写入 `~/.pod/graph/feedback.json`。v1 不参与自动学习，只用于量化 H1（多少条被确认）与人工调规则表；不引入 ML、不引入遥测。

---

## 8. 分阶段实施

> 实施计划先覆盖 **Phase 1**；Phase 2/3 在 Phase 1 验收通过后各自生成独立实施计划。

### Phase 1（约 2 周）：静态图 + 静态毒性路径

**交付物**

- `graph-core`：图模型、D2 分类器、毒性规则、diff 建议器（纯函数 + 单测）。
- `graph-static`：复用 `discoverTargets`/`checkBypass` 发现 agent/server；`tools/list` introspection + schema 缓存。
- CLI：`pod graph build`、`pod graph toxic --graph potential`、`pod graph explain`。
- 报告：Markdown + `policy-diff.json`（复用 `pod policy draft --diff` 格式）。

**退出标准**：H3 在 dogfood 机器上达成；失败模式测试覆盖第 6 节前四项。

### Phase 2（约 2 周）：观测图 + 差集 + 跨 agent 毒性路径

**交付物**

- `graph-observe`：从 `~/.pod/audit` 推断能力，生成 `observed.json`。
- CLI：`pod graph observe`、`pod graph diff`、`pod graph toxic --graph both --cross-agent`、`pod graph mark`。
- 差集输出：权限过载 / 影子能力。
- 跨 agent 路径与 `attribution: weak` 标注。

**退出标准**：H1 在 dogfood 机器上达成；跨 agent 路径可 `explain` 到语料证据。

### Phase 3（约 2-3 周）：B4 每 agent 最小权限基线

**交付物**

- 基于潜在图 + 观测图，为每个 agent 生成最小权限策略基线（复用 `policy draft`）。
- 将 `pod graph diff` 的"权限过载"边转换为策略收紧建议。
- H4 留存数据：`feedback.json` 的 confirmed/false-positive 统计。

**退出标准**：连续 2 周主动使用（H4）；B4 生成的策略经人工 review 后能被 `pod lint` 接受。

---

## 9. 风险与开放问题

| # | 风险 / 开放问题 | 影响 | 处理 |
|---|---|---|---|
| R1 | 静态 introspection 需要启动 MCP server | 分析器成为攻击面 | dogfood 允许；产品化默认 `--no-exec` + 沙箱 introspection |
| R2 | D2 分类准确率 | 误报会杀死 H3 | 规则表 + 人工覆盖 + 置信度 + `mark` 反馈；先上高置信规则 |
| R3 | agent 身份自述 | 跨 agent 归因不可信 | 标 `attribution: weak`；身份治理留到 A4 |
| R4 | 语料冷启动 | 观测图为空 | 静态图保证第一天可用（C3） |
| R5 | 毒性路径过多 | 用户被淹没 | Top N + `--min-confidence` + 汇总计数 |
| R6 | 图过期 | 结论过时 | `config_fingerprint` + `generated_at` + `STALE` 警告 |
| R7 | 范围蔓延 | 单人产能 | 第 2.2 节非目标清单；Phase 3 之前不碰运行时 |
| R8 | 隐私 | 报告可能包含敏感路径 | 不输出密钥原文；路径可相对化/掩码；全程本地 |

**需在 Phase 1 验证的具体决策**

1. schema 缓存的存储位置与失效策略（默认 `~/.pod/graph/schema-cache/`，按 server command+version 作键）。
2. `tools/list` introspection 的超时与输出上限默认值（建议 10s / 1MB）。
3. `--min-confidence` 默认值（建议 0.5；低于此只在"未分类"中列出）。

---

## 10. 附录

### A. CLI 示例

```bash
# 1. 静态图 + 静态毒性路径（第一天就能跑）
pod graph build
pod graph toxic --graph potential --diff ~/.pod/policies/baseline.json

# 2. 采集几天语料后
pod graph observe --since 7d
pod graph diff
pod graph toxic --graph both --cross-agent --min-confidence 0.6

# 3. 追溯与反馈
pod graph explain path-001
pod graph mark path-001 confirmed --note "确实是我们没意识到的外泄链"
```

### B. 与现有代码的映射

| 新组件 | 复用的现有代码 |
|---|---|
| `graph-static` 发现 | `apps/cli/src/onboard.ts` 的 `discoverTargets`、`computeCoverage` |
| `graph-observe` 语料 | `apps/cli/src/evidence.ts` 的 `loadAllAuditFiles`、`packages/audit` |
| 策略 diff | `apps/cli/src/policy-draft.ts` 的 `diffPolicies` / `renderPolicyDiff` |
| 策略校验 | `packages/policy` 的 `lintPolicy` |
| MCP 连接 | `packages/gateway` 的 `StdioClientTransport` 使用方式（只取 `listTools`） |

### C. 术语

| 术语 | 含义 |
|---|---|
| 潜在图（potential） | 基于配置/schema 推断的"系统被允许做什么" |
| 观测图（observed） | 基于真实语料的"系统实际做了什么" |
| 权限过载 | 潜在 − 实际：授权了但未使用 |
| 影子能力 | 实际 − 潜在：使用了但未登记 |
| 毒性路径 | source 与 sink 被同一信任主体（同 agent 或跨 agent 组合）同时掌握 |
| source | 可获取敏感/不可信数据的能力 |
| sink | 可外发/执行/破坏的能力 |
| amplifier | 放大风险的中间能力（v1 仅 `credential-access`） |
