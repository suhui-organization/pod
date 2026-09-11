# 控制平面加固 — 需求与设计

> 来源：多 Harness / 多 Agent 安全风险分析（四层风险 × P0/P1/P2）与 `pod` 现状的逐条比对。
> 状态：2026-09-11 立项。本文是这批需求的锚点；实现与本文冲突时以本文为准（先改本文再改代码）。
> 约束：**所有判定规则由用户定义**（规则文件可编辑、可覆盖、可关闭），代码只提供默认值与执行器。

---

## 0. 一句话

pod 的审计原本只覆盖**数据平面**（工具调用）。这批需求把同一条哈希链扩展到**控制平面**（配置、钩子、身份、委托、记忆），并把"什么算风险"从代码里搬到用户可编辑的规则文件里。

## 1. 现状比对（缺口清单）

判定：✅ 已有 · ◐ 部分 · ○ 空白

| # | 风险层 | 缺口项 | 现状 | 本批目标 |
|---|--------|--------|------|----------|
| G1 | L1 | 配置变更哈希链审计 | ◐ 哈希链只覆盖工具调用 | 控制平面事件进同一条链（`kind` 字段） |
| G2 | L1 | 配置冻结项 + 漂移告警 | ○ 只有只读 coverage | `pod posture freeze/verify` 基线哈希 + 上链 + 退出码 |
| G3 | L1 | 生命周期钩子审计与判定 | ○ 完全空白 | `pod posture` 扫钩子配置，规则判定风险，变更上链 |
| G4 | L1 | 输入层净化 / 溯源标记 | ◐ 仅 `injection_suspect` 打标 | 规则驱动的注入信号词表 + 命中即上链 |
| G5 | L2 | MCP 包哈希固定 | ◐ 只查版本是否 pinned | 版本 pin 规则 + 本地包目录哈希指纹 |
| G6 | L2 | 工具元数据验证 | ◐ graph 内省有雏形 | 规则驱动的可疑描述检测（隐藏指令/外联/编码载荷） |
| G7 | L2 | A2A 协议级安全 | ○ | **不做协议本体**；等价能力本地化到 I1–I3（见 §3） |
| G8 | L3 | 级联失效熔断 | ○ | `pod quarantine`：熔断状态文件，网关强制 deny |
| G9 | L3 | 污染溯源 | ○ | `pod trace`：沿委托链 + 审计链反向回溯 |
| G10 | L3 | 信任传播异常检测 | ◐ 仅 deny_burst 弱告警 | `pod anomaly`：规则驱动的委托/权限扩散异常 |
| G11 | L4 | 每 agent 独立密码学身份 | ◐ 只有策略身份 | `pod identity`：ed25519 密钥对 + 指纹 |
| G12 | L4 | JIT / 短期令牌 | ○ | `pod grant`：签名、限时、限范围、可单次消费的令牌；网关校验 |
| G13 | L4 | 委托链权限收窄 | ○，但有 capability 地基 | `pod delegate`：能力子集校验 + 签名委托链 |
| G14 | L4 | 记忆完整性保护 | ○ | `pod posture` 记忆文件基线哈希 + 漂移检测 |
| G15 | L4 | Egress 层补齐 | ◐ 只有输出侧拦截 | 规则驱动的出网目标判定（agent→server 参数侧） |

**明确不做（写进 `threat-model.md` 的不防御清单）**：

- A2A 协议实现本体、mTLS/SPIFFE 工作负载身份（pod 的 ICP 没有跨组织 A2A 场景；本地签名链等价覆盖身份/委托/JIT 三项能力）。
- 沙箱隔离（进程内转发是 D3 既定取舍）。
- 行为漂移作为主防线（D2 决策：可判定规则优先；本批只做规则驱动的异常信号）。

## 2. 统一设计：规则文件 + 事实采集 + 一条链

```
用户规则 ~/.pod/rules.json ─┐
                            ├─▶ 事实采集（钩子/配置/记忆/包/元数据/身份/委托）
默认规则（代码内置）      ─┘        │
                                    ▼
                          规则求值 → findings（high/medium/low）
                                    │
                                    ├─▶ 报表（md / json）
                                    └─▶ 控制平面事件写入同一条 SHA-256 哈希链
```

### 2.1 规则文件（用户可编辑）

位置：`~/.pod/rules.json`，`--rules <file>` 可覆盖。缺省值见 `packages/posture` 的 `DEFAULT_RULES`。
合并语义：**对象深合并、数组整体替换**（用户写 `hooks.riskPatterns` 就完全替换默认表，不叠加）。

```jsonc
{
  "hookRisk": {
    "watchPaths": [
      { "path": "~/.claude/settings.json", "format": "claude-hooks" },
      { "path": "~/.codex/hooks.json", "format": "pod-hooks" },
      { "path": "~/Library/LaunchAgents/com.pod*.plist", "format": "launchd" }
    ],
    "riskPatterns": [
      { "id": "net-egress",    "re": "\\b(curl|wget|nc|ncat|scp|ssh)\\b", "severity": "high",   "why": "钩子里出现网络出口" },
      { "id": "persistence",   "re": "launchctl|crontab|LaunchAgents|systemctl", "severity": "high", "why": "钩子建立持久化" },
      { "id": "shell-init",    "re": "\\.(zshrc|bashrc|bash_profile|profile)\\b", "severity": "high", "why": "钩子改写 shell 启动文件" },
      { "id": "encoded-payload","re": "base64\\s+-d|eval\\s|python3?\\s+-c", "severity": "medium", "why": "钩子执行编码/动态载荷" }
    ],
    "trustedSources": ["~/.claude/plugins/local/**", "~/.pod/**"],
    "requireSigned": false
  },
  "freeze": {
    "paths": [
      "~/.claude/settings.json",
      "~/.claude.json",
      "~/.codex/config.toml",
      "~/.dsh/mcp-manager.json",
      "~/.cursor/mcp.json"
    ],
    "requireApprovalToChange": true
  },
  "identity": { "dir": "~/.pod/identity", "algorithm": "ed25519", "required": true },
  "delegation": {
    "dir": "~/.pod/delegations",
    "maxDepth": 2,
    "requireSubset": true,
    "policyDirs": ["~/.pod/policies"],
    "forbiddenEscalation": ["exec", "credential-access", "destructive-write"]
  },
  "anomaly": {
    "windowMinutes": 60,
    "delegationsPerWindow": 5,
    "capabilitiesPerWindow": 6,
    "highRiskCapabilities": ["exec", "credential-access", "destructive-write", "external-communication"]
  },
  "memory": {
    "paths": ["~/.claude/CLAUDE.md", "~/.codex/AGENTS.md", "~/.pod/memory/**"],
    "maxFileBytes": 1000000
  },
  "packages": { "requireVersionPin": true, "requireIntegrity": false },
  "toolMetadata": {
    "suspiciousPatterns": [
      { "id": "hidden-instruction", "re": "ignore (all )?(previous|above)|忽略(之前|上面)|do not tell", "severity": "high" },
      { "id": "credential-harvest","re": "\\.env|credentials|id_rsa|\\.ssh", "severity": "high" },
      { "id": "remote-endpoint",   "re": "https?://(?!localhost|127\\.0\\.0\\.1)", "severity": "medium" }
    ]
  },
  "injection": {
    "signals": [
      "ignore previous", "忽略之前", "system prompt", "you are now",
      "do not tell the user", "exfiltrate"
    ]
  },
  "quarantine": { "file": "~/.pod/quarantine.json" }
  ,
  "egress": {
    "enabled": false,
    "allowHosts": [],
    "denyHosts": [],
    "defaultDecision": "allow"
  },
  "grant": { "dir": "~/.pod/grants", "requiredForApprove": false }
}
```

### 2.2 控制平面事件进链

`packages/audit` 的 `AuditEntry` 增加可选字段 `kind`：

```ts
type AuditKind =
  | 'tool-call'      // 缺省，历史数据无此字段
  | 'config-change'  // 冻结项漂移
  | 'hook'           // 钩子发现/风险命中
  | 'metadata'       // 工具元数据可疑（tools/list 时判定）
  | 'memory'         // 记忆文件漂移
  | 'package'        // MCP 包来源未锁定/来源变化
  | 'identity'       // 身份创建/校验
  | 'delegation'     // 委托签发/收窄校验
  | 'grant'          // JIT 令牌签发/消费
  | 'quarantine'     // 熔断加入/解除
  | 'anomaly';       // 异常信号
```

向后兼容：字段缺省视作 `tool-call`；哈希口径不变（无 `kind` 的旧记录仍能通过 `verify`）。

### 2.3 规则由用户定义的边界

- **代码只内置默认规则**，任何一条都能被 `rules.json` 覆盖或清空（`[]`）。
- 判定阈值全部来自规则文件；代码里不出现魔法数字。
- 规则解析失败 = fail-closed：`pod posture` 报错退出，不静默使用默认值。

## 3. 实现映射

| 缺口 | 落地 |
|------|------|
| G1/G2 | `pod posture freeze` 写基线；`pod posture verify` 比对并上链 `config-change`，`--strict` 漂移时退出码 1 |
| G3 | `pod posture` 采集钩子条目（claude-hooks / launchd / pod-hooks），按 `hookRisk.riskPatterns` 判定；风险项上链 `hook` |
| G4 | 网关 `matchInjectionSignal` 改为读 `rules.injection.signals`；命中写 `injection_suspect` |
| G5 | `pod posture` 检查 `packages.requireVersionPin`，npx 无版本/@latest 记 high；有本地包目录时记 sha256 指纹 |
| G6 | `pod posture` 读 graph 潜在图的工具描述，按 `toolMetadata.suspiciousPatterns` 判定 |
| G7 | 不做协议本体；能力等价由 G11/G12/G13 覆盖 |
| G8 | `pod quarantine add/remove/list`；网关每次调用前读熔断状态，命中则 deny 并上链 |
| G9 | `pod trace <agent>`：沿审计链的 `delegatedBy`/`agent` 反向回溯，输出时间线 |
| G10 | `pod anomaly`：读审计窗口，按 `anomaly.*` 阈值判定委托扩散/高风险能力激增 |
| G11 | `pod identity init/list/verify`：ed25519 密钥对（私钥 0600），指纹 = sha256(pub) 前 16 位 |
| G12 | `pod grant issue/list`：`~/.pod/grants/*.json`，签名 + TTL + 工具/能力范围 + 单次消费 |
| G13 | `pod delegate issue/verify/check`：能力子集校验 + 签名委托链（`maxDepth`、`forbiddenEscalation`） |
| G14 | `pod posture` 记忆文件哈希基线，漂移记 high |
| G15 | `pod posture` 从工具参数里抽取 URL/主机，按规则判定出网目标 |

## 4. 验收标准

1. `pnpm build && pnpm test` 全绿；每个新模块有 vitest 单测。
2. 新规则删掉/改写后，判定结果随之变化（有测试证明"规则驱动"不是口号）。
3. 所有控制平面事件都能在 `pod verify-audit` 中通过哈希链校验。
4. 熔断生效时可复现：`pod quarantine add` 后网关拒绝对应 agent 的全部调用。
5. 文档同步：`threat-model.md`（新增 T10–T13 + 不防御清单）、`README.md`（命令表）、`opc-security-pod/backlog-90d.md`（本批需求归档）。

---

## 5. 实现状态（2026-09-11 落地）

| 缺口 | 代码位置 | 测试 | 与本文的差异 |
|------|----------|------|--------------|
| G1 | `packages/audit/src/index.ts`（`kind` 字段） | 共享（posture/gateway/CLI 用例均断言 kind） | 无 |
| G2 | `apps/cli/src/control-plane.ts`（`freezePosture`/`runPosture`）、`packages/posture` | `apps/cli/test/control-plane.test.ts` | `freeze.requireApprovalToChange` 落地为"漂移判定的严重级别开关"（true=high） |
| G3 | `packages/posture/src/collect.ts`（claude-hooks / pod-hooks / launchd 三种解析）+ `evaluate.ts` | `packages/posture/src/posture.test.ts` | 不解析 TOML（无标准库解析器）；Codex 的钩子请用 `pod-hooks` 清单或 launchd 形式登记 |
| G4 | `packages/gateway/src/proxy.ts`（`matchInjectionSignal(result, signals)`） | `packages/gateway/src/control-plane.test.ts` | 落地为**子串**匹配（不是正则）：信号词表写给人看，正则易写错且 fail-closed 代价高 |
| G5 | `packages/posture/src/collect.ts`（`collectPackages`）+ `evaluate.ts` | `packages/posture/src/posture.test.ts` | 完整性用"command+args 指纹"而非 npm 包哈希：离线可算、能抓住"同名 server 换包"，不需要联网查 registry |
| G6 | `packages/gateway/src/proxy.ts`（`matchToolMetadata`，`tools/list` 时判定） | `packages/gateway/src/control-plane.test.ts` | 放在网关而不是离线 posture：描述是运行时事实，顺带覆盖所有经过 pod 的 server |
| G7 | —— | —— | 见 `threat-model.md` §5：不做协议本体 |
| G8 | `apps/cli/src/control-plane.ts`（quarantine） + 网关 `checkQuarantine` | 两侧都有测试 | 无 |
| G9 | `apps/cli/src/control-plane.ts`（`buildTrace`） | `apps/cli/test/control-plane.test.ts` | 溯源依据是 pod 自己的委托记录 + 审计链；没有委托记录的 agent 只能看到自身事件 |
| G10 | `apps/cli/src/control-plane.ts`（`detectAnomalies`） | 同上 | 三类信号：delegation-burst / capability-spread / deny-burst，阈值全在规则里 |
| G11 | `packages/identity/src/index.ts` | `packages/identity/src/index.test.ts` | agent 名只允许 `A-Za-z0-9._-`（避免两个名字映射到同一目录而串身份） |
| G12 | `packages/identity` + 网关 `findCoveringGrant` + `apps/cli` grant | identity/gateway/CLI 三处测试 | 消费状态用同目录 `.consumed` 标记（简单、可人工核查），不是数据库 |
| G13 | `packages/identity`（`verifyDelegation`）+ `pod delegate check` | identity/posture/CLI 测试 | "收窄"以 D2 能力标签为单位（复用 `KNOWN_CAPABILITIES`），不做工具级差分 |
| G14 | `packages/posture/src/evaluate.ts`（`evaluateMemory`） | `packages/posture/src/posture.test.ts` | 只做完整性（是否被改），不做内容语义判定 |
| G15 | `packages/gateway/src/proxy.ts`（`checkEgress`） | `packages/gateway/src/control-plane.test.ts` | 只判定**参数里出现的 URL 主机**；server 自身的出网网关看不见（见 `egress-defense.md`），默认 `enabled: false` |

### 5.1 新增/改动的文件

- 新增包：`packages/identity`（身份/委托/JIT）、`packages/posture`（控制平面姿态引擎）
- 新增规则层：`packages/policy/src/rules.ts`（`RuleSet` / `DEFAULT_RULES` / `loadRules` / `validateRules`）
- 网关加固：`packages/gateway/src/proxy.ts`
- CLI：`apps/cli/src/control-plane.ts` + `apps/cli/src/index.ts` 的 7 组子命令与 `pod serve --rules`
- 审计：`packages/audit/src/index.ts`（`AuditKind`）

### 5.2 使用顺序（推荐）

```bash
pod identity init --agent <agent>     # 1. 先给每个 agent 一个身份
pod posture freeze                    # 2. 冻结当前姿态（配置/钩子/记忆/包来源）
pod posture --strict                  # 3. 挂 CI/定时任务，漂移即告警
pod quarantine add --agent <agent>    # 4. 出事时熔断（网关下一次调用即生效）
pod trace <agent>                     # 5. 追污染源与影响面
```

### 5.3 云端集成（podcloud）

控制平面事件可以随 `pod sync` 上云，服务端落在独立的 `pod_control_events` 表，
由 `GET /api/v1/control-events` 与 `/control-events/summary` 展示（前端「控制平面」页）。

两条**必须记住的约束**（踩过一次，写在这里避免复发）：

1. **`server` 是哈希链的标识，不是事件的语义字段。**
   `pod sync` 按审计文件分批推送，服务端用 `events[0].server` 找回该链的链尾。
   因此同一文件里的所有事件必须共用同一个 `server` 值——控制平面事件统一为
   `control`（与 `control.jsonl` 对齐），类别放在 `tool`（如 `hook` / `config`）。
   早期版本把 `server` 填成 finding 类别，同一个文件里 `server` 不一致，
   服务端会判成断链（409）。`apps/cli/test/control-plane.test.ts` 有回归用例。
2. **字段长度要对齐云端 schema。** `server` ≤64、`tool` ≤128、`reason` ≤2000；
   `appendControlEvent` 在出链处统一截断，避免一条长路径让整批同步 422。

云端不存 severity（只存 `kind`/`decision`），展示级别由服务端推导，响应里带
`severity_source=derived`。要让云端保留真实 severity，需要在 `AuditEntry` 上加字段，
属于后续项。
