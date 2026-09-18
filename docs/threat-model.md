# Security Pod — 威胁模型

> 框架：STRIDE-lite + [OWASP Agentic AI Top 10（2025-12 发布）](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) 映射。
> 编号用官方的 **ASI01–ASI10**（Agent Goal Hijack / Tool Misuse / Identity & Privilege Abuse /
> Agentic Supply Chain / Unexpected Code Execution / Memory & Context Poisoning /
> Insecure Inter-Agent Communication / Cascading Failures / Human-Agent Trust Exploitation /
> Rogue Agents），不另造编号。
> 目的：每个产品决策都能回答"它在防哪个威胁"；公开威胁模型本身是安全产品的信任资产。

---

## 1. 信任边界

```
┌────────────────────────────────────────────────────┐
│ 信任根：用户机器（本地）                              │
│                                                    │
│  Agent 进程 ──(不可信)──▶ pod gateway ──(不可信)──▶ 真实 MCP server
│     ▲                       │                         ▲
│     │  (不可信)              │ (可信：策略/审计/审批)    │ (不可信：外部代码/数据)
│     └──────── LLM 提供商 ◀───┘                         │
│              (不可信，出站)                             └── npm/网络拉取的 server 包
└────────────────────────────────────────────────────┘
```

**边界说明**：

- **agent 进程本身不可信**：它可能被 prompt injection 劫持，可能配置被改，可能在用户的授意下做错事。gateway 不信任 agent 的自述（session id 等元数据仅作参考）。
- **真实 MCP server 不可信**：npm 生态存在投毒先例（2025 年 postgrid-mcp 类攻击：恶意 MCP 包窃取 `.env`/密钥）；server 的响应可能携带恶意内容回灌给 agent（间接注入）。
- **LLM 提供商出站不可信**：数据一旦进 prompt 就离开机器，egress 策略是最后防线。
- **gateway 本身可信但可被绕过**：如果 agent 不走 gateway（直连 server），策略无效——所以"agent 侧的 MCP 配置锁定"是产品功能（配置校验 + 启动自检）。

## 2. 威胁清单（按 OPC 实际风险排序）

### T1 提示注入 → 工具滥用/数据外泄 【严重】
- **场景**：网页/邮件/文档里的恶意内容注入 agent 上下文，诱导其调用工具（读密钥文件、发请求到攻击者服务器、改代码）。
- **OWASP 映射**：ASI01 目标劫持（直接/间接提示注入）、ASI02 工具误用。
- **防线**：策略闸门（deny/approve 规则）为主；`deny_output_matching` 防密钥经工具输出外泄；egress 主机黑名单；审批要求 reason。
- **产品叙事**："不是防 AI 变坏，是防坏内容利用 AI 的手。"

### T2 密钥/凭据被读出并外泄 【严重】
- **场景**：agent 读 `~/.aws/credentials`、`.env`、`~/.ssh/id_*` 后经工具调用或响应输出传走。
- **OWASP 映射**：ASI03 身份与权限滥用（凭据被读出后即具备越权能力）。
- **防线**：策略 deny 敏感路径读取；输出侧脱敏正则；审计只记哈希不记原文。
- **产品叙事**：pod scan 的"密钥暴露面"是最好 demo。

### T3 破坏性操作 【高】
- **场景**：`rm -rf`、`git push --force`、数据库 DELETE、云资源销毁。
- **OWASP 映射**：ASI02 工具误用。
- **防线**：高危工具默认 approve 甚至 deny；写操作审批；fail-closed 超时。
- **注**：原计划中"半夜访问数据库"类异常检测降级为辅助信号（行为漂移导致误报高），主防线是"写操作必须经过审批"这种可判定的规则。

### T4 MCP 供应链投毒 【高】
- **场景**：安装恶意 npm MCP 包（postgrid-mcp 先例：窃取 .env 上传）；或依赖未锁版本被上游劫持。
- **OWASP 映射**：ASI04 供应链风险。
- **防线**：pod scan 检查 server 包来源、版本锁定；gateway 对未知 server 默认 deny；策略模板"新 server 零权限"。
- **产品叙事**：scan 报表第 1 屏就是"你的 17 个 MCP server 里 3 个没锁版本"。

### T5 数据经 prompt 外泄给 LLM 提供商 【高】
- **场景**：agent 把客户数据、代码、密钥上下文发往第三方 LLM API（OPC 常同时用多家 provider）。
- **OWASP 映射**：ASI03 身份与权限滥用（数据随合法凭据流出）。
- **防线**：egress 主机策略；提示用户"哪些 provider 可访问哪些目录"（资产级最小权限）；企业数据目录标记。
- **产品叙事**："你的代码在哪些模型手里？"——OPC 出海做 GDPR 的硬需求。

### T6 影子 agent（无清单、无治理）【中】
- **场景**：OPC 机器上多个未登记 agent（Cursor 内置、OpenClaw、Claude Code、DSH…），无人知道整体暴露面。
- **OWASP 映射**：ASI03 身份与权限滥用（资产不清 = 治理无从谈起）。
- **防线**：Asset Registry 自动发现 + 定期 scan；"一个 agent 一个身份一份策略"。
- **产品叙事**：scan 报表"你其实有 5 个 agent"。

### T7 审计被篡改/合规证据不足 【中】
- **场景**：需要向客户/监管证明"我的 agent 做了什么"（GDPR Art.30 处理活动记录、SOC 2 审计问答）。
- **OWASP 映射**：ASI10 失控 agent（无法回答"它到底做了什么"时就无法兜底）。
- **防线**：SHA-256 哈希链不可变审计；策略版本随审计记录（可证明"当时是什么策略"）。
- **产品叙事**：合规报告一键生成（付费功能）。

### T8 本地 Web 控制台被本机恶意进程利用 【低】
- **场景**：`pod ui` 本地服务端口被同机恶意软件调用执行策略变更。
- **防线**：绑定 127.0.0.1 + 随机 token 鉴权；策略变更写入审计；控制台只读模式默认。
- **纳管通道的额外防线**（2026-09 加入）：控制台唯一的写操作是纳管/移除 agent，
  要同时过四道闸门——① 包默认只读，`pod ui` 显式打开写能力；② token 鉴权；
  ③ `Content-Type: application/json`（跨站表单发不出这个类型）；
  ④ Origin 必须与 Host 同源。每次纳管/移除都写进控制平面哈希链
  （`console:enroll:<agent>` / `console:forget:<agent>`），且只写 `~/.pod`
  下的产物、**不改动任何 harness 配置**（那是 `pod onboard --yes` 的事，它有备份与回滚）。
- **接管通道**（2026-09 加入）：纳管之后还有一步"接管"——把 MCP server 的启动命令
  改写成经网关的包装命令。它是控制台里**唯一会改写用户配置**的操作，所以另有四条约束：
  先出计划（逐条"改前 → 改后"）再确认；改写前备份成 `<配置>.pod-backup-<时间戳>`
  且可从控制台还原；只碰**用户级**配置、不动仓库里的项目级配置（那正是 T15 的面）；
  `pod` 不在 PATH 上就**拒绝执行**（包装命令跑不起来会让该 harness 的 MCP server 全部失效）。
  包装默认 `--record-only`（只录不拦），切执法是显式动作。
- **切执法的前置闸门**（2026-09 加入）：把包装命令的 `--record-only` 去掉即进入执法，
  所以这一步必须挡住"假保护"——没有绑定该 agent 且含 server 规则的策略、
  或策略是 `allow:["*"]`（record 模板）时**拒绝执行**。执法前必须回答得出
  "用哪份策略、允许什么、编译时有多少语料"，否则界面显示的"已保护"就是假的。

### T9 误配置/误批准（人为）【低-中】
- **场景**：用户批量批准、策略写得太宽。
- **OWASP 映射**：ASI09 人机信任利用（agent 的解释诱导人批准）。
- **防线**：审批要求 reason；超时 fail-closed；策略 lint（`pod lint` 检查危险模式如 `deny: []` 空拒绝）；默认模板保守。

### T10 生命周期钩子被静默木马化（HookPry 类）【严重】
- **场景**：Agent harness 把 shell 命令绑定到运行时事件（会话启动、工具调用、文件编辑），这些命令以主机权限运行，却以配置项形式分发，且可能在 LLM 完全看不到的时机触发。攻击者只需控制插件元数据 + 钩子配置，就能让一个良性插件在"更新"后把攻击者的命令挂到良性事件上。
- **防线**：`pod posture` 采集钩子配置（Claude Code hooks / pod hooks / launchd），按 `rules.hookRisk.riskPatterns` 判定（网络出口、持久化、改写 shell 启动文件、编码载荷）；`riskPatterns: []` 即用户手动关闭。钩子内容进基线，**新增/改动钩子按 `freeze.requireApprovalToChange` 的级别报警**——这正是"良性插件更新即木马化"的发现点。`requireSigned` 打开后无签名钩子另行报警。
- **边界**：pod 不执行钩子、也不阻断钩子（钩子跑在 harness 里，不经过网关）；能力是**发现 + 取证 + 变更审计**。
- **OWASP 映射**：ASI04 供应链（钩子作为配置分发）+ ASI05 意外代码执行。

### T11 配置降级（审批关闭 / 网关地址被改 / 密钥明文）【严重】
- **场景**：攻击者不创造新的恶意动作，只在合法配置里替换一个关键参数——把密钥引用改成明文、把内部地址改成公开地址、关掉人工审批、扩大共享范围。Agent 仍然"正确"完成任务，但安全态势被悄悄降级。
- **防线**：`freeze.paths` 里声明的配置文件在 `pod posture freeze` 时记入基线哈希；此后任何改动报 `config-change`（严重级别由用户规则决定），并写进同一条哈希链。pod 自身的策略文件另有签名与 `pod lint`。
- **OWASP 映射**：ASI03 身份与权限滥用（把限制悄悄摘掉）。

### T12 身份与委托失控（共享凭证 / 权限扩散 / 无 JIT）【高】
- **场景**：多个 agent 共用一份凭证，出事无法回答"是谁做的"；高权限 agent 把权限委托给低权限子 agent 后权限扩散；长期静态令牌一旦泄露长期有效。
- **防线**：`pod identity` 给每个 agent 一对 ed25519 密钥（**策略身份 → 密码学身份**）；`pod delegate` 的委托链逐跳签名、能力必须逐跳收窄、受 `maxDepth` 与 `forbiddenEscalation` 约束；`pod grant` 的 JIT 令牌带 TTL、作用域（server/tool/capability）与单次消费；`pod delegate check` 静态校验两份策略之间的能力包含关系。
- **OWASP 映射**：ASI03 身份与权限滥用、ASI07 agent 间通信不安全（委托链部分）。

### T13 记忆投毒【高】
- **场景**：长期记忆（CLAUDE.md、AGENTS.md、pod memory 目录）被写入恶意内容，影响的不只是当前会话，而是之后每一次决策。
- **防线**：`memory.paths` 进基线，漂移按 high 报（记忆写入比普通数据更需要人工确认来源）。pod 不解释记忆内容语义，只保证"你看到的和上次是不是同一份"。
- **OWASP 映射**：ASI06 记忆与上下文投毒。

### T14 级联失效与信任传播【高】
- **场景**：一个被污染的 agent 会在数小时内影响大量下游 agent——被攻破的 agent 发出的委托与消息会被下游当作可信输入，绕过原有防御。
- **防线**：`pod quarantine` 熔断（网关下一次调用即 deny，写链）；`pod anomaly` 按用户阈值（`rules.anomaly`）检测窗口内的委托爆发与高风险能力扩散；`pod trace` 沿委托链 + 审计链反向定位污染源并列出可能受影响的下游。
- **边界**：pod 只看得到经过网关的调用与 pod 自己的委托记录，看不到 agent 之间的对话。跨 agent 的"推理级联"（Planner→Executor→Reviewer）不在覆盖范围内。
- **OWASP 映射**：ASI08 级联失效。

### T15 项目级配置在打开工作区时自动执行【高】
- **场景**：仓库里的 `.mcp.json` / `.cursor/mcp.json` / `.vscode/mcp.json` 被 clone 下来后，
  接受"信任此文件夹"这一个动作就足以让攻击者的命令以开发者权限启动。CurXecute 更进一步：
  一次外部提示注入改写 `~/.cursor/mcp.json`，下次启动即执行。
- **OWASP 映射**：ASI05 意外代码执行、ASI04 供应链。
- **防线**：`pod guard` 扫 `--workspace` 下的项目级配置并报出来；`pod onboard` 把这类
  server 包进网关后，策略对它有约束。
- **边界**：pod 不阻断 harness 自己启动项目级 server 这个动作——那是 harness 的行为，
  不在 MCP 边界内。能力是发现 + 取证。

### T16 以"跳过审批"参数启动 agent【高】
- **场景**：`--dangerously-skip-permissions` / `--yolo` / `--trust-all-tools` /
  `DANGEROUSLY_OMIT_AUTH` 把人类审批整条摘掉。s1ngularity（Nx 供应链事件）正是用这些
  参数把开发者本机的 AI CLI 变成无审批的侦察与打包工具。
- **OWASP 映射**：ASI09 人机信任利用、ASI02 工具误用。
- **防线**：`rules.guard.dangerousFlags` 命中即报；真正的执行侧防线是网关的 approve 闸门
  与 `pod grant` 的 JIT 令牌（用限时令牌替代关掉审批）。
- **边界**：agent 自己的 CLI flag 不在 pod 控制范围内，pod 只能发现配置里的放宽项。

### T17 远程 / HTTP 形态的 MCP 端点未鉴权【高】
- **场景**：MCP 的 Streamable HTTP / SSE 传输把工具执行暴露成网络接口。
  MCP Inspector 的 CVE-2025-49596（CVSS 9.4）是绑定 `0.0.0.0` 且无鉴权，
  一次 CSRF 直接变成远程代码执行；oatpp-mcp 的 CVE-2025-6515 用可预测 session id
  做提示词劫持。
- **OWASP 映射**：ASI07 agent 间通信不安全。
- **防线**：`pod serve --http` 绑定 127.0.0.1 + token；`pod guard` 从配置里发现
  `0.0.0.0` 绑定、关闭鉴权的开关、明文 HTTP 的远程端点并按 `rules.guard.allowedRemoteHosts` 判定。
- **边界**：第三方 server 自己的监听地址与鉴权策略 pod 看不到，只能从配置线索推断。

## 3. 设计决策的威胁溯源

| 产品决策 | 主要应对威胁 |
|---------|-------------|
| 闸门先于监控（D1） | T1/T2/T3（只有经过的点才能拦） |
| 策略+审批为主，异常检测为辅（D2） | T1/T3（可判定规则优于统计信号） |
| 本地优先 + 数据不出机器（D3） | T5/T7（隐私与信任是卖点不是代价） |
| 敏感内容只存哈希 | T2/T7（审计不成为新泄露面） |
| 新 agent 默认零权限 | T2/T6（最小权限落地） |
| server 版本锁定检查（scan） | T4 |
| 审批 reason + fail-closed | T9/T3 |
| 配置自检（agent 必须走 gateway） | 边界完整性 |
| 判定规则由用户文件提供（`~/.pod/rules.json`） | T1/T10/T14（可判定的规则优于不可解释的模型判断；用户能改才有人维护） |
| 控制平面事件进同一条哈希链（`kind` 字段） | T10/T11/T13（"谁在什么时候改了钩子/配置/记忆"必须可证明） |
| 每 agent 独立密钥 + 逐跳签名委托 | T12（共享凭证无法归因） |
| JIT 令牌（TTL + 作用域 + 单次） | T12/T3（长期静态令牌是最容易失窃的资产） |
| 熔断与异常检测阈值全部来自规则 | T14（误报率由用户按自己的噪声容忍度调） |
| 项目级配置扫描 + 危险启动参数检测（`pod guard`） | T15/T16 |
| 远程端点与鉴权开关检测（`pod guard`） | T17 |

## 3.1 威胁目录（AG-xx）

上面 T1–T17 是**本机的威胁清单**；`AG-01 – AG-18` 是**面向 agent/harness 生态的威胁目录**
（机器可读版本在 `packages/guard/src/catalog.ts`，可读版 `pod guard catalog`）。

两者的关系：AG 条目是"外部真实发生的攻击形态"，每条都映射回这里的 T 编号与
OWASP 的 ASI 编号，并标注 pod 的覆盖程度（covered / partial / gap）。
完整盘点、差距分析与 `pod guard` 的设计见 **[agent-harness-security.md](agent-harness-security.md)**。

## 4. 安全承诺（对外发布时的公开文档）

- 威胁模型公开（本文档开源）
- 核心安全逻辑（策略求值器、哈希链、脱敏）100% 单测 + 定期白盒 e2e（复用既有方法论）
- 提交前内部渗透清单（cheat-sheet 化的自查项）
- 漏洞披露渠道（security@ + SECURITY.md）
- 数据最小化声明：scan/网关默认零遥测，同步需显式开启

## 5. 明确不防御的（说清楚，避免虚假安全感）

- 不防御用户机器被完全攻陷（本地恶意软件能直接读文件/改策略）——防线是"别把蛋都放一个篮子"（密钥管理器、分开的机器）
- 不防御 agent 平台自身的后门（闭源 agent 内部做什么我们看不到——这正是选 MCP 边界的理由）
- 不防御 LLM 提供商侧的泄露（不可控，只能减暴露面）
- **不做 A2A 协议本体，也不引入 mTLS/SPIFFE 工作负载身份**：pod 的 ICP 是单机多 agent 的开发者/小团队，没有跨组织 A2A 场景。协议级攻击面（Agent Card 真实性、多跳身份丢失、虚假能力声明）在本地被等价物覆盖——签名委托链 + 能力收窄 + 独立密钥 + JIT 令牌——但 pod 不会去实现 A2A 协议栈，也不会声称能防协议级漏洞。
- **不做沙箱/容器隔离**：网关是进程内转发（D3 既定取舍）。需要强隔离时用平台原生沙箱或容器，pod 的策略与证据可以叠在上面。
- **不把行为漂移当主防线**：agent 行为随 prompt 版本漂移，基线永远在动，误报率降不下来（D2 决策）。`pod anomaly` 只做规则驱动的异常信号，不自动降权。
- **不做运行时推理级联检测**：Planner/Executor/Reviewer 之间的推理污染不在 pod 可见范围内（pod 只在工具边界）。
