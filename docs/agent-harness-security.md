# 多 agent / 多 harness 安全：现状盘点、威胁目录与加固

> 状态：2026-09。本文回答三个问题：
> 1. pod 现在对"多 agent / 多 harness"做了哪些安全工作？（§1–§3）
> 2. 外面真实发生的 agent/harness 攻击有哪些？（§4 威胁目录）
> 3. 哪些能自动判定、哪些拦不住？（§5 差距，§6 `pod guard`）
>
> 写法与 `threat-model.md` 一致：**每条威胁都要能追到原始披露方**，
> 覆盖不到的地方写"看不到"，不用"已加固"盖过去。

---

## 1. 为什么要单独看"多 agent / 多 harness"

单 agent 的安全问题（提示注入、工具滥用）已经被讨论得很多。真正被忽略的是
**同一台机器上同时跑着好几个 harness** 这件事本身：

- 每个 harness 有自己的 MCP 配置、自己的钩子、自己的记忆文件、自己的审批开关；
- 攻击者只需要其中**任意一个**没被治理的入口（CLI 配置里的一行、插件更新后的一个钩子、
  仓库里的一个 `.mcp.json`），就能拿到整台机器的权限——它们跑在同一个用户下；
- 而被攻陷的那一个会顺着共享凭据、共享文件、委托关系影响其他几个（级联）。

所以"多 agent 安全"的核心不是 N 份单 agent 安全的简单相加，而是三件额外的事：
**统一资产清单**、**跨 agent 的身份与归因**、**在每个 harness 的入口上都留下可核查的记录**。

---

## 2. 现状：pod 已经做了哪些工作

按"防线的位置"分层盘点。左列是能力，右列是它作用于多 agent 场景的具体形态。

### 2.1 资产与暴露面

| 已有能力 | 在多 agent 场景下的作用 | 位置 |
|---|---|---|
| `pod scan` 发现 6 类 harness 安装痕迹 | 回答"这台机器上其实有几个 agent"（影子 agent，T6） | `packages/scan` |
| `pod scan` 解析 MCP server 清单 | 统一列出各 harness 的 server 与来源 | `packages/scan` |
| `pod scan` 掩码识别 9 类密钥格式 | 找出落在**任意** harness 配置里的明文凭据 | `packages/scan` |
| `pod coverage --strict` | 找出绕过网关的 server，退出码可挂 CI | `apps/cli/src/onboard.ts` |
| `pod graph build/toxic` | 静态能力图 + source→sink 毒性链（含跨 agent） | `packages/graph` |

### 2.2 身份与归因（多 agent 的地基）

| 已有能力 | 作用 | 位置 |
|---|---|---|
| `pod identity` 每 agent 一对 ed25519 密钥 | 把"策略里的 agent 名"升级为**密码学身份**，共享凭据 → 可归因 | `packages/identity` |
| `pod delegate` 逐跳签名 + 能力必须收窄 | 高权限 agent 向子 agent 授权时不许扩权（T12） | `packages/identity` |
| `pod grant` JIT 令牌（TTL + 作用域 + 单次） | 用限时令牌替代"关掉审批"（下面 §4 的 AG-06 正是防这个） | `packages/identity` |
| `pod quarantine` 熔断 | 被污染的 agent 在下一次调用即被拒绝 | `apps/cli/src/control-plane.ts` |
| `pod anomaly` / `pod trace` | 委托爆发检测 + 沿委托链/审计链反向溯源（T14） | `apps/cli/src/control-plane.ts` |

### 2.3 执行点（工具边界）

| 已有能力 | 作用 | 位置 |
|---|---|---|
| 三态决策 `deny > approve > allow`，未登记一律拒绝 | 每个 agent 一份策略，互不污染 | `packages/policy` |
| `secrets.deny_input_paths` / `deny_output_matching` / 高熵兜底 | 凭据读取与**输出侧**外泄两条路都拦 | `packages/policy` |
| `rules.injection` 分级注入信号（默认阻断 high） | 工具响应里的注入内容不回到上下文 | `packages/policy` |
| `rules.toolMetadata` 在 `tools/list` 阶段摘除可疑工具 | 工具描述投毒（AG-17）在进入上下文之前被摘掉 | `packages/gateway` |
| `rules.egress` 主机判定 | 参数里出现的主机按白/黑名单判定 | `packages/gateway` |
| 来源白名单（`command`/包/版本） | 启动前挡住被换包的 server（AG-14） | `packages/gateway` |

### 2.4 控制平面（真正容易被忽略的一层）

| 已有能力 | 作用 | 位置 |
|---|---|---|
| `pod posture` 采集钩子（Claude hooks / pod hooks / launchd） | 钩子 = 以主机权限运行的配置项（HookPry 类，AG-05） | `packages/posture` |
| 钩子/配置/记忆进基线，漂移按级别报警 | "合法动作被滥用"的唯一可判定信号（AG-12） | `packages/posture` |
| `packages.requireIntegrity` 比对 server 指纹 | 同名 server 换包（rug pull，AG-14） | `packages/posture` |
| `auditHealth` 断链与空闲检测 | 把"看起来在记、其实没记"变成可见告警（AG-16） | `packages/posture` |
| 每条控制平面事件进同一条哈希链（`kind` 字段） | "谁在什么时候改了钩子/配置/记忆"可证明 | `packages/audit` |

### 2.5 证据与跨机器视图

| 已有能力 | 作用 | 位置 |
|---|---|---|
| SHA-256 哈希链 + `verify-audit` | 改一条整链对不上 | `packages/audit` |
| `export-evidence` / `verify-evidence` | 对方**自己**就能验，不需要信任 pod | `apps/cli/src/evidence.ts` |
| Pod Cloud（可选） | 跨 agent / 跨机器的 agent 注册、审计汇聚、告警、合规报告 | `cloud/` |

### 2.6 小结：已经比较扎实的部分

把上面这些对上 OWASP Agentic Top 10，缺口集中在四处：

1. **入口的"最后 10 厘米"**：配置与钩子的**内容**有没有被改，pod 只在 `posture freeze`
   之后才回答；没建基线时完全静默。
2. **agent 自己的启动参数**：`--dangerously-skip-permissions` 这类开关不在 pod 视野里。
3. **远程 / HTTP 形态的 MCP 端点**：第三方 server 的监听地址与鉴权策略 pod 看不到。
4. **持续性与变化**：`scan` / `posture` / `harden` 都是"跑一次"的；没有"只对变化说话"的常驻视图，
   而真实攻击恰恰发生在"你上次跑完之后"。

---

## 3. 现状小结：一句话版本

> pod 已经把**工具边界**（网关）和**控制平面姿态**（posture）都覆盖了，
> 并且有身份、委托、JIT、熔断、溯源。真正缺的不是判定能力，而是
> **覆盖面**（不认识足够多的 harness 与配置格式）、**持续性**（只对变化说话）、
> 和**可读的出口**（用户要的是"我该做什么"，不是一份原始 findings）。

`pod guard` 就是补这三样（§6）。

---

## 4. 威胁目录（AG-01 – AG-18）

机器可读版本在 `packages/guard/src/catalog.ts`，可读版用 `pod guard catalog` 打印
（含完整出处与 pod 的覆盖声明）。这里给一张速览表。

覆盖列的含义：

- **covered**：有确定性判定 + 有执行点（网关 / posture / guard），处理完这类问题就消失；
- **partial**：能发现，但拦不住（例如钩子跑在 harness 里）；
- **gap**：pod 看不到（明确写出来，避免虚假安全感）。

| 编号 | 威胁 | 级别 | 覆盖 | 主要出处 |
|---|---|---|---|---|
| AG-01 | 明文凭据进了 agent / MCP 配置 | high | covered | Wiz（s1ngularity）、CWE-522 |
| AG-02 | MCP server 来源未锁定版本 | medium | partial | Koi Security、Snyk（postmark-mcp） |
| AG-03 | MCP server 绕过网关直连 | high | covered | OWASP Agentic Top 10 |
| AG-04 | 项目级 MCP 配置在打开文件夹时自动执行 | high | partial | Cato/Aim（CVE-2025-54135）、Check Point（CVE-2025-54136）、CSA |
| AG-05 | 生命周期钩子携带网络出口 / 持久化 / 编码载荷 | high | partial | PromptArmor、Lasso Security |
| AG-06 | agent 以"跳过审批"模式运行 | high | partial | StepSecurity、Wiz、AWS（CVE-2025-8217） |
| AG-07 | 长期记忆文件可被写入且未纳管 | high | partial | OWASP（ASI06） |
| AG-08 | 远程 / HTTP 形态的 MCP 端点未鉴权 | high | partial | Oligo/Tenable（CVE-2025-49596）、JFrog（CVE-2025-6515） |
| AG-09 | 致命三角：私密数据 + 不可信输入 + 外发通道 | high | partial | Invariant Labs（GitHub MCP）、Simon Willison、Legit Security（GitLab Duo） |
| AG-10 | 多个 agent / server 共用同一份凭据 | medium | covered | Wiz（s1ngularity） |
| AG-11 | 影子 agent：有 agent 在跑但无治理记录 | medium | covered | OWASP（ASI10） |
| AG-12 | agent 配置未冻结，可被静默降级 | high | covered | Cato/Aim（CurXecute） |
| AG-13 | 插件 / 技能市场来源未固定 | medium | partial | Snyk（ToxicSkills）、PromptArmor |
| AG-14 | MCP server 启动命令与基线不一致（rug pull） | high | covered | Invariant Labs（TPA）、Microsoft |
| AG-15 | 注入阻断与 egress 判定未启用 | medium | partial | NVD（CVE-2025-32711 EchoLeak）、Bugcrowd |
| AG-16 | 审计覆盖缺口：harness 在网关之外活动 | medium | covered | HackerOne 年度报告 |
| AG-17 | 工具描述投毒面：未走网关时摘除规则不生效 | medium | partial | Invariant Labs、Vulnerable MCP Project |
| AG-18 | MCP server 以宿主完整权限运行（无沙箱） | medium | **gap** | ReversingLabs（Amazon Q）、CWE-250 |

### 4.1 这批威胁的四个共同点

把 18 条摊开看，模式很清楚——这四条决定了加固该往哪儿放：

1. **入口是配置，不是代码**。AG-04/05/06/12/13/14 全都通过"改配置"落地：
   一行 `args`、一个钩子、一个 `--dangerously-*`、一次插件"更新"。
   → 加固点是**冻结 + 漂移**，不是运行时扫描。
2. **不需要漏洞就能打**。AG-09（致命三角）里每一环都是**合法功能**：
   读私有仓库是它的工作，发 PR 也是它的工作。
   → 加固点是**拆权限**（少一条边），不是检测恶意内容。
3. **有多 agent 才成立**。AG-03/10/11/16 的风险来自"不止一个"：
   一个没治理的 harness 就够，一份共享凭据就能横向。
   → 加固点是**清点 + 每 agent 一份身份**。
4. **"看起来在记"比"没记"更危险**。AG-16 的形态是链断了以后 agent 照常工作、
   本地一条不再落。
   → 加固点是**把静默失败变成告警**。

---

## 5. 从威胁到缺口：这批新增检测器解决了什么

| 缺口 | 对应威胁 | 之前的形态 | 现在 |
|---|---|---|---|
| 只认识 6 类 harness、只解析 2 种配置格式 | AG-02/03/11 | 报表漏掉一半安装 | 16 类 harness + 5 种配置格式（含 TOML），可用 `rules.guard.extraConfigPaths` 补 |
| 不看项目级配置 | AG-04 | 只在用户级配置里找 | `--workspace` 扫 `.mcp.json` / `.cursor/mcp.json` / `.vscode/mcp.json` … |
| 不看启动参数 | AG-06 | 完全看不到 | `rules.guard.dangerousFlags` 命中即报 |
| 不看远程端点 | AG-08 | 完全看不到 | 解析 `url`，明文 HTTP / 非本机 / 关闭鉴权开关都报 |
| 不做"三角"判定 | AG-09 | 只有 `pod graph toxic` 静态图 | 按 `privateDataHints` × `egressHints` 直接对同 harness 判定 |
| 不做共享凭据归因 | AG-10 | 无 | 同一份（类别 + 掩码）出现在 ≥2 个配置里就报 |
| 只跑一次 | AG-12/14 | 靠用户记得手动跑 | `pod guard baseline` + `watch` 只对新增/变化报警 |
| 输出是原始 findings | 全部 | 用户要自己判断先做什么 | 漏洞清单 + **建议清单**（按优先级、带命令、带覆盖声明） |

---

## 6. `pod guard`：持续扫描、漏洞清单、建议清单

### 6.1 四个子命令

```bash
pod guard scan                      # 漏洞清单 + 建议清单（只读）
pod guard scan --strict             # 有 high 时退出码 1，可直接挂 CI / 定时任务
pod guard baseline                  # 冻结当前 server/钩子指纹
pod guard watch --interval 300      # 每 5 分钟一轮，只对"新增/变化/消失"说话
pod guard remediate --llm           # 模型产出加固建议物（不自动生效）
pod guard catalog                   # 威胁目录与出处
```

### 6.2 判定规则归用户

新增的 `rules.guard` 段（`~/.pod/rules.json`）：

```json
{
  "guard": {
    "dangerousFlags": ["--dangerously-skip-permissions", "--yolo", "--trust-all-tools"],
    "privateDataHints": ["filesystem", "github", "postgres"],
    "egressHints": ["fetch", "browser", "slack"],
    "pluginPaths": ["~/.claude/plugins/**"],
    "extraConfigPaths": ["~/.my-harness/mcp.json"],
    "allowedRemoteHosts": ["mcp.internal.example.com"],
    "requireManaged": true,
    "baselinePath": "~/.pod/guard/baseline.json"
  }
}
```

与 pod 既有口径一致：数组是整体替换，写 `[]` 就是关掉这类判定；
规则写错 fail-closed 报错，不静默退回默认值。

### 6.3 模型辅助加固：建议权与执行权的分离

`pod guard remediate --llm` 沿用 `docs/llm-security-services.md` 的四条约束，
并按 guard 的场景收紧出网面：

| 约束 | 具体做法 |
|---|---|
| 出网一处 | 仍然只有 `apps/cli/src/llm.ts::callChat` 会发 HTTP |
| **出网的是枚举，不是数据** | 只发：威胁编号 + 级别 + 落在哪个 harness + 处数；**不发路径、不发主机名、不发配置原文、不发 finding 描述** |
| 建议不决策 | 模型产出 = 处置步骤 + 规则增量；规则增量必须过**放宽守卫**（`diffRules` + `detectRelaxations`），任何削弱现有防线的增量**整体拒绝** |
| 出网留痕 | 每次调用写 `kind=llm-call` 进哈希链（含失败），只记 provider/model/字符数 |

额外两条只属于 guard 的校验：

- **不许编造**：`actions[].threat` 必须出现在本轮问题清单里，否则整条丢弃并说明原因
  （与 `pod redteam` 的场景校验器同一立场）；
- **命令必须是 pod 命令**：`sanitizeCommand` 只放行 `pod …` 或 `pod … && pod …`，
  任何管道、重定向、命令替换都被去掉并在报告里说明——建议是给用户**照抄**的，
  不能长得像一条任意 shell。

### 6.4 实时监控的语义

`pod guard watch` 刻意**不对"没变化"说话**（除了 `--once` 那一次明确报告）：

```
[10:31:07] 新增 2 · 变化 0 · 消失 1（共 11 条）
   🔴 [新增] AG-14 MCP server 启动命令与基线不一致（rug pull） · claude-code · claude-code/github
      MCP server "github" 的启动命令与基线不一致——同名 server 可能被换成了另一个包（rug pull）
      建议：pod posture freeze && pod posture --strict
   ✅ [消失] AG-03:cursor:fs@~/.cursor/mcp.json（确认是真修好，还是扫描面变小了）
```

两条细节是有意为之：

- **"消失"要人确认**：问题不见可能是因为修好了，也可能是因为扫描面变小了（配置被删、
  harness 被卸载）。报表不替你下结论。
- **只有变化进审计链**：每轮把同一份告警写一遍会淹掉真正的信号。

### 6.5 与现有命令的边界

| 命令 | 回答的问题 | 形态 |
|---|---|---|
| `pod scan` | 这台机器暴露了什么？ | 一次性、获客 |
| `pod posture` | 控制平面被改了吗？ | 一次性 / 可挂 CI |
| `pod harden` | 给客户/审计方交什么？ | 一次性交付物 |
| **`pod guard`** | **现在有什么漏洞、我该先做什么、什么时候变的？** | **持续 + 建议清单** |

### 6.6 纳管：把扫描结果变成管理对象（`pod agents` / 控制台「加入监控」）

扫描只解决"看得见"。要让一个 harness 进入管理，得有三个东西：**身份**（可归因）、
**策略**（可约束）、**审计目录**（可证明）。纳管做的就是这三件——一次性、可确认、可撤销：

| 纳管会写 | 纳管不会写 |
|---|---|
| `identity/<agent>/`（ed25519，私钥 0600） | 任何 harness 的配置（`mcp.json` / `config.toml` / `settings.json`） |
| `policies/<agent>.json`（**零权限起点**： 未登记 server 一律拒绝；已有策略则不动） | 你正在生效的策略 |
| `audit/<agent>/` + **该 agent 链上**的控制平面事件（`kind=identity` / `config-change`） | 任何"自动加固"的判定（模型产出仍要走 §6.3 的闸门） |

事件写在**被改动 agent 的链**上，不是机器级的 `_control`：`pod sync` 按绑定的
`local_agent` 过滤事件，写错落点就会出现"本地记了、云端看不到"而界面还说"已纳管"
（线上真实发生过，`pod_control_events = 0`）。判断口径见
[control-plane-hardening.md §5.3](control-plane-hardening.md)。

为什么不顺手改写配置：**那是有备份与回滚的 `pod onboard --yes` 的事**。
一个网页按钮不该偷偷改用户的 `mcp.json`——这条边界比"少点两次"重要得多。
控制台上写着这句话，确认框里也写着；用户点之前就知道会发生什么。

纳管 ≠ 拦住。纳管之后，真正把工具调用管起来仍要走 §6.1 的 `pod onboard` +
策略执法——这一点写在纳管成功的提示里，不留给用户猜。

### 6.7 接管：把 server 放进网关（这一步才会真的经过闸门）

纳管之后还有一步：MCP server 仍然是**直连**的，策略与审计对它无效（AG-03）。
控制台卡片上的「接管（包进网关）」调的就是 `pod onboard`：把每个 server 的启动命令
改写成 `pod serve --record-only … --command <原命令>`。

它比纳管危险（**会改写用户的配置文件**），所以确认框里必须先摆出：

| 摆出来的东西 | 为什么必须 |
|---|---|
| 逐条"改前 → 改后"的启动命令 | 用户要能看懂自己的 `mcp.json` 会变成什么，而不是点一个"优化"按钮 |
| 备份文件路径 `<配置>.pod-backup-<时间戳>` | 出事时知道去哪儿找；卡片上的「还原配置」也从它恢复 |
| "只录不拦"四个字 | 接管 ≠ 拦住。切执法要等 `pod policy draft` 出来的策略复核通过 |
| 跳过的项与不支持项 | Codex 的 TOML 暂不支持自动改写——直接说出来，不假装成功 |

三条工程决定值得记下来：

1. **只碰用户级配置**。仓库里的 `.mcp.json` / `.cursor/mcp.json` 属于工作区，
   不在这个按钮的授权范围内（那正是 AG-04 那条威胁的面）。
2. **`pod` 不在 PATH 上就拒绝执行**。包装后的命令跑不起来会让该 harness 的
   MCP server 全部失效——一个"帮倒忙"的按钮比没有按钮糟得多，所以这里是 fail-closed。
3. **沿用已有策略而不是新建 allow-all 模板**。`pod onboard` 默认写的包装策略是
   `allow:['*']`（只录不拦时期够用）；如果用户纳管时已经有一份**零权限**策略，
  覆盖它等于把 fail-closed 悄悄换成 fail-open。所以控制台接管时指向那份已有策略、
  并且不覆盖——即使哪天去掉 `--record-only`，行为也是"全部拒绝"而不是"全部放行"。

### 6.8 切执法：让"接管"变成"真的在拦"

接管让调用**经过**网关，执法让网关**真的判**。第三步就是把包装命令里的
`--record-only` 去掉，并让它用编译好的策略。

这一步的产品风险与前面两步不同：改坏了有备份，真正危险的是**"看起来生效了、
其实没有保护"**。两种典型的假保护：

| 假保护 | 为什么危险 | 处理 |
|---|---|---|
| 用零权限策略执法（`servers: {}`） | 所有工具调用被拒——agent 立刻干不了活，用户会以为是 pod 坏了 | 拒绝：这不算"编译好的策略" |
| 用 `allow:["*"]` 的 record 模板执法 | 网关在跑、审计在记，但**什么都不拦** | 拒绝：模板文件名是 `onboard-*.json`，明确排除在执法选型之外 |

所以切执法的前置检查是硬性的：必须有一份**绑定该 agent、含 server 规则、且不是
allow-all** 的策略文件，否则拒绝执行并给出要跑的命令（`pod policy draft …`）
与当前语料量。

另外三件写进确认框的事：

1. **用哪份策略**——显示文件路径与 server / 工具 / 三态计数，并说明"这份策略编译时
   有多少条语料"（0 条时提示"策略可能只是一张猜测表"）。
2. **切完会发生什么**——命中 `approve` 的调用会挂起等审批；没在跑 `pod watch`
   就等到超时被拒（fail-closed）。免掉人工那一步的正道是 `pod grant` 的限时令牌。
3. **怎么退**——「回到只录不拦」（策略不变、不再阻断）或「还原配置」（逐步撤销）。

最后一条工程细节：界面必须显示**当前实际生效的策略文件**。因为纳管会写一份零权限
策略、编译后又多一份 draft，"一个 agent 两份策略"是常态；如果界面只说"有多份策略，
按后者展示"，用户根本不知道自己被哪一份管着。

### 6.9 漏斗：扫描完必须知道下一步做什么

漏洞清单如果停在清单，用户拿到的是一份**需要自己做判断**的报表——那是扫描器，
不是能被用起来的工具。所以 `pod guard scan` 的 §0 直接给两样东西：

1. **先做这三件事**：按"严重级别 → 能不能真的解决 → 影响面"排序，每条带一条
   可直接复制的 pod 命令和一条确认命令。排序里刻意把"只是复核一遍"的动作
   （例如凭据搬家的 `pod scan` 复核）排在改变状态的动作（纳管 / 冻结 / 接管）后面——
   让用户跑完第一件事拿到确定收益，而不是跑完一条什么都不改变的命令。
2. **从扫描到交付**：本轮可根治 / 只能降险 / pod 看不到各多少条，以及把同一批事实
   变成可交付报告的命令（`pod harden --out …`）。

命令是**带 harness 的实命令**，不是目录里的模板：`pod agents enroll --harness claude-code`
而不是 `pod agents enroll --harness <id>`。harness 名会先过 id 形态校验（`^[a-z0-9][._-]*$`），
不合法就退回通用形态——建议里的命令是给用户照抄的，不能是一段看起来像指令的任意 shell。

同一套映射也让 `pod guard watch` 的变化通知带上"这个 harness 该跑哪条命令"，
而不是只报一句"新增了一条 AG-03"。

### 6.10 与 `pod harden` 的交接

`pod guard` 是免费的入口，`pod harden` 是交付物；两者共用同一份事实与判定，不重跑两套逻辑：

| | `pod guard scan` | `pod harden` |
|---|---|---|
| 读者 | 操作者（本机开发者） | 客户 / 审计方 |
| 输出 | 漏洞清单 + 建议 + 先做这三件事 | 执行摘要 / 范围与方法 / 待办 / 覆盖边界 / 证据 / 验证指引 |
| 篇幅 | 一屏能读完 | 一份可归档、可复验的报告目录 |
| 验证 | `pod guard scan` 重跑 | `pod harden --verify <目录>`（逐文件 sha256） |

两个工程细节值得记下来：

- **交付物里同一处问题只出现一次**。钩子会被 `posture` 和 `guard` 各报一次、明文凭据会被
  `scan` 和 `guard` 各报一次；`pod harden` 按"级别 + 归一化路径 + 威胁类别映射"合并，
  保留 guard 那条（带 AG 编号与处置命令）。映射之外的一律不合并——宁可多报一条，
  也不能把真问题悄悄吞掉。
- **`§3 覆盖边界` 是交付物里最值钱的一节**。18 条里哪几条只能发现、哪条看不到，
  写清楚比给一个漂亮的绿色"通过"更能建立信任，也更容易在出事时界定责任。

---

## 7. 仍然做不到的（写清楚，不夸大）

1. **不阻断 harness 自己的行为**。钩子、项目级配置自动执行（`AG-04`）、
   `--dangerously-skip-permissions`（`AG-06`）都发生在 harness 进程里，不经过 MCP 边界。
   pod 的能力是**发现 + 取证 + 变更审计**，不是拦截。
2. **不审查插件 / 技能的正文**。提示词注入写在自然语言里（Snyk 对某市场扫描：
   36% 含注入）；pod 只审查它带来的钩子与命令（`AG-13`）。
3. **不校验 npm 包的签名与发布者**。版本锁定只回答"装的是哪一版"，
   回答不了"这一版是谁发的"（`AG-02`）。
4. **看不到第三方 server 的监听地址与鉴权策略**。只能从配置里发现线索（`AG-08`）。
5. **不做沙箱**。`AG-18` 是 catalog 里唯一标 `gap` 的条目：需要强隔离时用平台原生沙箱或容器，
   pod 的策略与证据叠在上面。
6. **不做语义级记忆投毒检测**。只保证"你看到的和上次是不是同一份"（`AG-07`）。

---

## 8. 代码落点

| 关注点 | 位置 |
|---|---|
| 威胁目录（含出处） | `packages/guard/src/catalog.ts` |
| harness 注册表与配置解析 | `packages/guard/src/harnesses.ts` |
| 只读事实采集 | `packages/guard/src/collect.ts` |
| 检测器（规则 × 事实 → findings） | `packages/guard/src/detect.ts` |
| 漏洞清单 + 建议清单渲染 | `packages/guard/src/report.ts` |
| 基线与实时 diff | `packages/guard/src/baseline.ts`、`packages/guard/src/watch.ts` |
| CLI 编排与模型校验闸门 | `apps/cli/src/guard.ts` |
| 判定规则 | `packages/policy/src/rules.ts`（`guard` 段） |
| 测试 | `packages/guard/src/guard.test.ts`、`apps/cli/test/guard.test.ts` |
