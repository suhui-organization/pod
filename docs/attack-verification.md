# 攻击验证报告 — 哪些防线真的挡住了

> 2026-09-12。**本文只写跑出来的结论**，不写设计意图。
> 每条都能用 `pnpm --filter @podsec/cli test -- attack-e2e` 复现。

---

## 0. 结论速览

| # | 攻击 | 结果 | 判定依据 |
|---|------|------|----------|
| 1 | 读 `~/.ssh/id_rsa`（T2 窃取私钥） | ✅ **挡住** | 调用根本没到靶机，副作用未发生 |
| 2 | 相对路径穿越读私钥 | ✅ **挡住** | 同上 |
| 3 | `run_shell` 执行任意命令（T3） | ✅ **挡住** | 无执行痕迹文件 |
| 4 | `write_file` 改写 `~/.zshrc` 持久化（T3） | ✅ **挡住** | 审批超时 fail-closed，目标文件不存在 |
| 5 | `send_data` 外发到攻击者主机（T5） | ✅ **挡住** | 无副作用 |
| 6 | 工具输出带 AWS 密钥（T2 回传） | ✅ **挡住** | 调用到达靶机但密钥没回到 agent |
| 7 | 工具被 allow 但能力被 deny | ✅ **挡住** | 能力闸门覆盖工具白名单 |
| 8 | 调用未登记工具 | ✅ **挡住** | fail-closed |
| 9 | 注入内容夹带外联地址 | ✅ **挡住** | egress 在参数侧拦下 |
| 10 | 注入内容回到 agent 上下文（T1，高置信信号） | ✅ **挡住** | 内容不回传，审计记 `injection_blocked` |
| 11 | 工具描述里嵌指令（G6 投毒） | ✅ **挡住** | 该工具不再出现在 `tools/list` |
| 12 | 低置信词命中（如 `system prompt`） | ⚠️ 只标记 | 正常文档里常见，见 §3.1 |

---

## 1. 验证方法（为什么这些结论可信）

普通的网关测试只证明"网关返回了拒绝"——那不能证明攻击没得手，只证明它说了句拒绝。
所以这次搭了一个**会造成真实副作用**的靶机（`apps/cli/test/fixtures/attack-server.ts`）：

```
攻击者(测试客户端) ──MCP──▶ pod serve ──MCP──▶ 靶机（真会读写文件/落执行痕迹）
                                              │
                                              └─▶ effects.log（每次被调用先记一笔）
```

三条判据，缺一不可：

1. **真子进程全链路**：`agent → pod serve → 靶机`，覆盖 CLI 参数解析与配置加载，
   不是 in-memory 的函数调用；
2. **判据是副作用，不是返回值**：靶机每次被调用**先写 effects log**。
   日志里没有这条调用 → 调用根本没到达 server → 副作用不可能发生；
3. **对照组**：允许的读取必须真的读到文件内容（用例 0）。
   没有这条，"其他攻击都没得手"可能只是因为链路整个是坏的。

---

## 2. 已验证真实可用的防线

| 攻击 | 拦它的那层 | 证据（可复现） |
|------|-----------|----------------|
| 读私钥 / 路径穿越 | `secrets.deny_input_paths`（路径段匹配，`~`/`./` 归一化后仍命中） | 审计 `reason` 含 `secrets.deny_input_paths`，effects log 无新行 |
| 任意命令执行 | 策略 `deny` 列表 | 靶机不产生 marker 文件 |
| 破坏性写入 | `approve` + 审批超时 fail-closed | 无人工审批 → 1s 后拒绝，目标文件不存在 |
| 数据外发 | `rules.egress.denyHosts`（扫描参数里所有字符串，不只看 URL 字段） | 审计 `reason` 含 `denyHosts` |
| 密钥经工具输出回传 | `secrets.deny_output_matching` | agent 拿到的内容不含密钥原文 |
| 能力越权 | `capabilityRules.deny` + `capabilityMap`（优先于工具白名单） | 工具在 `allow` 里仍然被拒 |
| 未登记工具 | 策略默认 `deny`（fail-closed） | 拒绝且不转发 |
| 注入夹带外联 | 同 egress：注入文案里的 URL 一样会被参数侧抓到 | 调用未转发 |

另外两项**静态**防线（此前已单独验证，见 `docs/hardening-service.md`）：

- `pod posture` 在真实机器上抓出了 Claude Code 钩子里的 `curl … | bash` 外联；
- `pod scan` 抓出了未锁版本的 npx MCP 包。

**攻击之后审计仍然可信**：上面全部攻击都被写进同一条 SHA-256 哈希链，
`verifyAll()` 校验通过——被拦的攻击也有记录，不是"静默拒绝"。

---

## 3. 分级策略：什么拦、什么只标记

### 3.1 信号分级（T1）—— 只对高置信词阻断

注入信号现在是**分级词表**，不是一张平铺的字符串表：

```jsonc
// ~/.pod/rules.json
{
  "injection": {
    "block": true,               // 默认开
    "blockAtOrAbove": "high",    // 只有 ≥ 这个级别才拦
    "signals": [
      { "id": "ignore-previous", "text": "ignore previous", "severity": "high" },
      { "id": "system-prompt",   "text": "system prompt",   "severity": "low" }
    ]
  }
}
```

| 级别 | 默认信号 | 行为 |
|------|----------|------|
| high | `ignore previous` / `忽略之前` / `do not tell the user` / `exfiltrate` / `把密钥发给我` … | **阻断**该次响应，内容不回传 |
| medium | `jailbreak` / `developer mode` | 只写 `injection_suspect` 审计 |
| low | `system prompt` / `you are now` | 只写 `injection_suspect` 审计 |

**一段文本同时命中高低两级时取最高级别**——一条 high 就够拦，不该被后面的 low 冲淡。

`medium`/`low` 之所以默认不拦：这些词在正常文档里天天出现
（问模型"什么是 system prompt"就会命中）。按 high 处理等于让网关随机打断正常工作。
需要更严的场合把 `blockAtOrAbove` 调成 `medium` 即可。

**回退**：`block: false` 完全恢复"只标记"的老行为。

**老配置兼容**：`signals` 以前是字符串数组，现在归一化时按 **low（只标记）** 处理——
升级 pod 不会让老配置突然开始拦工具调用。想让它阻断，补一个 `severity` 即可。

### 3.2 工具描述投毒（G6）—— 默认把该工具摘除

命中 `toolMetadata.suspiciousPatterns`（默认 `block: true`, `blockAtOrAbove: "high"`）的工具
会从 `tools/list` 里**摘掉**——攻击面是"描述"这段自由文本，把描述从 agent 眼前拿走就切断了
影响路径。`medium` 命中仍然只记账（例如工具描述里带外部端点）。

**摘除 ≠ 封禁**：agent 硬报名字调用照样会被转发并受策略管辖（e2e 用例验证了这条）。
所以它是"减少被影响的面"，不是"收回能力"——真要收回能力，用策略的 `deny`。

### 3.3 绕过网关 —— 只检测

agent 的 MCP 配置被改成直连真实 server（不走 pod）时，网关完全不在链路上。
`pod coverage --strict` 能发现并让 CI 退出码非 0，但**它不是运行时阻断**。

---

## 4. 架构上就不设防的（写清楚，避免虚假安全感）

- **MCP server 自身的出网**：网关只站在 agent 与 server 之间，看不见 server 进程自己发的请求
  （见 `docs/egress-defense.md`）。要覆盖必须靠容器/k8s NetworkPolicy 之类的部署层隔离；
- **agent 与 LLM 之间的 prompt**：这段流量不经过 pod，发给模型提供商的内容 pod 看不到；
- **本机被完全攻陷**：本地恶意软件能直接改 `rules.json`、读审计原文、杀网关；
- **harness 自身漏洞**：Claude Code / Codex / Cursor 内部做什么，pod 看不见。

---

## 5. 本次补上的缺口

| 缺口 | 之前 | 现在 |
|------|------|------|
| 工具输出注入（T1） | 只标记，内容仍回到 agent | **默认阻断**高置信信号：内容不回传 + 审计记 blocked；低置信仍只标记 |
| 工具描述投毒（G6） | 只记账，`tools/list` 原样返回 | **默认摘除** high 命中的工具；medium 只记账；可用 `block`/`blockAtOrAbove` 调 |

改动位置：

- 规则定义、分级词表、老格式归一：[rules.ts](../packages/policy/src/rules.ts)
  （`InjectionSignal` / `InjectionRules` / `MetadataRules` / `normalizeRules` / `severityRank`）
- 网关执行：[proxy.ts](../packages/gateway/src/proxy.ts)
  （`matchInjectionSignal` 返回最高置信命中；`tools/list` 摘除被拦工具）
- 规则可见性：`pod rules show` 打印"命中即阻断 / 仅标记"

---

## 6. 怎么复现

```bash
cd pod

# 真实对抗 e2e（14 条：攻击得手与否 + 审计完整性）
pnpm --filter @podsec/cli test -- attack-e2e

# 网关层单元测试（43 条：审批流、快照、输出脱敏、熔断、JIT 令牌、HTTP 网关）
pnpm --filter @podsec/gateway test

# 策略层红队（确定性判定，可与上面的 e2e 对照）
pod redteam --policy ~/.pod/policies/draft.json
```

**这套 e2e 的用法不止于验证**：它同时是回归测试——任何改动如果让某条攻击重新得手，
测试立刻变红。新增攻击手法时，往 `fixtures/attack-server.ts` 加一个工具、
往 `attack-e2e.test.ts` 加一条用例即可。
