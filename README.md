# pod — AI Agent 安全舱

> **你的 Agent 每一步，都有不可篡改的证据。**

AI 在替你动手之前，先回答三个问题：**它能碰什么？谁批准了？证据在哪？**
pod 给每个工具调用装三道闸——策略闸门、人工审批、哈希链审计。
最后一道是我们的核心：**每次调用写入 SHA-256 哈希链，改任何一条历史记录，校验立刻失败。**

```
调用 ──▶ 策略求值（deny > approve > allow）──▶ 审批（高危挂起）──▶ 执行
                                                              │
                                                              ▼
                                        ┌────────────────────────────┐
                                        │ 哈希链审计：                │
                                        │ #3 hash = sha256(#2 + 记录) │ ← 不可篡改
                                        │ #2 hash = sha256(#1 + 记录) │ ← 每步留痕
                                        │ #1 hash = sha256(首条)      │ ← 可验证
                                        └────────────────────────────┘
```

三个支柱：

- **🚪 闸门**：每个工具调用必经策略闸门，未授权默认拒绝（fail-closed），写操作需要人批准
- **📜 证据**：每次调用写入 SHA-256 哈希链——防篡改、可验证，出事了能拿出完整时间线
- **👁 视野**：OpenClaw、Claude Code、Cursor、DSH 各自管自己的权限——
  pod 是唯一给你**跨 agent 统一视图**的层（云端可选，审计只存哈希，数据不出机器）

> 你的 OpenClaw、Claude Code、Cursor、DSH 各自管自己的权限——但没有任何工具告诉你
> "你所有的 agent 合起来能碰什么、每一步的证据在哪"。pod 补上这一层。

```
Agent (OpenClaw / Claude Code / Cursor / DSH …)
      │ MCP
      ▼
┌─ pod gateway ──────────────┐    ┌────────────────┐
│ 策略求值 deny>approve>allow │───▶│ 真实 MCP server │
│ 审批挂起（fail-closed）      │    └────────────────┘
│ 哈希链审计（只存哈希）        │
└──────────┬─────────────────┘
           │ pod sync（游标增量） / pod pull-policy（策略下发）
           ▼
      Pod Cloud（可选 SaaS 控制平面：跨 agent 视图 / 策略中心 / 合规报告）
```

## 快速开始

```bash
# 安装（Node ≥ 20）
npm i -g @podsec/cli     # 或 brew install podsec/tap/pod（发布后）

# ① 扫描风险面（免费，只读，不上传任何数据）
pod scan
# → 发现 N 个 agent 平台 / MCP server 版本锁定 / 明文密钥（掩码）

# ② 接一个真实 MCP server（先录后拦）
pod record --config ~/.dsh/mcp-manager.json --server filesystem --agent openclaw-main
# 把 agent 的 MCP 配置指向本进程，所有调用落审计（record 不阻断）

# ③ 升级为强制策略
pod serve --agent openclaw-main --server filesystem --policy policy.json
# policy.json 示例：
# { "version": "0.1.0", "agent": "openclaw-main", "defaultDecision": "deny",
#   "servers": { "filesystem": { "allow": ["read_file", "list_directory"],
#                                 "approve": ["write_file"], "deny": ["delete_file"] } } }

# ④ 高危操作触发审批（stdio 被 MCP 占用，交互在另一终端）
# 网关提示: APPROVAL NEEDED #filesystem-3 ... approve: pod approve --id filesystem-3
pod approve --id filesystem-3 --reason "我在改配置"   # 超时(默认300s)自动拒绝

# ⑤ 审计查看（哈希链校验，篡改即报错）
pod audit --tail 20
```

## 命令一览

| 命令 | 说明 |
|------|------|
| `pod scan` | 只读风险扫描：影子 agent / MCP 供应链 / 密钥暴露 |
| `pod record` | 只录不拦：包装真实 MCP server，采集行为语料 |
| `pod serve` | 强制模式：三态策略 + 审批闸门 + 审计 |
| `pod audit` | 查看审计（SHA-256 哈希链，可验证不可篡改） |
| `pod approve / deny / pending` | 审批旁路通道 |
| `pod sync` | 推送审计到 Pod Cloud（游标增量、幂等） |
| `pod pull-policy` | 拉取云端策略到本地生效 |

## 威胁模型

见 [docs/threat-model.md]（T1 提示注入 / T2 密钥外泄 / T3 破坏性操作 / T4 MCP 供应链 / T5 数据外泄 / T6 影子 agent / T7 审计篡改），对齐 [OWASP Top 10 for Agentic AI](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)。

**安全承诺**：本地优先（数据不出机器，Pod Cloud 同步需显式开启）；审计只存参数哈希不存原文；核心安全逻辑 100% 单测（`pnpm -r test`，67 用例）。

## 开发

```bash
pnpm install
pnpm -r build && pnpm -r test   # 67 测试全绿
```

- `packages/audit`：哈希链审计存储（不可变、可验证）
- `packages/policy`：三态策略求值器（deny > approve > allow，fail-closed）
- `packages/gateway`：MCP 双向代理 + 审批/审计钩子
- `packages/scan`：风险扫描器
- `apps/cli`：pod CLI

## License

Apache-2.0。安全相关报告见 [SECURITY.md](SECURITY.md)。
