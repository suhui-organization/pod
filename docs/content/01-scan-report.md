# 我扫描了自己的机器：6 个 AI Agent、14 个 MCP 服务器、5 处明文密钥

> 发布渠道：GitHub / 即刻 / V2EX / Hacker News
> 状态：v0.2.0 校订版（数字于 2026-09-12 复扫确认，与首扫 2026-09-01 一致）

我的电脑上装了 6 个 AI Agent 平台：DeepSeek Harness、OpenClaw、Claude Code、
Cursor、Codex、OpenCode。它们一共配置了 14 个 MCP 服务器。

我写了一个只读扫描器（`pod scan`，[项目主页](https://gitee.com/suhuisoftwares/pod)），
实测 **0.19 秒**扫完——结论有点吓人。这份报表就是我的 Agent 的**信任基线**：
看清风险面，是给每一步留下不可篡改证据的第一步。

想在自己机器上跑同一份扫描（只读、不联网、不上传任何数据）：

```bash
curl -fsSL https://gitee.com/suhuisoftwares/pod/raw/v0.4.1/scripts/install.sh | sh
pod scan
```

## 发现 1：12/14 的 MCP 服务器没有锁定版本

```
context7        → npx @upstash/context7-mcp           （未锁定）
playwright      → npx @playwright/mcp@latest          （@latest）
github          → npx @modelcontextprotocol/server-github （未锁定）
…共 12 个
```

每个 `npx -y <包>` 都是**供应链风险**：`@latest` 意味着下次启动可能跑的是
别人刚上传的代码。2025 年已经有真实案例——恶意 MCP 包在 npm 上窃取 `.env`。
我的 github server 带着我的 PAT（Personal Access Token）每天从 `@latest` 拉取。

## 发现 2：5 处明文密钥躺在 agent 配置文件里

| 位置 | 类型 |
|------|------|
| ~/.dsh/mcp-manager.json | GitHub token ×2 |
| ~/.codex/config.toml | OpenAI key |
| ~/.cursor/mcp.json | GitHub token |
| ~/.config/opencode/opencode.json | OpenAI key |

（掩码显示，具体值不公布——你可以在自己机器上跑 `pod scan` 看。）

任何一个能读到这些文件的进程/agent，都等于拿到了我的 GitHub 和 OpenAI 账号。

## 发现 3：6 个 agent，没有统一清单

Cursor 知道自己的权限，OpenClaw 知道自己的，但没有一个工具能回答：
**"我所有的 agent 合起来能碰什么？"**——这就是影子 agent 问题。

## 怎么办

1. **锁定版本**：`npx -y pkg@1.2.3`，别用 `@latest`
2. **密钥进钥匙串**：`.env` 里的 token 迁到系统钥匙串/secret 管理器
3. **加一道闸门**：让 agent 的工具调用经过一个策略层（`pod serve`），
   敏感路径直接拒绝、密钥输出直接拦截、每次调用留哈希链审计

扫描器开源免费（Apache-2.0）。安装见上面那条命令；`pod scan` 只读本地配置，
不联网、不上传任何数据——报表里的密钥一律掩码显示。

---

*文中的数据来自作者真实机器的扫描结果（首扫 2026-09-01，v0.2.0 发布前于 2026-09-12 复扫确认）。
具体密钥值不公布——任何人都可以在自己机器上跑 `pod scan` 得到属于自己的那一份。*
