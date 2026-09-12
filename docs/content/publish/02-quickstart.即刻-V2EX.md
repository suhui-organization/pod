# 即刻 / V2EX 投放版（短）

> 用法：正文直接复制；配图用 `pod scan` 的报表截图（掩码版）。
> 完整版：../02-quickstart.md

---

我的电脑上装了 6 个 AI agent，一共配了 14 个 MCP server。
其中 12 个没锁版本，5 处明文密钥躺在配置文件里。

不是吓人，是我刚扫的。扫描器开源，只读、不联网：

```bash
curl -fsSL https://gitee.com/suhuisoftwares/pod/raw/v0.2.0/scripts/install.sh | sh
pod scan
```

看完风险面，再花五分钟装个闸门：敏感路径直接拒、写操作要你批、
每次工具调用进哈希链（改一条历史，整链校验立刻失败）。

```bash
pod init --template baseline
pod serve --agent <你的agent> --server filesystem --policy ~/.pod/policies/baseline.json --command mcp-server-filesystem --arg /path/to/project
```

Apache-2.0，策略和审计都在你机器上，不上传任何数据。
能力与边界都写在 README：https://gitee.com/suhuisoftwares/pod

---

**发帖检查**：图 1 = scan 报表（密钥掩码）；图 2 = `pod serve` 触发审批的终端截图；
评论区准备好回答"和 X 网关有什么区别"（答案：网关给你执行点，pod 给你**策略本身** + 可验证证据）。
