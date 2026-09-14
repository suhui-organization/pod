# 对外内容（按发布顺序排列）

发布顺序与检查清单见 [../PUBLISHING.md](../PUBLISHING.md)。发布前先跑：

```bash
bash scripts/preflight-publish.sh
```

| 顺位 | 文件 | 主题 | 状态 |
|---|---|---|---|
| 1 | [02-quickstart.md](02-quickstart.md) | 五分钟给 agent 装上闸门（**先发**） | v0.2.0 已校订 |
| 2 | [01-scan-report.md](01-scan-report.md) | 我扫了自己机器：6 agent / 14 server / 5 处密钥 | v0.2.0 已校订，数字 2026-09-12 复扫确认 |
| 3 | [03-owasp-101.md](03-owasp-101.md) | OWASP Agentic Top 10 大白话（ASI01–ASI10） | v0.2.0 已校订 |
| 4 | [04-forensics.md](04-forensics.md) | 出事后 5 分钟取证 | v0.2.0 已校订 |

四篇的安装命令都钉在 `v0.3.2`（当前发布版），每篇的 `pod` 命令都在干净环境里实跑过。
表里的「已校订」说的是**内容准确性**的复核时间（数字、编号、命令），它不跟着版本号走——
安装命令钉当前版，校订声明留着它当时被核对的那个版本，两者不一致是正常的。
