# pod graph — 跨 agent 能力图与毒性路径

`pod graph` 是只读分析器：它不进入运行时，不修改任何 agent 配置。

## 快速开始

```bash
pod graph build                      # 读 agent 配置 + 工具 schema，生成潜在图
pod graph toxic --diff <baseline>    # 找 source→sink 毒性路径 + 定点策略 diff
pod graph explain path-001           # 追溯某条路径的证据
```

## 命令

| 命令 | 作用 |
|---|---|
| `pod graph build` | 生成 `~/.pod/graph/potential.json` |
| `pod graph toxic` | 生成 `paths.json`、`report.md`、`policy-diff.json` |
| `pod graph explain <id>` | 打印某条路径的 source/sink/证据/建议 |
| `pod graph retention [--days 14]` | H4 留存信号：连续活跃天数 + confirmed/false-positive 统计（读 `usage.jsonl`） |

## H4 留存信号

`usage.jsonl` 是 append-only 的使用流水（`~/.pod/graph/usage.jsonl`），每次 `pod graph <子命令>` 追加一行；
产物文件都是幂等覆盖写的，只有这条流水能回答「连续多少天在用」。

活跃口径（2026-09-10 定）：只有分析类命令算主动使用 —— `build` / `observe` / `diff` / `toxic` / `baseline`；
`explain` / `mark` / `apply` 仍记录但不计入活跃日。

## 退出码

- `0`：分析成功，无高危路径
- `1`：分析成功，存在高危路径（适合 CI）
- `2`：分析失败或数据不可信

## 安全边界

- 只调用 `tools/list`，不调用 `tools/call`
- introspection 不继承全量环境变量，只传 `PATH/HOME/SHELL/TERM/LANG/LC_ALL/USER/LOGNAME/TMPDIR` + server 配置里声明的 env
- 报告不含密钥原文；全程本地、不联网
