# 出事后 5 分钟取证：你的 Agent 到底干了什么？

> 发布渠道：GitHub / 即刻 / V2EX / Hacker News
> 场景：你的 agent 半夜改了不该改的文件 / 读了 .env / 把密钥带回了对话。

AI Agent 出事的两种结局：
- **没有审计**：你只能猜。删库的 agent 永远不知道它为什么、什么时候、经谁批准。
- **有哈希链审计**：5 分钟拿出完整时间线，还能证明时间线没被改过。

pod 是第二种。[项目主页](https://gitee.com/suhuisoftwares/pod)

```bash
curl -fsSL https://gitee.com/suhuisoftwares/pod/raw/v0.2.0/scripts/install.sh | sh
```

## 剧本：凌晨 1:40，agent 试图删除文件

这是真实发生在作者机器上的一次调用（策略拦住了它）：

```
$ pod timeline --since 2h --tool delete_file

2026-09-01 01:40:08  [deny] delete_file  filesystem  agent=openclaw-main
                     args=cb1533f3…  pol=0.1.0  reason=tool "delete_file" is denied on "filesystem"  blocked
```

三秒钟看清三件事：**谁**（openclaw-main）、**想干什么**（delete_file）、**为什么没干成**（策略 deny，当时策略版本 0.1.0）。

（真实输出是紧凑的一行，长这样：）

```
2026-09-01 01:40:08  [deny   ] delete_file        filesystem   agent=openclaw-main  args=cb1533f3… pol=0.1.0  reason=tool "delete_file" is denied on "filesystem"  blocked
```

## 第一步：时间线回放（2 分钟）

```bash
pod timeline --since 2h            # 最近两小时全部动作
pod timeline --since 24h --tool write_file   # 只看写操作
pod timeline --agent openclaw-main # 只看某个 agent
```

每条记录：时间 / 工具 / 服务器 / agent / **参数哈希** / 决策 / 结果 / 审批人 / **当时策略版本**。
参数只存哈希——取证时不泄露更多数据，但能证明"确实发生过"。

## 第二步：自证未篡改（1 分钟）

```bash
$ pod verify-audit
# pod 审计完整性自检报告

## openclaw-main/filesystem.jsonl
- 状态：✅ 哈希链完整
- 条目数：8
- 链首 hash：f7a56fb90350…（完整 64 位十六进制，此处省略）
- 链尾 hash：06f31666c4e8…
**结论：全部审计记录可验证、不可篡改。**
```

每一条记录都锁着前一条的哈希。**改任何一条历史，校验立刻失败**——这比"日志系统显示已记录"强一个量级：它证明日志本身没被动过。

## 第三步：打包证据（2 分钟）

```bash
$ pod export-evidence
[pod] 证据包已导出: ~/.pod/evidence/pod-evidence-2026-09-01.json
[pod]   审计文件: 1 个 | 策略快照: 1 个
[pod]   顶层哈希: 9f9e6ed35ed1c0b9…
[pod]   一页式报告: ~/.pod/evidence/pod-evidence-2026-09-01.json.md

$ pod verify-evidence --out ~/.pod/evidence/pod-evidence-2026-09-01.json
[pod] ✅ 证据包有效（顶层哈希匹配，未被修改）
```

一个文件带走：审计 + **当时生效的策略快照** + 自检结果 + 顶层哈希。
发给客户、监管、同事——对方可以自行验证包没有被改过。

## 云端：跨 Agent 证据链（可选）

```bash
pod sync    # 审计上云
```

云端控制平面也在同一个开源仓库里（Apache-2.0），一条命令起一个：

```bash
bash deploy/install.sh
```

「时间线」页把所有 agent 的事件统一回放；合规报告（GDPR Art.30 支撑证据）
内嵌最近 20 条事件时间线。数据方向是单向的：本地只推 SHA-256 哈希上云，
审计原文不出你的机器；云端挂了也不影响本地执法。

## 为什么是哈希链，不是普通日志

| | 普通日志 | pod 哈希链审计 |
|---|---|---|
| 记录调用 | ✅ | ✅ |
| 记录参数原文 | ✅（泄露面） | ❌ 只存哈希（隐私） |
| 记录当时策略版本 | ❌ | ✅ |
| 事后可证明未被篡改 | ❌ 谁都能改日志 | ✅ 改一条全链报警 |
| 可导出可验证的证据包 | ❌ | ✅ |

> 不是所有 agent 都听话。pod 保证：**它做了什么，永远赖不掉。**

5 分钟上手：

```bash
curl -fsSL https://gitee.com/suhuisoftwares/pod/raw/v0.2.0/scripts/install.sh | sh
pod init --template baseline
pod serve --agent <name> --server <name> --policy ~/.pod/policies/baseline.json --command <cmd>
```
