# 端 A ↔ 端 B 的契约（本机 pod ↔ Pod Cloud）

> 状态：2026-09-18。对照实现：`apps/cli/src/protocol.ts`、`cloud/server/app/protocol.py`、
> `cloud/server/app/routers/sync.py`。**改这条契约（字段含义 / 端点语义）必须同时改这两个文件与本页。**

## 0. 一句话

两端**分开发布**：端 A 按 tag 发（用户装完就不动），端 B 按镜像滚（随时会更新）。
所以"版本错配"不是异常，是常态——契约要做的不是阻止它，而是**让它可判定、可解释**。

## 1. 两端的职责边界

| | 端 A（本机 pod） | 端 B（Pod Cloud） |
|---|---|---|
| 在哪跑 | 用户机器上（CLI + `pod ui` + 网关） | 服务器（SaaS 或用户自部署） |
| 看得到什么 | 本机文件、工具调用、审计链 | 只有机器**推上来的**东西 |
| 判定与执法 | ✅ 全在这里（策略判定、审批、熔断收敛） | ❌ 云端不在调用路径上 |
| 留痕 | ✅ 哈希链在本机 | 收到的是哈希与摘要，不是原文 |
| 汇总 / 下发 / 告警 | ❌ | ✅ |

**一条硬约束**：云端挂了，端 A 照常工作。任何"要求云端在线才能拦"的设计都不属于这套架构。

## 2. 通道清单（方向 / 触发 / 传什么）

| 通道 | 方向 | 触发 | 传什么 | 鉴权 |
|---|---|---|---|---|
| `POST /api/v1/sync/events` | A → B | `pod sync`（默认每 30 分钟） | 审计事件：`tool` / `args_hash` / `output_hash` / `decision` / `reason` / `prev_hash` / `hash` / `seq` / `kind`。**不含参数与输出原文** | `X-Sync-Token` |
| `POST /api/v1/sync/ping` | A → B | 同上次 sync 一起 | 心跳 + 版本 + **健康摘要**（见 §3）。老客户端不带 body，照常 200 | `X-Sync-Token` |
| `POST /api/v1/sync/inventory` | A → B | 随 `pod sync` | **② 资产清单**：harness 清单 + 纳管状态、MCP server 清单与是否经过网关、覆盖率、规则版本（见 §3.2） | `X-Sync-Token` |
| `POST /api/v1/sync/findings` | A → B | 随 `pod sync` | **③ 发现**：漏洞扫描与控制平面姿态的结果，按（威胁/类别 × 级别 × harness）聚合计数（见 §3.3） | `X-Sync-Token` |
| `POST /api/v1/harden/reports` | A → B | `pod harden --upload`（手动/一次性） | `report.md` + `findings.json`。**不含 `evidence.json`（原始审计链）** | `X-Sync-Token` |
| `GET /api/v1/sync/quarantine` | B → A | 随 `pod sync` | 熔断**期望状态**（幂等，机器什么时候上线都会收敛） | `X-Sync-Token` |
| `GET /api/v1/sync/policies` | B → A | `pod pull-policy` | 签名策略（本地验签后生效） | `X-Sync-Token` |

## 3. 版本与健康（v0.4.0 起）

每个上云请求都带两个 header：

```
X-Pod-Protocol: 1        # 协议版本；只在破坏性变更时 +1
X-Pod-Version: 0.4.0     # 客户端版本（pod --version 打的是同一个数）
```

心跳 body（**全部可选**，老客户端不带也照常工作）：

```json
{
  "protocol_version": 1,
  "pod_version": "0.4.0",
  "health": {
    "audit":    { "chains": 2, "broken": 0, "last_call_at": "2026-09-18T06:00:00.000Z" },
    "coverage": { "servers": 3, "unmanaged": 1 },
    "guard":    { "high": 2, "medium": 1, "low": 0, "scanned_at": "2026-09-18T06:00:00.000Z" },
    "errors": []
  }
}
```

心跳响应会回协议判定，客户端据此提示（**不拒绝请求**，可用性优先）：

```json
{ "pong": true, "server_protocol": 1, "min_client_protocol": 1, "client_outdated": false }
```

### 为什么要有健康摘要

云端此前只知道"这台机器多久没同步"。但**"在线" ≠ "真的在保护"**：

- 网关可能根本没起（`last_call_at` 为空）；
- 审计链可能被改过（`broken > 0`）——而"看起来在记、其实没记"是最危险的形态；
- 还有 server 绕过网关（`unmanaged > 0`），拦与不拦都覆盖不到它。

这三件事只有机器自己能看见，所以由机器上报。控制台把它们与"在线"分开显示：
在线只说明还能同步，不说明安全。

### 隐私边界（不可让步）

健康摘要**只允许计数、布尔与时间戳**：没有路径、没有主机名、没有配置原文、
没有未纳管 server 的名字。这条与审计同步同源：云端拿到的永远不是内容。

### 3.2 ② 资产清单（`/sync/inventory`）

```json
{
  "inventory": {
    "pod_version": "0.4.1", "rules_version": "1", "scanned_at": "2026-09-18T06:00:00.000Z",
    "machine_id": "a1b2c3d4e5f60718",
    "coverage": { "servers": 3, "unmanaged": 1 },
    "harnesses": [ { "id": "claude-code", "label": "Claude Code", "installed": true, "managed": true, "managed_by": ["policy"] } ],
    "servers":   [ { "name": "github", "harness": "claude-code", "transport": "stdio",
                     "behind_gateway": false, "record_only": false, "scope": "user",
                     "package": "@modelcontextprotocol/server-github", "pinned": false } ]
  }
}
```

**为什么要它**：podcloud 是数据侧，但它看不到本机文件。"这台机器上有几个 harness、
哪些纳管了、哪些 server 绕过网关"只能由机器自己说。没有这条通道，云端资产表就只能靠人手工维护。

**快照语义**：每次上报**整体替换**该 agent 的资产行——server 被删掉时会自然消失。

**`machine_id`（伪匿名）**：资产是**机器级**快照，而云端一行 Agent = 一个绑定。
一台机器接多个 agent 时清单会复制多份，Dashboard 必须按 `machine_id` 去重才不会翻倍
（真机上踩到过：三个绑定 → "48 个 server 绕过网关"其实是 16 × 3）。
取值是 `sha256(hostname|username|platform)` 前 16 位——**哈希而非明文**，
云端无法反推主机名，只能判断"是不是同一台机器"。同一标识也随 `X-Pod-Machine` 头
用于发现上报。老客户端不上报时按 `agent_id` 计（宁可不合并，也不错合并）。

**隐私边界**：只出标识与布尔（name / harness / behind_gateway / scope / 包名 / 是否锁版本）。
**没有路径、没有 args、没有 env 取值、没有配置原文**。

### 3.3 ③ 发现（`/sync/findings`）

```json
{
  "findings": {
    "scanned_at": "2026-09-18T06:00:00.000Z",
    "totals": { "high": 3, "medium": 1, "low": 0 },
    "findings": [
      { "source": "guard",   "key": "AG-03", "severity": "high",   "harness": "claude-code", "count": 2 },
      { "source": "posture", "key": "hook",  "severity": "medium", "harness": "machine",     "count": 1 }
    ]
  }
}
```

- `source: guard` = 漏洞扫描（`key` 是 AG-xx）；`source: posture` = 控制平面姿态（`key` 是类别）。
- **同样是快照**：修好之后下次上报就消失，不会在云端永远留一条红。
- **不出证据**：只出"哪个威胁、多严重、落在哪个 harness、几处"；路径与证据留在本机报告
  与 `pod harden` 交付物里。

### 3.4 云端的落库与展示

| 表 | 存什么 | 谁用 |
|---|---|---|
| `pod_agent_assets` | ② 的一行一个资产（harness / server） | Agent 卡片、Dashboard 覆盖率 |
| `pod_agent_findings` | ③ 的一行一条聚合发现 | Agent 卡片、Dashboard Top 威胁 |

两端都只做"存储 + 聚合展示"：**云端不做任何判定**，判定与拦截永远在 pod 上。

## 4. 兼容策略

| 组合 | 行为 |
|---|---|
| 新客户端 → 老服务端 | 老服务端忽略多余的 body 与 header（HTTP 语义），同步照常；客户端拿不到协议字段就不提示 |
| 老客户端 → 新服务端 | 心跳无 body 也 200；服务端记下 `protocol_version=0`，响应里带 `client_outdated=true`（老客户端会忽略） |
| 客户端协议 < `min_client_protocol` | 响应里给 `message`，客户端**打印提示但继续同步**——"少了一半能力"必须说出来，但不能让同步失败 |
| 协议做大版本升级 | 老端 A 依旧能推事件（字段只增不减）；新端点若必须破坏兼容，走新路径而不是改老路径的语义 |

**加可选字段不算破坏性变更**：不动 `protocol_version`，两端按"缺省即退回旧行为"处理。
**只有改字段含义 / 删字段 / 改语义才 +1**，并在本页记录。

## 5. 出问题时看哪里

```bash
# 机器侧：这次同步带上去的版本与健康
KUBECONFIG=... pod sync            # 有协议提示会直接打出来
pod --version                      # 客户端版本

# 云端侧：这台机器上报了什么
curl -s -H "Authorization: Bearer <jwt>" https://<podcloud>/api/v1/agents | python3 -m json.tool
```
