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
