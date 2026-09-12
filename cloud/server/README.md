# Pod Cloud — AI Agent 安全舱 · SaaS 控制平面

> 你的 Agent 每一步，都有不可篡改的证据。

Pod Cloud 是「AI Agent 安全舱」的云端控制平面：注册本地 agent 资产、汇聚各 agent 网关推送的哈希链审计事件、策略中心、告警与时间线视图。配合开源的本地网关 [pod](https://gitee.com/suhuisoftwares/pod)（策略执行 + 审计落链）组成完整闭环。

## 架构

```
┌─ Agent 侧（本地）──────────────────────────────┐   ┌─ Pod Cloud（云端）──────────┐
│  Hermes / Codex / OpenClaw / DSH ...           │   │  /api/v1/sync/events        │
│        │ MCP (stdio / Streamable HTTP)         │   │      ▲  哈希链审计事件      │
│        ▼                                       │   │      │  X-Sync-Token        │
│  pod 网关（策略评估→审批→转发→输出检查→审计）    │───┼──────┘                      │
│  audit/*.jsonl  SHA-256 哈希链                  │   │  时间线 / 告警 / 策略 / 订阅  │
└────────────────────────────────────────────────┘   └─────────────────────────────┘
```

- **每个 agent 一次注册**：Web 填名称即完成，平台自动生成 sync token 与安装脚本
- **一键接入**：注册后复制一条命令，在 agent 机器上执行即自动写入 `~/.pod/cloud.json` 并验证同步
- **只存哈希**：服务端不存审计明文，敏感内容以 SHA-256 哈希保留证据

## 控制平面事件（与数据平面分表）

数据平面事件（`pod_sync_events`）回答"agent 做了什么"；控制平面事件
（`pod_control_events`）回答"agent 的运行环境被谁改过"，两者分表存放、分别展示。

控制平面事件由本地 pod 的 `pod posture` / `pod quarantine` / `pod delegate` /
`pod identity` / `pod grant` 等命令产生，写入 `<audit-dir>/<agent>/control.jsonl`，
随 `pod sync` 上云。事件类型（`kind`）：

| kind | 含义 |
| --- | --- |
| `hook` | 生命周期钩子被新增/改写/命中风险规则 |
| `config-change` | 冻结项（审批模式、网关地址、权限范围）与基线不一致 |
| `memory` | 长期记忆文件漂移（投毒会影响后续所有会话） |
| `package` | MCP server 来源未锁定版本 / 同名换包 |
| `identity` | Agent 身份的建立与校验 |
| `delegation` | 委托链签发（含能力收窄校验） |
| `grant` | JIT 令牌签发/消费 |
| `quarantine` | 熔断状态的加入与解除 |
| `anomaly` | 信任传播异常信号 |
| `metadata` | 工具元数据可疑（`tools/list` 时判定） |

- **接口**：`GET /api/v1/control-events`（支持 `limit` / `minutes` / `kind` / `agent_id`）、
  `GET /api/v1/control-events/summary`（按 kind / severity 聚合）
- **链连续性**：控制平面事件在云端继续用 `prev_hash`/`hash` 串联；链标识为 `control`，
  **同一批次必须来自同一条链**（数据平面与控制平面事件混批返回 400，断链返回 409）
- **展示级别**：服务端不存 severity，按 `kind` 与 `decision` 推导（响应里带
  `severity_source=derived`，不假装是原始事实）

## 快速开始（Docker Compose）

```bash
# 构建镜像
docker build -f deploy/Dockerfile -t podcloud-server:0.1.6 .

# 部署
cd deploy && cp .env.example .env && docker compose up -d
# 访问 http://127.0.0.1:18088
```

## Kubernetes

```bash
kubectl apply -f deploy/k8s/   # 00-namespace → 01-pvc → 02-secret → 03-deployment-server → 04-service-server → 05-deployment-web → 06-service-web
```

## 生产部署（Caddy + HTTPS）

见 [deploy/production/DEPLOY.md](deploy/production/DEPLOY.md)。

## 初始化管理员（私有化）

私有化部署时注册接口关闭，首次部署执行：

```bash
python -m scripts.bootstrap_admin --email admin@your.com --password '强密码'
```

## 开发

```bash
uv run uvicorn app.main:app --reload --port 8000
uv run pytest tests/ -q
```

## 仓库配套

| 仓库 | 说明 |
| --- | --- |
| [pod](https://gitee.com/suhuisoftwares/pod) | 本地网关 + CLI（开源核心）：策略执行、哈希链审计、`pod sync` 同步 |
| **podcloud-server**（本仓库） | SaaS 后端：agent 资产、sync 接收、策略中心、告警、订阅 |
| [podcloud-web](https://gitee.com/suhuisoftwares/podcloud-web) | SaaS 前端（Vue 3 + Element Plus + ECharts） |
