# Pod Cloud 本地 k8s 完整安装路径

从零到 agent 审计上云的两段式脚本（均幂等，可反复执行，环境变量见脚本头注释）：

```
① 部署云端（本目录）
   bash deploy/k8s/install-local.sh \
     ADMIN_EMAIL=admin@x.com ADMIN_PASSWORD=xxx
   # → 预检 kind/SC → 构建+load 镜像 → 渲染清单(占位符注入 tag/密钥) → apply → 端口 18088 → 健康验证 → 管理员引导

② 接入本机 agent（pod 仓库 scripts/）
   bash scripts/setup-agent.sh \
     ADMIN_EMAIL=admin@x.com ADMIN_PASSWORD=xxx
   # → CLI 就绪 → cloud.json 绑定(可自动注册) → 策略 → pod serve 网关 → Hermes MCP 配置 → pod sync(401 自动轮换) → 云端状态验证
```

## 为什么"两条命令"就够

- 清单模板不再写死版本与密钥：镜像 tag 用源码内容指纹占位符 `__SERVER_IMAGE_TAG__`（03）/
  `__WEB_IMAGE_TAG__`（05），JWT 密钥用 `__JWT_SECRET__`（02），由 ① 在部署时注入；
  集群已有 Secret 则复用（避免重装轮换 JWT 导致登录失效）。
- 环境缺口全部在脚本内预检：kind 集群名自动探测、StorageClass 检查、工具链检查、
  Hermes config.yaml 自动定位、同步 401 自动轮换 token 并对齐 cloud.json。
- 常驻进程（端口转发、pod 网关）带 pid 文件，重复运行自动复用或平滑重启。

## 手动等价操作（对照调试用）

| 环节 | 等价命令 |
|---|---|
| **发版/滚动更新** | **改完代码直接 `bash install-local.sh`**——源码指纹(仅镜像输入文件)变化时自动 重建→kind load→滚动重启;无变化幂等空跑。手工等价: `kubectl -n podcloud set image deploy/... server=podcloud-server:<tag>` / `rollout undo` |
| 端口暴露 | `kubectl -n podcloud port-forward svc/podcloud-web 18088:80` |
| 网关 | `pod serve --agent hermes --server filesystem --policy ~/.pod/policies/baseline.json --command npx --arg -y --arg @modelcontextprotocol/server-filesystem --arg $HOME/Workspaces --transport http --port 8787` |
| 同步 | `pod sync` |
| 审批 | `pod pending` / `pod approve --id N` |
| 卸载 | `kubectl delete ns podcloud` |

## 数据

- sqlite 数据库在 PVC `podcloud-data`（/app/data/podcloud.db），StorageClass `standard`（本地 local-path）
- JWT 密钥真源在集群 Secret `podcloud-secrets`（仓库只留占位符；生产环境轮换）
- 备份：`kubectl -n podcloud exec deploy/podcloud-server -- cp /app/data/podcloud.db /app/data/podcloud.db.bak`

## 服务器集群（不是 kind）：`install-server.sh`

上线的那套跑在一台真实服务器集群上（`192.168.66.8`，ns `podcloud`，出口
`https://podcloud.dlszjr.com` → nginx → NodePort 30088）。它和本地 kind 有四点不同，
所以**不能套用 install-local.sh**：

| | 服务器集群 | 本机 kind |
|---|---|---|
| 镜像 tag | `main-<commit>` | `fp-<内容指纹>` |
| 构建位置 | **节点上就地构建**（集群没有可达的公网镜像仓） | 本机 |
| 让 k8s 看见镜像 | `docker save \| ctr -n k8s.io images import -`（**docker 里的镜像 kubelet 看不见**） | `kind load` |
| 清单 | 线上对象手工调过；脚本只 `set image`，不 apply | 仓库模板渲染后 apply |

```bash
# 一条命令：预检 → 解析目标 commit → 备份库 → 节点构建 → 导入 containerd → server→web 滚动 → 验证
KUBECONFIG=~/.kube/config-server.yaml PUBLIC_URL=https://podcloud.dlszjr.com \
  bash install-server.sh

GIT_REF=main bash install-server.sh      # 指定要发布的 ref（默认 main）
DRY_RUN=1 bash install-server.sh         # 只打印计划
SKIP_BUILD=1 IMAGE_TAG=main-fbf730b bash install-server.sh   # 镜像已在节点，只滚动
```

三条硬约束写在脚本里，别绕过：

1. **顺序**：server 先滚完并就绪，再滚 web（新前端会调服务端新端点，同时重启会出现
   "新前端 + 旧后端"的 404 窗口）。
2. **备份用 sqlite 的在线备份**，不是 `cp`——库在 WAL 模式，`cp` 主文件会丢掉
   `-wal` 里已提交的事务（线上实测 WAL 有 4 MB）。
3. **不 apply 清单**：这些对象是手工调过的（nodeSelector→hadoop8、hostPath PV、
   NodePort 30088、server 用 `Recreate` 因为 SQLite 不能被两个 Pod 同时写）。
   脚本只改 image，避免把线上调优冲掉。

清单的只读快照在 [server-cluster-snapshot.yaml](server-cluster-snapshot.yaml)
（从线上导出、去掉了运行时字段与 Secret），用途是"集群重建时有据可依"，
以及让"服务器上到底跑的是什么"不只存在于集群里。

回滚：`kubectl -n podcloud rollout undo deploy/podcloud-web` 再
`... deploy/podcloud-server`（**顺序反过来**：先退 web，老前端调的都是老端点）。

## 单源约束

- 镜像 tag：默认按源码内容指纹自动生成 `fp-<hash>`（server/web 各自独立），内容变化
  自动换 tag，kubelet 必然拉新（根因修复同 tag 缓存）；显式 `IMAGE_TAG` 可覆盖为固定 tag。
- 版本号不再散落于清单（历史问题：compose 0.1.6 / k8s 0.1.17 / package.json 0.2.0 各自为政）。
