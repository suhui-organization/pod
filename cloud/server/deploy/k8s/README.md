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

## 单源约束

- 镜像 tag：默认按源码内容指纹自动生成 `fp-<hash>`（server/web 各自独立），内容变化
  自动换 tag，kubelet 必然拉新（根因修复同 tag 缓存）；显式 `IMAGE_TAG` 可覆盖为固定 tag。
- 版本号不再散落于清单（历史问题：compose 0.1.6 / k8s 0.1.17 / package.json 0.2.0 各自为政）。
