# 部署 Pod Cloud（可选云端控制平面）

> 本地部分（CLI + 网关）装完就能用，**云端是可选的**：不要它，`pod` 依然能编译策略、执法、留证据。
> 要跨机器/跨 agent 统一看审计、要策略下发与告警，就把它跑起来。

## 一键部署（单机 Docker Compose）

```bash
git clone --branch v0.3.1 --depth 1 https://gitee.com/suhuisoftwares/pod.git && cd pod
bash deploy/install.sh
```

> 想跟主干就把 `v0.2.0` 换成 `main`。钉版本的意义是：安装脚本、本地 CLI、
> 云端镜像来自同一份代码，出问题时能对上号。

脚本会：预检 docker → 生成 `.env`（含随机 JWT 密钥）→ 构建镜像 → 起服务 → 等健康检查 → 打印访问地址。
首次约 2–5 分钟。

```bash
# 想顺手建好管理员，带上这两个变量
ADMIN_EMAIL=you@example.com ADMIN_PASSWORD='强密码' bash deploy/install.sh

# 换端口（默认 18088）
WEB_PORT=18089 bash deploy/install.sh
```

部署完访问 `http://<主机>:<端口>`。默认公开注册；`PODCLOUD_IS_PRIVATE=true` 可关闭注册，只留管理员建号。

## 你需要提供什么（必填只有一项）

| 项 | 必填 | 说明 |
|---|---|---|
| `PODCLOUD_JWT_SECRET` | **是**（脚本自动生成） | 登录签名密钥。**部署后不要再改**，改了所有人被登出 |
| `WEB_PORT` | 否（默认 18088） | 浏览器访问端口 |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | 否 | 想跳过页面注册就带上；不填则在页面自助注册 |
| `PUBLIC_BASE_URL` | 建议 | 找回密码邮件里的链接地址；部署到域名后**必须**改成对外地址 |
| `PODCLOUD_IS_PRIVATE` | 否 | `true` = 关闭公开注册 |
| SMTP（`PODCLOUD_SMTP_*`） | 否 | 留空则重置链接写服务端日志（`docker compose logs` 可见），自托管下是既定行为 |
| `PODCLOUD_DB_URL` | 否 | 默认 SQLite（存在卷 `podcloud-data`）。要 PostgreSQL 时填连接串 |
| `PODCLOUD_BILLING_ENABLED` | 否 | `auto`（默认，配了支付通道才启用）/ `off`（强制关闭）/ `on`（强制启用） |
| `PADDLE_*` / `STRIPE_*` | 否 | 计费凭据。**不填即完全关闭**，不影响其它功能 |
| `PODCLOUD_LLM_*` | 否 | AI 摘要类接口。不填则该功能提示未配置，其余正常 |

### 计费开关（自托管请保持关闭）

本地/私有化部署不需要收费能力。计费关闭时：

- 前端**不显示订阅入口**，订阅页改为一句说明（不会出现点了报错的付费按钮）；
- `POST /subscription/checkout` 返回 **400**「本部署未启用计费」，语义明确；
- **agent 数量不再受套餐限制**（默认免费套餐是 3 个，自托管不该被它卡住）；
- 支付平台回调仍然接收并验签——关掉计费是"不再卖新订阅"，不是"抹掉已发生的交易"，
  已订阅客户的续费/取消事件照常落库（否则支付平台会因 404 一直重试）。

开启方式：`PODCLOUD_BILLING_ENABLED=on` + 填好对应平台的凭据（如 Paddle 的
`PADDLE_API_KEY` / `PADDLE_PRICE_PRO` / `PADDLE_WEBHOOK_SECRET` / `PADDLE_CLIENT_TOKEN`），
重启后订阅入口自动出现。provider 名字写错时会**保持启用并大声报错**（503 带原因），
不会被 auto 悄悄降级成"免费无限"。

### 界面语言

控制台支持中英切换：登录页右上角与登录后的用户菜单里都有开关，选择记在浏览器
本地（`localStorage.podcloud_locale`），未选过时跟随浏览器语言。Element Plus 的
内置文案（日期选择、分页等）一并切换。

实现上是**中文原文即词条键**：没翻译的字符串原样显示中文，不会出现空白或 key 名，
所以可以按页面逐步补齐英文，不存在"必须一次翻完才能发版"的阻塞。

覆盖进度自查：`bash scripts/i18n-coverage.sh`（仓库根目录跑，`--strict` 有缺口时
退出 1）。它把「代码里 `t()` 用到的键」和「英文词表里的键」做差集，两个方向都报：
代码有、词表没有 = 这句还是中文；词表有、代码没有 = 改了文案留下的僵尸键，或者
键多/少了空格（曾经因此让一整句英文不生效）。注意它只能看 `t()` 调用——
**完全没包 `t()` 的硬编码中文它看不见**，那类只能靠界面走查。

## 真机逐页验收（控制台）

```bash
PODCLOUD_WEB_EMAIL=you@example.com PODCLOUD_WEB_PASSWORD='...' \
  bash scripts/web-acceptance.sh
```

它会：起 `kubectl port-forward`（默认 `podcloud/podcloud-server` → 127.0.0.1:8000）→
起 vite dev → 开一个**无头 Chrome**（零依赖，走 CDP，用系统装的 Chrome）→ 登录 →
逐页断言 → 收尾清理（转发和 dev server 都停掉）。

断言两条，缺一不可：

1. **页面真的渲染出内容**（行数 ≥ `MIN_LINES`，默认 4）——否则空白页也会被算作"没有中文"；
2. **没有非数据的中文**。"数据"指：登录账号与同租户成员的名字（头像只取首字）、
   以及机器同步上云的审计原文（`posture:` / `quarantine:` 等，按设计不翻）。

为什么非要真机跑：i18n 的三类问题里，有两类静态检查**永远看不见**——根本没包
`t()` 的硬编码文案，以及包了 `t()` 但键对不上（真例：Vue 模板在编译期把 `&gt;`
解码成 `>`，而词表里存的是实体，于是英文界面静默回退中文）。再加一类"页面压根
没渲染出来"，也会伪装成"没有中文"。覆盖率脚本 `i18n-coverage.sh` 管"词表齐不齐"，
这个脚本管"界面上到底长什么样"，两个都要跑。

常用环境变量：`PODCLOUD_WEB_TOKEN`（跳过登录界面，CI 用）、`PODCLOUD_LOCALE`
（默认 `en-US`，可设 `zh-CN` 反测：应当全页报错）、`WEB_PORT` / `API_PORT` /
`K8S_NS` / `K8S_SVC`、`SKIP_FORWARD=1` / `SKIP_DEV=1`（复用已有进程）。

**服务端也会跟着切**。前端每个请求带 `Accept-Language`（也可用 `?lang=en-US`），
服务端在统一出口按语言输出：

| 服务端输出 | 是否随语言切换 |
|---|---|
| API 错误文案（登录失败、额度不足、策略不存在…） | ✅ 统一异常处理里翻译，路由不用改 |
| 一键接入脚本的输出（写没写进配置、清了几条失效绑定） | ✅ 脚本里的 `print`/`echo` |
| 模型供应商说明（设置页的 Provider 列表） | ✅ |
| **审计事件 / 告警的原文** | ❌ **故意不翻**——见下 |
| 脚本注释 | ❌ 保持中文（实现说明，翻了只增加维护成本） |

为什么审计原文不翻：那是本机 `pod` 生成后同步上来的**证据**，原文进过本机哈希链。
按界面语言改写展示等于篡改证据（threat-model 的 T7）。要覆盖它们，应该在
**产生端**（CLI）做语言支持，而不是在展示端重写历史。

配置都在 `deploy/.env`（由 `.env.example` 复制而来，每个字段都有注释）。

**agent 侧需要提供什么**：不需要额外配置——在控制台注册 agent 后，页面会给你一条一键接入命令（`curl ... | bash`），它自动写 `~/.pod/cloud.json` 并验证同步。

## 数据在哪、怎么备份

| 内容 | 位置 |
|---|---|
| 账号、agent、审计事件、策略、告警 | 卷 `podcloud-data` → 容器内 `/app/data/podcloud.db`（SQLite） |
| 审计原文 | **不在云端**。云端只收 SHA-256 哈希与元数据，原文留在 agent 机器上 |

```bash
# 备份
docker compose exec -T podcloud-server cp /app/data/podcloud.db /app/data/podcloud.db.bak
docker cp "$(docker compose ps -q podcloud-server)":/app/data/podcloud.db ./podcloud-backup.db

# 停止（保留数据）
docker compose down

# 停止并删除数据（不可恢复）
docker compose down -v
```

## 运维命令

```bash
docker compose ps                    # 状态
docker compose logs -f podcloud-server
docker compose up -d --build         # 更新代码后重建
docker compose pull                  # （用预构建镜像时才需要）
```

## Kubernetes

仓库里保留了 k8s 清单作为参考：`cloud/server/deploy/k8s/`。它面向"本机 kind/Docker-Desktop 集群 + 源码指纹打 tag"的流程，脚本是 `install-local.sh`。

上生产前请注意：那份清单用的是 `imagePullPolicy: IfNotPresent` 与本地构建的镜像，把它接到你自己的镜像仓库（CI 构建推送）更合适——把 Deployment 里的 `image:` 换成你的 registry 地址即可。反过来，如果你的集群能直连本机 docker（如 Docker Desktop），原脚本可以直接用：

```bash
bash cloud/server/deploy/k8s/install-local.sh
```

## 与本地 agent 的关系

```
agent 机器（本地，信任根）                  云端（可选）
  agent ──▶ pod 网关 ──▶ 真实 MCP server      Pod Cloud
              │ 策略/审批/审计                  ▲
              └──── pod sync（只推哈希）────────┘
```

- `pod serve` 不依赖云端：云端挂了，本地执法与审计照常。
- 云端挂了只会影响跨机器的可视化与策略下发，不会让 agent 停下来。
- 数据方向是**单向**的：本地推哈希上云；云端下发策略（可选验签）。
