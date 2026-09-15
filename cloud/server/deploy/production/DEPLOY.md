# Pod Cloud 公网部署指南（对外发布）

目标：一台 VPS + 一个域名，30 分钟内上线 HTTPS 服务。
前提：Docker + Docker Compose；域名 A 记录指向服务器 IP。

## 1. 目录与配置

```bash
mkdir -p /opt/podcloud && cd /opt/podcloud
# 从仓库拷 compose 与 .env（见 deploy/compose/）
cp -r <repo>/deploy/compose/* .
cp .env.example .env
```

`.env` 必改项：

```bash
PODCLOUD_JWT_SECRET=$(openssl rand -hex 32)     # 强密钥
PUBLIC_BASE_URL=https://pod.yourdomain.com      # 对外地址（支付成功跳回、找回密码链接）
PODCLOUD_BILLING_PROVIDER=paddle                # 计费平台（见 §4）
# PODCLOUD_ALLOW_PLAN_SWITCH=0                  # 别开：开了任何人可白拿 pro（见 §4）
PADDLE_API_KEY=pdl_live_apikey_...              # 配置后（见下）
PADDLE_WEBHOOK_SECRET=ntfset_...
PADDLE_PRICE_PRO=pri_...                        # Paddle 价格 id
PADDLE_CLIENT_TOKEN=live_...                    # 公开值：前端加载 Paddle.js 用
PADDLE_ENV=live                                 # sandbox | live（默认 sandbox，配错也只打测试环境）
WEB_PORT=8080                                   # 容器内端口（Caddy 反代）
```

## 2. Caddy（自动 HTTPS）

`Caddyfile`：

```
pod.yourdomain.com {
    reverse_proxy 127.0.0.1:8080
    encode gzip
    header {
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
    }
}
```

Caddy 一条命令（自动申请/续期 Let's Encrypt）：

```bash
docker run -d --name caddy -p 80:80 -p 443:443 \
  -v /opt/podcloud/Caddyfile:/etc/caddy/Caddyfile \
  -v caddy-data:/data -v caddy-config:/config \
  caddy:2
```

## 3. 防火墙（VPS 侧）

```bash
# ufw 示例：只开 22/80/443
ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw enable
```

## 4. 计费通道配置

### 4.1 平台：Paddle（MoR）

`PODCLOUD_BILLING_PROVIDER` 默认且当前只支持 `paddle`。

Paddle 是 MoR（Merchant of Record）：法律上的卖家是 Paddle，它替你收全球的卡、
代算代缴 VAT/GST、开发票、处理拒付，打款走 Wise/Payoneer。中国大陆个人不需要
海外主体就能开通 —— 这也是它取代 PSP 通道的原因。

再接新平台的做法：在 `app/services/billing.py` 实现一个 `BillingProvider`
（`is_configured` / `create_checkout` / `parse_webhook` 三个方法），注册进
`PROVIDERS`，然后把 `PODCLOUD_BILLING_PROVIDER` 指过去。路由、`Subscription`
表、前端都不用改 —— 它们只认归一后的 `BillingEvent` 与 `checkout_url`。

### 4.2 免支付切换开关

`PODCLOUD_ALLOW_PLAN_SWITCH` 默认值等于「是不是 dev 环境」：

- `PODCLOUD_ENV=dev` → 开启（本地开发、测试用）
- 其他任何值（含本指南的 `production`）→ **关闭**

关闭后：升级到 pro 必须走支付通道（`POST /subscription/plan` 返回 403），
降级到 free 仍可自助。**不要在生产打开它** —— 该接口只校验"租户管理员"，
而每个注册用户都是自己租户的管理员，打开就等于任何人一个 API 调用白拿 pro。

### 4.2.1 每日巡检（可选，默认开）

控制台「系统自检」页的检查项，每天会自动跑一遍并把结果落库；失败时走
「设置 · 告警通知」里配好的 webhook / 邮件推一条，**同时在「告警」列表里留一条
平台级记录**（agent 显示为 Pod Cloud，可走未解决/已确认/已解决那套处置流程；
同一条失败未处理完不会重复建）。启停与时刻：

**闭环**：某一项下一轮检查通过了，还挂着的那条平台告警会**自动标为已解决**
（open / acknowledged 都会关；手动点过「已解决」的保持不动），自检页会提示
"这次检查通过的项已自动关闭 N 条告警"，历史里也留痕。人不需要去手动关一遍。

> 升级提醒：带结构性迁移的版本（要重建表的）在启动时**先自动把 SQLite 库文件
> 拷一份**（`<db>.bak-<时间>-pre-structural-migration`）再做改动，改完核对行数，
> 对不上整笔回滚。备份开关 `PODCLOUD_MIGRATE_BACKUP=off`。确认无误后可删掉备份。

```bash
PODCLOUD_SELFCHECK_ENABLED=on     # off 可完全关掉
PODCLOUD_SELFCHECK_HOUR=8         # 北京时间整点，默认 8
PODCLOUD_SELFCHECK_REPAIR=0       # 1 = 巡检时先做安全自修复（默认只报不改）
PODCLOUD_SELFCHECK_NOTIFY=fail    # fail（默认）| all（连警告一起推）| off
```

注意：巡检里包含一次**真实模型调用**（验证模型可用性），每天每租户一次；
没配模型的租户只会得到一条"模型还没配好"的警告，不会反复失败告警。

### 4.3 Paddle 配置

1. Paddle → Catalog → 建 "Pod Cloud Pro"（$19/月）→ 复制价格 id 到 `.env` 的 `PADDLE_PRICE_PRO`
2. Paddle → Developer Tools → Authentication → 生成 API key → `PADDLE_API_KEY`
3. Paddle → Developer Tools → Notifications → 添加端点
   `https://pod.yourdomain.com/api/v1/subscription/webhook`
   - 订阅事件至少勾 `subscription.created` / `subscription.updated` / `subscription.canceled`
   - 复制通知密钥到 `PADDLE_WEBHOOK_SECRET`（验签用；缺了接口一律 400，不会漏放）
4. 客户端：把 default payment link 配好（收银台地址由它决定），
   Client-side token 填 `PADDLE_CLIENT_TOKEN`（公开值，前端加载 Paddle.js 用）
5. `PADDLE_ENV` 先 `sandbox` 跑通，再切 `live`
6. 重启：`docker compose up -d`（compose 的 env_file 会读取 .env）

> 验签用的是**原始 body**，且 Paddle 的时间戳容差只有 5 秒 —— 服务器时钟要准
> （装个 chrony/ntpd）。时钟漂移会让所有回调都被判成重放。

> 注意：`.env` 里的 `PODCLOUD_DB_URL` / `PODCLOUD_ENV` 由 compose 的
> `environment:` 段写死（见 `deploy/docker-compose.yml`），改 `.env` 不生效；
> 计费相关变量不在该段里，走 `env_file`，改 `.env` 即可。

## 5. 上线检查清单

- [ ] HTTPS 可访问（https://pod.yourdomain.com 显示 Pod Cloud）
- [ ] 注册 → 登录 → 建 Agent → 订阅页显示"支付已接入"
- [ ] 本地 `pod sync` 可推送（cloud.json 指向 https 地址）
- [ ] Paddle sandbox 走通一次 checkout（Paddle 测试环境用测试卡 4242 4242 4242 4242）
- [ ] `POST /api/v1/subscription/plan` 升级被拒（403）—— 免支付升级确实关着；降级到 free 仍可自助
- [ ] 生产加固：`PODCLOUD_ENV=production`（已在 compose 设）、JWT ≥32 字节、数据库备份
- [ ] 法务页面上线（/legal/privacy、/legal/terms，替换占位联系方式）

## 6. 备份

```bash
# 每日备份 sqlite（cron）：
docker compose exec podcloud-server sh -c 'cp /app/data/podcloud.db /app/data/podcloud.db.$(date +%F)'
# 或卷级备份：docker run --rm -v podcloud-data:/data -v $PWD:/backup alpine tar czf /backup/podcloud-data.tar.gz /data
```

## 7. 回滚

```bash
docker compose up -d --no-deps podcloud-server   # 用旧镜像 tag（compose 里 image 固定 tag）
```

## 8. 尚未就绪项（发布前）

- [ ] 计费通道：Paddle（MoR，无海外主体也能开通）—— 见 §4.1
- [ ] 域名购买与 DNS
- [ ] 法务文档替换占位联系方式（docs/legal/）并经法律审核
- [ ] 隐私政策中的联系方式/管辖地/保留期限定稿
