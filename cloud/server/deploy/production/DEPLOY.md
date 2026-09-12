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
PUBLIC_BASE_URL=https://pod.yourdomain.com      # 对外地址（Stripe 回调）
PODCLOUD_BILLING_PROVIDER=stripe                # 计费平台（见 §4）
# PODCLOUD_ALLOW_PLAN_SWITCH=0                  # 别开：开了任何人可白拿 pro（见 §4）
STRIPE_SECRET_KEY=sk_live_...                   # 配置后（见下）
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_PRO=price_...                      # Stripe 产品价格 id
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

### 4.1 先选平台：有没有海外主体决定一切

`PODCLOUD_BILLING_PROVIDER` 指定用哪个支付平台，默认 `stripe`。

| 你的主体情况 | 该走的路 | 说明 |
| --- | --- | --- |
| 中国大陆个人，无海外公司 | **MoR**（Paddle / Creem / Waffo 这类） | MoR 是法律上的卖家，替你收税、开票、处理拒付；你只需要个人身份 + Wise/Payoneer/CNY 提现 |
| 已有受支持地区主体（美国 LLC / 香港 / 新加坡） | Stripe | 费率更低、控制力更强，但 VAT/GST 申报要自己处理 |

Stripe 的可用国家列表里没有中国大陆，所以**没有海外主体时 Stripe 开不了账户**。
接 MoR 的做法：在 `app/services/billing.py` 实现一个 `BillingProvider`
（`is_configured` / `create_checkout` / `parse_webhook` 三个方法），
注册进 `PROVIDERS`，然后把 `PODCLOUD_BILLING_PROVIDER` 指过去。
路由、`Subscription` 表、前端都不需要改 —— 它们只认归一后的
`BillingEvent` 与 `checkout_url`。

### 4.2 免支付切换开关

`PODCLOUD_ALLOW_PLAN_SWITCH` 默认值等于「是不是 dev 环境」：

- `PODCLOUD_ENV=dev` → 开启（本地开发、测试用）
- 其他任何值（含本指南的 `production`）→ **关闭**

关闭后：升级到 pro 必须走支付通道（`POST /subscription/plan` 返回 403），
降级到 free 仍可自助。**不要在生产打开它** —— 该接口只校验"租户管理员"，
而每个注册用户都是自己租户的管理员，打开就等于任何人一个 API 调用白拿 pro。

### 4.3 Stripe 配置（provider=stripe 且主体就绪后）

1. Stripe Dashboard → Products → 创建 "Pod Cloud Pro"（$19/月）→ 复制 price id 到 `.env` STRIPE_PRICE_PRO
2. Developers → Webhooks → 添加端点 `https://pod.yourdomain.com/api/v1/subscription/webhook`
   - 事件：`checkout.session.completed`、`customer.subscription.deleted`
   - 复制签名密钥到 `STRIPE_WEBHOOK_SECRET`
3. 重启：`docker compose up -d`（compose 的 env_file 会读取 .env）

> 注意：`.env` 里的 `PODCLOUD_DB_URL` / `PODCLOUD_ENV` 由 compose 的
> `environment:` 段写死（见 `deploy/docker-compose.yml`），改 `.env` 不生效；
> 计费相关变量不在该段里，走 `env_file`，改 `.env` 即可。

## 5. 上线检查清单

- [ ] HTTPS 可访问（https://pod.yourdomain.com 显示 Pod Cloud）
- [ ] 注册 → 登录 → 建 Agent → 订阅页显示"支付已接入"
- [ ] 本地 `pod sync` 可推送（cloud.json 指向 https 地址）
- [ ] Stripe 测试模式走通一次 checkout（Stripe 有测试卡 4242 4242 4242 4242）
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

- [ ] 计费通道二选一：MoR（无海外主体，推荐）或 Stripe（需支持地区主体）—— 见 §4.1
- [ ] 域名购买与 DNS
- [ ] 法务文档替换占位联系方式（docs/legal/）并经法律审核
- [ ] 隐私政策中的联系方式/管辖地/保留期限定稿
