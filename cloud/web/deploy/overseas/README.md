# 境外可达性（现状 + 预案）

> 2026-09-17 更新：运营商已解除境外入向限制，境外访问恢复正常，**日常不再需要本目录的静态镜像**。
> 静态镜像保留为「再次被封锁时的预案」；其余内容是这次排障留下的结论与运维要点。

## 一、现状（2026-09-17 实测）

| 检查项 | 结果 |
| --- | --- |
| 境外节点直连源站 TCP 80 / 443 | 12/12 连通（0.18–0.34s） |
| `https://podcloud.dlszjr.com/login` | 10/10 节点 200 |
| `https://podcloud.dlszjr.com/` | 9/10 节点 200 |
| `https://podcloud.dlszjr.com/product`、`/legal/refund` | 各 7/8 节点 200 |
| `http://` 访问 | 6/6 正常 301 跳 https |
| 国内访问 | 200，约 0.12s |

同一时间窗、修复前的对照：境外 12 个节点 TCP 80/443 **全部超时**、ICMP 无响应；
经 ESA 回源一律 `522 Origin Connection Time-out`。

## 二、排障留档（再遇到照这个顺序查）

1. **先分清是国内还是境外**：国内正常、境外全挂 —— 大概率是线路侧的境外入向策略，
   不是站点或 CDN 的问题。
2. **用真正的境外视角实测**（不要拿本机 VPN 当境外，出口 IP 还是国内）：
   - HTTP：`https://check-host.net/check-http?host=<urlencoded-url>&max_nodes=10`，
     再取 `https://check-host.net/check-result/<request_id>`；
   - TCP：`https://check-host.net/check-tcp?host=<ip>%3A<port>&max_nodes=6`；
   - 判读看整体比例：check-host 有少数节点自身有问题（实测见过 `uk1`、`ro1` 连不上；
     `ua3` 在 Cloudflare WARP 后面会给 2ms 的假成功），别被单点带偏。
3. **确认 CDN 救不了**：回源路径断了的话，预热/刷新/换套餐全都无效 ——
   实测 ESA 预热 16/16 全部「源站响应异常」。
4. **找运营商放行**：以「该 IP 的 TCP 80/443 境外入向不可达、国内正常」为事实基础提工单，
   附境外多点测试结果，并按对方要求提交风险确认。2026-09-17 已放行。

## 三、ESA 关键配置（照着核一遍）

站点：`dlszjr.com`（站点 ID `178725950900440`，基础版），加速区域 全球（不含中国内地）。

1. **回源规则必须强制 HTTPS**：规则名「回源强制HTTPS」，作用范围「所有传入请求」，
   回源协议 `HTTPS`、端口 `443`。
   - 为什么必须：ESA 的回源协议默认为「**跟随客户端**」。预热任务走 HTTP 回源时会被源站的
     `http → https` 301 拦下，预热记录显示「**源站响应错误码301**」，100% 失败。
     加上这条规则后预热 8/8 完成。
   - 位置：规则 → 回源规则 → 新增规则（基础版配额 10 条）。
2. **多级缓存要开两层**：缓存 → 多级缓存 必须是「边缘缓存层 + 区域缓存层」；
   只有单层「边缘缓存层」时预热不生效（任务会显示「完成」，但内容并没有留在边缘）。
3. 预热额度：基础版 **10000 条/日**（免费版为 0，预热不可用）。

## 四、发版后要做的事（预热）

公开页共 8 条 URL，改版后**先刷新再预热**：

```
https://podcloud.dlszjr.com/
https://podcloud.dlszjr.com/index.html
https://podcloud.dlszjr.com/login
https://podcloud.dlszjr.com/product
https://podcloud.dlszjr.com/pricing
https://podcloud.dlszjr.com/legal/terms
https://podcloud.dlszjr.com/legal/refund
https://podcloud.dlszjr.com/legal/privacy
```

- 控制台：缓存 → 预热缓存 → 即时预热（把上面 8 行一次粘进去提交）。
- API：`PreloadCaches`（预热）、`PurgeCaches`（刷新）—— 内容变了先 Purge 再 Preload。
- 验收：预热记录里 8 条应全部「完成 100%」；若出现「源站响应错误码301」，
  说明「回源强制 HTTPS」那条规则没生效。

## 五、监控与加固建议

- 把「境外可达性」接进每日巡检：抽 3–5 个境外节点请求 `/product`，
  任一轮里 ≥2 个节点非 200（522 / 525 / 超时）就告警 —— 这次就是被悄悄封了很久才发现。
- 已知偶发：个别节点 `525 Origin SSL Handshake Error`（源站 TLS 握手偶发失败，
  本轮实测约 1/10 节点）。加固方向：
  ① 源站证书换成通用 CA（当前是 Xcc Trust 的 `*.dlszjr.com` 通配符证书）并确保中间证书链完整；
  ② 回源超时时间从默认 30s 调大（规则 → 回源超时时间）。
- ESA 的配置属于「控制台状态」，不在 IaC 里；改完记得同步回这份文档。

## 六、备选预案：海外静态镜像（仅在境外再次不可达时启用）

下面这套东西来自第一次封禁时的方案，保留备用 —— 它比预热更彻底（连缓存过期都不用怕），
但要维护一台海外机器，所以**日常不要启用**。

### 架构

```
国内访客 ──> 云解析「默认」线路 ──> A 59.46.235.173（原源站，K8s）   ← 完全不变
境外访客 ──> 云解析「境外」线路 ──> A <海外机器 IP> ──> nginx 静态产物
```

启用时把 ESA 站点从境外解析里摘出去（`podcloud` 的境外线路 CNAME 改成海外机器的 A 记录）；
以后要恢复走 ESA，把那条记录改回去即可。

### 一次性装机（在海外机器上）

```bash
apt-get update && apt-get install -y nginx rsync certbot python3-certbot-nginx
mkdir -p /var/www/podcloud /var/www/certbot

# 证书：先确保 podcloud.dlszjr.com 已有一条指向本机的解析（默认线路也可），
# 才能过 HTTP-01 校验。
certbot --nginx -d podcloud.dlszjr.com --agree-tos -m iverson.wuwei@gmail.com --redirect
```

然后把 `nginx-podcloud.conf` 放到 `/etc/nginx/conf.d/podcloud.conf`：

```bash
rsync nginx-podcloud.conf root@<海外IP>:/etc/nginx/conf.d/podcloud.conf
ssh root@<海外IP> 'nginx -t && systemctl reload nginx'
```

### 每次发版

```bash
cd cloud/web/deploy/overseas
HOST=<海外机器IP> bash deploy-static.sh
```

脚本会构建、rsync、reload，最后打一遍状态码 —— 境外的可用性另外用外部服务确认
（`check-host.net`、`api.microlink.io`）。

### 已知边界

- **只服务公开页**：`/product`、`/pricing`、`/legal/*` 以及 SPA 外壳。
  `/api/*` 直接返回 503 —— 后端还在国内源站，代理过去等于把不稳定的国际链路又引回来。
  要用控制台的海外用户请走国内线路。
- 静态站是**只读镜像**：源站后续更新公开页内容，记得跑一次 `deploy-static.sh`。
