# 海外静态镜像站（境外线路专用）

## 为什么有这个东西

`podcloud.dlszjr.com` 的源站在国内一条电信城域网线路上。**国内访问完全正常**
（实测 ~0.11s），但**境外到源站的链路时好时坏**：

| 测试 | 结果 |
| --- | --- |
| 境外直连源站 IP（HTTP） | 有时成功、有时超时 |
| 境外走 ESA 边缘 → 回源 | 有的节点成功，有的返回 `522 Origin Connection Time-out` |

CDN 只能缓存「已经成功回源过的内容」，救不了回源本身不稳定。所以境外线路
**不再回源**：由这台海外机器直接提供静态产物。

顺带解决另一个隐患：原来是「ESA 回源到源站」，这一段若是明文 HTTP 就是降级；
现在境外这一段是**端到端 HTTPS**。

## 试过的零成本做法：ESA「缓存预热」——免费版不支持

思路是对的：预热由阿里云自己回源（走国内链路，实测完全正常），把内容推到各
边缘节点后，境外访客首次访问即命中缓存，不用碰那条抖动的国际链路。

**但 ESA 免费版（entranceplan）的预热额度是 0**：控制台「缓存 → 预热缓存」页面
直接写着「每日额度上限 0 条，当前剩余额度 0 条」。所以这条路要么升级套餐，
要么换别的托管。

如果以后升到带额度的套餐，预热这组 URL 即可：

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

（对应 API：`PreloadCaches` 预热、`PurgeCaches` 刷新 —— 改版发布后要重新预热一次。
若 HTML 没被判为可缓存，还需先在「规则 → 缓存规则」里给这些路径显式开缓存。）

**备选：海外静态镜像（本目录剩下的内容）** —— 只有当你有一台国际可达的机器时
才用得上；它比预热更彻底（连缓存过期都不用怕），但要维护一台服务器。

## 架构

```
国内访客 ──> 云解析「默认」线路 ──> A 59.46.235.173（原源站，K8s）   ← 完全不变
境外访客 ──> 云解析「境外」线路 ──> A <海外机器 IP> ──> nginx 静态产物
```

ESA 站点保留但**不参与境外解析**（`podcloud` 的境外线路从 ESA 的 CNAME 改成
海外机器的 A 记录）。以后要恢复走 ESA，把那条记录改回去即可。

## 一次性装机（在海外机器上）

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

## 每次发版

```bash
cd cloud/web/deploy/overseas
HOST=<海外机器IP> bash deploy-static.sh
```

脚本会构建、rsync、reload，最后对本机（国内）打一遍状态码 —— 境外的可用性
另外用外部服务确认（`api.microlink.io`、`api.hackertarget.com/httpheaders`）。

## 已知边界

- **只服务公开页**：`/product`、`/pricing`、`/legal/*` 以及 SPA 外壳。
  `/api/*` 直接返回 503 —— 后端还在国内源站，代理过去等于把不稳定的国际
  链路又引回来。要用控制台的海外用户请走国内线路。
- 静态站是**只读镜像**：源站后续更新公开页内容，记得跑一次 `deploy-static.sh`。
