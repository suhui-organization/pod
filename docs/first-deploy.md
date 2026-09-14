# 首次部署操作顺序（web + 本地工具）

> 场景：第一次把 SecurityHarness 部署到服务器（k8s / Docker），并让用户机器上的
> agent 受 web 控制台监控与防护。云端本身的部署细节见 [deploy-cloud.md](deploy-cloud.md)，
> 本文只讲**顺序**与**每步的验收点**。

---

## 0. 先理解两条方向

```
机器 → web（上行，机器主动推）：审计事件 / 控制平面事件 / 加固报告
web → 机器（下行，机器主动拉）：策略 / 规则包 / 熔断
```

**关键前提**：下行通道是"机器主动拉"的（机器在 NAT 后面，服务端推不到它）。
所以每台机器上必须有一个**周期任务在跑 `pod sync`**——没有它，你在控制台上点的
「熔断」永远到不了那台机器。

好消息：**接入脚本会自动装好这个定时任务**（launchd / systemd --user / cron），
不需要手工配置。第 4 步会验证它确实装上了。

---

## 1. 起 SaaS（服务器上，一次性）

```bash
git clone --branch v0.3.1 --depth 1 https://gitee.com/suhuisoftwares/pod.git && cd pod
ADMIN_EMAIL=you@example.com ADMIN_PASSWORD='强密码' bash deploy/install.sh
```

**验收**：浏览器打开 `http://<主机>:<端口>` 能登录。

k8s 部署见 [deploy-cloud.md](deploy-cloud.md) 的 Kubernetes 一节。三个要点：

- `PODCLOUD_JWT_SECRET` 一旦部署不要再改（改了所有人被登出）；
- 数据库持久化卷要挂上（`podcloud.db` 或外部 Postgres）；
- 反向代理要带 `X-Forwarded-Proto` / `X-Forwarded-Host`——接入脚本里的 API 地址
  是靠它们拼的，少了会让机器用错地址连不上。

---

## 2. 第一次登录，建第一个 agent

控制台 →「Agent 资产」→「+ 添加 Agent」→ 填一个名字（例如 `mac-mini`，代表一台机器）。

**验收**：页面上出现这张卡片，状态是「未接入」。

---

## 3. 确认新通道的页面都在

左侧导航应能看到这些页面：

| 页面 | 用途 | 没看到说明 |
|------|------|-----------|
| 规则包 | 下发加固规则（订阅式） | web 没构建到最新版，重新 `npm run build` |
| 加固报告 | 看 `pod harden` 的交付物 | 同上 |
| 策略中心 / 控制平面 | 已有 | — |

---

## 4. 在用户机器上接入（每台机器一次）

点该 agent 卡片上的「接入命令」，复制它给出的那条 `curl ... | bash`，在**目标机器**上执行。

脚本会做四件事（幂等，可重复执行）：

1. 写 `~/.pod/cloud.json`（并清掉已失效的旧绑定）；
2. 没装就装 `pod` CLI；
3. 跑一次 `pod sync` 推历史审计；
4. **安装定时同步**（`~/.pod/sync-job.sh` + launchd/systemd/cron）。

**验收三条都要看**：

```bash
cat ~/.pod/cloud.json            # ① 绑定写好了
launchctl list | grep podsec.sync   # ② macOS：定时任务在
# Linux: systemctl --user list-timers | grep pod-sync
# 兜底:  crontab -l | grep pod-sync
```

③ 回控制台，这台机器应变成「在线」。脚本最后一行会明确打印装了什么：

```
⏱  已安装定时同步：launchd（每 300s）——控制台上的熔断/规则包由此才能下发到这台机器。
```

### 可调的两项

```bash
# 改同步间隔（默认 300 秒）：重跑接入命令并带上变量
curl -fsSL "<接入命令地址>" | POD_SYNC_INTERVAL=60 bash

# 不装定时任务（例如你自己用 k8s CronJob 统一管理）
curl -fsSL "<接入命令地址>" | POD_NO_SCHEDULE=1 bash
```

间隔就是**熔断的生效延迟上限**。默认 5 分钟是"够用且不吵"的折中；要更快就调小，
代价是更频繁的出网与日志。

---

## 5. 验收三条闭环（部署完一定要跑）

### ① 上行：审计真的上来了

机器上正常用一会儿 agent（网关要跑着），然后 `pod sync`。
控制台「时间线」应出现记录。**没有记录**通常是绑定名与本地 agent 名不一致
（接入脚本会提示本机实际有哪些名字，用 `LOCAL_AGENT=<名字>` 重跑）。

### ② 下行：熔断能到机器

控制台「Agent 资产」→ 该 agent →「熔断」→ 填原因 → 确认。等一个同步周期后：

```bash
cat ~/.pod/quarantine.json    # 应出现该 agent，by=cloud
pod quarantine list
```

网关会立刻拒绝该 agent 的全部调用（热路径检查，不用重启）。再点「解除熔断」，
等一个周期后应消失。

注意语义：云端只能解除**自己下的**熔断。你在机器上手工 `pod quarantine add` 过的那条
不会被云端解除——这是刻意的（否则拿到 token 的人就能解除人工处置）。

### ③ 交付物：加固报告能上来

```bash
pod harden --upload
```

控制台「加固报告」出现记录，点开能看到正文。命令会打印传了什么：

```
已上传到云端（报告 #1）：report.md + findings.json
  未上传：evidence.json（原始审计链）——它在本地目录里，需要时你自己决定要不要给。
```

---

## 6. 日常运维

| 事项 | 怎么做 |
|------|--------|
| 同步日志 | `~/.pod/sync.log`（超过 1MB 自动只留最后 200 行） |
| 停用定时同步 | 删 `~/.pod/sync-job.sh` + 对应的 launchd plist / systemd unit / cron 行 |
| 改同步间隔 | 带 `POD_SYNC_INTERVAL=<秒>` 重跑接入命令（会覆盖旧的） |
| token 泄漏 / 换机器 | 控制台 → 该 agent →「重新生成接入命令」，再重跑接入命令 |
| 机器长期离线 | 不影响本地防护；上行按链的游标续传；熔断等它上线才生效 |

---

## 7. 常见坑

- **控制台点了熔断、机器没反应**：先查定时任务在不在（第 4 步验收 ②）。
  这是这条通道唯一的依赖。
- **agent 显示在线但审计永远是 0**：绑定名与本地 agent 名不一致，或本地网关没跑过。
- **反代后接入脚本里的地址不对**：反向代理没传 `X-Forwarded-Proto` / `X-Forwarded-Host`。
- **`pod sync` 报 409 哈希链断裂**：本地那条审计链自己就不连续（历史上并发写坏过）。
  归档出问题的那条链后重跑；脚本会给出具体命令。
