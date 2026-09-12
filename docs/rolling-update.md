# 滚动更新手册（Pod Cloud）

> 面向已上线的部署：怎么把新版本滚上去、滚的时候用户会遇到什么、出事怎么退。
> 首次部署见 [first-deploy.md](first-deploy.md)。

---

## 1. 先判断这次发布能不能滚动

三个问题，按顺序问：

| 问题 | 本次（577e335）的答案 |
|------|----------------------|
| DB 变更是追加式还是破坏式？ | 追加式：新增 2 张表 + `pod_agents` 4 个列，没改类型、没删列 |
| 新前端依赖新后端吗？ | 依赖：新页面调 `/api/v1/rules/*`、`/api/v1/harden/*` |
| 老客户端配新服务端会坏吗？ | 不会：老客户端不调新端点，新字段它忽略 |

结论：可以滚动更新，但有顺序要求（先 server 后 web）。

### 为什么"追加式"就等于能滚动

- `create_all` 建新表：老 Pod 的模型里没有这些表，不受影响；
- `ADD COLUMN` 带默认值：老 Pod 的 SELECT 不引用新列，两种数据库都允许并发读写；
- 回滚同样安全：新列留在表里，回退后的老代码直接忽略它们。

反过来，如果哪天要**改列类型 / 删列 / 加 NOT NULL 无默认值**，就不能滚动更新了——
必须先停旧版本再迁移。这条判断要在动模型之前做。

---

## 2. 操作顺序

### ① 备份数据库

```bash
kubectl -n podcloud exec deploy/podcloud-server -- \
  cp /app/data/podcloud.db /app/data/podcloud.db.bak-$(date +%F)
```

### ② 拉新代码并滚动更新

```bash
git pull
bash cloud/server/deploy/k8s/install-local.sh
```

脚本幂等：按源码指纹判断要不要重建镜像；重建时先滚 server 并等就绪，再滚 web。

### ③ 验收四条

```bash
kubectl -n podcloud rollout status deploy/podcloud-server --timeout=120s
kubectl -n podcloud rollout status deploy/podcloud-web    --timeout=120s
curl -s -o /dev/null -w "rules/pack: %{http_code}\n"     http://127.0.0.1:18088/api/v1/rules/pack
curl -s -o /dev/null -w "harden/reports: %{http_code}\n" http://127.0.0.1:18088/api/v1/harden/reports
```

前两条应就绪；后两条**401 = 端点在了、只是没鉴权**（正确），
**404 = 还在跑旧版本**（镜像没滚上去）。再确认控制台左侧出现「规则包」「加固报告」。

### ④ 存量机器：补装定时同步（这次必须做）

本次之前接入的机器没有定时同步，而熔断与规则包下发依赖机器主动拉。
不补这一条，控制台上的「熔断」对老机器完全无效。

做法：控制台 →「Agent 资产」→ 该 agent →「接入命令」，在对应机器上**重跑同一条命令**。
脚本幂等，只会补上缺的部分；token 没轮换过的话 URL 都不用换。

```bash
launchctl list | grep podsec.sync                  # macOS
systemctl --user list-timers | grep pod-sync       # Linux
```

机器很多时：用 `POD_NO_SCHEDULE=1` 让接入脚本不装，改用你已有的配置管理
（Ansible / k8s CronJob）统一跑 `pod sync`。定时任务本身只是"周期执行 pod sync"。

---

## 3. 回滚

```bash
kubectl -n podcloud rollout undo deploy/podcloud-web
kubectl -n podcloud rollout undo deploy/podcloud-server
```

**顺序反过来：先退 web 再退 server**——退 web 后前端调的都是老端点，老服务端一定有。

DB 不用回滚：本次迁移是追加式的，老代码忽略新列新表。
真要回滚 DB 就用第 ① 步的备份，那是最后手段。

---

## 4. 本次一并修掉的两个滚动更新风险

### 4.1 并发迁移会让新 Pod 启动即崩

`migrate()` 原来是"查列存在性 → 不存在就 ALTER"。滚动更新时新 Pod 在旧 Pod 还活着时
就起来，两个进程可能同时判定"列不存在"、各自 ALTER，**后到的那个报 duplicate column
而崩溃**。又因为 `maxUnavailable: 0`，旧 Pod 不会先撤——结果是滚动更新**卡死**。

修法：ALTER 失败后重新查一次，列已存在就认定是并发同伴建的、跳过；不存在才抛。
见 `cloud/server/app/migrations.py` 与 `tests/test_migrations.py`。

### 4.2 两个 Deployment 同时重启 → 新前端撞旧后端

脚本原来把 server 与 web 放在一条 `rollout restart` 里，于是出现"新前端 + 旧后端"的窗口：
用户刷新到新页面，新页面调新端点，得到 404。

修法：先滚 server 并等就绪，再滚 web。见 `cloud/server/deploy/k8s/install-local.sh`。

---

## 5. 客户端（机器侧）的兼容性

服务端先上是安全的，因为老客户端不调用新端点。反方向也不炸：

| 场景 | 行为 |
|------|------|
| 老客户端 → 新服务端 | 不调 `/rules/*`、`/harden/*`，熔断拉取也不调；一切照旧 |
| 新客户端 → 老服务端 | `/sync/quarantine` 返回 404 → 只打警告、不算同步失败、保持本地现状 |
| 新客户端 → 新服务端 | 完整能力 |

所以升级可以分批：先把云端滚上去，机器按自己的节奏升级。
