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

### ① 备份数据库（**别用 cp**）

库跑在 WAL 模式，`cp podcloud.db` 只拷主文件、丢掉 `-wal` 里已提交的事务，
得到的是一份**过期**的快照（线上实测：主文件 380 KB，而 WAL 有 4 MB）。
要么用 sqlite 的在线备份，要么把三个文件一起拷：

```bash
kubectl -n podcloud exec deploy/podcloud-server -- python3 -c "
import sqlite3
src = sqlite3.connect('/app/data/podcloud.db')
dst = sqlite3.connect('/app/data/podcloud.db.bak-$(date +%F)')
src.backup(dst); dst.close(); src.close()
"
```

`install-server.sh` / `install-local.sh` 的服务器路径已经内置这一步。

### ② 拉新代码并滚动更新

两个目标各有一条命令（**别互相套用**，见下表的区别）：

```bash
# 服务器集群（192.168.66.8 / ns podcloud）：在节点就地构建 → 导入 containerd → set image
KUBECONFIG=~/.kube/config-server.yaml PUBLIC_URL=https://podcloud.dlszjr.com \
  bash cloud/server/deploy/k8s/install-server.sh

# 本机 kind：内容指纹 tag → kind load → apply 仓库清单
bash cloud/server/deploy/k8s/install-local.sh
```

| | 服务器集群 | 本机 kind |
|---|---|---|
| 脚本 | `install-server.sh` | `install-local.sh` |
| 镜像 tag | `fp-<内容指纹>`（server / web 各自独立；commit 记在 Deployment 注解 `podsec/build-commit`） | `fp-<内容指纹>` |
| 构建在哪 | **节点上**（集群没有公网镜像仓） | 本机 |
| 怎么让 k8s 看到镜像 | `docker save \| ctr -n k8s.io images import -`（docker 里的镜像 kubelet 看不见） | `kind load docker-image` |
| 清单来源 | 线上对象（手工调过，见 [server-cluster-snapshot.yaml](../cloud/server/deploy/k8s/server-cluster-snapshot.yaml)）；脚本只 `set image`，**不 apply** | 仓库模板渲染后 apply |
| server 发布策略 | `Recreate`（SQLite 不能被两个 Pod 同时写）→ **几十秒 API 不可用** | RollingUpdate |

**为什么 tag 不跟 commit 走。** server 重启是 `Recreate`，一次就是几十秒 API 不可用。
按 commit 打 tag 的话，"只改了 pod CLI / 文档"的合并也会换 tag → 白重启一次。
所以 tag 只跟**真正进镜像的文件内容**走：`cloud/server`（Dockerfile + requirements +
`app/` + `scripts/`）与 `cloud/web` 各自算指纹，谁的指纹变了才滚谁。

因此：

- 只改 CLI / 文档 / `deploy/k8s` 下脚本的合并 → **不重建、不重启**（脚本幂等空跑）；
- 只改前端 → 只滚 web，server 不动，连数据库备份都跳过（server 没重启）；
- 只改后端 → 只滚 server（仍先备份库），web 不动；
- 从旧的 `main-<commit>` 切换过来时，脚本会算出那个 commit 的内容指纹并比对——
  内容一致就空跑，**切换本身不触发重启**，等 `cloud/` 真变了再自然换 tag。

要查线上跑的到底是哪个 commit：

```bash
kubectl -n podcloud get deploy podcloud-server \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"  "}{.metadata.annotations.podsec/build-commit}{"\n"}'
# podcloud-server:fp-77edcdf5a8a4  5adea8ac469ca8aa1b0d701b29ae04dcc8e38be
```

两条脚本都是幂等的：已经在目标 tag 上就空跑退出。

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

**更确定的做法：直接看构建标识。** 后端把镜像 tag 写进了 `/api/v1/auth/config`：

```bash
curl -s https://podcloud.dlszjr.com/api/v1/auth/config | python3 -c 'import json,sys;print(json.load(sys.stdin)["build"])'
# 输出应当等于本次发布的 tag，例如 fp-77edcdf5a8a4（server 的内容指纹）
```

401/404 只能说明"端点新旧"，构建标识能说明**"这个实例就是那次构建"**。
控制台侧栏也显示同一行。

**"只滚了一半"按 commit 判断，不按 tag。** 两个镜像的 tag 是各自的内容指纹
（`fp-<hash>`，server 与 web 天生不同），拿 tag 比必然不等、只会变成假告警。
所以 `/api/v1/auth/config` 另外返回 `build_commit`，前端拿自己的 `BUILD_COMMIT`
与它对照，不一致才标红（新前端撞旧后端 → 新页面 404，见 §4.2）：

```bash
curl -s https://podcloud.dlszjr.com/api/v1/auth/config | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["build"], d["build_commit"])'
# fp-77edcdf5a8a4 672289fe0f02be181faa9be588a73a35139de100
```

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

---

## 6. 排障

### 6.1 症状 → 处置

先看一眼**发布脚本自己的判定行**，大多数问题在这一行就有答案：

```bash
KUBECONFIG=~/.kube/config-server.yaml DRY_RUN=1 bash cloud/server/deploy/k8s/install-server.sh
# 镜像 tag : server=fp-… web=fp-…（按 cloud/ 内容指纹）
# 当前运行 : server=podcloud-server:fp-… web=podcloud-web:fp-…
# 判定     : server=内容未变（跳过）  web=内容已变（发布）
```

| 症状 | 原因 | 处置 |
|------|------|------|
| Pod 重启了，但镜像 tag 没变 | 同 tag 重建时镜像引用没变，`set image` 是空操作；kubelet 按 tag 命中旧层缓存 | 用 `REPUBLISH=1 bash install-server.sh`——脚本按"镜像引用是否变化"自动二选一（变了走 `set image`，没变走 `rollout restart`） |
| 只改了 pod CLI / 文档，server 却重启了 | 旧版本 tag 跟 commit 走（`main-<sha>`），main 一动就换 tag | 现在的 tag 是每镜像独立的内容指纹。看到 `判定: 内容未变（跳过）` 就说明它没动线上；若真重启了，先确认跑的是不是最新的脚本 |
| 侧栏标红"与后端不是同一次构建" | 真的只滚了一半（新前端撞旧后端，见 §4.2） | 按 §4.2 顺序补滚：先 server 后 web。界面现在按 **commit** 比（`/auth/config` 的 `build_commit`）——tag 是每镜像指纹，天生不同、不可比 |
| `/auth/config` 的 `build` 还是旧 tag | 镜像没滚上去，或只滚了一半 | 见 6.2 的三条命令 |
| 镜像不在 containerd | `docker` 与 `kubelet` 看的是两套镜像存储 | 脚本会检测到并重建导入；手工等价：`docker save <img>` → `ssh root@<node> ctr -n k8s.io images import -` |
| `rollout undo` 之后界面仍标红 | 只退了一个 Deployment | 退的顺序是**先 web 再 server**（§3）；两边都退了才会一致 |

### 6.2 三条命令回答"线上是什么"

```bash
# 1) 两个 Deployment 的镜像 + 它们是哪个 commit 构建的
kubectl -n podcloud get deploy podcloud-server \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"  "}{.metadata.annotations.podsec/build-commit}{"\n"}'
kubectl -n podcloud get deploy podcloud-web \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"  "}{.metadata.annotations.podsec/build-commit}{"\n"}'

# 2) 后端实例自报的 tag 与 commit（前端侧栏显示的是同一组值）
curl -s https://podcloud.dlszjr.com/api/v1/auth/config \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["build"], d["build_commit"])'

# 3) 该 tag 的镜像在不在 kubelet 看得见的那套存储里
ssh root@192.168.66.8 "ctr -n k8s.io images ls | grep podcloud-"
```

**tag 与 commit 的分工**：tag（`fp-<内容指纹>`）回答"是不是这份内容"，commit 回答
"是不是同一次发布"。两个 tag 永远不同（server / web 各自算），所以判断"只滚了一半"
只能按 commit——拿 tag 比只会得到假告警。

### 6.3 一次完整的发布路径记录（2026-09-18，真机）

```text
── 1/6 解析目标版本（main）
[ok]   目标 commit: 9158d49
     镜像 tag : server=fp-211aacdb942a web=fp-ad8601b4a2b5（按 cloud/ 内容指纹）
     当前运行 : server=podcloud-server:fp-77edcdf5a8a4 web=podcloud-web:fp-b6d910a16e64
     判定     : server=内容已变（发布）  web=内容已变（发布）
── 2/6 备份数据库      → /app/data/podcloud.db.bak-2026-09-18（sqlite 在线备份，含 WAL）
── 3/6 构建镜像        → podcloud-server:fp-211aacdb942a / podcloud-web:fp-ad8601b4a2b5（在节点上）
── 4/6 导入 containerd → 两个镜像都进了 k8s.io 那套存储（kubelet 可见）
── 5/6 滚动发布        → 先 server 滚完并就绪，再滚 web（顺序是硬约束，见 §4.2）
── 6/6 验证            → 集群内自证 web→server 反代正常；后端 build=fp-211aacdb942a；
                        公开地址 200（rules=401 harden=401）
```

发布后核对：

```text
podcloud-server  fp-211aacdb942a  commit=9158d49…   READY
podcloud-web     fp-ad8601b4a2b5  commit=9158d49…   READY
/auth/config     build=fp-211aacdb942a  build_commit=9158d498c8d2eeb6780a359edc3f057fe6cf1205
前端产物         内含同一个 commit → 与后端一致，不误报
```

**这次踩到的坑（写在这里，别再踩）**：`REPUBLISH=1` 的第一版实现无条件走
`rollout restart`，而当时 Deployment 的镜像引用还是旧的 `main-5adea8a`——重启只是把
**同一个旧 tag 又拉了一遍**：白挨几十秒停机，镜像没换。

正确的判断是"**镜像引用变没变**"：

| 情况 | 该用哪条命令 | 为什么 |
|------|--------------|--------|
| 引用变了（含旧 `main-<sha>` → `fp-<hash>`） | `kubectl set image` | 改的是 Pod 模板 → 自然触发滚动 |
| 引用没变（同 tag 重建，`REPUBLISH=1`） | `kubectl rollout restart` | `set image` 是空操作；必须显式重启才会拉新内容 |

脚本现在两个分支都在，`DRY_RUN=1` 也能提前看出会走哪条。
