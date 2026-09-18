# Changelog

## 未发布 — 端 A ↔ 端 B 的契约层：协议版本 + 健康摘要

一期架构是两段式：**端 A**（本机安装的监控/执法程序）与 **端 B**（SaaS 或用户自部署的控制台）。
两端分开发布——端 A 按 tag 发、端 B 按镜像滚——所以"版本错配"不是异常，是常态。
这一版把这条契约补上：不改变任何安全流程，纯粹让两端知道彼此的状态。

### 1. 协议版本（两端可判定"能不能配合"）

每个上云请求带 `X-Pod-Protocol` 与 `X-Pod-Version`；心跳 body 也带协议版本。
服务端据此回 `client_outdated` + 说明，客户端打印提示**但继续同步**（可用性优先）。

此前没有版本时，错配的表现是**静默半失效**：老客户端不认 `/sync/quarantine`（只打一行警告）、
新字段没人读。有了版本，"少了一半能力"才会被说出来。

### 2. 健康摘要（把"在线"和"真的在保护"分开）

心跳新增一份**只含计数**的摘要：审计链条数 / 断裂数 / 最近一次工具调用时间、
server 总数与绕过网关的数量、最近一次漏洞扫描的 high/medium/low。

为什么必须由机器上报：**云端看不到本机文件**。而"部署了但没生效"恰恰是最常见的形态——
网关没起（没有调用记录）、链被改过（broken > 0）、还有 server 绕过网关（unmanaged > 0）。
控制台现在把这三件事与"在线"分开显示；没上报就写"未上报"，不用默认值冒充健康。

隐私边界不变：**只出计数、布尔与时间戳**，没有路径、主机名、配置原文，
也没有未纳管 server 的名字。

### 3. 契约写进一个文件

新增 [docs/local-cloud-contract.md](docs/local-cloud-contract.md)：两端职责边界、五条通道、
版本与健康字段、兼容矩阵（四种组合各自的行为）、出问题时看哪里。
两端的常量分别在 `apps/cli/src/protocol.ts` 与 `cloud/server/app/protocol.py`；
改契约要同时动这两处与本页。

测试：`apps/cli/test/sync-protocol.test.ts`（5 项，含"摘要里不出现本机路径"的隐私断言与
老服务端兼容）、`cloud/server/tests/test_sync_protocol.py`（3 项，含老客户端无 body 仍 200）。

## v0.4.0 — 多 agent 漏洞扫描 + 纳管/接管/切执法；审计交付物可被对方独立校验

这一版把"多 harness 的安全"从概念做成闭环：**扫描**（`pod guard`）→ **纳管/接管/切执法**
（`pod agents` + 本地控制台）→ **可交付的审计物**（`pod harden`，对方能用 `--verify` 独立校验）。
同时补上英文正文、`pod --version` 自查、以及按内容指纹打 tag 的服务器发布。

下面每一节都是这一版的一部分——它们原先散在"未发布"里，发版时归拢到版本号下。

### 构建一致性改按 commit 判断；发布脚本支持强制重发

上一版把镜像 tag 改成每镜像独立的内容指纹（`fp-<hash>`）之后，带出两个尾巴，这一版收掉。

### 1. "只滚了一半"的检测从 tag 改成 commit

旧口径靠"两个镜像共用一个 `main-<commit>` tag"来判断前后端是否同一次发布。tag 改成
每镜像独立的内容指纹后，server 与 web 天生不同，拿 tag 比只会变成**假告警**——
而假告警会让人开始忽略那一行，等于把检测废掉。

所以现在：

- 两个镜像都打进 `BUILD_COMMIT`（`--build-arg`，来自本次发布的 commit）；
- 后端 `/api/v1/auth/config` 返回 `build_commit`；
- 前端拿自己的 `BUILD_COMMIT` 与它对照，**不一致才标红**；
- 没有 commit 的旧镜像 / 本地 dev 退回旧的 tag 规则（只在 `main-<sha>` 形态下比对）。

一句话：tag 回答"是不是这份内容"，commit 回答"是不是同一次发布"。

### 2. `REPUBLISH=1`：强制重发一次

内容未变时脚本幂等空跑——这通常是想要的，但偶尔需要真的重发一次（验证发布路径、
替换可疑镜像、节点镜像被清理）。`REPUBLISH=1 bash install-server.sh` 会强制重建并滚动。

这里有个容易踩的坑，一并修掉了：同 tag 重建时镜像引用没变，`set image` 是空操作，
必须走 `rollout restart` 才会真正拉到新镜像。现在脚本按"镜像引用是否变化"自动二选一
（引用变了 → `set image`；没变 → `rollout restart`）。

### 服务器发布按内容指纹打 tag：只改 CLI / 文档不再重启线上

`install-server.sh` 的镜像 tag 原来是 `main-<commit>`，于是**只要 main 往前走一次**
就会换 tag → 重建镜像 → `set image` 滚动。而 server 是 `Recreate`（SQLite 不能被两个
Pod 同时写），每次都是几十秒 API 不可用——哪怕这次合并只动了 pod CLI、文档或 k8s 脚本。

现在 tag 只跟**真正进镜像的文件内容**走：

| | 之前 | 现在 |
|---|---|---|
| tag | `main-<commit>` | `fp-<内容指纹>`，且 **server 与 web 各自独立** |
| 只改 CLI / 文档 | 重建 + 重启 server 与 web | 幂等空跑，零重启 |
| 只改前端 | 重建 + 重启两个 | 只滚 web（server 不动，连库备份都跳过） |
| 只改后端 | 重建 + 重启两个 | 只滚 server（仍先备份库），web 不动 |
| "线上是哪个 commit" | 看 tag | 看 Deployment 注解 `podsec/build-commit` |

两个实现细节：

- **指纹用 git blob 列表算**（`git ls-tree -r --full-tree <rev> -- <镜像输入路径>`），
  在节点上直接对目标 commit 求值，不需要先 checkout；只有真正进镜像的路径参与
  （server：Dockerfile + requirements.txt + `app/` + `scripts/`；web：整个 `cloud/web`），
  所以改 `deploy/k8s` 下的脚本不会误触发。
- **切换本身不重启**：旧的 `main-<sha>` tag 会被识别为"同一个 sha 的内容指纹"并比对，
  内容一致就空跑——采纳这个改动当天不会多挨一次重启，等 `cloud/` 真变了再自然换 tag。

顺带修掉一个隐患：原来"tag 相同就空跑"不看镜像是否还在 containerd；镜像被清理过时
空跑会让集群起不来。现在内容一致还要加一条"镜像确实在 containerd 里"才敢跳过。

### 英文正文补全：海外读者拿到的是一份全英文的报告

上一版把框架文案翻了，但缺一块要命的：**报告正文**（威胁目录的标题/摘要/处置建议、
判定层生成的 finding 文案、策略草稿的判定依据）。英文模式下会中英混排——对一份要交给
海外客户/审计方的报告来说，"这是给谁看的"这个判断会被直接削弱。这一版补齐。

### 覆盖范围（英文模式下不再出现中文）

- **威胁目录 115 条**：18 条威胁的标题、现象描述、处置动作、处置理由、覆盖边界与已有防线；
- **判定层 31 条**：`detect.ts` 生成的全部 finding 文案（含计数与枚举的分隔符）；
- **默认规则的原因文案**：`hookRisk.riskPatterns[].why`——命中内置默认值时翻译，
  用户自己在 `rules.json` 里写的说明原样显示（`t()` 查不到词条即回显原文）；
- **策略草稿 12 条**：草稿标题、判定依据、策略 diff 的变更标签与汇总行；
- **报表排版**：括号（全角/半角）、枚举分隔符、`1 finding` / `2 findings` 的单复数。

验收方式是三条端到端断言，而不是人工看一眼：

- `apps/cli/test/guard.test.ts`：用**带问题的 home** 跑 `guard scan --lang en-US`，
  断言零 CJK（之前用的是空 home——不出 finding，断言是空转的）；
- `apps/cli/test/harden.test.ts`：`report.md` / `findings.json` / `harness-scan.md`
  三份交付物在英文模式下零 CJK；
- `packages/guard/src/catalog-i18n.test.ts`（新增）：目录与默认规则的**每条**文案
  都必须有英文词条。这是 CI 门禁，不是"记得就手动跑一下"的脚本。

### 一处工程机制

目录文案是**数据**，渲染时才按 `t(entry.title)` 查表，静态的 `t('…')` 抽取看不见调用点
（`scripts/i18n-coverage.sh` 会因此把它们算成僵尸键）。所以：

- 覆盖率脚本新增 `DATA_SOURCES` 例外：在 `catalog.ts` / `rules.ts` 里作为**完整字符串
  字面量**出现的词条不计入僵尸键；必须带引号匹配，否则 '代码执行' 这类短词会命中长句里的
  子串、把真缺口一起吞掉；
- "这些数据键有没有英文"改由 vitest 断言（能真的拿到目录对象，比在 shell 里猜字符串可靠）。

顺带：`localizeThreat()` 在**渲染时**求值而不是模块加载时——`--lang` 在 import 之后才生效，
模块级求值会把标题冻在默认语言上。

全量 `pnpm test` 572 项通过，typecheck 通过，i18n 覆盖 751/751（100%）。

### 扫描变成漏斗，审计交付物变成客户能自己验的东西

这一版改的是**交付形态**，不是判定能力：同样一份扫描结果，操作者要的是"我现在做什么"，
客户要的是"这份结论能不能被复核"。两者需要两份不同的输出。

### `pod guard`：清单 → 漏斗

- **§0 新增「先做这三件事」**：按"严重级别 → 能不能真的解决 → 影响面"排序，每条带
  一条可直接复制的 pod 命令和一条确认命令。排序把"只是复核一遍"的动作
  （如凭据搬家的 `pod scan`）排在改变状态的动作（纳管 / 冻结 / 接管）后面。
- **命令带 harness**：建议里给的是 `pod agents enroll --harness claude-code`，
  而不是目录里的 `pod agents enroll --harness <id>` 模板；harness 名先过 id 形态
  校验（`^[a-z0-9][._-]*$`），不合法就退回通用形态——建议是给用户照抄的，
  不能是一段看起来像指令的任意 shell。
- **交付入口**：同一节给出"本轮可根治 / 只能降险 / pod 看不到"的计数，
  以及把同一批事实变成可交付报告的命令（`pod harden --out …`）。
- `pod guard watch` 的变化通知也用上同一套映射：报"新增 AG-03"时直接给出该跑哪条命令。

### `pod harden`：报告目录 → 可交付审计物

- **接入 16 类 harness 扫描**：原来只跑 `pod scan` 的 6 类平台；现在交付物里包含
  `harness-scan.md` / `harness-findings.json`，client 复核不用重跑。
- **报告重构成可交付结构**：§0 执行摘要 / §1 范围与方法（含"没建基线时哪类判定不生效"）/
  §2 结论与待办（每条带可执行命令）/ §3 覆盖边界（**看不到什么**）/ §4–§8 子报告 /
  §9 如何验证 / §10 产物清单与交付声明。
- **交付元信息**：`--client` / `--auditor` / `--engagement` 写进封面、`findings.json`
  与 `manifest.json`，同一客户多次审计能对上工单号。
- **`pod harden --verify <目录>`**：收到报告的一方逐文件重算 sha256 比对 manifest，
  不需要重跑审计、也不需要信任出具方；被改动过的文件会被指出并按 `--strict` 语义退出 1。
- **跨层去重**：同一个钩子（posture + guard）、同一处明文凭据（scan + guard）
  在交付物里只出现一次，保留 guard 那条（带 AG 编号与处置命令）。只按"级别 + 归一化
  路径 + 威胁类别映射"合并，映射之外一律不合并——宁可多报一条，也不吞掉真问题。
- **计数口径修正**：交付物 §0 的 MCP server 数改用 harness 扫描（覆盖面更大）的结果，
  不再出现 §0 说 0 个、§5 说 2 个的自相矛盾。

测试：`packages/guard` 新增漏斗层 4 项（含 harness 名注入防护与排序），
`apps/cli/test/harden.test.ts` 新增 5 项（封面元信息、可交付结构、`--verify` 通过/失败/
非交付目录、跨层去重）。全量 `pnpm test` 565 项通过，i18n 覆盖 100%。

### 纳管/接管/切执法的事件改成"上得了云"的落点

一个用户最先发现的问题：**pocloud 上看不到本地做的事**。查下来是事件落点错了。

### 修复：控制平面事件写进被改动 agent 的链

纳管、接管、切执法、还原、移除纳管这五个动作，事件原来统一写机器级的
`~/.pod/audit/_control/control.jsonl`，而 `pod sync` 是按绑定里的 `local_agent`
过滤事件的（`e.agent === local_agent`）——于是这些事件**一条都没上云**。
线上实测：`pod_control_events = 0`（数据平面 58 条、同步记账 397 条），
云端「控制平面」页永远是空的，而本地界面还在说"已纳管"。

现在这些事件写进**被改动的那个 agent** 的链
（`audit/<agent>/control.jsonl`，`agent` 字段就是该 agent 名），沿用既有绑定即可上云。
判断口径写进了 [docs/control-plane-hardening.md](docs/control-plane-hardening.md)：
**某个 agent 被改了 → 写那个 agent 的链；与具体 agent 无关的机器级事实 → `_control`。**
真正的机器级事件（`pod posture` 的全局发现、LLM 调用留痕）仍留在 `_control`，
它们要上云需要一条 `local_agent: "_control"` 的绑定（文档 §5.3 第 4 条）。

### 顺带修掉两个被这次改动暴露出来的问题

- **语料计数把控制平面事件算进去了**：`pod agents enforce` 的前置检查说"当前审计语料
  N 条"，而 N 会把 identity / config-change 数进去。那些不是工具调用——数进去会让人
  以为"已经采到 N 条调用了"，拿一张空表去切执法。现在只数数据平面。
- **`changed.auditDir` 会误报 false**：事件写进 agent 链时会顺手 `mkdir`，
  于是"审计目录是不是我建的"这个判定发生在它之后，明明是我们建的却报 false。
  改成先判定并建目录，再写事件。

### 测试

- 新增 `apps/cli/test/control-plane-sync.test.ts`：证明纳管之后，
  `collectPendingEvents` 能把它捞出来（且只有该 agent 的绑定捞得到、游标不会重复推）。
  这是这条链路唯一的自动化保险——线上那个"0 条"正是没有它才悄悄发生的。
- 控制台三个测试文件的断言从 `_control` 改成 agent 链。

### 页面与 API 都能看出"这是哪次构建"

起因是一个很直接的问题：**"从页面上怎么看出哪些是新功能？"**——答案是看不出来：
两个控制台都没有构建标识，只能靠"找新元素"或翻运维命令判断版本。

### 后端：`/api/v1/auth/config` 新增 `build`

`deploy/Dockerfile` 的 `ARG BUILD_TAG` → `PODCLOUD_BUILD_TAG` → `app/config.py` →
接口返回。于是"新版本滚上去了没有"从"端点返回 401 还是 404（猜）"变成
**"curl 一下看 build 是否等于本次 tag"**（确定）。两个 install 脚本都会传这个参数。

### 云端控制台：侧栏显示「构建 <tag>」

同一个 tag 经 `VITE_BUILD_TAG` 打进前端产物；侧栏底部显示后端 tag，
并与前端自己的 tag 对照——**不一致就标红**并给出提示，因为那正是滚动发布
最容易漏掉的一种破法（新前端撞旧后端，见 docs/rolling-update.md §4.2）。

### 本地控制台：侧栏显示 `build <commit>[+] · <构建时间>`

commit 由 Vite 构建时注入；`+` 表示**构建时工作区有未提交改动**——
本地控制台就是从工作区构建的，只写 commit 会让人以为页面等于某个干净的版本
（悬停能看到完整时间与说明）。

### 部署脚本

`install-server.sh` 新增 `LOCAL_BUILD=1`：代码还没 push 时在本机构建、
`docker save | ssh ctr import` 送进节点（tag 仍指向真实 commit，只是尚未推送）。
默认仍是"从节点的 origin/<ref> 构建"，保证镜像对应已推送的 commit。
发布验证也换成了核对构建标识，而不是拿 401/404 猜。

### 服务器集群发布固化成脚本（`install-server.sh`）

### 新增：`cloud/server/deploy/k8s/install-server.sh`

上线的服务器集群（192.168.66.8 / ns `podcloud` / `podcloud.dlszjr.com`）此前**没有
发布脚本**：镜像是手工在节点上构建、手工 `ctr import`、手工 `set image` 的，
而且节点的源码 clone 停在 #11（静默落后 9 个提交）。这次把它固化成一条命令：

```bash
KUBECONFIG=~/.kube/config-server.yaml PUBLIC_URL=https://podcloud.dlszjr.com \
  bash cloud/server/deploy/k8s/install-server.sh
```

它做六件事：预检（连得上集群 / ssh 得通构建节点 / 节点有 docker+ctr+git）→
解析目标 commit 并打印"相对运行版本改了什么"→ 备份数据库 → 在节点上
`git checkout` 到目标 commit 并构建镜像 → 导入 containerd → **server 先滚完就绪
再滚 web** → 验证（集群内自证 + 公开地址）。

三条硬约束写进了脚本与文档，因为它们各自都踩过坑：

1. **docker 里的镜像 kubelet 看不见**，必须 `docker save | ctr -n k8s.io images import -`；
2. **备份必须用 sqlite 的在线备份 API**：库在 WAL 模式，`cp podcloud.db` 会丢掉
   `-wal` 里已提交的事务（线上实测主文件 380 KB / WAL 4 MB，旧文档教的正是 `cp`）；
3. **只 `set image`、不 apply 清单**：线上对象是手工调过的（nodeSelector→hadoop8、
   hostPath PV、NodePort 30088、server 用 `Recreate`），apply 会把调优冲掉。

幂等：已经在目标 tag 上就空跑退出。

### 新增：`server-cluster-snapshot.yaml`

线上清单的只读快照（去掉运行时字段，**不含 Secret**），从集群导出。
此前"服务器上到底跑的是什么"只存在于集群里，集群重建时无据可依。
已验证它 `kubectl apply --dry-run=server` 全部 `configured`（不是 create）。

### 修复：滚动更新手册的两处

- **备份命令是错的**：`cp /app/data/podcloud.db` 在 WAL 模式下得到的是过期快照。
  改为 sqlite 在线备份，并说明为什么。
- **只写了 kind 一条路**：手册标题是"面向已上线的部署"，但只教了
  `install-local.sh`（本机 kind）。现在两条路并列，附一张区别表（tag 形式、
  构建位置、镜像怎么进集群、清单来源、server 发布策略）。

### 本次发布（服务器集群）

`main-4ba4f91` → **`main-fbf730b`**（web `main-5007bd8` → `main-fbf730b`）。
`cloud/server` 自 4ba4f91 起零差异，`cloud/web` 只多了 `deploy/overseas/*`
（不进运行时镜像）——也就是说这次滚动**对齐的是 tag 与可追溯性**，不是新代码。
发布后验证：集群内 web→server 反代正常，公开地址 `/` `/pricing` `/product` 200、
`/api/v1/rules/pack` 与 `/api/v1/harden/reports` 401（401 = 端点在，404 = 旧版本）。

### 第三步：切执法（让网关真的拦）

接管只是让调用**经过**网关；这一步让网关**真的判**。

### 新增：控制台「切执法 / 回到只录不拦」+ `pod agents enforce`

卡片上在已接管之后出现第三个动作：

- **切执法**：去掉包装命令里的 `--record-only`，并让它使用你编译好的策略；
- **回到只录不拦**：把 `--record-only` 加回来（策略不变，只是不再阻断）——执法打断
  正常干活时的快速退路。

这一步最危险的失败不是"改坏了"（有备份），而是**"看起来生效了、其实没有保护"**，
所以前置检查是硬性的，不满足直接拒绝执行：

| 检查 | 不满足时 |
|---|---|
| 有一份**绑定该 agent 且含 server 规则**的策略 | 拒绝，并给出要跑的命令与当前语料量 |
| 那份策略不是 `allow:["*"]` | 拒绝——record 模板拿去执法只会制造"已保护"的错觉 |
| server 确实处于只录不拦 | 拒绝，并说明先用「接管」 |

确认框里显示：**用哪份策略执法**（路径 + server/工具/allow·approve·deny 计数 +
编译时的语料量）、改前 → 改后、备份路径，以及切完会发生什么（命中 `approve` 的调用
挂起等审批；没跑 `pod watch` 就等到超时被拒——fail-closed）。

### 改进了「多份策略」这件常态

纳管写一份零权限策略、编译后又多一份 draft，于是"一个 agent 两份策略"成了常态。
卡片现在直接显示**当前实际生效的策略文件**（从包装命令的 `--policy` 读出来），
不用用户去猜哪一份在管自己。

### 「还原配置」变成逐步撤销

接管台账记了 `history`：接管 → 切执法 → 回到只录不拦 之后连点两次「还原配置」，
会先退到只录不拦、再退回到接管之前。历史空了才结束这次接管。

### 事实层

`@podsec/guard` 的 `ServerFact` 新增 `recordOnly`：进网关与真的在拦是两件事，
只看 `behindGateway` 会把"只录不拦"显示成"已保护"——那是这个产品最不该犯的错。

### 测试

- `@podsec/console`：`enforce.test.ts` 9 例（四种前置拒绝、计划只读、切执法、
  回到只录不拦、重复切换被拒、逐步撤销）；`server.test.ts` 补 3 例。
- `pod agents` 补 4 例（无策略拒绝、dry-run、切执法、退回）。合计新增 16 例。

### 第二步：接管（把 MCP server 包进网关）

纳管只把资产纳入管理；MCP server 仍然是直连的，策略与审计对它无效。这一版补上第二步：

### 新增：控制台「接管（包进网关）」+ `pod agents onboard | revert`

卡片上新增「接管（包进网关）」按钮（只在还有直连 server 时出现）。它调的就是
`pod onboard`：把每个 server 的启动命令改写成 `pod serve --record-only … --command <原命令>`。

因为它**会改写用户的配置文件**，比纳管危险，所以流程是"先看计划、再确认"——
确认框里逐条列出改前/改后命令、备份路径、包装策略，并写清三件事：

- **只录不拦**（`--record-only`）：接管当天不打断工作流；采几天语料 →
  `pod policy draft` 编译最小权限策略 → 复核后去掉 `--record-only` 才切执法。
- **可回滚**：改写前备份成 `<配置>.pod-backup-<时间戳>`，卡片上的「还原配置」
  从最近的备份恢复（`pod agents revert --agent <name>`）。
- **跳过与不支持项照实说**：Codex 的 TOML 暂不支持自动改写，直接标出来而不是假装成功。

三条工程决定：

1. **只碰用户级配置**：仓库里的项目级配置（`.mcp.json` / `.cursor/mcp.json` 等）
   属于工作区，不在这个按钮的授权范围内——那正是 AG-04 那条威胁的面。
2. **`pod` 不在 PATH 上就拒绝执行**：包装后的命令跑不起来会让该 harness 的
   MCP server 全部失效；这种"帮倒忙"比不接管糟得多，所以这里 fail-closed。
3. **沿用已有策略，不新建 allow-all 模板**：`pod onboard` 默认写的包装策略是
   `allow:['*']`；如果纳管时已经有一份**零权限**策略，覆盖它等于把 fail-closed
   悄悄换成 fail-open。现在接管指向那份已有策略且不覆盖——去掉 `--record-only`
   时的结果是"全部拒绝"而不是"全部放行"。

控制台与 CLI 走同一条写路径（`@podsec/console` 的 `planTakeover` / `applyTakeover` /
`revertTakeover`），纳管与接管都记进哈希链（`console:takeover:<agent>` /
`console:revert:<agent>`）。

### 重构

- 接管实现（发现 + 改写 + 回滚）从 `apps/cli/src/onboard.ts` 移到新包 `@podsec/onboard`：
  控制台按钮与 `pod onboard` 必须共用一份实现，否则"网页改的"和"CLI 改的"会漂移。
  CLI 侧继续 re-export，既有 import 路径与测试不变。
- `OnboardApplyOptions` 新增 `policyPathFor` 与 `keepExistingPolicy`（默认行为不变），
  供控制台实现"沿用已有零权限策略"。

### 修复

- 接管台账 `~/.pod/console/takeover.json` 的父目录没建就写，会出现"配置已改、
  台账没记上"的半截状态（`pod agents revert` 只能靠兜底路径猜）。现在先建目录再写。

### 测试

- `@podsec/console`：`takeover.test.ts` 8 例（计划只读、pod 不在 PATH 拒绝、
  TOML 标注不支持、跳过已包装、备份+还原、不覆盖已有零权限策略、不碰其它 harness）；
  `server.test.ts` 补 3 例（计划接口只读、接管+还原端到端、只读模式下 403）。
- `pod agents` 补 4 例（dry-run 不改配置、`--yes` 接管、revert 还原、缺 pod 时拒绝）。

### 一键纳管：扫描本机 agent，逐个加入监控

### 新增：控制台「扫描本机 agent」+「加入监控」（`pod agents`）

控制台顶栏加了**扫描本机 agent**按钮：点一次列出这台机器上装了什么 harness，
每个 harness 一张卡——安装证据、MCP server 数、其中几个绕过网关、`pod guard`
的漏洞计数。卡上**加入监控**即纳管；已纳管的卡显示 agent 名与来源，并给出**移除监控**。

纳管的语义（也是确认框里写给用户看的话）：

- **写**：`~/.pod/identity/<agent>/`（ed25519 身份，私钥 0600）、
  `~/.pod/policies/<agent>.json`（**零权限起点**：未登记 server 一律拒绝；已有策略不动）、
  `~/.pod/audit/<agent>/`、控制平面哈希链事件（`kind=identity` / `config-change`）。
- **不写**：任何 harness 的配置。改写配置是 `pod onboard --yes` 的事（它有备份与 `--revert`），
  一个网页按钮不该偷偷改用户的 `mcp.json`。
- **不拦流量**：纳管只是把资产纳入管理；真正拦工具调用还要 `pod onboard` 把 server 包进网关。
  这句提示同时出现在卡片、确认框与纳管成功的反馈里。

其余细节：

- **同一条写路径**：控制台按钮与 `pod agents enroll` 都调 `@podsec/console` 的
  `enrollAgent()`，不存在"网页能做而 CLI 不能做"的操作。
- **四道闸门**（T8）：包默认只读（`pod ui` 显式打开）、token 鉴权、
  `Content-Type: application/json`、Origin 与 Host 同源。`pod ui --read-only` 关掉整个写通道。
- **可撤销**：`forget` 只删**纳管时创建的**那份策略（台账 `~/.pod/console/enrolled.json` 记着），
  身份默认保留（删了就无法再证明历史上的调用是它做的），要连私钥一起删用 `--purge-identity`。
- **幂等**：重复纳管不覆盖已有策略、不重复记事件。
- 控制台不再自称"只读"：顶栏状态 pill 读服务端的真实能力（可纳管 / 只读）。

### 重构

- `appendControlEvent` / `CONTROL_CHAIN` 从 `apps/cli/src/control-plane.ts` 移到
  `@podsec/audit`：CLI 与控制台都要写控制平面事件，各写一份的后果是链格式漂移，
  而链格式漂移会让 `pod verify-audit` 与云端同步以最难排查的方式坏掉。
  CLI 侧继续 re-export，既有 import 路径不变。

### 测试

- `@podsec/console`：`enroll.test.ts`（10 例：幂等、不覆盖用户策略、只删自己写的东西、
  身份默认保留、非法名字不留半截产物）+ `server.test.ts`（12 例：四道闸门、
  端到端纳管/移除、返回新鲜 payload）。
- `pod agents`：`apps/cli/test/agents.test.ts`（10 例，真跑子进程）。

### 多 agent / 多 harness 持续加固（`pod guard`）

### 新增：`pod guard`

把"一次性扫描"补成"持续 + 可执行建议"。命令形态：

```bash
pod guard scan                 # 漏洞清单 + 建议清单（只读）
pod guard scan --strict        # 有 high 时退出码 1，可挂 CI / 定时任务
pod guard baseline             # 冻结 server / 钩子指纹
pod guard watch --interval 300 # 常驻，只对新增/变化/消失说话，并写哈希链
pod guard remediate --llm      # 模型产出加固建议物（不自动生效）
pod guard catalog              # 威胁目录与出处
```

- **新包 `@podsec/guard`**：16 类 harness 注册表 + 5 种配置格式解析（含 Codex 的 TOML 子集）、
  项目级配置扫描（`.mcp.json` / `.cursor/mcp.json` / `.vscode/mcp.json` …）、
  18 条威胁目录（`AG-01…AG-18`，每条带可核查的外部出处与 covered/partial/gap 覆盖声明）、
  17 个确定性检测器、建议清单渲染、基线与实时 diff。
- **新增威胁**：项目级配置自动执行（T15）、跳过审批的启动参数（T16）、
  远程 MCP 端点未鉴权（T17）。
- **规则归用户**：新增 `rules.guard` 段（危险参数、私密数据/外发能力提示词、
  插件目录、额外配置路径、允许的远程主机、基线路径）。数组整体替换，写 `[]` 即关闭该类判定。
- **模型只有建议权**：`remediate --llm` 的出网面只有"威胁编号 + 级别 + harness + 处数"，
  不含路径、主机名与配置原文；产出的规则增量必须过**放宽守卫**（`diffRules` + `detectRelaxations`，
  与 `pod rules apply` 同一套判定），编造的 threat 与非 `pod` 命令一律丢弃并说明原因。

### 修复

- **`pod posture` 不再因坏 agent 名崩掉**：`~/.pod/policies` 里一个名字含空格的策略文件，
  会让只读报表命令抛栈退出。现在记成 `identity:<agent>:invalid-name` 的 high finding，
  并提示改名——报表要的是可执行提示，不是堆栈。
- **stdio 网关的 PPID 看门狗在容器里不再失效**：原来的判定是 `process.ppid === 1`，
  但被收养时的新父进程不一定是 pid 1（容器里常见 subreaper，实测会收养到别的 pid），
  于是看门狗永不触发、孤儿网关照旧滞留——正是它本来要防的泄漏。
  现在比对"PPID 与启动时是否相同"。同一个用例从 23s 超时变为 5.7s 通过。

### 文档

- 新增 [docs/agent-harness-security.md](docs/agent-harness-security.md)：
  多 agent / 多 harness 安全的现状盘点、威胁目录（含 HackerOne / Bugcrowd / CVE / 厂商出处）、
  差距分析与 `pod guard` 的设计边界。
- `docs/threat-model.md` 补 T15–T17 与 AG 目录的映射说明。

## v0.3.2 — 登录页排版修复

### 控制台（cloud/web）

- **修掉登录页的排版回归**：`LoginView.vue` 的 `<style scoped>` 在 i18n 批量改动（3eff333）里被提前闭合，
  `.login-logo` 的规则掉到了样式块外、从未生效——于是 logo 按 SVG 原始尺寸 256px 渲染且左对齐，
  把登录卡撑到 739px 高（720px 视口下出现竖向滚动条）。现在这些规则回到样式块内。
- **品牌头居中**：logo（原始尺寸的 60%，154px）、标题、副标题统一沿卡片中轴居中；表单字段保持左对齐。
  卡片总高 637px，一屏放得下。

### 已知边界

控制台状态刷新仍是 5 秒轮询（没有 WebSocket），agent 列表一次性返回，规模大时应接分页。

## v0.3.1 — 控制台修复 + 发布流程硬化

这一版修掉一个"照着文档做也做不成"的控制台 bug，并把发布流程本身关进闸门。

### 控制台（cloud/web）

- **「添加 Agent」弹窗补回创建按钮**：表单阶段底部两个按钮（`取消` / `我知道了`）此前都只做关窗，
  唯一能提交的路径是输入框里回车——界面上不写、按钮上也没有，用户点按钮就以为"添加失败"
  （实测服务端只收到列表轮询，没有收到任何创建请求）。现在 footer 是 `取消` + `创建`，
  创建按钮带 loading 状态。
- **修掉回车重复建单**：回车会同时触发 `el-form` 的 submit 与输入框的 `@keyup.enter`，
  一次操作建出两个同名 agent（实测两个 agent 相隔 16ms 创建）。现在只保留表单 submit
  一条提交路径，并加重入保护兜底。

### 仓库 / 发布

- `main` 分支保护落地：只走 PR、CI 四项（`test` / `local-smoke` / `cloud-server` /
  `cloud-web`）必绿、禁止强推与删除，**对管理员同样生效**（`enforce_admins`）。
- 新增 `CONTRIBUTING.md` 与 PR 模板；`docs/PUBLISHING.md` 写明维护者直推前也要留痕
  （先开 issue 说明，事后立刻恢复保护）。
- 发布预检新增**双远端镜像一致性**检查（Gitee 是 GitHub 的只读镜像，漂移即报错），
  并把四篇内容稿的安装命令 re-pin 到当前版本。

### 已知边界

控制台状态刷新仍是 5 秒轮询（没有 WebSocket），agent 列表一次性返回，规模大时应接分页。

## v0.3.0 — 大模型安全服务 + 中英双语

这一版把"大模型"从一句口号做成了**有闸门的功能**，整个产品（CLI / 控制台 / 云端）都能中英切换。

### 本地（agent 机器上）

- **自动化红队 `pod redteam`**：攻击场景由模型**当数据**提出（`--llm`，可选），判定走与网关**同一条纯函数流水线**（`decideCall`）——所以"挡住没有"可复现、可进 CI（高危绕过退出码 1）。出网的只有**权限面**（server/tool 名 + 三态位置），用 `--export-surface` 显式导出。
- **模型调用只有一处出网**（`apps/cli/src/llm.ts`）：provider/model/base_url 统一解析，配置不静默回落；每次调用（含失败）写一条 `kind='llm-call'` 进本地哈希链——只记 provider/model/字符数/端点，**不记 prompt 正文**。
- **加固审计交付物 `pod harden`**：一条命令跑完暴露面扫描 + 控制平面姿态 + 最小权限草稿 + 证据自检，产出一份可直接交给客户的报告目录（含逐文件 sha256）。全程本地，零上报。
- **订阅式规则包 `pod rules`**：pack / verify / apply / pull 四个动作，Ed25519 签名；**放宽已有规则的包默认拒绝应用**（`--allow-relax` 才放行）。
- **中英切换**：`pod --lang en-US`，或一次 `POD_LANG=en-US`（也读 `LC_ALL`/`LANG`）。覆盖 CLI 全部输出与报告；未翻译的串原样显示中文，不会出现 key 名或空白。

### 云端（可选控制平面）

- **规则包分发**：控制台发布/撤回签名规则包，机器侧 `pod rules pull` 拉取；公钥不与包同路（`rules_public_key`），放宽守卫在机器侧兜底。
- **熔断下发**：控制台熔断/解除，机器下次 `pod sync` 生效；人工在机器上加的熔断不会被云端误解除。
- **加固报告归档**：`pod harden --upload` 只上传 `report.md` 与 `findings.json`（已脱敏），原始审计链 `evidence.json` 永不出机器。
- **模型配置**：provider 清单（DeepSeek / OpenAI / OpenAI 兼容 / 离线 mock）、连通性测试、AI 生成策略、告警摘要、AI 日报；出网面写着改（见下）。结构化 payload（能力清单、provider 说明）随 `Accept-Language` 切换。
- **中英切换**：登录页与用户菜单里的开关，选择记在浏览器本地；Element Plus 内置文案一并切换。

### 安全

- **告警出网收口**：送进模型的告警只留白名单字段；`message` 里的**文件路径打码成 `<path>`**（保留目录结构、去掉用户名/项目名），**命中密钥模式整条不出网**，剔除条数如实告知模型。密钥规则与服务端策略模板的 `deny_output_matching` 共用同一份（`app/security.py::SECRET_PATTERNS`），顺带补齐了 `sk-proj-…` / `gho_` / `glpat-` 三个漏网格式。
- **结构化 payload 的翻译出口**：异常 `detail` 有统一翻译出口，结构化返回值没有——设置页的能力清单与"为什么不可用"因此漏翻过，现已收口并有测试兜住。

### 仓库 / 发布

- **发布预检 30 项**（`scripts/preflight-publish.sh`）：含干净环境安装 + 主路径冒烟、钉版本安装链接可达、赞助入口一致性。
- **i18n 两把尺子**：`scripts/i18n-coverage.sh` 管"词表齐不齐"（CLI/Web 差集 + 僵尸键 + 实体键陷阱）；`scripts/web-acceptance.sh` 管"界面上到底长什么样"（真机无头 Chrome 逐页断言"渲染出内容 + 无非数据中文"）。
- **GitHub Sponsors**：`.github/FUNDING.yml` + README 入口；预检会校验两处账号一致。

### 已知边界

模型**不参与判定、不执行动作**：它只能产出数据（场景、策略草稿、摘要），改状态的入口都有它过不去的闸门（签名 + 放宽守卫 + 纯函数判定器）。注入检测目前是分级词表 + 工具描述摘除，模型分类器未做。其余边界见 [docs/threat-model.md](docs/threat-model.md) 与 [docs/llm-security-services.md](docs/llm-security-services.md)。

## v0.2.0 — 首个完整开源版本

本地与云端第一次在同一个仓库里发布：装一条命令拿到本地 CLI/网关，再一条命令起云端控制平面。

### 本地（agent 机器上）

- **策略编译闭环**：`pod record` 只录不拦 → `pod policy draft` 从真实调用编译最小权限策略 → `--diff` 输出收紧/放宽清单 → `pod serve` 执法（deny > approve > allow，fail-closed）→ `pod verify-audit` / `export-evidence` 留证。
- **控制平面加固**（G1–G16）：生命周期钩子审计、配置冻结与漂移、记忆完整性、MCP 包来源固定、工具元数据验证、每 agent 独立密码学身份、签名委托链与能力收窄、JIT 令牌、熔断、信任传播异常、污染溯源。
- **判定规则归用户**：所有阈值、正则、严重级别、可信来源都在 `~/.pod/rules.json`（`--rules` 可覆盖）；规则写错 fail-closed 报错，不静默退回默认值。
- **审计链可靠性**：跨进程文件锁（`pod ingest`、控制平面事件、网关写入）根治并发分叉；`rules.auditHealth` 把"链断裂"和"静默停摆"变成可见告警。
- **能力图与毒性路径**：`pod graph build/toxic/explain/apply/observe/diff/baseline`，跨 agent 的 source→sink 组合风险。
- **本地控制台**：`pod ui`（只读，token 保护）。

### 云端（可选控制平面）

- **审计同步**：数据平面（工具调用）与控制平面（钩子/配置/身份/委托/熔断）两套事件流，分别入表、分别展示；敏感内容只传 SHA-256 哈希。
- **一键接入**：控制台注册 agent 后给一条 `curl ... | bash`，自动写 `~/.pod/cloud.json`、清理失效绑定、验证同步。
- **控制平面页**、时间线、策略中心、告警（含 webhook/邮件）、总览仪表盘（活跃度双口径：近 7 天 + 累计）、合规报告。
- **部署**：`deploy/install.sh` 一条命令（Docker Compose），必填配置只有一项（JWT 密钥，脚本自动生成）。

### 仓库

- 原 `podcloud-server` / `podcloud-web` 两个仓库已并入 `cloud/` 下并归档，历史链接会看到指向本仓库的告示。
- 清掉 FinHarness 遗留（3 个零引用模型、7 张死表迁移、配置回退、品牌与 CSS 令牌前缀），全仓库无 `finharness` 字样。
- CI 四份门禁：本地测试、本地闭环冒烟、云端 pytest、前端构建。

### 已知边界

不做沙箱隔离、不实现 A2A/mTLS/SPIFFE 协议本体、不把行为漂移当主防线；详见 [docs/threat-model.md](docs/threat-model.md) 的"明确不防御"。

## v0.1.0 — 早期快照

2026-09-03 的开放快照（仅本地 CLI/网关的早期形态），已由 v0.2.0 取代。
