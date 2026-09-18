# Changelog

## 未发布 — 页面与 API 都能看出"这是哪次构建"

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

## 未发布 — 服务器集群发布固化成脚本（`install-server.sh`）

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

## 未发布 — 第三步：切执法（让网关真的拦）

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

## 未发布 — 第二步：接管（把 MCP server 包进网关）

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

## 未发布 — 一键纳管：扫描本机 agent，逐个加入监控

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

## 未发布 — 多 agent / 多 harness 持续加固（`pod guard`）

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
