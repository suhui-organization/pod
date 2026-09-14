# Changelog

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
