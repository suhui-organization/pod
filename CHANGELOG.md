# Changelog

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
