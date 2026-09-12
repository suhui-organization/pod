# pod — least-privilege compiler for AI agents

[![CI](https://github.com/suhui-organization/pod/actions/workflows/ci.yml/badge.svg)](https://github.com/suhui-organization/pod/actions/workflows/ci.yml)

> Your agent ran for a week. pod compiles what it actually did into the smallest policy it needs.
>
> 让 AI Agent 只拥有它真正需要的权限——从真实行为编译最小权限策略。

**Record → compile → enforce → prove.**

Most agent security tools stop at one of two places: a scanner that tells you what your agent *could* touch, or a gateway that asks you to *hand-write* a policy. pod closes the loop — run your agent in record-only mode for a few days, compile a least-privilege policy from its real tool calls, enforce it, and keep tamper-evident evidence for everything that ran.

```text
record real calls ──▶ compile least-privilege policy ──▶ enforce (deny > approve > allow)
       │                        │                                  │
       │                        │                                  ▼
       │                        │                    ┌──────────────────────────┐
       └── SHA-256 hash chain ───┴───────────────────▶│ tamper-evident audit     │
          (every call, hashes only)                  │ verify / export evidence │
                                                     └──────────────────────────┘
```

## 中文速览

- **不是又一个 MCP 网关**：网关让你手写策略；pod 从 agent 的真实行为里**编译**出最小权限策略。
- **闭环**：`pod record`（只录不拦）→ `pod policy draft`（生成策略 + 与基线 diff）→ 人工复核 → `pod serve`（执法）。
- **证据**：每一次工具调用进入 SHA-256 哈希链，可校验、可导出为证据包（敏感内容只存哈希）。
- **本地优先**：策略、审计、密钥不出你的机器；Pod Cloud 是可选控制平面。

## See it in 5 minutes

No agent, no account, no data leaves your machine — everything runs in a temp directory:

```bash
git clone https://gitee.com/suhuisoftwares/pod.git && cd pod
pnpm install && pnpm build
bash scripts/demo-least-privilege.sh
```

It seeds a realistic week of tool calls (reads, writes, a delete, and one `.env` access), then compiles a policy from that corpus and diffs it against a permissive baseline:

```text
## 策略 diff（baseline → draft）

| server     | tool                 | baseline | draft      | 变化     |
|------------|----------------------|----------|------------|----------|
| *          | *                    | allow    | deny       | 默认决策 |
| filesystem | read_file            | allow    | deny       | 收紧     |
| filesystem | write_file           | allow    | approve    | 收紧     |
| filesystem | delete_file          | allow    | deny       | 收紧     |
| github     | create_pull_request  | allow    | approve    | 收紧     |
| shell      | execute_command      | allow    | approve    | 收紧     |
| filesystem | get_file_info        | allow    | (unlisted) | 移除     |

**汇总**：收紧 8 · 新增 0 · 移除 1 · 放宽 0
```

Two details matter here: `read_file` is locked down because it touched `.env` **once** (observation beats guessing), and `get_file_info` is removed because it never appeared in the corpus (least privilege = don't grant what you didn't observe).

## Install

```bash
# macOS / Linux — builds from source, no npm account needed
curl -fsSL https://gitee.com/suhuisoftwares/pod/raw/main/scripts/install.sh | sh
pod --help
```

The installer clones to `~/.pod/src`, builds, and puts `pod` in `~/.local/bin`. Override with `POD_SRC`, `POD_BIN_DIR`, `POD_REPO_URL`, `POD_VERSION`.

Requires **Node.js ≥ 22.13** (pnpm 11's runtime floor) and git.

## What's in this repo

一个仓库包含完整闭环：本地在 agent 机器上执法，云端（可选）做跨机器视图。

| 路径 | 是什么 | 怎么装 |
|---|---|---|
| `packages/` | 核心库：策略求值、审计哈希链、网关、能力图、控制平面姿态、身份/委托/JIT、扫描器 | `pnpm install && pnpm build` |
| `apps/cli` | `pod` 命令行（网关 + 策略编译 + 证据 + 控制平面命令） | `bash scripts/install.sh` |
| `apps/web` | 本地控制台（`pod ui`，只读） | 随 CLI 构建 |
| `cloud/server` | 可选云端控制平面后端（FastAPI）：agent 注册、审计同步、策略中心、告警、时间线、控制平面事件 | `bash deploy/install.sh` |
| `cloud/web` | 云端控制台前端（Vue 3 + Element Plus） | 同上（随 docker 构建） |
| `deploy/` | 一键部署：`install.sh` + `docker-compose.yml` + `.env.example`（含每个配置项说明） | `bash deploy/install.sh` |
| `cloud/server/deploy/k8s/` | Kubernetes 清单（参考，适合本机 kind/Docker-Desktop 集群） | `bash cloud/server/deploy/k8s/install-local.sh` |

能力与价值速览见 [docs/FEATURES.md](docs/FEATURES.md)。

From source:

```bash
git clone https://gitee.com/suhuisoftwares/pod.git && cd pod
pnpm install && pnpm build
node apps/cli/dist/index.js --help
```

> `npm i -g @podsec/cli` is **not live yet** — use the installer above until the package is published.

## From zero to enforcement

```bash
pod scan                              # 1. see what is exposed (read-only)
pod onboard                           # 2. preview the takeover plan (dry-run)
pod onboard --yes                     #    wrap agents in record-only mode (backups kept)
# ... use your agents normally for a day or two ...
pod policy draft --diff <baseline>    # 3. compile least-privilege policy + show the diff
pod lint --policy ~/.pod/policies/draft.json
pod serve --agent <name> --server <name> --policy ~/.pod/policies/draft.json \
  --command <cmd> --arg <value>       # 4. switch to enforcement
pod watch                             # 5. approve high-risk calls from a second terminal
pod verify-audit                      #    tamper check over the whole chain
pod export-evidence                   #    verifiable evidence bundle
```

## What pod is / is not

| pod is | pod is not |
| --- | --- |
| A **policy compiler**: turns real tool-call corpora into least-privilege rules | A sandbox or a container runtime |
| A **policy enforcement point** on the MCP boundary (fail-closed) | A replacement for your agent's own sandbox |
| A **tamper-evident audit + evidence layer** across agents | An LLM content-moderation firewall |
| **Local-first**: policies, audits and secrets stay on your machine | A cloud service that needs your logs |

Compared with the rest of the market: platform-native sandboxes (Claude Code, Codex, Gemini CLI) protect **one agent**; MCP gateways (agentgateway, ToolHive, ContextForge, Docker) give you a **place to enforce hand-written rules**; scanners (Snyk Agent Scan, mcp-guard) tell you **what is exposed**. pod is the missing step between "what is exposed" and "what is allowed": it **writes the policy for you from observed behavior**, then proves what happened.

## Core capabilities

- **`pod policy draft`** — compile a least-privilege policy from recorded calls. Read-only tools → `allow`, write/exec → `approve`, destructive → `deny`; any observed sensitive-path or secret hit forces `deny`. `--diff <baseline.json>` prints exactly what got tightened, added, removed or loosened.
- **Policy gate** — evaluated `deny > secrets-input > approve > allow`, fail-closed by default; unlisted servers/tools are denied.
- **Approval gate** — high-risk calls suspend and wait for a human; timeout fails closed; approvals are recorded with approver + reason.
- **Tamper-evident audit** — append-only SHA-256 hash chain; `pod verify-audit` detects any historical edit; sensitive content is stored as hashes only.
- **Evidence bundles** — `pod export-evidence` / `pod verify-evidence` produce and verify a portable evidence bundle plus a one-page report.
- **Secret gates** — sensitive input paths (`.env`, `.ssh`, `.aws`, …), known-format output regexes, and high-entropy fallback detection for unknown secret formats.
- **Rollback points** — `pod serve --snapshot` captures write operations; `pod rollback` restores files.
- **Coverage + drift** — `pod coverage --strict` exits non-zero when an MCP server is bypassing the gateway.
- **Supply-chain gate (T4)** — the gateway validates the declared server source (`command` / `package` / `version`) before startup.
- **Control-plane posture (`pod posture`)** — same rules, applied to the control plane: lifecycle hooks, frozen config, memory files, MCP package sources, agent identities, delegation chains. Drift is reported against a `pod posture freeze` baseline; `--strict` exits 1.
- **User-owned rules** — every verdict comes from `~/.pod/rules.json` (or `--rules <file>`): risk patterns, severities, thresholds, trusted sources, egress lists. Code ships defaults; you own the decisions. Invalid rules fail closed.
- **Agent identities + delegation narrowing (`pod identity` / `pod delegate`)** — ed25519 keypair per agent; delegations are signed hop-by-hop and must narrow capabilities; `--ttl` bounds every hop.
- **JIT grants (`pod grant`)** — signed, time-boxed, scope-limited tokens; a valid grant satisfies an `approve` decision without a human in the loop, and single-use grants are consumed atomically.
- **Circuit breaker (`pod quarantine`)** — quarantine an agent and the gateway denies its calls on the next invocation (no restart), with the decision written to the audit chain.
- **Trust-propagation anomalies + pollution tracing (`pod anomaly` / `pod trace`)** — thresholds from `rules.anomaly`; trace walks the delegation chain and the audit chain to find where a poisoned agent came from and who it could reach.

## Policy example

```json
{
  "version": "0.1.0",
  "agent": "openclaw",
  "defaultDecision": "deny",
  "servers": {
    "filesystem": {
      "allow":   ["read_file", "list_directory", "search_files"],
      "approve": ["write_file", "edit_file"],
      "deny":    ["delete_file"]
    }
  },
  "secrets": {
    "deny_input_paths": ["~/.ssh", ".env", "credentials", "id_rsa", ".aws", "known_hosts"],
    "deny_output_matching": ["ghp_[A-Za-z0-9]{36}", "sk-[A-Za-z0-9]{20,}", "AKIA[0-9A-Z]{16}"],
    "entropy": { "enabled": true, "min_length": 24, "threshold": 4.5, "block": true }
  }
}
```

## CLI

```text
pod init            scaffold policy templates (baseline / record)
pod onboard         discover local MCP servers and wrap them behind pod (dry-run by default)
pod serve           run the gateway (stdio / Streamable HTTP)
pod record          record-only mode: log every call without blocking (corpus collection)
pod policy draft    compile a least-privilege policy from real calls (+ --diff baseline)
pod approve|deny|pending   side-channel approvals
pod watch           resident approval queue
pod snapshots       list write-operation snapshots (rollback points)
pod rollback        restore files from a snapshot (serve --snapshot enables capture)
pod timeline        audit timeline filtered by agent / tool / time
pod verify-audit    verify the full hash chain, emit a report
pod digest          local weekly security digest (no network)
pod coverage        managed vs. unmanaged MCP servers; --strict exits 1 on drift
pod export-evidence / verify-evidence   export & verify evidence bundles
pod lint | doctor   policy lint / environment health
pod scan            free local security scan (config & bypass checks)
pod posture [freeze]   control-plane posture: hooks / frozen config / memory / packages / identities / delegations
pod identity           per-agent ed25519 identity: init | list | verify
pod delegate           signed delegation: issue | verify | check (capability narrowing)
pod grant              JIT capability tokens: issue | list (signed, TTL, scope, single-use)
pod quarantine         circuit breaker: list | add | remove (enforced by the gateway)
pod anomaly            convention-burst / capability-spread signals over the rules window
pod trace <agent>      pollution tracing: delegation chain + related audit entries
pod graph build     static capability graph from agent configs + tool schemas
pod graph toxic     source→sink toxic paths + targeted policy diff
pod graph explain   trace a path back to evidence
pod sync / pull-policy   optional Pod Cloud sync & policy distribution
```

## Supported agents

| Agent | Transport | Status |
| --- | --- | --- |
| Hermes | Streamable HTTP | ✅ verified end-to-end |
| OpenClaw | stdio wrapper | ✅ verified end-to-end |
| Codex | stdio wrapper + PostToolUse hook | ✅ ready (see docs) |
| DSH / Claude Code / Cursor | MCP | pluggable via MCP |

## Documentation

- [能做什么、给你带来什么](docs/FEATURES.md) ← 先看这个
- [部署 Pod Cloud（云端控制平面）](docs/deploy-cloud.md) ← 部署与"你需要提供什么"
- [Positioning & wedge](docs/positioning.md)
- [Threat model](docs/threat-model.md)
- [Egress defense](docs/egress-defense.md)
- [Control-plane hardening (requirements + design)](docs/control-plane-hardening.md)
- [Agent onboarding](docs/agent-onboarding.md)
- [Automation (launchd/systemd/cron)](docs/automation.md)

## Pod Cloud (optional, in this repo)

本地部分开箱可用，**云端是可选的**：没有它，`pod` 照样编译策略、执法、留证据。
需要跨机器/跨 agent 的统一视图、策略下发、告警与合规报告时，一条命令起一个：

```bash
bash deploy/install.sh            # 单机 Docker Compose（首次 2-5 分钟）
# 或带管理员：ADMIN_EMAIL=you@x.com ADMIN_PASSWORD='...' bash deploy/install.sh
```

数据方向是单向的：本地只推 SHA-256 哈希上云，审计原文不出你的机器；云端不参与本地执法（云端挂了 agent 不受影响）。
必填配置只有一项（JWT 密钥，脚本自动生成），其余见 [docs/deploy-cloud.md](docs/deploy-cloud.md)。

## License

Apache-2.0 — see [LICENSE](LICENSE). Security notes: [SECURITY.md](SECURITY.md).
