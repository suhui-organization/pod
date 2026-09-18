# pod — least-privilege compiler for AI agents

[![CI](https://github.com/suhui-organization/pod/actions/workflows/ci.yml/badge.svg)](https://github.com/suhui-organization/pod/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/Sponsor-GitHub%20Sponsors-ea4aaa?logo=github)](https://github.com/sponsors/suhui-organization)

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
# 链接钉在发布版上（可复现）：想跟主干就把 v0.3.2 换成 main
curl -fsSL https://gitee.com/suhuisoftwares/pod/raw/v0.3.2/scripts/install.sh | sh
# 主源连不上时用 GitHub 镜像（同一个脚本）：
# curl -fsSL https://raw.githubusercontent.com/suhui-organization/pod/v0.3.2/scripts/install.sh | sh
pod --help
```

The installer clones `v0.3.2` to `~/.pod/src`, builds, and puts `pod` in `~/.local/bin`. Override with `POD_SRC`, `POD_BIN_DIR`, `POD_REPO_URL`, `POD_VERSION`（`POD_VERSION=main` 跟主干）。

**中文 / English**：CLI 输出支持中英切换——`pod --lang en-US <cmd>`，或设一次
`POD_LANG=en-US`（也会读 `LC_ALL` / `LANG`）。默认中文；未翻译的句子原样显示，
不会出现空白或 key 名。`pod guard` 与 `pod harden` 的报表、威胁目录与交付物
**整篇有英文**（含 finding 正文与策略草稿的判定依据），由 CI 断言守门。
覆盖进度自查：`bash scripts/i18n-coverage.sh`
（列出还没英文词条的串和词表里的僵尸键，`--strict` 有缺口时退出 1）；控制台另有
真机逐页验收 `bash scripts/web-acceptance.sh`（指到 k8s 后端、无头 Chrome 点一遍，
断言"每页都渲染了内容且没有非数据中文"）。

### Run the MCP gateway as a container

同一个网关也能以自包含镜像运行：镜像里已经构建好 CLI、预装了上游 filesystem server，
默认用 `baseline` 策略（只读工具放行，写操作进审批），从 stdio 暴露 MCP。

```bash
docker build -f deploy/Dockerfile.mcp -t pod-mcp .
docker run -i --rm pod-mcp        # 接到任意 MCP 客户端即可（stdio）
```

要换成别的上游 server 或策略，覆盖 entrypoint 参数即可；默认等价于
`pod serve --agent glama --server filesystem --command mcp-server-filesystem --arg /workspace`。
（公开目录收录时要求的检查也是这两步：进程能启动、能响应 `initialize` / `tools/list`。）

Requires **Node.js ≥ 22.13** (pnpm 11's runtime floor) and git.

## What's in this repo

一个仓库包含完整闭环：本地在 agent 机器上执法，云端（可选）做跨机器视图。

| 路径 | 是什么 | 怎么装 |
|---|---|---|
| `packages/` | 核心库：策略求值、审计哈希链、网关、能力图、控制平面姿态、身份/委托/JIT、扫描器 | `pnpm install && pnpm build` |
| `apps/cli` | `pod` 命令行（网关 + 策略编译 + 证据 + 控制平面命令） | `bash scripts/install.sh` |
| `apps/web` | 本地控制台（`pod ui`：读为主，写操作只有纳管/移除） | 随 CLI 构建 |
| `cloud/server` | 可选云端控制平面后端（FastAPI）：agent 注册、审计同步、策略中心、告警、时间线、控制平面事件 | `bash deploy/install.sh` |
| `cloud/web` | 云端控制台前端（Vue 3 + Element Plus） | 同上（随 docker 构建） |
| `deploy/` | 一键部署：`install.sh` + `docker-compose.yml` + `.env.example`（含每个配置项说明） | `bash deploy/install.sh` |
| `cloud/server/deploy/k8s/` | Kubernetes 清单（参考，适合本机 kind/Docker-Desktop 集群） | `bash cloud/server/deploy/k8s/install-local.sh` |

能力与价值速览见 [docs/FEATURES.md](docs/FEATURES.md)。

From source:

```bash
git clone --branch v0.3.2 --depth 1 https://gitee.com/suhuisoftwares/pod.git && cd pod
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
- **Hardening audit deliverable (`pod harden`)** — one command runs multi-harness scan + exposure scan + control-plane posture + least-privilege compilation + evidence export and writes a client-ready report directory: executive summary, scope and method, prioritized to-dos with runnable commands, an honest coverage-boundary section, and a per-file sha256 manifest. `--client` / `--auditor` / `--engagement` stamp the cover; `pod harden --verify <dir>` lets the **recipient** re-check every artifact by hash without trusting the sender. Local only, never uploaded; secrets appear as masks, never prefixes.
- **Continuous agent/harness guard (`pod guard`)** — scans 16 harnesses (Claude Code, Codex, Cursor, DSH, OpenClaw, OpenCode, Gemini CLI, Windsurf, Zed, VS Code, Cline, Kilo, Amazon Q, Copilot CLI, Amp, Continue), 5 config formats (incl. Codex TOML) plus project-level `.mcp.json` / `.cursor/mcp.json` / `.vscode/mcp.json`, and reports against an 18-entry threat catalog (`AG-01…AG-18`, each with cited sources and an honest coverage verdict). Output opens with **the three things to do first** — each a copy-paste `pod` command **bound to the harness it affects** (`pod agents enroll --harness claude-code`) plus the command that confirms it worked — then the vulnerability list and a prioritized recommendation list, and finally a hand-off to the deliverable (`pod harden`). `pod guard baseline` + `pod guard watch` make it continuous: it only speaks on new/changed/gone findings and writes those to the hash chain. `pod guard remediate --llm` has a model draft proposals from an outbound allowlist that carries **no paths, no hostnames and no config text**; rule deltas must pass the same relaxation guard as `pod rules apply`, and any non-`pod` command is stripped.
- **Enrollment from the console (`pod agents` / the "Enroll" button)** — one click scans the host for installed harnesses and lists them as cards with their evidence, MCP-server count, how many of those bypass the gateway, and their `pod guard` finding counts. Enrolling an agent creates an ed25519 identity, a **zero-permission policy** (unregistered servers denied) and an audit directory, then appends `kind=identity` / `config-change` events to **that agent's** hash chain — so `pod sync` carries them to the cloud's control-plane view (machine-wide facts stay on the local `_control` chain). It **never rewrites harness configuration** — that stays with `pod onboard --yes` (which backs up and can revert). Enrolling is idempotent, removable (`forget`, identity kept by default), and `pod ui --read-only` turns the whole write path off. The console's POST endpoints require the token, `Content-Type: application/json` and a same-origin `Origin`.
- **Takeover (`pod agents onboard` / the "Take over" button)** — step two: rewrites each MCP server's command to `pod serve --record-only … --command <original>` so calls actually cross the gateway. Because it edits your files, the console shows the **before/after command per server**, the backup path and the "records but does not block" caveat *before* you confirm. It only touches user-level configs (never repo-level `.mcp.json`), refuses to run when `pod` is not on PATH (a broken wrapper would take every MCP server down), and reuses your existing zero-permission policy instead of writing an `allow:['*']` template — so dropping `--record-only` later fails closed rather than open. `pod agents revert --agent <name>` restores from the most recent `.pod-backup-*`.
- **Enforcement switch (`pod agents enforce` / the "Enforce" button)** — step three: drops `--record-only` and points the wrapper at your compiled policy, so the gateway actually decides. The failure mode here is not "broke the config" but **"looks enforced while protecting nothing"**, so it hard-refuses unless a policy exists that is bound to the agent, has server rules, and is not `allow:["*"]` — and the dialog shows which policy is in force, its allow/approve/deny counts and how much corpus it was compiled from. Switching back to record-only, or "restore config" (which undoes one step at a time), are both one click.
- **Subscribed rules (`pod rules`)** — rules ship as signed Ed25519 packs (`pack` / `verify` / `apply` / `pull`). Network sources must be verified. A pack that would *loosen* any of your existing rules is refused unless you pass `--allow-relax`, so an "update" can never silently weaken your posture.
- **Policy red team (`pod redteam`)** — attack scenarios are drilled against your policy through the *same* pure pipeline the gateway uses (`decideCall`), so "blocked" means blocked in production too, and the results are reproducible in CI. A model can *propose* scenarios (`--llm`), but only as data: it never gets a verdict, never gets execution, and never touches an MCP server. Only the capability surface (server/tool names + verdicts) leaves the machine, and every model call is written to the hash chain as `kind=llm-call`.
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
pod guard [scan]    continuous multi-agent / multi-harness vulnerability scan → vulnerability list + prioritized recommendations
pod guard watch     re-scan on an interval; speaks only on new/changed/gone findings, records them in the audit chain
pod guard remediate --llm   model drafts hardening proposals (never auto-applied; must pass the relaxation guard)
pod guard catalog   the threat catalog (AG-01…AG-18) with sources and pod's coverage for each
pod agents [scan]   list the harnesses installed on this machine (and whether each is already enrolled)
pod agents enroll --harness <id>   enroll one: identity + zero-permission policy + audit dir (never touches harness config)
pod agents onboard --harness <id> [--yes]   take over (rewrite that harness's MCP servers to go through the gateway; backup + revert)
pod agents enforce --harness <id> [--record-only] [--yes]   switch to enforcement (or back to record-only) — refuses unless a compiled policy exists
pod agents revert --agent <name>   restore the config from the most recent .pod-backup-*
pod agents forget --agent <name>   remove the enrollment (policy deleted; identity kept unless --purge-identity)
pod ui [--read-only]   local console; the "Scan this machine" + "Enroll" + "Take over" buttons call the same write paths as pod agents
pod harden          one-shot hardening audit: harness scan + exposure + posture + policy draft + evidence → client-ready report directory (--verify re-checks a delivered one)
pod posture [freeze]   control-plane posture: hooks / frozen config / memory / packages / identities / delegations
pod rules              rule packs for subscribed hardening: show | pack | verify | apply | pull
pod redteam            attack scenarios vs. your policy (offline built-in library, or --llm generated); exit 1 on a high-severity bypass
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

> 云端控制平面原先分两个独立仓库（`podcloud-server` / `podcloud-web`），
> 已并入本仓库 `cloud/` 下并**归档原仓库**——历史链接会看到指向这里的告示。
- [Positioning & wedge](docs/positioning.md)
- [Threat model](docs/threat-model.md)
- [Multi-agent / multi-harness security](docs/agent-harness-security.md) ← 现状盘点 · 威胁目录 · 差距
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

## Sponsor

pod is Apache-2.0 and stays that way: the CLI, the gateway, the audit chain and the
evidence export are complete on your own machine, and nothing is locked behind a
sponsorship. Sponsorship pays for the parts that do not demo well — CI minutes, a
machine to run the multi-harness attack suites on, and the security maintenance
that only shows up as *absence* of incidents.

The only official channel is **GitHub Sponsors**:
[github.com/sponsors/suhui-organization](https://github.com/sponsors/suhui-organization)
(or the **Sponsor** button at the top of this repository).

赞助不是解锁功能的前置条件——核心能力本地全都有。不给钱也一样欢迎：提一个真实的
误报、贴一份 `pod scan` 的输出、或者帮下一个人装起来，都是等价的帮忙。

## License

Apache-2.0 — see [LICENSE](LICENSE). Security notes: [SECURITY.md](SECURITY.md).
