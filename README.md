# pod — AI Agent Security Gateway

> **Every step your agent takes, has immutable evidence.**

Before an AI agent touches your machine, pod answers three questions: **What can it touch? Who approved it? Where is the evidence?**

pod sits between your agents and their tools over **MCP**, adding three gates to every tool call — a policy gate, human approval, and a SHA-256 hash-chain audit. The last one is the core promise: every call is appended to a tamper-evident chain; alter any historical record and verification fails immediately.

```
Tool call ──▶ Policy (deny > approve > allow) ──▶ Approval (high-risk suspends) ──▶ Execute
                                                                                    │
                                                                                    ▼
                                              ┌────────────────────────────────────────┐
                                              │ Hash-chain audit (append-only JSONL):  │
                                              │ #3 hash = sha256(#2 + record)          │ ← tamper-evident
                                              │ #2 hash = sha256(#1 + record)          │ ← every step logged
                                              │ #1 hash = sha256(seed)                 │ ← verifiable
                                              └────────────────────────────────────────┘
```

## Why pod

OpenClaw, Claude Code, Cursor, Hermes and DSH each manage their own sandbox — but nothing tells you **what all your agents can touch together**, or gives you **evidence for what they did**. pod is the missing layer.

- 🚪 **Gate** — every tool call passes a policy gate; unauthorized calls are rejected by default (fail-closed); writes require human approval
- 📜 **Evidence** — every call lands in a SHA-256 hash chain: tamper-proof, independently verifiable (`pod verify-audit`), exportable as a signed evidence bundle
- 👁 **Sight** — one audit view across heterogeneous agents; sensitive content is stored as hashes only; with the optional cloud plane your audit stays local-first

```
Agent (OpenClaw / Claude Code / Cursor / Hermes / DSH …)
      │ MCP (stdio or Streamable HTTP)
      ▼
┌─ pod gateway ─────────────────┐      ┌───────────────────┐
│ Policy  deny>approve>allow     │─────▶│ Real MCP server    │
│ Approval suspend (fail-closed) │      │ (filesystem, etc.) │
│ Hash-chain audit (hashes only) │      └───────────────────┘
└───────────────┬────────────────┘
                │ pod sync (cursor-based push) / pod pull-policy (policy distribution)
                ▼
        ┌────────────────────┐
        │ Pod Cloud (optional)│  Dashboard · Alerts · Policy templates · AI digest
        └────────────────────┘
```

## Quick start

```bash
# 1. install & scaffold (Node 18+ required)
npm i -g @podsec/cli    # or: pnpm i -g @podsec/cli
pod init --template baseline

# 2. serve a real MCP server behind the gateway
pod serve --agent openclaw --server filesystem \
  --policy policies/baseline.json \
  --command mcp-server-filesystem --arg /path/to/workspace \
  --transport stdio

# 3. point your agent at the gateway (OpenClaw example)
#    openclaw config set mcp.servers.pod-filesystem.url http://127.0.0.1:8783/mcp
#    Hermes:  mcp_servers.pod-filesystem.url = http://127.0.0.1:8784/mcp
#    Codex:   codex mcp add pod-filesystem -- pod-serve-stdio.sh

# 4. see what happened
pod timeline
pod verify-audit            # tamper check over the whole chain
pod export-evidence         # produce a verifiable evidence bundle
```

**Policy example** (`policies/baseline.json`):

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

Decisions are evaluated `deny > secrets-input > approve > allow`, fail-closed. Gateway startup also validates the declared server source (`command`/`package`/`version`) — T4 supply-chain gate.

Outputs are checked twice: known-format regexes (`deny_output_matching`) and high-entropy
detection (`secrets.entropy`) for unknown secret formats. Hex hashes cap at 4.0 bits/char,
so the default 4.5 threshold does not flag commit SHAs.

## CLI

```
pod init            scaffold policy templates (baseline / record)
pod onboard         discover local MCP servers and wrap them behind pod (dry-run by default)
pod serve           run the gateway (stdio / Streamable HTTP)
pod record          record-only mode: log every call without blocking (corpus collection)
pod approve|deny|pending   side-channel approvals
pod watch           resident approval queue: prompt on new requests (TTY) or print commands
pod snapshots       list write-operation snapshots (rollback points)
pod rollback        restore files from a snapshot (serve --snapshot enables capture)
pod policy draft    turn recorded corpus into a least-privilege policy draft
pod timeline        audit timeline filtered by agent / tool / time
pod verify-audit    verify the full hash chain, emit a report
pod digest          local weekly security digest (no network)
pod coverage        managed vs. unmanaged MCP servers; --strict exits 1 on drift
pod export-evidence / verify-evidence   export & verify evidence bundles (+ one-page report)
pod lint | doctor   policy lint / environment health
pod scan            free local security scan (config & bypass checks)
pod sync            push audit to Pod Cloud (cursor-based)
pod pull-policy     pull policies from Pod Cloud
```

### From zero to enforcement

```bash
pod scan                              # 1. see what is exposed
pod onboard                           # 2. preview the takeover plan (dry-run)
pod onboard --yes                     #    wrap agents in record-only mode (backups kept)
# ... use your agents normally for a day or two ...
pod policy draft                      # 3. generate a least-privilege policy from real calls
pod lint --policy ~/.pod/policies/draft.json
pod serve --agent <name> --server <name> --policy ~/.pod/policies/draft.json \
  --command <cmd> --arg <value>       # 4. switch to enforcement
pod watch                             # 5. approve high-risk calls from a second terminal
pod snapshots                         # 6. list rollback points (serve --snapshot)
pod rollback --id <snapshot-id>       #    undo a write operation
```

For a resident HTTP gateway, set `--auth-token` (or `POD_AUTH_TOKEN`) so other local
processes cannot connect and impersonate the agent:

```bash
pod serve --transport http --port 8786 --auth-token "$POD_AUTH_TOKEN" ...
```

## Pod Cloud (optional SaaS plane)

Local-first core is free & open. Pod Cloud adds the control plane: one-step agent onboarding, cross-agent timeline, 11 alert rules with webhook/email delivery, policy templates (balanced / high-security / audit-only / locked-down), natural-language policy generation with human confirmation, and an AI daily digest. Audits are pushed as hashes only.

## Supported agents

| Agent | Transport | Status |
| --- | --- | --- |
| Hermes | Streamable HTTP | ✅ verified end-to-end |
| OpenClaw | stdio wrapper | ✅ verified end-to-end |
| Codex | stdio wrapper | ✅ ready (see docs) |
| DSH / Claude Code / Cursor | MCP | pluggable via MCP |

## Documentation

- [Threat model](docs/threat-model.md)
- [Egress defense](docs/egress-defense.md)
- [Agent onboarding](docs/agent-onboarding.md)
- [Automation (launchd/systemd/cron)](docs/automation.md)

## Repository family

- **pod** (this repo) — local gateway & CLI, open source
- podcloud-server / podcloud-web — SaaS control plane (private)

## License

MIT — see [LICENSE](LICENSE). Security notes: [SECURITY.md](SECURITY.md)
