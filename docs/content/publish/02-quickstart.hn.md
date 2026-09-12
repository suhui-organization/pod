# Show HN 投放版（英文）

> 用法：标题用下面第一行；正文直接复制。
> Full version: ../02-quickstart.md

---

**Show HN: pod – compile a least-privilege policy from what your AI agent actually did**

I run six agent platforms on one laptop. Between them they have 14 MCP servers
configured, 12 of them unpinned (`npx -y pkg@latest`), and five plaintext API
keys sitting in config files. I only knew that after writing a read-only scanner.

That scanner turned into pod. The piece I care about is the middle step that
every existing tool skips:

```
record    run your agent through pod in record-only mode for a few days
compile   pod policy draft  -> least-privilege rules from real observed calls
enforce   pod serve         -> deny > approve > allow, fail-closed
prove     pod verify-audit  -> SHA-256 hash chain you can hand to someone else
```

Gateways (agentgateway, ToolHive, …) give you a place to enforce rules you write
by hand. Scanners tell you what is exposed. pod writes the rules from behavior —
`read_file` gets denied because it touched `.env` exactly once, and tools that
never appeared in the corpus are simply not granted.

Two things that make it different in practice:

1. **The evidence is independently verifiable.** Every call goes into a hash
   chain; `pod export-evidence` produces a bundle anyone can verify without
   trusting me or the host. Sensitive content is stored as hashes only.
2. **You own the rules.** Thresholds, regexes, severities and trusted sources
   live in `~/.pod/rules.json`. Invalid rules fail closed instead of silently
   falling back to defaults.

There is also a control-plane side most tools ignore: lifecycle hooks, frozen
config, agent identities, delegation chains, memory-file drift. All of it lands
in the same audit chain.

Install (macOS/Linux, builds from source, no npm account needed):

```bash
curl -fsSL https://gitee.com/suhuisoftwares/pod/raw/v0.2.0/scripts/install.sh | sh
pod scan        # read-only, no network
```

Apache-2.0. Local-first: policies, audits and secrets stay on your machine; the
optional cloud control plane is in the same repo. Honest boundaries are in the
threat model (no sandboxing, no A2A/mTLS protocol implementation, no
behavioral-drift-as-primary-defense).

https://gitee.com/suhuisoftwares/pod (mirror: https://github.com/suhui-organization/pod)

I would especially like feedback on the compile step: whether the
observed-behavior-to-policy mapping is too coarse for real workflows, and where
it produces obviously wrong rules.
