# 04-forensics 英文全平台投放包（2026-09-18 第 4 轮）

> 源文：[04-forensics.md](../04-forensics.md)（出事后 5 分钟取证）
> 素材轮次：第 1 轮 02-quickstart、第 2 轮 01-scan-report、第 3 轮 03-owasp-101、**本轮 04-forensics**
> 统一语气：一个使用者在讲自己踩到的坑，不写成产品宣传。

## dev.to 长文（标题 + 正文，tag: security / ai / opensource / mcp）

**Title**：Agent forensics in five minutes: what it did, and proof the log wasn't edited

**Body**（Markdown）：

```markdown
An agent incident ends one of two ways.

Without an audit trail, you guess: what it did, when, with which arguments, under which policy, approved by whom. With a hash-chained audit, five minutes gets you a full timeline — and a way to show the timeline itself hasn't been edited since.

I run agents on my own laptop (Claude Code, Cursor, OpenClaw, DSH), so I've had this happen. Here is the whole runbook, on real output.

## The script: 01:40, an agent tries to delete a file

A real call from my machine — the policy stopped it:

~~~
$ pod timeline --since 2h --tool delete_file

2026-09-01 01:40:08  [deny   ] delete_file        filesystem   agent=openclaw-main  args=cb1533f3… pol=0.1.0  reason=tool "delete_file" is denied on "filesystem"  blocked
~~~

Three seconds to read three things: **who** (openclaw-main), **what it wanted to do** (delete_file), **why it didn't happen** (policy deny, with the policy version in force at that moment — 0.1.0).

## Step 1 — replay the timeline (2 minutes)

~~~bash
pod timeline --since 2h                       # everything, last two hours
pod timeline --since 24h --tool write_file    # only writes
pod timeline --agent openclaw-main            # only one agent
~~~

Every row carries: time / tool / server / agent / **argument hash** / decision / outcome / approver / **the policy version in force**. Arguments are stored as hashes only — during an incident that means you don't leak more than you have to, while still being able to prove the call happened.

## Step 2 — prove the log wasn't touched (1 minute)

~~~
$ pod verify-audit

## openclaw-main/filesystem.jsonl
- status: hash chain intact
- entries: 8
- head hash: f7a56fb90350…
- tail hash: 06f31666c4e8…

conclusion: every record verifiable, none modified
~~~

Each record locks in the hash of the one before it. Edit any historical entry and verification fails immediately. That's a stronger claim than "the log shows it": it's "the log itself wasn't edited after the fact".

## Step 3 — package the evidence (2 minutes)

~~~
$ pod export-evidence
evidence bundle: ~/.pod/evidence/pod-evidence-2026-09-01.json
  audit files: 1 | policy snapshots: 1
  top-level hash: 9f9e6ed35ed1c0b9…
  one-page report: ~/.pod/evidence/pod-evidence-2026-09-01.json.md

$ pod verify-evidence --out ~/.pod/evidence/pod-evidence-2026-09-01.json
✅ evidence bundle valid (top-level hash matches, nothing modified)
~~~

One file to hand over: the audit, **the policy snapshot that was in force**, the self-check result, and a top-level hash. Whoever receives it can verify the bundle themselves — no need to trust your machine.

## Optional: cross-agent evidence in the cloud

~~~bash
pod sync
~~~

The control plane lives in the same Apache-2.0 repo (`bash deploy/install.sh`). The data direction is one-way: only SHA-256 hashes go up, the audit text stays on your machine, and the cloud being down doesn't affect local enforcement.

## Why a hash chain instead of plain logs

| | Plain log | pod hash-chained audit |
|---|---|---|
| Records the call | yes | yes |
| Records raw arguments | yes (that's the leak surface) | no — hash only |
| Records the policy version in force | no | yes |
| Provable that nobody edited it | no — anyone can edit a log | yes — one edit breaks the chain |
| Portable, verifiable evidence bundle | no | yes |

Not every agent behaves. The audit's job is narrower and more useful: what it did, it can't deny.

Install (v0.3.2):

~~~bash
curl -fsSL https://gitee.com/suhuisoftwares/pod/raw/v0.3.2/scripts/install.sh | sh
pod init --template baseline
pod serve --agent <name> --server <name> --policy ~/.pod/policies/baseline.json --command <cmd>
~~~
```

## X（正文 ≤280，链接放在首条自回复）

> An agent tried to delete a file on my laptop at 1:40am. The policy blocked it — and the audit chain gave me the full timeline in five minutes: who, what, which policy version, plus proof the log itself wasn't edited afterwards.

首条回复：`The whole runbook, on real output: <dev.to 链接>`

## Bluesky（正文 + 链接合计 ≤300）

> An agent tried to delete a file on my laptop at 1:40am. The audit chain gave me the timeline in five minutes — who, what, which policy version — and proof the log wasn't edited.
>
> <dev.to 链接>

（正文 181 字符，留给链接约 115 字符；超限时先压正文。）

## LinkedIn（长文，结尾放 gitee 仓库）

> An agent incident ends one of two ways. Without an audit trail you guess — what it did, when, with which arguments, under which policy, approved by whom. With a hash-chained audit you get a full timeline in five minutes, plus a way to show the timeline itself hasn't been edited.
>
> A real one from my laptop: at 01:40 an agent (openclaw-main) tried to delete a file on the filesystem server. The policy denied it, and the timeline line said exactly that — who, what, and the policy version in force at the time (0.1.0). Three seconds of reading.
>
> The part people skip is the second half: proving the log wasn't touched afterwards. Each audit record locks in the hash of the previous one. Edit any historical entry and verification fails immediately — that's `pod verify-audit`, one minute.
>
> Then `pod export-evidence` packs the audit, the policy snapshot that was in force, the self-check and a top-level hash into one file. The recipient verifies it themselves; they don't have to trust your machine.
>
> Detail that matters in an incident: arguments are stored as hashes, not raw text, so the evidence proves a call happened without widening the blast radius.
>
> I've been building pod around this — scan, compile a least-privilege policy from observed calls, enforce it, and keep tamper-evident evidence: https://gitee.com/suhuisoftwares/pod

## Hacker News（链接贴，标题 ≤80 字符，指向 dev.to 长文）

**Title**：`Agent forensics in five minutes: what it did, and proof the log wasn't edited`

（标题 78 字符；注意别用裸数字——第 3 轮标题里的 `10` 被 HN 吞掉过。）

## CSDN（英文稿，入口 mp.csdn.net/edit，标签必填）

**标题**：Agent forensics in five minutes: what it did, and proof the log wasn't edited

正文：同 dev.to 长文（Markdown 直接粘进 CKEditor）。
