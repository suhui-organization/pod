# pod graph dogfood 记录（2026-09-09 计划 / 2026-09-10 实际执行）

## 环境

- 机器：macOS（darwin），Node v24.18.0，pnpm 11.7.0
- 工作区：`.worktrees/multiagent-capability-graph`（分支 `feat/multiagent-capability-graph`）
- 扫描的真实配置：`~/.dsh/mcp-manager.json`、`~/.cursor/mcp.json`、`~/.claude.json`

## 图规模

| 指标 | 值 |
|---|---|
| agent | 2（`cursor`、`dsh`） |
| server | 28 |
| tool | 407 |
| warning | 133（绝大多数是 `unclassified`） |
| 不可 introspection 的 server | 2（`filesystem` 与 `mcp-server-filesystem`，`Connection closed`） |

## H3 首次价值

| 步骤 | 耗时 |
|---|---|
| `pod graph build --timeout 5000` | **36.2s** |
| `pod graph toxic --cross-agent --min-confidence 0.4` | **<1s** |
| 合计 | **<1 分钟** |

**结论：H3 通过**（门槛 ≤10 分钟）。

## H1 发现力

默认 `--max-paths 20` 输出 20 条高危路径（全部 `injection-exec`）。把上限放到 500 后：

- 返回 500 条，**总路径 15,621 条**
- 466 条 intra-agent，**34 条 cross-agent**
- 全部为 `injection-exec`（source `read-untrusted-input` → sink `exec`）

### 最有价值的跨 agent 链（待人工确认）

```text
dsh.firecrawl_scrape  [read-untrusted-input 0.7]
  └─▶ cursor.docker_exec  [exec 0.9]          injection-exec

dsh.firecrawl_scrape  [read-untrusted-input 0.7]
  └─▶ cursor.exec_in_pod  [exec 0.9]          injection-exec
```

### 同一 agent 内的链（待人工确认）

```text
dsh.firecrawl_scrape → dsh.docker.docker_exec      (exec 0.9)
dsh.firecrawl_scrape → dsh.kubernetes.exec_in_pod  (exec 0.9)
dsh.firecrawl_scrape → dsh.supabase.execute_sql    (exec 0.9)
```

**判断**：`firecrawl_scrape` 读取外部网页（不可信内容），`docker_exec` / `exec_in_pod` / `execute_sql` 可执行代码——这条链是真实的注入→执行风险，且此前没有被显式意识到。**H1 通过（≥1 条此前未知且真实的路径）**；最终 confirmed/false-positive 需用户逐条确认。

## 噪声与误报（下一轮输入）

1. **路径爆炸**：15,621 条，绝大多数是同一个 source 对多个 sink 的笛卡尔积。需要按 `(source capability, sink capability)` 聚合，而不是枚举每个工具对。
2. **分类过宽**：
   - `browser_click` 被标为 `read-untrusted-input`（它其实是 UI 操作，不是内容摄取）。
   - `firecrawl_interact` 被标为 `exec`（需要看它的 schema 里是否真有 `code`/`command` 参数）。
3. **未分类 133 个**：docker / kubernetes / chrome-devtools / amap / memory / supabase 等工具名没有命中规则表。这正是设计文档里"你的真实工具名 → D2 标签映射表"要解决的部分。
4. **发现缺口**：`~/.claude.json` 没有顶层 `mcpServers`（count=0），Claude Code 的 MCP 配置在别处（`~/.claude/settings.json` 或项目 `.mcp.json`）；当前发现器未覆盖。
5. **introspection 失败**：`filesystem` / `mcp-server-filesystem` 返回 `Connection closed`；需要更清晰的降级提示与缓存回退。

## 验收结论

| 门槛 | 结果 |
|---|---|
| H3（≤10 分钟首次价值） | ✅ 通过（<1 分钟） |
| H1（≥1 条此前未知且真实的毒性路径） | ✅ 通过（跨 agent 注入→执行链） |
| H4（连续 2 周主动使用） | ⏳ 待观察 |

## 下一步（Phase 1 之后）

1. 按 `(source capability, sink capability)` 聚合路径，把 15,621 条压到几十条可读链。
2. 由用户补 D2 工具名映射表（5-10 行），优先覆盖 docker / kubernetes / supabase / chrome-devtools / firecrawl。
3. 补 Claude Code MCP 配置发现（`~/.claude/settings.json`、项目 `.mcp.json`）。
4. 评估把 `--cross-agent` 设为默认：本次最有价值的发现来自跨 agent 组合。

## 映射收敛后（2026-09-10，同一台机器）

按 dogfood 结果补了 D2 工具映射（chrome-devtools / kubernetes / docker / firecrawl / amap / memory / supabase），并实现按 `(rule, source capability, sink capability)` 聚合：

| 指标 | 映射前 | 映射后 |
|---|---:|---:|
| 未分类工具 | 133 | **11** |
| 总路径数 | 15,621 | 30,047 |
| 聚合后的链类型 | — | **4** |

路径数上升是因为 `click/fill/type_text` 等被正确识别为 `external-communication`（新增 sink），这是分类更准确的结果；可读性由聚合解决：

| 链类型 | source → sink | 路径数 | 跨 agent |
|---|---|---:|---:|
| exfiltration | `read-private-data → external-communication` | 14,723 | 7,365 |
| injection-exfil | `read-untrusted-input → external-communication` | 11,794 | 5,913 |
| injection-exec | `read-untrusted-input → exec` | 3,500 | 1,752 |
| destruction | `destructive-write → destructive-write` | 30 | 0 |

**映射裁定**：`browser click/fill/type_text` = 外发 + 读不可信；`firecrawl_interact/monitor_run` 改回读不可信（修正误报的 exec）；docker 构建/启动/停止/拉取 = exec + write；kubectl 变更 = destructive；`supabase.execute_sql` 保持 exec（SQL 可能写库）。

**剩余 11 个未分类**：memory 的写工具（`create_entities/create_relations/add_observations`，只有 write context）、`sequentialthinking`（无 source/sink）、`pod-filesystem.move_file`、`kubectl_reconnect`。

**下一步**：给 4 条链类型打分/排序（优先跨 agent 且高置信的链），而不是继续枚举工具对。

## 链打分（2026-09-10）

评分模型：`rule + severity + cross-agent 比例 + source 敏感度 + sink 危险度 + 置信度 + 出现频次`，满分约 155，分档 critical ≥130 / high ≥100 / medium ≥70。

| score | 风险 | 链 | 路径数 | 跨 agent |
|---:|---|---|---:|---:|
| **139** | critical | `exfiltration: read-private-data → external-communication` | 14,723 | 7,365 |
| **139** | critical | `injection-exec: read-untrusted-input → exec` | 3,500 | 1,752 |
| **114** | high | `injection-exfil: read-untrusted-input → external-communication` | 11,794 | 5,913 |
| **73** | medium | `destruction: destructive-write → destructive-write` | 30 | 0 |

排序结果符合直觉：**读私有数据 + 外发**与**读不可信内容 + 执行**并列最高，破坏性写最低（不跨 agent、无外发）。用户第一眼看到的是这 4 条链，而不是 30,047 条明细。

## Phase 2 三项（2026-09-10）

1. **链级 diff**：`suggestChainDiff` 计算链级最小割。工具级最小割 ≤3 时给出精确改动；>3 时降级为能力级建议。本次 dogfood 的 4 条链全部是能力级：
   - chain-001 exfiltration：需要改 99 个 sink → 建议对 `external-communication` 统一加审批
   - chain-003 injection-exec：需要改 24 个 sink → 建议对 `exec` 统一加审批
   - chain-002 injection-exfil：需要改 81 个 sink → 建议对 `external-communication` 统一加审批
   - chain-004 destruction：需要改 30 个 sink → 建议对 `destructive-write` 统一加审批

   **结论**：工具级策略无法用"1-2 条改动"切断这种笛卡尔积链；需要引入 capability-level policy（按 D2 能力统一 allow/approve/deny）。这是下一步最明确的产品缺口。
2. **Claude Code 配置发现**：已支持 `~/.claude/settings.json`、`~/.claude.json` 的 `projects[*].mcpServers`、`~/.mcp.json`、项目 `.mcp.json`。本机 Claude Code 没有配置 MCP server（`~/.claude.json` 无 `mcpServers`/`projects`），所以本次图规模未变化。
3. **跨 agent 默认开启**：`pod graph toxic` 默认 `--cross-agent`，`--no-cross-agent` 可关闭。本次 dogfood 未加 flag，跨 agent 路径正常计入。

## Capability-level policy（2026-09-10）

- `pod graph apply` 把真实图的 **396 个工具 → D2 能力**映射写进策略的 `capabilityMap`。
- 示例 `capabilityRules: { approve: ["external-communication"], deny: ["read-secret"] }` 通过 `pod lint`（0 error / 0 warning）。
- `pod serve` 在配置了 `capabilityRules` 时自动加载 `~/.pod/graph/potential.json` 并合并映射（策略里显式声明的映射优先）；运行时按能力规则求值，端到端验证见 `apps/cli/test/capability-serve.test.ts`（`servers.allow` 里的工具因 `external-communication` 能力被 deny）。
- 链级 diff 现在输出 `capability-diff.json`，内容可直接加入策略：
  ```json
  [{ "capabilityRules": { "approve": ["external-communication"] } }]
  ```
- 效果：chain-001/002 从"改 99/81 个工具"变成"1 条能力规则"，这才是能落地的断链方式。
