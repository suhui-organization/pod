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
