# 多智能体能力图 Phase 1 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在单机异构多 agent 环境中生成静态能力图，识别同一 agent 内的 source→sink 毒性路径，并产出定点策略 diff。

**Architecture:** 新增纯函数包 `@podsec/graph`（分类器/规则/差集/diff 建议），IO 适配器放在 `apps/cli/src/graph/`（发现、MCP introspection、schema 缓存、图文件读写）。CLI 新增 `pod graph build|toxic|explain`，复用现有 `discoverTargets` 与 `policy draft --diff` 格式。Phase 1 只做静态图与 intra-agent 毒性路径；跨 agent 规则引擎在核心层实现并测试，CLI 通过 `--cross-agent` 显式开启。

**Tech Stack:** TypeScript 5.9、Node ≥22.13、pnpm 11.7、Vitest 3、`@modelcontextprotocol/sdk`。

---

## 文件结构

| 文件 | 责任 |
|---|---|
| `packages/graph/package.json` | 新包 `@podsec/graph` |
| `packages/graph/tsconfig.json` | 继承根 tsconfig |
| `packages/graph/src/types.ts` | 图/能力/毒性路径类型 + 常量 |
| `packages/graph/src/serialize.ts` | 稳定序列化与 schema 校验 |
| `packages/graph/src/classify.ts` | D2 能力分类器（纯函数） |
| `packages/graph/src/toxic.ts` | 毒性规则引擎（纯函数） |
| `packages/graph/src/diff.ts` | 策略 diff 建议器（纯函数） |
| `packages/graph/src/report.ts` | Markdown 报告渲染 |
| `packages/graph/src/index.ts` | 包导出 |
| `packages/policy/src/index.ts` | 修改：`Policy.capabilities` 覆盖字段 |
| `apps/cli/src/graph/io.ts` | 图文件原子读写 |
| `apps/cli/src/graph/schema-cache.ts` | 工具 schema 缓存 |
| `apps/cli/src/graph/introspect.ts` | MCP `tools/list` introspection（env 白名单 + 超时） |
| `apps/cli/src/graph/static.ts` | 静态潜在图构建（发现 + introspection + 分类） |
| `apps/cli/src/graph/commands.ts` | `graph build/toxic/explain` 命令处理 |
| `apps/cli/src/index.ts` | 修改：CLI 路由与 usage |
| `apps/cli/test/fixtures/graph/danger-server.ts` | 测试用 MCP server（危险工具名） |
| `apps/cli/test/fixtures/graph/hanging-server.ts` | 测试用超时 MCP server |
| `apps/cli/test/graph-*.test.ts` | CLI 集成与失败模式测试 |
| `scripts/demo-graph.sh` | 可复现 demo |
| `docs/graph.md` | 用户文档 |
| `docs/dogfood/2026-09-09-graph-dogfood.md` | dogfood 验收记录 |

---

## Task 1: 脚手架与核心类型

**Files:**
- Create: `packages/graph/package.json`
- Create: `packages/graph/tsconfig.json`
- Create: `packages/graph/src/types.ts`
- Create: `packages/graph/src/index.ts`
- Create: `packages/graph/src/serialize.test.ts`

- [ ] **Step 1: 写失败测试**

`packages/graph/src/serialize.test.ts`：

```ts
import { describe, expect, it } from 'vitest';
import { GRAPH_SCHEMA_VERSION, parseGraph, serializeGraph } from './index.js';

const graph = {
  schema_version: GRAPH_SCHEMA_VERSION,
  source: 'static' as const,
  generated_at: '2026-09-09T00:00:00.000Z',
  meta: { tool_version: '0.1.0', config_fingerprint: 'sha256:x', warnings: [] },
  nodes: [
    { id: 'tool:b.z', type: 'tool' as const },
    { id: 'agent:a', type: 'agent' as const },
  ],
  edges: [
    { from: 'server:s', to: 'tool:b.z', type: 'exposes' as const },
    { from: 'agent:a', to: 'server:s', type: 'connects' as const },
  ],
};

describe('serializeGraph', () => {
  it('sorts nodes and edges for stable git diffs', () => {
    const text = serializeGraph(graph);
    expect(text.indexOf('agent:a')).toBeLessThan(text.indexOf('tool:b.z'));
    expect(text.endsWith('\n')).toBe(true);
  });
});

describe('parseGraph', () => {
  it('round-trips a valid graph', () => {
    expect(parseGraph(serializeGraph(graph)).schema_version).toBe(GRAPH_SCHEMA_VERSION);
  });

  it('rejects a schema version mismatch', () => {
    expect(() => parseGraph(JSON.stringify({ ...graph, schema_version: '9.9.9' }))).toThrow(
      /unsupported graph schema_version/,
    );
  });

  it('rejects invalid JSON', () => {
    expect(() => parseGraph('{nope')).toThrow(/not valid JSON/);
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pnpm --filter @podsec/graph test`

Expected: FAIL（包不存在，命令报 `No projects matched the filters`）。

- [ ] **Step 3: 创建包与实现**

`packages/graph/package.json`：

```json
{
  "name": "@podsec/graph",
  "version": "0.1.0",
  "type": "module",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "default": "./dist/index.js"
    }
  },
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "test": "vitest run",
    "typecheck": "tsc -p tsconfig.json --noEmit"
  },
  "dependencies": {
    "@podsec/policy": "workspace:*"
  }
}
```

`packages/graph/tsconfig.json`：

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "rootDir": "src",
    "outDir": "dist"
  },
  "include": ["src"]
}
```

`packages/graph/src/types.ts`：

```ts
export const GRAPH_SCHEMA_VERSION = '0.1.0';

export type Capability =
  | 'read-secret'
  | 'read-private-data'
  | 'read-untrusted-input'
  | 'external-communication'
  | 'exec'
  | 'destructive-write'
  | 'credential-access';

export const CAPABILITIES: readonly Capability[] = [
  'read-secret',
  'read-private-data',
  'read-untrusted-input',
  'external-communication',
  'exec',
  'destructive-write',
  'credential-access',
] as const;

export type CapabilityOrigin = 'name' | 'schema' | 'policy' | 'observed' | 'heuristic';

export interface CapabilityAssertion {
  capability: Capability;
  confidence: number;
  origin: CapabilityOrigin;
  evidence: string[];
}

export interface GraphNode {
  id: string;
  type: 'agent' | 'server' | 'tool' | 'capability';
  agent?: string;
  server?: string;
  tool?: string;
  command?: string;
  writeContext?: boolean;
}

export interface GraphEdge {
  from: string;
  to: string;
  type: 'connects' | 'exposes' | 'has_capability';
  confidence?: number;
  origin?: CapabilityOrigin;
  evidence?: string[];
}

export type GraphWarningCode =
  | 'config_unreadable'
  | 'server_unintrospectable'
  | 'schema_missing'
  | 'unclassified'
  | 'stale_graph';

export interface GraphWarning {
  code: GraphWarningCode;
  message: string;
  where?: string;
}

export interface CapabilityGraph {
  schema_version: string;
  source: 'static' | 'observed';
  generated_at: string;
  meta: {
    tool_version: string;
    config_fingerprint: string;
    warnings: GraphWarning[];
  };
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface ToolRef {
  agent: string;
  server: string;
  tool: string;
  nodeId: string;
  writeContext: boolean;
  capabilities: CapabilityAssertion[];
}

export interface PathEndpoint {
  agent: string;
  server: string;
  tool: string;
  capability: Capability;
  confidence: number;
}

export interface PolicyDiffHint {
  target: string;
  from: 'allow' | 'approve' | 'deny' | '(unlisted)';
  to: 'approve' | 'deny';
  rationale: string;
}

export interface ToxicPath {
  id: string;
  kind: 'intra-agent' | 'cross-agent';
  rule: string;
  severity: 'high' | 'medium' | 'low';
  confidence: number;
  source: PathEndpoint;
  sink: PathEndpoint;
  amplifier: PathEndpoint | null;
  evidence: string[];
  explain: string;
  suggested_diff: PolicyDiffHint | null;
}
```

`packages/graph/src/index.ts`：

```ts
export * from './types.js';
export * from './serialize.js';
```

> 后续任务会依次追加 `classify.js`、`toxic.js`、`diff.js`、`report.js` 的导出，避免 Task 1 因文件尚未创建而构建失败。

`packages/graph/src/serialize.ts`：

```ts
import { GRAPH_SCHEMA_VERSION, type CapabilityGraph } from './types.js';

export class GraphSchemaError extends Error {}

export function normalizeGraph(graph: CapabilityGraph): CapabilityGraph {
  const nodes = [...graph.nodes].sort((a, b) => a.id.localeCompare(b.id));
  const edges = [...graph.edges].sort(
    (a, b) => a.from.localeCompare(b.from) || a.to.localeCompare(b.to) || a.type.localeCompare(b.type),
  );
  return { ...graph, nodes, edges };
}

export function serializeGraph(graph: CapabilityGraph): string {
  return JSON.stringify(normalizeGraph(graph), null, 2) + '\n';
}

export function parseGraph(text: string): CapabilityGraph {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new GraphSchemaError(`graph is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  const g = raw as Partial<CapabilityGraph>;
  if (!g || typeof g !== 'object') throw new GraphSchemaError('graph must be an object');
  if (g.schema_version !== GRAPH_SCHEMA_VERSION) {
    throw new GraphSchemaError(
      `unsupported graph schema_version "${String(g.schema_version)}" (expected ${GRAPH_SCHEMA_VERSION})`,
    );
  }
  if (!Array.isArray(g.nodes) || !Array.isArray(g.edges)) {
    throw new GraphSchemaError('graph.nodes and graph.edges must be arrays');
  }
  if (g.source !== 'static' && g.source !== 'observed') {
    throw new GraphSchemaError('graph.source must be "static" or "observed"');
  }
  return g as CapabilityGraph;
}
```

- [ ] **Step 4: 安装并运行测试**

Run: `pnpm install && pnpm --filter @podsec/graph test`

Expected: PASS（3 个测试）。

- [ ] **Step 5: 提交**

```bash
git add packages/graph
git commit -m "feat(graph): 新增 @podsec/graph 包与图序列化"
```

---

## Task 2: D2 能力分类器

**Files:**
- Create: `packages/graph/src/classify.ts`
- Create: `packages/graph/src/classify.test.ts`

- [ ] **Step 1: 写失败测试**

```ts
import { describe, expect, it } from 'vitest';
import { classifyTool, tokenize } from './classify.js';

const tool = (name: string, inputSchema?: unknown) => ({ name, inputSchema });

describe('tokenize', () => {
  it('splits snake/kebab/camel/dot', () => {
    expect(tokenize('read_file')).toEqual(['read', 'file']);
    expect(tokenize('createPullRequest')).toEqual(['create', 'pull', 'request']);
    expect(tokenize('fs.read')).toEqual(['fs', 'read']);
  });
});

describe('classifyTool', () => {
  it('classifies destructive / exec / external / read tools', () => {
    expect(classifyTool(tool('delete_file')).assertions[0]?.capability).toBe('destructive-write');
    expect(classifyTool(tool('execute_command')).assertions[0]?.capability).toBe('exec');
    expect(classifyTool(tool('send_email')).assertions[0]?.capability).toBe('external-communication');
    expect(classifyTool(tool('read_file', { type: 'object', properties: { path: { type: 'string' } } })).assertions
      .map((a) => a.capability)
      .sort()).toEqual(['read-private-data', 'read-secret']);
  });

  it('classifies http_request as ambiguous (untrusted input + external communication)', () => {
    const result = classifyTool(
      tool('http_request', {
        type: 'object',
        properties: { url: { type: 'string' }, method: { type: 'string' }, body: { type: 'string' } },
      }),
    );
    expect(result.assertions.map((a) => a.capability).sort()).toEqual([
      'external-communication',
      'read-untrusted-input',
    ]);
  });

  it('honors explicit overrides with confidence 1 and origin policy', () => {
    const result = classifyTool(tool('acme_sync'), ['external-communication']);
    expect(result.assertions).toEqual([
      {
        capability: 'external-communication',
        confidence: 1,
        origin: 'policy',
        evidence: ['policy override'],
      },
    ]);
  });

  it('marks unknown tools as unclassified and detects write context', () => {
    expect(classifyTool(tool('acme_sync')).unclassified).toBe(true);
    expect(classifyTool(tool('write_file')).writeContext).toBe(true);
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pnpm --filter @podsec/graph test -- classify`

Expected: FAIL（`classify.ts` 不存在）。

- [ ] **Step 3: 实现分类器**

先追加导出：在 `packages/graph/src/index.ts` 末尾加 `export * from './classify.js';`。

`packages/graph/src/classify.ts`：

```ts
import type { Capability, CapabilityAssertion, CapabilityOrigin } from './types.js';

export interface ToolDescriptor {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

export type CapabilityOverrides = Capability[];

interface NameRule {
  capability: Capability;
  tokens?: string[];
  patterns?: RegExp[];
  confidence: number;
  evidence: string;
}

interface SchemaRule {
  capability: Capability;
  properties: RegExp[];
  confidence: number;
  evidence: string;
}

const WRITE_TOKENS = new Set([
  'write', 'edit', 'create', 'update', 'patch', 'move', 'rename', 'copy', 'mkdir', 'touch', 'append', 'insert',
]);

const NAME_RULES: NameRule[] = [
  {
    capability: 'destructive-write',
    tokens: ['delete', 'remove', 'drop', 'truncate', 'destroy', 'purge', 'wipe', 'revoke', 'uninstall', 'force'],
    confidence: 0.9,
    evidence: 'tool name contains a destructive verb',
  },
  {
    capability: 'exec',
    tokens: ['exec', 'execute', 'run', 'shell', 'command', 'spawn', 'eval', 'terminal', 'bash'],
    confidence: 0.9,
    evidence: 'tool name contains an execution verb',
  },
  {
    capability: 'external-communication',
    tokens: ['send', 'email', 'mail', 'message', 'post', 'publish', 'webhook', 'notify', 'comment', 'upload'],
    confidence: 0.8,
    evidence: 'tool name contains an external communication verb',
  },
  {
    capability: 'external-communication',
    patterns: [/pull[_-]?request|create[_-]?pr|\bpr\b|\bissue\b/i],
    confidence: 0.6,
    evidence: 'tool name references a public PR/issue surface',
  },
  {
    capability: 'credential-access',
    tokens: ['assume', 'mint', 'oauth', 'keychain', 'credential', 'token'],
    confidence: 0.8,
    evidence: 'tool name contains a credential operation',
  },
  {
    capability: 'read-secret',
    tokens: ['secret', 'env', 'dotenv', 'ssh', 'aws', 'kubeconfig', 'id_rsa'],
    confidence: 0.7,
    evidence: 'tool name references secret material',
  },
  {
    capability: 'read-untrusted-input',
    tokens: ['fetch', 'scrape', 'browser', 'web', 'url', 'rss', 'inbox'],
    confidence: 0.7,
    evidence: 'tool name references external content',
  },
  {
    capability: 'read-private-data',
    tokens: ['read', 'get', 'list', 'query', 'search', 'load', 'cat'],
    confidence: 0.5,
    evidence: 'tool name is read-like',
  },
];

const SCHEMA_RULES: SchemaRule[] = [
  { capability: 'read-secret', properties: [/^(path|file|filename)$/i], confidence: 0.4, evidence: 'path-like argument can point at .env/.ssh' },
  { capability: 'read-private-data', properties: [/^(path|file|filename|repo|database|table|query)$/i], confidence: 0.6, evidence: 'data-source argument' },
  { capability: 'external-communication', properties: [/^(to|recipient|channel|webhook|url|body|content|message)$/i], confidence: 0.6, evidence: 'destination/body argument' },
  { capability: 'read-untrusted-input', properties: [/^(url|uri|link|feed)$/i], confidence: 0.5, evidence: 'URL-like argument' },
  { capability: 'exec', properties: [/^(command|cmd|script|code)$/i], confidence: 0.8, evidence: 'command/code argument' },
  { capability: 'destructive-write', properties: [/^(force|recursive|hard)$/i], confidence: 0.4, evidence: 'destructive modifier' },
];

export function tokenize(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function schemaProperties(inputSchema: unknown): string[] {
  if (!inputSchema || typeof inputSchema !== 'object') return [];
  const properties = (inputSchema as { properties?: unknown }).properties;
  if (!properties || typeof properties !== 'object') return [];
  return Object.keys(properties as Record<string, unknown>);
}

export interface ClassifyResult {
  assertions: CapabilityAssertion[];
  writeContext: boolean;
  unclassified: boolean;
}

export function classifyTool(tool: ToolDescriptor, overrides: CapabilityOverrides = []): ClassifyResult {
  const tokens = tokenize(tool.name);
  const byCapability = new Map<Capability, CapabilityAssertion>();
  const add = (capability: Capability, confidence: number, origin: CapabilityOrigin, evidence: string): void => {
    const existing = byCapability.get(capability);
    if (!existing) {
      byCapability.set(capability, { capability, confidence, origin, evidence: [evidence] });
      return;
    }
    existing.confidence = Math.max(existing.confidence, confidence);
    if (!existing.evidence.includes(evidence)) existing.evidence.push(evidence);
    if (confidence > existing.confidence) existing.origin = origin;
  };

  for (const capability of overrides) add(capability, 1, 'policy', 'policy override');

  for (const rule of NAME_RULES) {
    const hit =
      rule.tokens?.some((token) => tokens.includes(token)) ||
      rule.patterns?.some((pattern) => pattern.test(tool.name)) ||
      false;
    if (hit) add(rule.capability, rule.confidence, 'name', rule.evidence);
  }

  const properties = schemaProperties(tool.inputSchema);
  for (const rule of SCHEMA_RULES) {
    if (rule.properties.some((pattern) => properties.some((property) => pattern.test(property)))) {
      add(rule.capability, rule.confidence, 'schema', rule.evidence);
    }
  }

  const assertions = [...byCapability.values()].sort(
    (a, b) => b.confidence - a.confidence || a.capability.localeCompare(b.capability),
  );
  return {
    assertions,
    writeContext: tokens.some((token) => WRITE_TOKENS.has(token)),
    unclassified: assertions.length === 0,
  };
}
```

- [ ] **Step 4: 运行测试**

Run: `pnpm --filter @podsec/graph test -- classify`

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add packages/graph/src/classify.ts packages/graph/src/classify.test.ts
git commit -m "feat(graph): D2 能力分类器"
```

---

## Task 3: 毒性规则引擎

**Files:**
- Create: `packages/graph/src/toxic.ts`
- Create: `packages/graph/src/toxic.test.ts`

- [ ] **Step 1: 写失败测试**

```ts
import { describe, expect, it } from 'vitest';
import type { CapabilityGraph } from './types.js';
import { findToxicPaths } from './toxic.js';

function graphWithAgents(): CapabilityGraph {
  const nodes = [
    { id: 'agent:a', type: 'agent' as const, agent: 'a' },
    { id: 'agent:b', type: 'agent' as const, agent: 'b' },
    { id: 'server:s', type: 'server' as const, server: 's' },
    { id: 'tool:s.read_file', type: 'tool' as const, server: 's', tool: 'read_file' },
    { id: 'tool:s.send_email', type: 'tool' as const, server: 's', tool: 'send_email' },
    { id: 'tool:s.execute_command', type: 'tool' as const, server: 's', tool: 'execute_command' },
    { id: 'tool:s.http_request', type: 'tool' as const, server: 's', tool: 'http_request' },
    { id: 'tool:s.delete_file', type: 'tool' as const, server: 's', tool: 'delete_file', writeContext: true },
  ];
  const edges = [
    { from: 'agent:a', to: 'server:s', type: 'connects' as const },
    { from: 'agent:b', to: 'server:s', type: 'connects' as const },
    { from: 'server:s', to: 'tool:s.read_file', type: 'exposes' as const },
    { from: 'server:s', to: 'tool:s.send_email', type: 'exposes' as const },
    { from: 'server:s', to: 'tool:s.execute_command', type: 'exposes' as const },
    { from: 'server:s', to: 'tool:s.http_request', type: 'exposes' as const },
    { from: 'server:s', to: 'tool:s.delete_file', type: 'exposes' as const },
    { from: 'tool:s.read_file', to: 'capability:read-secret', type: 'has_capability' as const, confidence: 0.7, evidence: ['name'] },
    { from: 'tool:s.send_email', to: 'capability:external-communication', type: 'has_capability' as const, confidence: 0.8, evidence: ['name'] },
    { from: 'tool:s.execute_command', to: 'capability:exec', type: 'has_capability' as const, confidence: 0.9, evidence: ['name'] },
    { from: 'tool:s.http_request', to: 'capability:read-untrusted-input', type: 'has_capability' as const, confidence: 0.5, evidence: ['schema'] },
    { from: 'tool:s.delete_file', to: 'capability:destructive-write', type: 'has_capability' as const, confidence: 0.9, evidence: ['name'] },
  ];
  return {
    schema_version: '0.1.0',
    source: 'static',
    generated_at: '2026-09-09T00:00:00.000Z',
    meta: { tool_version: '0.1.0', config_fingerprint: 'sha256:x', warnings: [] },
    nodes,
    edges,
  };
}

describe('findToxicPaths', () => {
  it('finds intra-agent exfiltration and injection-exec', () => {
    const { paths } = findToxicPaths(graphWithAgents(), { minConfidence: 0.4 });
    const rules = paths.map((p) => p.rule);
    expect(rules).toContain('exfiltration');
    expect(rules).toContain('injection-exec');
    expect(rules).toContain('destruction');
  });

  it('does not pair across agents by default, but does with crossAgent', () => {
    const graph = graphWithAgents();
    const intra = findToxicPaths(graph, { minConfidence: 0.4 });
    expect(intra.paths.every((p) => p.kind === 'intra-agent')).toBe(true);
    const cross = findToxicPaths(graph, { minConfidence: 0.4, crossAgent: true });
    expect(cross.paths.some((p) => p.kind === 'cross-agent')).toBe(true);
  });

  it('filters by minConfidence and caps maxPaths while counting total', () => {
    const { paths, total } = findToxicPaths(graphWithAgents(), { minConfidence: 0.4, maxPaths: 1 });
    expect(paths).toHaveLength(1);
    expect(total).toBeGreaterThan(1);
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pnpm --filter @podsec/graph test -- toxic`

Expected: FAIL（`toxic.ts` 不存在）。

- [ ] **Step 3: 实现规则引擎**

先追加导出：在 `packages/graph/src/index.ts` 末尾加 `export * from './toxic.js';`。

`packages/graph/src/toxic.ts`：

```ts
import type {
  Capability,
  CapabilityAssertion,
  CapabilityGraph,
  PathEndpoint,
  ToolRef,
  ToxicPath,
} from './types.js';

export interface ToxicRule {
  id: string;
  severity: 'high' | 'medium';
  sources: Capability[];
  sinks: Capability[];
  rationale: string;
}

export const TOXIC_RULES: ToxicRule[] = [
  {
    id: 'exfiltration',
    severity: 'high',
    sources: ['read-secret', 'read-private-data'],
    sinks: ['external-communication'],
    rationale: '敏感数据可被读取，同时存在外发通道，构成数据外泄链。',
  },
  {
    id: 'injection-exec',
    severity: 'high',
    sources: ['read-untrusted-input'],
    sinks: ['exec'],
    rationale: '可读外部不可信内容，同时可执行命令，构成注入→执行链。',
  },
  {
    id: 'injection-exfil',
    severity: 'medium',
    sources: ['read-untrusted-input'],
    sinks: ['external-communication'],
    rationale: '可读外部内容并可外发，存在被注入后外泄的风险。',
  },
  {
    id: 'credential-abuse',
    severity: 'high',
    sources: ['credential-access'],
    sinks: ['exec', 'external-communication'],
    rationale: '可获取凭据并具备执行/外发能力，构成凭据滥用链。',
  },
];

export interface FindToxicOptions {
  crossAgent?: boolean;
  minConfidence?: number;
  maxPaths?: number;
}

export function buildToolRefs(graph: CapabilityGraph): ToolRef[] {
  const agentsByServer = new Map<string, string[]>();
  for (const edge of graph.edges) {
    if (edge.type !== 'connects') continue;
    const server = edge.to.replace(/^server:/, '');
    const agent = edge.from.replace(/^agent:/, '');
    const list = agentsByServer.get(server);
    if (list) list.push(agent);
    else agentsByServer.set(server, [agent]);
  }

  const toolsByServer = new Map<string, { nodeId: string; server: string; tool: string; writeContext: boolean }>();
  for (const node of graph.nodes) {
    if (node.type !== 'tool' || !node.server || !node.tool) continue;
    toolsByServer.set(node.id, {
      nodeId: node.id,
      server: node.server,
      tool: node.tool,
      writeContext: node.writeContext === true,
    });
  }

  const capabilitiesByTool = new Map<string, CapabilityAssertion[]>();
  for (const edge of graph.edges) {
    if (edge.type !== 'has_capability') continue;
    const capability = edge.to.replace(/^capability:/, '') as Capability;
    const list = capabilitiesByTool.get(edge.from);
    const assertion: CapabilityAssertion = {
      capability,
      confidence: edge.confidence ?? 0.5,
      origin: edge.origin ?? 'heuristic',
      evidence: edge.evidence ?? [],
    };
    if (list) list.push(assertion);
    else capabilitiesByTool.set(edge.from, [assertion]);
  }

  const refs: ToolRef[] = [];
  for (const tool of toolsByServer.values()) {
    const agents = agentsByServer.get(tool.server) ?? [];
    for (const agent of agents) {
      refs.push({
        agent,
        server: tool.server,
        tool: tool.tool,
        nodeId: tool.nodeId,
        writeContext: tool.writeContext,
        capabilities: capabilitiesByTool.get(tool.nodeId) ?? [],
      });
    }
  }
  return refs;
}

function endpoint(ref: ToolRef, assertion: CapabilityAssertion): PathEndpoint {
  return {
    agent: ref.agent,
    server: ref.server,
    tool: ref.tool,
    capability: assertion.capability,
    confidence: assertion.confidence,
  };
}

function assertionsFor(ref: ToolRef, capabilities: Capability[]): CapabilityAssertion[] {
  return ref.capabilities.filter((a) => capabilities.includes(a.capability));
}

export function findToxicPaths(
  graph: CapabilityGraph,
  opts: FindToxicOptions = {},
): { paths: ToxicPath[]; total: number } {
  const minConfidence = opts.minConfidence ?? 0.5;
  const maxPaths = opts.maxPaths ?? 20;
  const refs = buildToolRefs(graph);
  const byAgent = new Map<string, ToolRef[]>();
  for (const ref of refs) {
    const list = byAgent.get(ref.agent);
    if (list) list.push(ref);
    else byAgent.set(ref.agent, [ref]);
  }

  const candidates: ToxicPath[] = [];
  let seq = 0;
  const makePath = (
    kind: 'intra-agent' | 'cross-agent',
    rule: ToxicRule,
    sourceRef: ToolRef,
    sourceAssertion: CapabilityAssertion,
    sinkRef: ToolRef,
    sinkAssertion: CapabilityAssertion,
  ): ToxicPath => {
    const confidence = Number(Math.min(sourceAssertion.confidence, sinkAssertion.confidence).toFixed(2));
    const source = endpoint(sourceRef, sourceAssertion);
    const sink = endpoint(sinkRef, sinkAssertion);
    return {
      id: `path-${String(++seq).padStart(3, '0')}`,
      kind,
      rule: rule.id,
      severity: rule.severity,
      confidence,
      source,
      sink,
      amplifier: null,
      evidence: [
        `${source.agent}.${source.server}.${source.tool} → ${source.capability} (${source.confidence})`,
        `${sink.agent}.${sink.server}.${sink.tool} → ${sink.capability} (${sink.confidence})`,
      ],
      explain:
        `${source.agent} 的 ${source.tool} 具备 ${source.capability}，` +
        `${sink.agent} 的 ${sink.tool} 具备 ${sink.capability}；${rule.rationale}`,
      suggested_diff: null,
    };
  };

  for (const rule of TOXIC_RULES) {
    for (const [agent, agentRefs] of byAgent) {
      const sources = agentRefs.flatMap((ref) =>
        assertionsFor(ref, rule.sources).map((a) => ({ ref, assertion: a })),
      );
      const sinks = agentRefs.flatMap((ref) =>
        assertionsFor(ref, rule.sinks).map((a) => ({ ref, assertion: a })),
      );
      for (const source of sources) {
        for (const sink of sinks) {
          if (source.ref.nodeId === sink.ref.nodeId) continue;
          if (Math.min(source.assertion.confidence, sink.assertion.confidence) < minConfidence) continue;
          candidates.push(makePath('intra-agent', rule, source.ref, source.assertion, sink.ref, sink.assertion));
        }
      }
    }

    if (opts.crossAgent) {
      const agents = [...byAgent.keys()];
      for (const sourceAgent of agents) {
        for (const sinkAgent of agents) {
          if (sourceAgent === sinkAgent) continue;
          const sources = (byAgent.get(sourceAgent) ?? []).flatMap((ref) =>
            assertionsFor(ref, rule.sources).map((a) => ({ ref, assertion: a })),
          );
          const sinks = (byAgent.get(sinkAgent) ?? []).flatMap((ref) =>
            assertionsFor(ref, rule.sinks).map((a) => ({ ref, assertion: a })),
          );
          for (const source of sources) {
            for (const sink of sinks) {
              if (Math.min(source.assertion.confidence, sink.assertion.confidence) < minConfidence) continue;
              candidates.push(
                makePath('cross-agent', rule, source.ref, source.assertion, sink.ref, sink.assertion),
              );
            }
          }
        }
      }
    }
  }

  for (const [agent, agentRefs] of byAgent) {
    const destructive = agentRefs.filter((ref) =>
      ref.capabilities.some((a) => a.capability === 'destructive-write'),
    );
    const hasWrite = agentRefs.some((ref) => ref.writeContext);
    if (!hasWrite || destructive.length === 0) continue;
    for (const ref of destructive) {
      const assertion = ref.capabilities.find((a) => a.capability === 'destructive-write')!;
      if (assertion.confidence < minConfidence) continue;
      candidates.push({
        id: `path-${String(++seq).padStart(3, '0')}`,
        kind: 'intra-agent',
        rule: 'destruction',
        severity: 'medium',
        confidence: assertion.confidence,
        source: endpoint(ref, assertion),
        sink: endpoint(ref, assertion),
        amplifier: null,
        evidence: [`${agent} 同时具备写能力与破坏性工具 ${ref.tool}`],
        explain: `${agent} 同时具备写能力与破坏性工具，存在不可逆破坏风险。`,
        suggested_diff: null,
      });
    }
  }

  const seen = new Set<string>();
  const deduped = candidates.filter((path) => {
    const key = `${path.rule}|${path.kind}|${path.source.agent}.${path.source.tool}|${path.sink.agent}.${path.sink.tool}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  deduped.sort(
    (a, b) =>
      (a.severity === b.severity ? 0 : a.severity === 'high' ? -1 : 1) ||
      b.confidence - a.confidence ||
      a.id.localeCompare(b.id),
  );
  const total = deduped.length;
  return { paths: deduped.slice(0, maxPaths), total };
}
```

- [ ] **Step 4: 运行测试**

Run: `pnpm --filter @podsec/graph test -- toxic`

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add packages/graph/src/toxic.ts packages/graph/src/toxic.test.ts
git commit -m "feat(graph): 毒性规则引擎"
```

---

## Task 4: 策略 diff 建议器与报告

**Files:**
- Create: `packages/graph/src/diff.ts`
- Create: `packages/graph/src/diff.test.ts`
- Create: `packages/graph/src/report.ts`
- Create: `packages/graph/src/report.test.ts`

- [ ] **Step 1: 写失败测试**

```ts
import { describe, expect, it } from 'vitest';
import type { Policy } from '@podsec/policy';
import { suggestDiff } from './diff.js';
import type { ToxicPath } from './types.js';

const policy: Policy = {
  version: '0.1.0',
  agent: 'a',
  defaultDecision: 'deny',
  servers: { s: { allow: ['read_file', 'send_email'] } },
};

const path: ToxicPath = {
  id: 'path-001',
  kind: 'intra-agent',
  rule: 'exfiltration',
  severity: 'high',
  confidence: 0.7,
  source: { agent: 'a', server: 's', tool: 'read_file', capability: 'read-secret', confidence: 0.7 },
  sink: { agent: 'a', server: 's', tool: 'send_email', capability: 'external-communication', confidence: 0.8 },
  amplifier: null,
  evidence: [],
  explain: '',
  suggested_diff: null,
};

describe('suggestDiff', () => {
  it('tightens the sink from allow to approve first', () => {
    expect(suggestDiff(path, policy)).toMatchObject({ target: 's.send_email', from: 'allow', to: 'approve' });
  });

  it('returns null when the sink is already denied', () => {
    const denied: Policy = { ...policy, servers: { s: { deny: ['send_email'] } } };
    expect(suggestDiff(path, denied)).toBeNull();
  });
});
```

`packages/graph/src/report.test.ts`：

```ts
import { describe, expect, it } from 'vitest';
import { renderToxicReport } from './report.js';
import type { CapabilityGraph, ToxicPath } from './types.js';

const graph: CapabilityGraph = {
  schema_version: '0.1.0',
  source: 'static',
  generated_at: '2026-09-09T00:00:00.000Z',
  meta: { tool_version: '0.1.0', config_fingerprint: 'sha256:x', warnings: [] },
  nodes: [],
  edges: [],
};

const path: ToxicPath = {
  id: 'path-001',
  kind: 'intra-agent',
  rule: 'exfiltration',
  severity: 'high',
  confidence: 0.7,
  source: { agent: 'a', server: 's', tool: 'read_file', capability: 'read-secret', confidence: 0.7 },
  sink: { agent: 'a', server: 's', tool: 'send_email', capability: 'external-communication', confidence: 0.8 },
  amplifier: null,
  evidence: ['e1'],
  explain: 'why',
  suggested_diff: null,
};

describe('renderToxicReport', () => {
  it('renders path id, rule and counts', () => {
    const text = renderToxicReport({ graph, paths: [path], total: 1, maxPaths: 20, minConfidence: 0.5 });
    expect(text).toContain('path-001');
    expect(text).toContain('exfiltration');
    expect(text).toContain('高危（1）');
  });

  it('renders a clear no-path message', () => {
    const text = renderToxicReport({ graph, paths: [], total: 0, maxPaths: 20, minConfidence: 0.5 });
    expect(text).toContain('未发现毒性路径');
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pnpm --filter @podsec/graph test -- diff report`

Expected: FAIL。

- [ ] **Step 3: 实现**

先追加导出：在 `packages/graph/src/index.ts` 末尾加：

```ts
export * from './diff.js';
export * from './report.js';
```

`packages/graph/src/diff.ts`：

```ts
import type { Policy } from '@podsec/policy';
import type { PolicyDiffHint, ToxicPath } from './types.js';

export function decisionFor(
  policy: Policy,
  server: string,
  tool: string,
): 'allow' | 'approve' | 'deny' | '(unlisted)' {
  const rules = policy.servers?.[server];
  if (!rules) return '(unlisted)';
  if (rules.deny?.includes(tool)) return 'deny';
  if (rules.approve?.includes(tool)) return 'approve';
  if (rules.allow?.includes(tool)) return 'allow';
  return '(unlisted)';
}

export function suggestDiff(path: ToxicPath, policy: Policy): PolicyDiffHint | null {
  const sink = decisionFor(policy, path.sink.server, path.sink.tool);
  if (sink === 'deny') return null;
  if (sink === 'allow' || sink === '(unlisted)') {
    return {
      target: `${path.sink.server}.${path.sink.tool}`,
      from: sink,
      to: 'approve',
      rationale: 'sink 是链路末端；改为审批可保留可用性，同时阻断自动外发。',
    };
  }
  const source = decisionFor(policy, path.source.server, path.source.tool);
  if (source === 'allow' || source === '(unlisted)') {
    return {
      target: `${path.source.server}.${path.source.tool}`,
      from: source,
      to: 'approve',
      rationale: 'sink 已需审批，收紧 source 可进一步降低自动触发的风险。',
    };
  }
  if (source === 'approve') {
    return {
      target: `${path.source.server}.${path.source.tool}`,
      from: 'approve',
      to: 'deny',
      rationale: '两端均已需审批；若要彻底断链，需 deny source（会改变工作流，需人工确认）。',
    };
  }
  return null;
}
```

`packages/graph/src/report.ts`：

```ts
import type { CapabilityGraph, ToxicPath } from './types.js';

export interface ToxicReportInput {
  graph: CapabilityGraph;
  paths: ToxicPath[];
  total: number;
  maxPaths: number;
  minConfidence: number;
}

export function renderGraphSummary(graph: CapabilityGraph): string {
  const agents = graph.nodes.filter((n) => n.type === 'agent').length;
  const servers = graph.nodes.filter((n) => n.type === 'server').length;
  const tools = graph.nodes.filter((n) => n.type === 'tool').length;
  const lines = [
    `# pod graph（${graph.source}）`,
    '',
    `生成时间：${graph.generated_at}`,
    `agent：${agents} · server：${servers} · tool：${tools}`,
    `配置指纹：${graph.meta.config_fingerprint}`,
  ];
  if (graph.meta.warnings.length > 0) {
    lines.push('', '## 警告');
    for (const warning of graph.meta.warnings) {
      lines.push(`- [${warning.code}] ${warning.message}${warning.where ? `（${warning.where}）` : ''}`);
    }
  }
  return lines.join('\n');
}

export function renderToxicReport(input: ToxicReportInput): string {
  const { graph, paths, total, maxPaths, minConfidence } = input;
  const lines = ['# pod graph toxic — 毒性路径', ''];
  lines.push(`生成时间：${graph.generated_at}`);
  lines.push(`阈值：min-confidence=${minConfidence} · max-paths=${maxPaths}`);
  lines.push('');
  if (graph.meta.warnings.length > 0) {
    lines.push('## 警告');
    for (const warning of graph.meta.warnings) {
      lines.push(`- [${warning.code}] ${warning.message}${warning.where ? `（${warning.where}）` : ''}`);
    }
    lines.push('');
  }
  if (paths.length === 0) {
    lines.push('未发现毒性路径。');
    return lines.join('\n');
  }
  const high = paths.filter((p) => p.severity === 'high');
  const medium = paths.filter((p) => p.severity === 'medium');
  lines.push(`## 高危（${high.length}）`);
  lines.push('');
  for (const path of high) lines.push(...renderPath(path));
  if (medium.length > 0) {
    lines.push(`## 中危（${medium.length}）`);
    lines.push('');
    for (const path of medium) lines.push(...renderPath(path));
  }
  if (total > paths.length) {
    lines.push(`> 还有 ${total - paths.length} 条路径未显示；用 --max-paths 调整。`);
  }
  return lines.join('\n');
}

function renderPath(path: ToxicPath): string[] {
  const lines = [
    `### ${path.id}  ${path.rule}（${path.kind}，置信度 ${path.confidence}）`,
    `  ${path.source.agent}.${path.source.server}.${path.source.tool} [${path.source.capability} ${path.source.confidence}]`,
    `    └─▶ ${path.sink.agent}.${path.sink.server}.${path.sink.tool} [${path.sink.capability} ${path.sink.confidence}]`,
    `  说明：${path.explain}`,
  ];
  if (path.suggested_diff) {
    lines.push(
      `  建议：将 ${path.suggested_diff.target} 从 ${path.suggested_diff.from} 改为 ${path.suggested_diff.to}`,
    );
    lines.push(`  理由：${path.suggested_diff.rationale}`);
  }
  lines.push('');
  return lines;
}
```

- [ ] **Step 4: 运行测试**

Run: `pnpm --filter @podsec/graph test -- diff report`

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add packages/graph/src/diff.ts packages/graph/src/diff.test.ts packages/graph/src/report.ts packages/graph/src/report.test.ts
git commit -m "feat(graph): 策略 diff 建议器与报告渲染"
```

---

## Task 5: Policy 能力覆盖字段

**Files:**
- Modify: `packages/policy/src/index.ts`
- Modify: `packages/policy/src/index.test.ts`

- [ ] **Step 1: 写失败测试**

在 `packages/policy/src/index.test.ts` 末尾加：

```ts
describe('capability overrides', () => {
  it('accepts and preserves capabilities without affecting evaluation', () => {
    const policy: Policy = {
      version: '0.1.0',
      agent: 'a',
      defaultDecision: 'deny',
      servers: { s: { allow: ['acme_sync'] } },
      capabilities: { 's.acme_sync': ['external-communication'] },
    };
    expect(evaluate(policy, { agent: 'a', server: 's', tool: 'acme_sync' }).decision).toBe('allow');
    expect(lintPolicy(policy).filter((i) => i.severity === 'error')).toEqual([]);
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pnpm --filter @podsec/policy test`

Expected: FAIL（`capabilities` 不在 `Policy` 类型上）。

- [ ] **Step 3: 加字段**

在 `packages/policy/src/index.ts` 的 `Policy` 接口中、`secrets?: SecretRules;` 之前加：

```ts
  /**
   * 能力覆盖（由 @podsec/graph 消费）：键为 "server.tool" 或 "tool"，
   * 值为 D2 能力标签。policy 引擎本身不解释该字段。
   */
  capabilities?: Record<string, string[]>;
```

- [ ] **Step 4: 运行测试**

Run: `pnpm --filter @podsec/policy test && pnpm typecheck`

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add packages/policy/src/index.ts packages/policy/src/index.test.ts
git commit -m "feat(policy): 支持能力覆盖字段"
```

---

## Task 6: 图文件 IO 与 schema 缓存

**Files:**
- Create: `apps/cli/src/graph/types.ts`
- Create: `apps/cli/src/graph/io.ts`
- Create: `apps/cli/src/graph/schema-cache.ts`
- Create: `apps/cli/test/graph-io.test.ts`

- [ ] **Step 1: 写失败测试**

```ts
import { describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GRAPH_SCHEMA_VERSION, type CapabilityGraph } from '@podsec/graph';
import { readGraphFile, writeGraph } from '../src/graph/io.js';
import { cacheKey, readSchemaCache, writeSchemaCache } from '../src/graph/schema-cache.js';

const graph: CapabilityGraph = {
  schema_version: GRAPH_SCHEMA_VERSION,
  source: 'static',
  generated_at: '2026-09-09T00:00:00.000Z',
  meta: { tool_version: '0.1.0', config_fingerprint: 'sha256:x', warnings: [] },
  nodes: [],
  edges: [],
};

describe('graph io', () => {
  it('writes atomically and reads back', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-graph-io-'));
    const path = join(dir, 'potential.json');
    writeGraph(path, graph);
    expect(readGraphFile(path)).toEqual(graph);
  });

  it('rejects a corrupt graph file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-graph-io-bad-'));
    const path = join(dir, 'potential.json');
    writeFileSync(path, '{bad', 'utf8');
    expect(() => readGraphFile(path)).toThrow(/not valid JSON/);
  });
});

describe('schema cache', () => {
  it('round-trips tool descriptors', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-graph-cache-'));
    const key = cacheKey('node', ['server.js']);
    expect(readSchemaCache(dir, key)).toBeNull();
    writeSchemaCache(dir, key, [{ name: 'read_file' }]);
    expect(readSchemaCache(dir, key)).toEqual([{ name: 'read_file' }]);
    expect(readFileSync(join(dir, `${key}.json`), 'utf8')).toContain('read_file');
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pnpm vitest run apps/cli/test/graph-io.test.ts`

Expected: FAIL。

- [ ] **Step 3: 实现**

`apps/cli/src/graph/types.ts`：

```ts
export interface ToolDescriptor {
  name: string;
  description?: string;
  inputSchema?: unknown;
}
```

`apps/cli/src/graph/io.ts`：

```ts
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { parseGraph, serializeGraph, type CapabilityGraph, type ToxicPath } from '@podsec/graph';

export function graphDir(home = homedir()): string {
  return join(home, '.pod', 'graph');
}

export function writeFileAtomic(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, content, 'utf8');
  renameSync(tmp, path);
}

export function writeGraph(path: string, graph: CapabilityGraph): void {
  writeFileAtomic(path, serializeGraph(graph));
}

export function readGraphFile(path: string): CapabilityGraph {
  return parseGraph(readFileSync(path, 'utf8'));
}

export function writePaths(path: string, paths: ToxicPath[]): void {
  writeFileAtomic(path, JSON.stringify(paths, null, 2) + '\n');
}

export function readPaths(path: string): ToxicPath[] {
  return JSON.parse(readFileSync(path, 'utf8')) as ToxicPath[];
}
```

`apps/cli/src/graph/schema-cache.ts`：

```ts
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ToolDescriptor } from './types.js';

export function cacheKey(command: string, args: string[]): string {
  return createHash('sha256').update(JSON.stringify({ command, args })).digest('hex').slice(0, 16);
}

export function readSchemaCache(dir: string, key: string): ToolDescriptor[] | null {
  const path = join(dir, `${key}.json`);
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as ToolDescriptor[];
  } catch {
    return null;
  }
}

export function writeSchemaCache(dir: string, key: string, tools: ToolDescriptor[]): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${key}.json`), JSON.stringify(tools, null, 2) + '\n', 'utf8');
}
```

- [ ] **Step 4: 运行测试**

Run: `pnpm vitest run apps/cli/test/graph-io.test.ts`

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add apps/cli/src/graph/io.ts apps/cli/src/graph/schema-cache.ts apps/cli/test/graph-io.test.ts
git commit -m "feat(graph): 图文件 IO 与 schema 缓存"
```

---

## Task 7: MCP introspection 适配器

**Files:**
- Create: `apps/cli/src/graph/introspect.ts`
- Create: `apps/cli/test/fixtures/graph/danger-server.ts`
- Create: `apps/cli/test/fixtures/graph/hanging-server.ts`
- Create: `apps/cli/test/graph-introspect.test.ts`

- [ ] **Step 1: 写失败测试**

`apps/cli/test/graph-introspect.test.ts`：

```ts
import { describe, expect, it } from 'vitest';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { IntrospectionTimeoutError, introspectTools, safeEnv } from '../src/graph/introspect.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const DANGER = join(HERE, 'fixtures/graph/danger-server.ts');
const HANGING = join(HERE, 'fixtures/graph/hanging-server.ts');

describe('safeEnv', () => {
  it('keeps only allowlisted vars plus declared ones', () => {
    const env = safeEnv({ PATH: '/bin', HOME: '/home/x', OPENAI_API_KEY: 'sk-secret' }, { ACME_TOKEN: 't' });
    expect(env.PATH).toBe('/bin');
    expect(env.ACME_TOKEN).toBe('t');
    expect(env.OPENAI_API_KEY).toBeUndefined();
  });
});

describe('introspectTools', () => {
  it('lists tools from a real MCP server', async () => {
    const tools = await introspectTools({
      command: process.execPath,
      args: ['--import', 'tsx', DANGER],
      timeoutMs: 10_000,
    });
    expect(tools.map((t) => t.name)).toEqual([
      'read_file', 'send_email', 'execute_command', 'delete_file', 'http_request',
    ]);
  });

  it('times out instead of hanging forever', async () => {
    await expect(
      introspectTools({ command: process.execPath, args: ['--import', 'tsx', HANGING], timeoutMs: 500 }),
    ).rejects.toBeInstanceOf(IntrospectionTimeoutError);
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pnpm vitest run apps/cli/test/graph-introspect.test.ts`

Expected: FAIL。

- [ ] **Step 3: 实现**

`apps/cli/src/graph/introspect.ts`：

```ts
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { ToolDescriptor } from './types.js';

export type { ToolDescriptor };

export const ENV_ALLOWLIST = [
  'PATH', 'HOME', 'SHELL', 'TERM', 'LANG', 'LC_ALL', 'USER', 'LOGNAME', 'TMPDIR',
];

export function safeEnv(base: NodeJS.ProcessEnv, declared?: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of ENV_ALLOWLIST) {
    const value = base[key];
    if (typeof value === 'string') out[key] = value;
  }
  for (const [key, value] of Object.entries(declared ?? {})) out[key] = value;
  return out;
}

export class IntrospectionTimeoutError extends Error {}

export interface IntrospectOptions {
  command: string;
  args: string[];
  declaredEnv?: Record<string, string>;
  timeoutMs: number;
  maxTools?: number;
}

export async function introspectTools(opts: IntrospectOptions): Promise<ToolDescriptor[]> {
  const transport = new StdioClientTransport({
    command: opts.command,
    args: opts.args,
    env: safeEnv(process.env, opts.declaredEnv),
  });
  const client = new Client({ name: 'pod-graph-introspect', version: '0.1.0' }, { capabilities: {} });
  await client.connect(transport);
  try {
    const result = await Promise.race([
      client.listTools(),
      new Promise<never>((_, reject) => {
        setTimeout(
          () => reject(new IntrospectionTimeoutError(`tools/list timed out after ${opts.timeoutMs}ms`)),
          opts.timeoutMs,
        ).unref();
      }),
    ]);
    return result.tools
      .slice(0, opts.maxTools ?? 500)
      .map((tool) => ({ name: tool.name, description: tool.description, inputSchema: tool.inputSchema }));
  } finally {
    await transport.close().catch(() => {});
  }
}
```

`apps/cli/test/fixtures/graph/danger-server.ts`：

```ts
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const server = new Server({ name: 'danger-fixture', version: '0.1.0' }, { capabilities: { tools: {} } });
const TOOLS = [
  { name: 'read_file', description: 'Read a file', inputSchema: { type: 'object', properties: { path: { type: 'string' } } } },
  { name: 'send_email', description: 'Send an email', inputSchema: { type: 'object', properties: { to: { type: 'string' }, body: { type: 'string' } } } },
  { name: 'execute_command', description: 'Run a shell command', inputSchema: { type: 'object', properties: { command: { type: 'string' } } } },
  { name: 'delete_file', description: 'Delete a file', inputSchema: { type: 'object', properties: { path: { type: 'string' } } } },
  { name: 'http_request', description: 'Make an HTTP request', inputSchema: { type: 'object', properties: { url: { type: 'string' }, method: { type: 'string' }, body: { type: 'string' } } } },
];

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
server.setRequestHandler(CallToolRequestSchema, async () => ({ content: [{ type: 'text', text: 'ok' }] }));
await server.connect(new StdioServerTransport());
```

`apps/cli/test/fixtures/graph/hanging-server.ts`：

```ts
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const server = new Server({ name: 'hanging-fixture', version: '0.1.0' }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => new Promise(() => {}));
await server.connect(new StdioServerTransport());
```

- [ ] **Step 4: 运行测试**

Run: `pnpm vitest run apps/cli/test/graph-introspect.test.ts`

Expected: PASS（2 个测试，超时测试约 500ms）。

- [ ] **Step 5: 提交**

```bash
git add apps/cli/src/graph/introspect.ts apps/cli/test/fixtures/graph apps/cli/test/graph-introspect.test.ts
git commit -m "feat(graph): MCP introspection（env 白名单 + 超时）"
```

---

## Task 8: 静态图构建器

**Files:**
- Create: `apps/cli/src/graph/static.ts`
- Create: `apps/cli/test/graph-static.test.ts`
- Modify: `apps/cli/src/onboard.ts`（`DiscoverOptions.onWarning`，用于报告不可读配置）

- [ ] **Step 1: 写失败测试**

```ts
import { describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildStaticGraph } from '../src/graph/static.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const DANGER = join(HERE, 'fixtures/graph/danger-server.ts');

function fixtureHome(): string {
  const home = mkdtempSync(join(tmpdir(), 'pod-graph-static-'));
  mkdirSync(join(home, '.claude'), { recursive: true });
  writeFileSync(
    join(home, '.claude.json'),
    JSON.stringify({
      mcpServers: {
        demo: { command: process.execPath, args: ['--import', 'tsx', DANGER] },
      },
    }),
    'utf8',
  );
  return home;
}

describe('buildStaticGraph', () => {
  it('discovers tools and classifies them', async () => {
    const home = fixtureHome();
    const { graph } = await buildStaticGraph({
      home,
      noExec: false,
      timeoutMs: 10_000,
      cacheDir: join(home, '.pod', 'graph', 'schema-cache'),
      policy: null,
    });
    expect(graph.nodes.filter((n) => n.type === 'agent')).toHaveLength(1);
    expect(graph.nodes.filter((n) => n.type === 'tool')).toHaveLength(5);
    const read = graph.edges.find((e) => e.from === 'tool:demo.read_file' && e.to === 'capability:read-private-data');
    expect(read?.confidence).toBeGreaterThan(0);
  });

  it('falls back to name heuristics with noExec and warns schema_missing', async () => {
    const home = fixtureHome();
    const { graph } = await buildStaticGraph({
      home,
      noExec: true,
      timeoutMs: 1_000,
      cacheDir: join(home, '.pod', 'graph', 'schema-cache'),
      policy: null,
    });
    expect(graph.meta.warnings.some((w) => w.code === 'schema_missing')).toBe(true);
    expect(graph.nodes.filter((n) => n.type === 'tool')).toHaveLength(0);
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pnpm vitest run apps/cli/test/graph-static.test.ts`

Expected: FAIL。

- [ ] **Step 3: 实现**

先修改 `apps/cli/src/onboard.ts`：在 `DiscoverOptions` 加可选回调，并在 JSON 解析失败时上报：

```ts
export interface DiscoverOptions {
  home: string;
  config?: string;
  agent?: string;
  /** 配置不可读/不可解析时上报（pod graph build 用于产出 config_unreadable 警告） */
  onWarning?: (warning: { path: string; message: string }) => void;
}
```

在 `discoverTargets` 的 `try { raw = JSON.parse(readFileSync(c.path, 'utf8')); } catch { continue; }` 中，把 `continue` 前加上：

```ts
      opts.onWarning?.({
        path: c.path,
        message: `无法解析 ${c.path}：${err instanceof Error ? err.message : String(err)}`,
      });
```

（若现有 catch 没有绑定 `err`，改为 `catch (err) {`。）

`apps/cli/src/graph/static.ts`：

```ts
import { createHash } from 'node:crypto';
import type { Policy } from '@podsec/policy';
import { CAPABILITIES, classifyTool, type Capability, type CapabilityGraph, type GraphEdge, type GraphNode, type GraphWarning } from '@podsec/graph';
import { discoverTargets } from '../onboard.js';
import { introspectTools, type ToolDescriptor } from './introspect.js';
import { cacheKey, readSchemaCache, writeSchemaCache } from './schema-cache.js';

export interface BuildStaticOptions {
  home: string;
  config?: string;
  noExec: boolean;
  timeoutMs: number;
  cacheDir: string;
  policy: Policy | null;
}

function fingerprint(targets: ReturnType<typeof discoverTargets>): string {
  const payload = targets.map((t) => ({
    agent: t.agent,
    servers: t.servers.map((s) => ({ name: s.name, command: s.command, args: s.args })),
  }));
  return `sha256:${createHash('sha256').update(JSON.stringify(payload)).digest('hex').slice(0, 16)}`;
}

function overridesFor(policy: Policy | null, server: string, tool: string): Capability[] {
  const raw = policy?.capabilities?.[`${server}.${tool}`] ?? policy?.capabilities?.[tool] ?? [];
  return raw.filter((value): value is Capability => (CAPABILITIES as readonly string[]).includes(value));
}

export async function buildStaticGraph(opts: BuildStaticOptions): Promise<{ graph: CapabilityGraph }> {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const warnings: GraphWarning[] = [];
  const targets = discoverTargets({
    home: opts.home,
    config: opts.config,
    onWarning: (warning) =>
      warnings.push({ code: 'config_unreadable', message: warning.message, where: warning.path }),
  });

  const addNode = (node: GraphNode): void => {
    nodes.set(node.id, node);
  };

  for (const target of targets) {
    const agentId = `agent:${target.agent}`;
    addNode({ id: agentId, type: 'agent', agent: target.agent });
    for (const server of target.servers) {
      const serverId = `server:${server.name}`;
      addNode({ id: serverId, type: 'server', server: server.name, command: server.command });
      edges.push({ from: agentId, to: serverId, type: 'connects' });

      if (server.transport && server.transport !== 'stdio') {
        warnings.push({
          code: 'server_unintrospectable',
          message: `server "${server.name}" 使用非 stdio transport，Phase 1 不 introspection`,
          where: target.configPath,
        });
        continue;
      }

      const key = cacheKey(server.command, server.args);
      let tools: ToolDescriptor[] | null = readSchemaCache(opts.cacheDir, key);
      if (opts.noExec) {
        if (!tools) {
          warnings.push({
            code: 'schema_missing',
            message: `server "${server.name}" 无缓存 schema，仅按工具名启发式分类`,
            where: target.configPath,
          });
          tools = [];
        }
      } else {
        try {
          tools = await introspectTools({
            command: server.command,
            args: server.args,
            declaredEnv: server.env,
            timeoutMs: opts.timeoutMs,
          });
          writeSchemaCache(opts.cacheDir, key, tools);
        } catch (err) {
          warnings.push({
            code: 'server_unintrospectable',
            message: `server "${server.name}" introspection 失败：${err instanceof Error ? err.message : String(err)}`,
            where: target.configPath,
          });
          tools = tools ?? [];
        }
      }

      for (const tool of tools) {
        const toolId = `tool:${server.name}.${tool.name}`;
        const result = classifyTool(tool, overridesFor(opts.policy, server.name, tool.name));
        addNode({
          id: toolId,
          type: 'tool',
          server: server.name,
          tool: tool.name,
          writeContext: result.writeContext,
        });
        edges.push({ from: serverId, to: toolId, type: 'exposes' });
        for (const assertion of result.assertions) {
          const capabilityId = `capability:${assertion.capability}`;
          addNode({ id: capabilityId, type: 'capability' });
          edges.push({
            from: toolId,
            to: capabilityId,
            type: 'has_capability',
            confidence: assertion.confidence,
            origin: assertion.origin,
            evidence: assertion.evidence,
          });
        }
        if (result.unclassified) {
          warnings.push({
            code: 'unclassified',
            message: `tool "${server.name}.${tool.name}" 无法分类，需人工确认`,
            where: target.configPath,
          });
        }
      }
    }
  }

  return {
    graph: {
      schema_version: '0.1.0',
      source: 'static',
      generated_at: new Date().toISOString(),
      meta: {
        tool_version: '0.1.0',
        config_fingerprint: fingerprint(targets),
        warnings,
      },
      nodes: [...nodes.values()],
      edges,
    },
  };
}
```

- [ ] **Step 4: 运行测试**

Run: `pnpm vitest run apps/cli/test/graph-static.test.ts`

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add apps/cli/src/graph/static.ts apps/cli/test/graph-static.test.ts
git commit -m "feat(graph): 静态潜在图构建器"
```

---

## Task 9: `pod graph build` CLI

**Files:**
- Create: `apps/cli/src/graph/commands.ts`
- Modify: `apps/cli/src/index.ts`
- Modify: `apps/cli/package.json`（加 `@podsec/graph` 依赖）
- Create: `apps/cli/test/graph-build.test.ts`

- [ ] **Step 1: 写失败测试**

```ts
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '../src/index.ts');
const DANGER = join(HERE, 'fixtures/graph/danger-server.ts');

function fixtureHome(): string {
  const home = mkdtempSync(join(tmpdir(), 'pod-graph-build-'));
  writeFileSync(
    join(home, '.claude.json'),
    JSON.stringify({ mcpServers: { demo: { command: process.execPath, args: ['--import', 'tsx', DANGER] } } }),
    'utf8',
  );
  return home;
}

describe('pod graph build', () => {
  it('writes a potential graph and prints a summary', () => {
    const home = fixtureHome();
    const out = join(home, '.pod', 'graph', 'potential.json');
    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'build', '--home', home, '--out', out],
      { encoding: 'utf8', timeout: 30_000 },
    );
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('pod graph');
    const graph = JSON.parse(readFileSync(out, 'utf8'));
    expect(graph.source).toBe('static');
    expect(graph.nodes.some((n: { id: string }) => n.id === 'tool:demo.read_file')).toBe(true);
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pnpm vitest run apps/cli/test/graph-build.test.ts`

Expected: FAIL（unknown command: graph）。

- [ ] **Step 3: 实现命令与路由**

先在 `apps/cli/package.json` 的 `dependencies` 中加：

```json
"@podsec/graph": "workspace:*",
```

然后运行 `pnpm install`。

`apps/cli/src/graph/commands.ts`：

```ts
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { findToxicPaths, renderGraphSummary, renderToxicReport, suggestDiff, type ToxicPath } from '@podsec/graph';
import type { Policy } from '@podsec/policy';
import { buildStaticGraph } from './static.js';
import { graphDir, readGraphFile, readPaths, writeFileAtomic, writeGraph, writePaths } from './io.js';

export interface GraphBuildOptions {
  home: string;
  config?: string;
  noExec: boolean;
  timeoutMs: number;
  out: string;
  policyPath?: string;
  json: boolean;
}

export async function cmdGraphBuild(opts: GraphBuildOptions): Promise<number> {
  let policy: Policy | null = null;
  if (opts.policyPath) {
    try {
      policy = JSON.parse(readFileSync(opts.policyPath, 'utf8')) as Policy;
    } catch (err) {
      process.stderr.write(`policy unreadable: ${err instanceof Error ? err.message : String(err)}\n`);
      return 2;
    }
  }
  const { graph } = await buildStaticGraph({
    home: opts.home,
    config: opts.config,
    noExec: opts.noExec,
    timeoutMs: opts.timeoutMs,
    cacheDir: join(graphDir(opts.home), 'schema-cache'),
    policy,
  });
  writeGraph(opts.out, graph);
  if (opts.json) {
    process.stdout.write(JSON.stringify({ out: opts.out, graph }, null, 2) + '\n');
  } else {
    process.stdout.write(renderGraphSummary(graph) + '\n');
    process.stdout.write(`\n已写入：${opts.out}\n`);
  }
  return 0;
}

export interface GraphToxicOptions {
  graphPath: string;
  outDir: string;
  crossAgent: boolean;
  minConfidence: number;
  maxPaths: number;
  baselinePath?: string;
  json: boolean;
}

export function cmdGraphToxic(opts: GraphToxicOptions): number {
  if (!existsSync(opts.graphPath)) {
    process.stderr.write(`graph not found: ${opts.graphPath}\n`);
    return 2;
  }
  let graph;
  try {
    graph = readGraphFile(opts.graphPath);
  } catch (err) {
    process.stderr.write(`graph unreadable: ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }
  const { paths, total } = findToxicPaths(graph, {
    crossAgent: opts.crossAgent,
    minConfidence: opts.minConfidence,
    maxPaths: opts.maxPaths,
  });
  let policy: Policy | null = null;
  if (opts.baselinePath) {
    try {
      policy = JSON.parse(readFileSync(opts.baselinePath, 'utf8')) as Policy;
    } catch (err) {
      process.stderr.write(`baseline unreadable: ${err instanceof Error ? err.message : String(err)}\n`);
      return 2;
    }
  }
  const withDiff: ToxicPath[] = paths.map((path) => ({
    ...path,
    suggested_diff: policy ? suggestDiff(path, policy) : null,
  }));
  writePaths(join(opts.outDir, 'paths.json'), withDiff);
  writeFileAtomic(
    join(opts.outDir, 'report.md'),
    renderToxicReport({ graph, paths: withDiff, total, maxPaths: opts.maxPaths, minConfidence: opts.minConfidence }) + '\n',
  );
  if (policy) {
    const diff = withDiff
      .map((p) => p.suggested_diff)
      .filter((d): d is NonNullable<typeof d> => d !== null);
    writeFileAtomic(join(opts.outDir, 'policy-diff.json'), JSON.stringify(diff, null, 2) + '\n');
  }
  if (opts.json) {
    process.stdout.write(
      JSON.stringify({ total, paths: withDiff, warnings: graph.meta.warnings }, null, 2) + '\n',
    );
  } else {
    process.stdout.write(
      renderToxicReport({ graph, paths: withDiff, total, maxPaths: opts.maxPaths, minConfidence: opts.minConfidence }) + '\n',
    );
  }
  return withDiff.some((p) => p.severity === 'high') ? 1 : 0;
}

export interface GraphExplainOptions {
  pathsPath: string;
  id: string;
  json: boolean;
}

export function cmdGraphExplain(opts: GraphExplainOptions): number {
  if (!existsSync(opts.pathsPath)) {
    process.stderr.write(`paths not found: ${opts.pathsPath}\n`);
    return 2;
  }
  const paths = readPaths(opts.pathsPath);
  const path = paths.find((p) => p.id === opts.id);
  if (!path) {
    process.stderr.write(`path not found: ${opts.id}\n`);
    return 2;
  }
  if (opts.json) {
    process.stdout.write(JSON.stringify(path, null, 2) + '\n');
  } else {
    process.stdout.write(
      [
        `${path.id}  ${path.rule}（${path.kind}，置信度 ${path.confidence}）`,
        `source: ${path.source.agent}.${path.source.server}.${path.source.tool} [${path.source.capability}]`,
        `sink:   ${path.sink.agent}.${path.sink.server}.${path.sink.tool} [${path.sink.capability}]`,
        `说明:   ${path.explain}`,
        ...path.evidence.map((e) => `证据:   ${e}`),
        ...(path.suggested_diff
          ? [`建议:   ${path.suggested_diff.target} ${path.suggested_diff.from} → ${path.suggested_diff.to}`]
          : []),
      ].join('\n') + '\n',
    );
  }
  return 0;
}
```

在 `apps/cli/src/index.ts` 顶部加 import：

```ts
import { cmdGraphBuild, cmdGraphExplain, cmdGraphToxic } from './graph/commands.js';
import { graphDir } from './graph/io.js';
```

在 parseArgs options 中加：

```ts
      home: { type: 'string' },
      'no-exec': { type: 'boolean' },
      timeout: { type: 'string' },
      graph: { type: 'string' },
      'cross-agent': { type: 'boolean' },
      'min-confidence': { type: 'string' },
      'max-paths': { type: 'string' },
      'out-dir': { type: 'string' },
```

在 `if (cmd === 'onboard')` 之前加路由：

```ts
  if (cmd === 'graph') {
    const sub = positionals[1];
    const home = values.home ?? homedir();
    const outDir = values['out-dir'] ?? graphDir(home);
    if (sub === 'build') {
      const code = await cmdGraphBuild({
        home,
        config: values.config,
        noExec: values['no-exec'] === true,
        timeoutMs: Number.parseInt(values.timeout ?? '10000', 10),
        out: values.out ?? join(outDir, 'potential.json'),
        policyPath: values.policy,
        json: values.json === true,
      });
      process.exit(code);
    }
    if (sub === 'toxic') {
      const code = cmdGraphToxic({
        graphPath: values.graph ?? join(outDir, 'potential.json'),
        outDir,
        crossAgent: values['cross-agent'] === true,
        minConfidence: Number.parseFloat(values['min-confidence'] ?? '0.5'),
        maxPaths: Number.parseInt(values['max-paths'] ?? '20', 10),
        baselinePath: values.diff,
        json: values.json === true,
      });
      process.exit(code);
    }
    if (sub === 'explain') {
      const id = positionals[2];
      if (!id) {
        console.error('pod graph explain requires <path-id>');
        process.exit(1);
      }
      process.exit(cmdGraphExplain({ pathsPath: join(outDir, 'paths.json'), id, json: values.json === true }));
    }
    console.error(`unknown graph subcommand: ${sub ?? '(none)'} (available: build, toxic, explain)`);
    process.exit(1);
  }
```

在 usage 中加：

```text
  pod graph build [--home <dir>] [--config <path>] [--no-exec] [--timeout <ms>] [--out <file>] [--policy <file>] [--json]
  pod graph toxic [--graph <file>] [--out-dir <dir>] [--cross-agent] [--min-confidence <0-1>] [--max-paths <n>] [--diff <baseline.json>] [--json]
  pod graph explain <path-id> [--out-dir <dir>] [--json]
```

- [ ] **Step 4: 运行测试**

Run: `pnpm vitest run apps/cli/test/graph-build.test.ts`

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add apps/cli/src/graph/commands.ts apps/cli/src/index.ts apps/cli/test/graph-build.test.ts
git commit -m "feat(cli): pod graph build"
```

---

## Task 10: `pod graph toxic` CLI

**Files:**
- Create: `apps/cli/test/graph-toxic.test.ts`

- [ ] **Step 1: 写失败测试**

```ts
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '../src/index.ts');
const DANGER = join(HERE, 'fixtures/graph/danger-server.ts');

function builtHome(): string {
  const home = mkdtempSync(join(tmpdir(), 'pod-graph-toxic-'));
  writeFileSync(
    join(home, '.claude.json'),
    JSON.stringify({ mcpServers: { demo: { command: process.execPath, args: ['--import', 'tsx', DANGER] } } }),
    'utf8',
  );
  const res = spawnSync(process.execPath, ['--import', 'tsx', CLI, 'graph', 'build', '--home', home], {
    encoding: 'utf8',
    timeout: 30_000,
  });
  expect(res.status).toBe(0);
  return home;
}

describe('pod graph toxic', () => {
  it('writes paths/report/policy-diff and exits 1 on high severity', () => {
    const home = builtHome();
    const outDir = join(home, '.pod', 'graph');
    const baseline = join(home, 'baseline.json');
    writeFileSync(
      baseline,
      JSON.stringify({
        version: '0.1.0',
        agent: 'claude-code',
        defaultDecision: 'deny',
        servers: { demo: { allow: ['read_file', 'send_email', 'execute_command', 'http_request', 'delete_file'] } },
      }),
      'utf8',
    );
    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'toxic', '--out-dir', outDir, '--diff', baseline, '--min-confidence', '0.4'],
      { encoding: 'utf8', timeout: 30_000 },
    );
    expect(res.status).toBe(1);
    expect(res.stdout).toContain('path-001');
    expect(existsSync(join(outDir, 'paths.json'))).toBe(true);
    expect(existsSync(join(outDir, 'report.md'))).toBe(true);
    const diff = JSON.parse(readFileSync(join(outDir, 'policy-diff.json'), 'utf8'));
    expect(diff.length).toBeGreaterThan(0);
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pnpm vitest run apps/cli/test/graph-toxic.test.ts`

Expected: FAIL（`graph toxic` 尚未实现或退出码不符）。

- [ ] **Step 3: 确认实现（Task 9 的产物）**

确认 `apps/cli/src/index.ts` 中存在以下 `graph toxic` 分支；若不存在，添加它：

```ts
    if (sub === 'toxic') {
      const code = cmdGraphToxic({
        graphPath: values.graph ?? join(outDir, 'potential.json'),
        outDir,
        crossAgent: values['cross-agent'] === true,
        minConfidence: Number.parseFloat(values['min-confidence'] ?? '0.5'),
        maxPaths: Number.parseInt(values['max-paths'] ?? '20', 10),
        baselinePath: values.diff,
        json: values.json === true,
      });
      process.exit(code);
    }
```

- [ ] **Step 4: 运行测试**

Run: `pnpm vitest run apps/cli/test/graph-toxic.test.ts`

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add apps/cli/test/graph-toxic.test.ts
git commit -m "test(cli): pod graph toxic 集成测试"
```

---

## Task 11: `pod graph explain` CLI

**Files:**
- Create: `apps/cli/test/graph-explain.test.ts`

- [ ] **Step 1: 写失败测试**

```ts
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '../src/index.ts');
const DANGER = join(HERE, 'fixtures/graph/danger-server.ts');

describe('pod graph explain', () => {
  it('prints a known path id', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-graph-explain-'));
    writeFileSync(
      join(home, '.claude.json'),
      JSON.stringify({ mcpServers: { demo: { command: process.execPath, args: ['--import', 'tsx', DANGER] } } }),
      'utf8',
    );
    const outDir = join(home, '.pod', 'graph');
    spawnSync(process.execPath, ['--import', 'tsx', CLI, 'graph', 'build', '--home', home], { timeout: 30_000 });
    spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'toxic', '--out-dir', outDir, '--min-confidence', '0.4'],
      { timeout: 30_000 },
    );
    const paths = JSON.parse(readFileSync(join(outDir, 'paths.json'), 'utf8')) as Array<{ id: string }>;
    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'explain', paths[0]!.id, '--out-dir', outDir],
      { encoding: 'utf8', timeout: 30_000 },
    );
    expect(res.status).toBe(0);
    expect(res.stdout).toContain(paths[0]!.id);
    expect(res.stdout).toContain('source:');
    expect(res.stdout).toContain('sink:');
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pnpm vitest run apps/cli/test/graph-explain.test.ts`

Expected: FAIL（若 explain 未实现）。

- [ ] **Step 3: 确认实现（Task 9 的产物）**

确认 `apps/cli/src/index.ts` 中存在以下 `graph explain` 分支；若不存在，添加它：

```ts
    if (sub === 'explain') {
      const id = positionals[2];
      if (!id) {
        console.error('pod graph explain requires <path-id>');
        process.exit(1);
      }
      process.exit(cmdGraphExplain({ pathsPath: join(outDir, 'paths.json'), id, json: values.json === true }));
    }
```

- [ ] **Step 4: 运行测试**

Run: `pnpm vitest run apps/cli/test/graph-explain.test.ts`

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add apps/cli/test/graph-explain.test.ts
git commit -m "test(cli): pod graph explain 集成测试"
```

---

## Task 12: 失败模式集成测试

**Files:**
- Create: `apps/cli/test/graph-failure.test.ts`

- [ ] **Step 1: 写失败测试**

```ts
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { GRAPH_SCHEMA_VERSION } from '@podsec/graph';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '../src/index.ts');
const HANGING = join(HERE, 'fixtures/graph/hanging-server.ts');

function run(args: string[]): ReturnType<typeof spawnSync> {
  return spawnSync(process.execPath, ['--import', 'tsx', CLI, ...args], { encoding: 'utf8', timeout: 30_000 });
}

describe('graph failure modes', () => {
  it('warns config_unreadable and exits 0', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-graph-bad-config-'));
    writeFileSync(join(home, '.claude.json'), '{bad', 'utf8');
    const res = run(['graph', 'build', '--home', home, '--json']);
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('config_unreadable');
  });

  it('warns server_unintrospectable on timeout and exits 0', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-graph-timeout-'));
    writeFileSync(
      join(home, '.claude.json'),
      JSON.stringify({ mcpServers: { demo: { command: process.execPath, args: ['--import', 'tsx', HANGING] } } }),
      'utf8',
    );
    const res = run(['graph', 'build', '--home', home, '--timeout', '500', '--json']);
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('server_unintrospectable');
  });

  it('exits 2 on an unsupported graph schema version', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-graph-bad-schema-'));
    writeFileSync(
      join(dir, 'potential.json'),
      JSON.stringify({
        schema_version: '9.9.9',
        source: 'static',
        generated_at: '2026-09-09T00:00:00.000Z',
        meta: { tool_version: '0.1.0', config_fingerprint: 'x', warnings: [] },
        nodes: [],
        edges: [],
      }),
      'utf8',
    );
    const res = run(['graph', 'toxic', '--graph', join(dir, 'potential.json'), '--out-dir', dir]);
    expect(res.status).toBe(2);
    expect(res.stderr).toContain('unsupported graph schema_version');
  });

  it('warns stale_graph when generated_at is old', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-graph-stale-'));
    writeFileSync(
      join(dir, 'potential.json'),
      JSON.stringify({
        schema_version: GRAPH_SCHEMA_VERSION,
        source: 'static',
        generated_at: '2020-01-01T00:00:00.000Z',
        meta: { tool_version: '0.1.0', config_fingerprint: 'x', warnings: [] },
        nodes: [],
        edges: [],
      }),
      'utf8',
    );
    const res = run(['graph', 'toxic', '--graph', join(dir, 'potential.json'), '--out-dir', dir, '--json']);
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('stale_graph');
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pnpm vitest run apps/cli/test/graph-failure.test.ts`

Expected: FAIL（stale_graph 尚未实现）。

- [ ] **Step 3: 实现 stale 检测与 config 警告**

`config_unreadable` 由 Task 8 的 `onWarning` 回调产出；确认 `apps/cli/src/graph/static.ts` 中存在：

```ts
  const targets = discoverTargets({
    home: opts.home,
    config: opts.config,
    onWarning: (warning) =>
      warnings.push({ code: 'config_unreadable', message: warning.message, where: warning.path }),
  });
```

以及 `apps/cli/src/onboard.ts` 的 `DiscoverOptions` 含 `onWarning`，且 JSON 解析失败时调用它。

在 `apps/cli/src/graph/commands.ts` 的 `cmdGraphToxic` 读取 graph 后加：

```ts
const ageMs = Date.now() - new Date(graph.generated_at).getTime();
if (Number.isFinite(ageMs) && ageMs > 7 * 24 * 60 * 60 * 1000) {
  graph.meta.warnings.push({
    code: 'stale_graph',
    message: `graph 生成于 ${graph.generated_at}，超过 7 天，结论仅供参考`,
  });
}
```

- [ ] **Step 4: 运行测试**

Run: `pnpm vitest run apps/cli/test/graph-failure.test.ts`

Expected: PASS（4 个测试）。

- [ ] **Step 5: 提交**

```bash
git add apps/cli/src/graph/static.ts apps/cli/src/graph/commands.ts apps/cli/test/graph-failure.test.ts
git commit -m "test(graph): 失败模式与降级"
```

---

## Task 13: Demo 脚本与文档

**Files:**
- Create: `scripts/demo-graph.sh`
- Create: `docs/graph.md`
- Modify: `README.md`

- [ ] **Step 1: 写 demo 脚本**

`scripts/demo-graph.sh`：

```bash
#!/usr/bin/env bash
# 5 分钟 demo：静态能力图 → 毒性路径 → 定点策略 diff
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
cd "$REPO_DIR"

if [ ! -d "$REPO_DIR/node_modules/tsx" ]; then
  echo "缺少 tsx，请先运行: pnpm install" >&2
  exit 1
fi

HOME_DIR="$TMP_DIR/home"
mkdir -p "$HOME_DIR"
cat > "$HOME_DIR/.claude.json" <<EOF
{
  "mcpServers": {
    "demo": {
      "command": "$(command -v node)",
      "args": ["--import", "tsx", "$REPO_DIR/apps/cli/test/fixtures/graph/danger-server.ts"]
    }
  }
}
EOF

cat > "$TMP_DIR/baseline.json" <<'EOF'
{
  "version": "0.1.0",
  "agent": "claude-code",
  "defaultDecision": "deny",
  "servers": {
    "demo": {
      "allow": ["read_file", "send_email", "execute_command", "http_request", "delete_file"]
    }
  }
}
EOF

POD=(node --import tsx "$REPO_DIR/apps/cli/src/index.ts")

echo "== 1/3 构建静态能力图 =="
"${POD[@]}" graph build --home "$HOME_DIR" --out "$TMP_DIR/potential.json"

echo
echo "== 2/3 识别毒性路径 =="
"${POD[@]}" graph toxic --graph "$TMP_DIR/potential.json" --out-dir "$TMP_DIR" \
  --diff "$TMP_DIR/baseline.json" --min-confidence 0.4 || true

echo
echo "== 3/3 定点策略 diff =="
cat "$TMP_DIR/policy-diff.json"
```

- [ ] **Step 2: 运行 demo**

Run: `chmod +x scripts/demo-graph.sh && bash scripts/demo-graph.sh`

Expected: 输出包含 `path-001`、`exfiltration`、`policy-diff.json`。

- [ ] **Step 3: 写用户文档**

`docs/graph.md`：

```markdown
# pod graph — 跨 agent 能力图与毒性路径

`pod graph` 是只读分析器：它不进入运行时，不修改任何 agent 配置。

## 快速开始

```bash
pod graph build                      # 读 agent 配置 + 工具 schema，生成潜在图
pod graph toxic --diff <baseline>    # 找 source→sink 毒性路径 + 定点策略 diff
pod graph explain path-001           # 追溯某条路径的证据
```

## 命令

| 命令 | 作用 |
|---|---|
| `pod graph build` | 生成 `~/.pod/graph/potential.json` |
| `pod graph toxic` | 生成 `paths.json`、`report.md`、`policy-diff.json` |
| `pod graph explain <id>` | 打印某条路径的 source/sink/证据/建议 |

## 退出码

- `0`：分析成功，无高危路径
- `1`：分析成功，存在高危路径（适合 CI）
- `2`：分析失败或数据不可信

## 安全边界

- 只调用 `tools/list`，不调用 `tools/call`
- introspection 不继承全量环境变量，只传 `PATH/HOME/SHELL/TERM/LANG/LC_ALL/USER/LOGNAME/TMPDIR` + server 配置里声明的 env
- 报告不含密钥原文；全程本地、不联网
```

在 `README.md` 的 CLI 代码块中加：

```text
pod graph build     static capability graph from agent configs + tool schemas
pod graph toxic     source→sink toxic paths + targeted policy diff
pod graph explain   trace a path back to evidence
```

- [ ] **Step 4: 运行全量校验**

Run: `pnpm typecheck && pnpm test`

Expected: 现有测试 + 新增测试全绿。

- [ ] **Step 5: 提交**

```bash
git add scripts/demo-graph.sh docs/graph.md README.md
git commit -m "docs(graph): 用户文档与 demo 脚本"
```

---

## Task 14: Dogfood 验收（人工）

**Files:**
- Create: `docs/dogfood/2026-09-09-graph-dogfood.md`

- [ ] **Step 1: 在真实机器上构建**

Run: `pnpm build && node apps/cli/dist/index.js graph build`

Expected: 生成 `~/.pod/graph/potential.json`；记录 agent/server/tool 数量。

- [ ] **Step 2: 跑毒性分析**

Run: `node apps/cli/dist/index.js graph toxic --cross-agent --diff ~/.pod/policies/baseline.json --min-confidence 0.4`

Expected: 输出路径或"未发现毒性路径"。记录耗时。

若 `~/.pod/policies/baseline.json` 不存在，先运行 `node apps/cli/dist/index.js init --template baseline`。

- [ ] **Step 3: 逐条确认**

对每条高危路径运行：

```bash
node apps/cli/dist/index.js graph explain <path-id>
```

记录：是否为真实风险（confirmed / false-positive）、是否此前已知。

- [ ] **Step 4: 写验收记录**

`docs/dogfood/2026-09-09-graph-dogfood.md` 记录：

```markdown
# pod graph dogfood 记录（2026-09-09）

- 机器：<OS / Node 版本>
- agent 数：<n>（列出）
- server 数：<n>
- tool 数：<n>
- H3 首次价值：build + toxic 耗时 <x> 分钟
- H1 发现力：<n> 条路径，其中 <m> 条此前未知且确认真实
- 误报：<n> 条，原因：<...>
- 结论：H1/H3 是否通过
```

- [ ] **Step 5: 提交**

```bash
git add docs/dogfood/2026-09-09-graph-dogfood.md
git commit -m "docs(graph): dogfood 验收记录"
```

---

## 验收清单

- [ ] `pnpm typecheck` 全绿
- [ ] `pnpm test` 全绿（现有 175 + 新增 graph 测试）
- [ ] `bash scripts/demo-graph.sh` 输出 `path-001` 与 `policy-diff.json`
- [ ] `pod graph build` 在 dogfood 机器上 ≤10 分钟完成（H3）
- [ ] `pod graph toxic --cross-agent` 找到 ≥1 条此前未知且确认真实的路径（H1）
- [ ] 报告不含密钥原文，全程不联网
- [ ] 失败模式退出码符合设计文档第 6 节
