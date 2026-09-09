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

interface ToolOverride {
  capabilities: Capability[];
  evidence: string;
  /** true = 只使用本表映射，不再跑名称/schema 启发式（用于修正误报） */
  exclusive: boolean;
  writeContext?: boolean;
}

function curated(
  capabilities: Capability[],
  evidence: string,
  opts: { exclusive?: boolean; writeContext?: boolean } = {},
): ToolOverride {
  return { capabilities, evidence, exclusive: opts.exclusive ?? true, writeContext: opts.writeContext };
}

/**
 * 人工校准的工具映射（dogfood 后收敛噪声用）。
 * 键为工具名（跨 server 复用，如 click 在 chrome-devtools 与 mcp-chrome-devtools 同时生效）。
 */
const TOOL_OVERRIDES: Record<string, ToolOverride> = {
  // chrome-devtools：页面交互 = 外发 + 读不可信；只读观测 = 读不可信
  evaluate_script: curated(['exec', 'read-untrusted-input'], 'runs arbitrary JS in page context'),
  click: curated(['external-communication', 'read-untrusted-input'], 'interacts with external pages'),
  fill: curated(['external-communication', 'read-untrusted-input'], 'types data into external pages'),
  fill_form: curated(['external-communication', 'read-untrusted-input'], 'fills forms on external pages'),
  type_text: curated(['external-communication', 'read-untrusted-input'], 'types data into external pages'),
  press_key: curated(['external-communication', 'read-untrusted-input'], 'sends keystrokes to external pages'),
  handle_dialog: curated(['external-communication', 'read-untrusted-input'], 'responds to page dialogs'),
  drag: curated(['external-communication', 'read-untrusted-input'], 'drags on external pages'),
  select_page: curated(['read-untrusted-input'], 'selects a page target'),
  emulate: curated(['read-untrusted-input'], 'emulates device/page state'),
  take_screenshot: curated(['read-untrusted-input'], 'captures page content'),
  take_snapshot: curated(['read-untrusted-input'], 'captures page snapshot'),
  lighthouse_audit: curated(['read-untrusted-input'], 'audits page content'),
  performance_analyze_insight: curated(['read-untrusted-input'], 'reads page performance data'),
  performance_start_trace: curated(['read-untrusted-input'], 'reads page performance data'),
  performance_stop_trace: curated(['read-untrusted-input'], 'reads page performance data'),
  take_heapsnapshot: curated(['read-untrusted-input'], 'captures page heap data'),
  wait_for: curated(['read-untrusted-input'], 'waits on page state'),
  hover: curated(['read-untrusted-input'], 'hovers on page element'),
  resize_page: curated(['read-untrusted-input'], 'resizes page viewport'),
  close_page: curated(['read-untrusted-input'], 'closes page target'),

  // kubernetes：变更 = destructive；只读 = private data；隧道 = 外发
  kubectl_patch: curated(['destructive-write'], 'patches cluster resources', { writeContext: true }),
  kubectl_scale: curated(['destructive-write'], 'scales cluster resources', { writeContext: true }),
  kubectl_rollout: curated(['destructive-write'], 'rolls out cluster changes', { writeContext: true }),
  cleanup: curated(['destructive-write'], 'cleans up cluster resources', { writeContext: true }),
  kubectl_describe: curated(['read-private-data'], 'reads cluster resource details'),
  kubectl_logs: curated(['read-private-data'], 'reads cluster logs'),
  kubectl_context: curated(['read-private-data'], 'reads/changes kube context'),
  ping: curated(['read-private-data'], 'checks cluster connectivity'),
  port_forward: curated(['external-communication'], 'opens a network tunnel'),
  stop_port_forward: curated(['external-communication'], 'closes a network tunnel'),

  // docker：构建/启动/停止/拉取 = exec + write；只读 = private data
  docker_build: curated(['exec'], 'builds container images', { writeContext: true }),
  docker_compose_up: curated(['exec'], 'starts containers', { writeContext: true }),
  docker_stop: curated(['exec'], 'stops containers', { writeContext: true }),
  docker_pull: curated(['exec'], 'pulls container images', { writeContext: true }),
  docker_ps: curated(['read-private-data'], 'lists containers'),
  docker_images: curated(['read-private-data'], 'lists images'),
  docker_logs: curated(['read-private-data'], 'reads container logs'),

  // firecrawl：抓取/解析/研究 = 读不可信；interact/monitor_run 修正误报的 exec
  firecrawl_agent: curated(['read-untrusted-input'], 'fetches external content'),
  firecrawl_agent_status: curated(['read-untrusted-input'], 'reads external job status'),
  firecrawl_check_crawl_status: curated(['read-untrusted-input'], 'reads external crawl status'),
  firecrawl_extract: curated(['read-untrusted-input'], 'extracts external content'),
  firecrawl_interact: curated(['read-untrusted-input'], 'interacts with external content (not code execution)'),
  firecrawl_interact_stop: curated(['read-untrusted-input'], 'stops external interaction'),
  firecrawl_monitor_check: curated(['read-untrusted-input'], 'checks external page changes'),
  firecrawl_monitor_checks: curated(['read-untrusted-input'], 'checks external page changes'),
  firecrawl_monitor_run: curated(['read-untrusted-input'], 'runs an external page monitor'),
  firecrawl_parse: curated(['read-untrusted-input'], 'parses external documents'),
  firecrawl_research_inspect_paper: curated(['read-untrusted-input'], 'reads external research content'),
  firecrawl_research_related_papers: curated(['read-untrusted-input'], 'reads external research content'),

  // amap：外部地图 API 查询
  maps_bicycling: curated(['read-untrusted-input'], 'queries external map API'),
  maps_direction_driving: curated(['read-untrusted-input'], 'queries external map API'),
  maps_direction_transit_integrated: curated(['read-untrusted-input'], 'queries external map API'),
  maps_direction_walking: curated(['read-untrusted-input'], 'queries external map API'),
  maps_distance: curated(['read-untrusted-input'], 'queries external map API'),
  maps_geo: curated(['read-untrusted-input'], 'queries external map API'),
  maps_ip_location: curated(['read-untrusted-input'], 'queries external map API'),
  maps_regeocode: curated(['read-untrusted-input'], 'queries external map API'),
  maps_weather: curated(['read-untrusted-input'], 'queries external map API'),

  // 其他
  open_nodes: curated(['read-private-data'], 'reads private memory graph'),
  create_entities: curated([], 'writes private memory graph', { writeContext: true }),
  create_relations: curated([], 'writes private memory graph', { writeContext: true }),
  add_observations: curated([], 'writes private memory graph', { writeContext: true }),
  create_repository: curated(['external-communication'], 'creates an external repository', { writeContext: true }),
  generate_typescript_types: curated(['read-private-data'], 'reads database schema'),
};

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
  const curatedOverride = TOOL_OVERRIDES[tool.name];
  const byCapability = new Map<Capability, CapabilityAssertion>();
  const add = (capability: Capability, confidence: number, origin: CapabilityOrigin, evidence: string): void => {
    const existing = byCapability.get(capability);
    if (!existing) {
      byCapability.set(capability, { capability, confidence, origin, evidence: [evidence] });
      return;
    }
    if (confidence > existing.confidence) {
      existing.confidence = confidence;
      existing.origin = origin;
    }
    if (!existing.evidence.includes(evidence)) existing.evidence.push(evidence);
  };

  for (const capability of overrides) add(capability, 1, 'policy', 'policy override');

  if (curatedOverride) {
    for (const capability of curatedOverride.capabilities) {
      add(capability, 0.9, 'heuristic', curatedOverride.evidence);
    }
  }

  if (!curatedOverride?.exclusive) {
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
  }

  const assertions = [...byCapability.values()].sort(
    (a, b) => b.confidence - a.confidence || a.capability.localeCompare(b.capability),
  );
  return {
    assertions,
    writeContext: curatedOverride?.writeContext ?? tokens.some((token) => WRITE_TOKENS.has(token)),
    unclassified: assertions.length === 0,
  };
}
