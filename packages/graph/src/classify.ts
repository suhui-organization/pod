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
    if (confidence > existing.confidence) {
      existing.confidence = confidence;
      existing.origin = origin;
    }
    if (!existing.evidence.includes(evidence)) existing.evidence.push(evidence);
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
