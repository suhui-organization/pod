import { buildToolRefs } from './toxic.js';
import type { CapabilityGraph } from './types.js';

export interface GraphDiffEntry {
  /** 归一化后的 server 名（用于跨 agent/跨命名比较） */
  server: string;
  /** 原始 server 名（可能带 mcp-server-/mcp-/pod- 前缀） */
  servers: string[];
  tool: string;
  agents: string[];
  capabilities: string[];
  calls?: number;
}

export interface GraphDiffResult {
  /** 潜在 − 观测：授权了但从未使用 */
  overPrivileged: GraphDiffEntry[];
  /** 观测 − 潜在：使用了但未登记 */
  shadow: GraphDiffEntry[];
  summary: {
    potentialTools: number;
    observedTools: number;
    overPrivileged: number;
    shadow: number;
  };
}

const CAPABILITY_PRIORITY = [
  'read-secret',
  'credential-access',
  'external-communication',
  'exec',
  'destructive-write',
  'read-private-data',
  'read-untrusted-input',
];

function priority(capabilities: string[]): number {
  const index = CAPABILITY_PRIORITY.findIndex((capability) => capabilities.includes(capability));
  return index === -1 ? CAPABILITY_PRIORITY.length : index;
}

/** 归一化 server 名：mcp-server-filesystem / mcp-filesystem / pod-filesystem → filesystem */
export function normalizeServer(server: string): string {
  return server.replace(/^(mcp-server-|mcp-|pod-)/, '').toLowerCase();
}

function entries(graph: CapabilityGraph): GraphDiffEntry[] {
  const byKey = new Map<string, GraphDiffEntry>();
  for (const ref of buildToolRefs(graph)) {
    const normalized = normalizeServer(ref.server);
    const key = `${normalized}|${ref.tool}`;
    const calls = graph.nodes.find((node) => node.id === ref.nodeId)?.calls ?? 0;
    const existing = byKey.get(key);
    if (existing) {
      if (!existing.agents.includes(ref.agent)) existing.agents.push(ref.agent);
      if (!existing.servers.includes(ref.server)) existing.servers.push(ref.server);
      existing.calls = (existing.calls ?? 0) + calls;
      for (const assertion of ref.capabilities) {
        if (!existing.capabilities.includes(assertion.capability)) existing.capabilities.push(assertion.capability);
      }
    } else {
      byKey.set(key, {
        server: normalized,
        servers: [ref.server],
        tool: ref.tool,
        agents: [ref.agent],
        capabilities: ref.capabilities.map((assertion) => assertion.capability),
        calls,
      });
    }
  }
  return [...byKey.values()];
}

export function diffGraphs(potential: CapabilityGraph, observed: CapabilityGraph): GraphDiffResult {
  const potentialEntries = entries(potential);
  const observedEntries = entries(observed);
  const keyOf = (entry: GraphDiffEntry): string => `${entry.server}|${entry.tool}`;
  const potentialKeys = new Set(potentialEntries.map(keyOf));
  const observedKeys = new Set(observedEntries.map(keyOf));

  const overPrivileged = potentialEntries
    .filter((e) => !observedKeys.has(keyOf(e)))
    .sort((a, b) => priority(a.capabilities) - priority(b.capabilities) || a.tool.localeCompare(b.tool));
  const shadow = observedEntries
    .filter((e) => !potentialKeys.has(keyOf(e)))
    .sort((a, b) => priority(a.capabilities) - priority(b.capabilities) || a.tool.localeCompare(b.tool));

  return {
    overPrivileged,
    shadow,
    summary: {
      potentialTools: potentialEntries.length,
      observedTools: observedEntries.length,
      overPrivileged: overPrivileged.length,
      shadow: shadow.length,
    },
  };
}
