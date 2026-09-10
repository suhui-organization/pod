import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import {
  capabilityMapFromGraph,
  CAPABILITIES,
  classifyTool,
  type Capability,
  type CapabilityGraph,
  type GraphEdge,
  type GraphNode,
  type GraphWarning,
} from '@podsec/graph';
import { loadAllAuditFiles, parseSince } from '../evidence.js';
import { readGraphFile } from './io.js';

export interface BuildObservedOptions {
  auditDir: string;
  since?: string;
  potentialPath?: string;
}

interface ToolStat {
  agent: string;
  server: string;
  tool: string;
  calls: number;
  lastSeen: string;
  capabilities: Set<Capability>;
}

/** 从审计语料构建观测图：实际用了哪些工具、调用多少次、命中过哪些能力信号 */
export function buildObservedGraph(opts: BuildObservedOptions): { graph: CapabilityGraph; entries: number } {
  const files = loadAllAuditFiles(opts.auditDir);
  const sinceTs = parseSince(opts.since);
  const potential =
    opts.potentialPath && existsSync(opts.potentialPath)
      ? readGraphFile(opts.potentialPath)
      : null;
  const potentialCapabilities = potential ? capabilityMapFromGraph(potential) : {};

  const stats = new Map<string, ToolStat>();
  let entries = 0;
  for (const file of files) {
    for (const entry of file.log.entries) {
      if (sinceTs !== null && entry.ts < sinceTs) continue;
      entries += 1;
      const key = `${entry.agent}|${entry.server}|${entry.tool}`;
      const stat = stats.get(key) ?? {
        agent: entry.agent,
        server: entry.server,
        tool: entry.tool,
        calls: 0,
        lastSeen: entry.ts,
        capabilities: new Set<Capability>(),
      };
      stat.calls += 1;
      if (entry.ts > stat.lastSeen) stat.lastSeen = entry.ts;
      const reason = entry.reason ?? '';
      if (reason.includes('secrets-input') || reason.includes('secret_leak') || reason.includes('secret_entropy')) {
        stat.capabilities.add('read-secret');
      }
      if (reason.includes('injection_suspect')) stat.capabilities.add('read-untrusted-input');
      stats.set(key, stat);
    }
  }

  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const warnings: GraphWarning[] = [];
  for (const stat of stats.values()) {
    const agentId = `agent:${stat.agent}`;
    const serverId = `server:${stat.server}`;
    const toolId = `tool:${stat.server}.${stat.tool}`;
    nodes.set(agentId, { id: agentId, type: 'agent', agent: stat.agent });
    nodes.set(serverId, { id: serverId, type: 'server', server: stat.server });
    nodes.set(toolId, {
      id: toolId,
      type: 'tool',
      server: stat.server,
      tool: stat.tool,
      calls: stat.calls,
      lastSeen: stat.lastSeen,
    });
    edges.push({ from: agentId, to: serverId, type: 'connects' });
    edges.push({ from: serverId, to: toolId, type: 'exposes' });

    const fromPotential = (potentialCapabilities[`${stat.server}.${stat.tool}`] ?? []).filter(
      (value): value is Capability => (CAPABILITIES as readonly string[]).includes(value),
    );
    const capabilities = new Set<Capability>([...fromPotential, ...stat.capabilities]);
    if (capabilities.size === 0) {
      for (const assertion of classifyTool({ name: stat.tool }).assertions) {
        capabilities.add(assertion.capability);
      }
    }
    for (const capability of capabilities) {
      const capabilityId = `capability:${capability}`;
      nodes.set(capabilityId, { id: capabilityId, type: 'capability' });
      edges.push({
        from: toolId,
        to: capabilityId,
        type: 'has_capability',
        confidence: 0.9,
        origin: 'observed',
        evidence: [`observed ${stat.calls} call(s)`],
      });
    }
  }

  if (entries === 0) {
    warnings.push({ code: 'corpus_empty', message: `审计目录 ${opts.auditDir} 在给定时间窗内没有记录` });
  }
  const fingerprint = `sha256:${createHash('sha256')
    .update(JSON.stringify({ auditDir: opts.auditDir, since: opts.since ?? null, files: files.length, entries }))
    .digest('hex')
    .slice(0, 16)}`;

  return {
    graph: {
      schema_version: '0.1.0',
      source: 'observed',
      generated_at: new Date().toISOString(),
      meta: { tool_version: '0.1.0', config_fingerprint: fingerprint, warnings },
      nodes: [...nodes.values()],
      edges,
    },
    entries,
  };
}
