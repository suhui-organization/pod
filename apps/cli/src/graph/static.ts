import { createHash } from 'node:crypto';
import type { Policy } from '@podsec/policy';
import {
  CAPABILITIES,
  classifyTool,
  type Capability,
  type CapabilityGraph,
  type GraphEdge,
  type GraphNode,
  type GraphWarning,
} from '@podsec/graph';
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
