import type {
  Capability,
  CapabilityAssertion,
  CapabilityGraph,
  PathEndpoint,
  ToolRef,
  ToxicGroup,
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

/** 按 (rule, source capability, sink capability) 聚合，把笛卡尔积压成可读的链类型。 */
export function groupToxicPaths(paths: ToxicPath[]): ToxicGroup[] {
  const groups = new Map<string, ToxicGroup>();
  for (const path of paths) {
    const key = `${path.rule}|${path.source.capability}|${path.sink.capability}`;
    let group = groups.get(key);
    if (!group) {
      group = {
        id: '',
        rule: path.rule,
        severity: path.severity,
        sourceCapability: path.source.capability,
        sinkCapability: path.sink.capability,
        count: 0,
        intraAgent: 0,
        crossAgent: 0,
        sourceTools: [],
        sinkTools: [],
        sourceEndpoints: [],
        sinkEndpoints: [],
        sample: path,
      };
      groups.set(key, group);
    }
    group.count += 1;
    if (path.kind === 'cross-agent') group.crossAgent += 1;
    else group.intraAgent += 1;
    const sourceTool = `${path.source.agent}.${path.source.tool}`;
    const sinkTool = `${path.sink.agent}.${path.sink.tool}`;
    if (!group.sourceTools.includes(sourceTool)) group.sourceTools.push(sourceTool);
    if (!group.sinkTools.includes(sinkTool)) group.sinkTools.push(sinkTool);
    const sourceKey = `${path.source.agent}|${path.source.server}|${path.source.tool}|${path.source.capability}`;
    const sinkKey = `${path.sink.agent}|${path.sink.server}|${path.sink.tool}|${path.sink.capability}`;
    if (!group.sourceEndpoints.some((e) => `${e.agent}|${e.server}|${e.tool}|${e.capability}` === sourceKey)) {
      group.sourceEndpoints.push(path.source);
    }
    if (!group.sinkEndpoints.some((e) => `${e.agent}|${e.server}|${e.tool}|${e.capability}` === sinkKey)) {
      group.sinkEndpoints.push(path.sink);
    }
  }
  return [...groups.values()]
    .sort(
      (a, b) =>
        b.count - a.count || a.rule.localeCompare(b.rule) || a.sourceCapability.localeCompare(b.sourceCapability),
    )
    .map((group, index) => ({ ...group, id: `chain-${String(index + 1).padStart(3, '0')}` }));
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
): { paths: ToxicPath[]; total: number; groups: ToxicGroup[] } {
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
  return { paths: deduped.slice(0, maxPaths), total, groups: groupToxicPaths(deduped) };
}
