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
