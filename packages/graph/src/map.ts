import type { CapabilityGraph } from './types.js';

/** 从能力图提取 "server.tool" → D2 能力标签，供 pod graph apply / pod serve 使用 */
export function capabilityMapFromGraph(graph: CapabilityGraph): Record<string, string[]> {
  const toolNodes = new Map<string, { server: string; tool: string }>();
  for (const node of graph.nodes) {
    if (node.type === 'tool' && node.server && node.tool) {
      toolNodes.set(node.id, { server: node.server, tool: node.tool });
    }
  }
  const map: Record<string, string[]> = {};
  for (const edge of graph.edges) {
    if (edge.type !== 'has_capability') continue;
    const tool = toolNodes.get(edge.from);
    if (!tool) continue;
    const capability = edge.to.replace(/^capability:/, '');
    const key = `${tool.server}.${tool.tool}`;
    const list = map[key] ?? [];
    if (!list.includes(capability)) list.push(capability);
    map[key] = list;
  }
  return map;
}
