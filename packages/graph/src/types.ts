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
