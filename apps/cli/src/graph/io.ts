import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  parseGraph,
  serializeGraph,
  type CapabilityGraph,
  type ScoredToxicGroup,
  type ToxicPath,
} from '@podsec/graph';

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

export function readChains(path: string): ScoredToxicGroup[] {
  return JSON.parse(readFileSync(path, 'utf8')) as ScoredToxicGroup[];
}
