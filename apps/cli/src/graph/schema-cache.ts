import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ToolDescriptor } from './types.js';

export function cacheKey(command: string, args: string[]): string {
  return createHash('sha256').update(JSON.stringify({ command, args })).digest('hex').slice(0, 16);
}

export function readSchemaCache(dir: string, key: string): ToolDescriptor[] | null {
  const path = join(dir, `${key}.json`);
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as ToolDescriptor[];
  } catch {
    return null;
  }
}

export function writeSchemaCache(dir: string, key: string, tools: ToolDescriptor[]): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${key}.json`), JSON.stringify(tools, null, 2) + '\n', 'utf8');
}
