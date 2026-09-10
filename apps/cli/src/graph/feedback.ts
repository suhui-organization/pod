import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

export type FeedbackVerdict = 'confirmed' | 'false-positive';

export interface FeedbackEntry {
  id: string;
  verdict: FeedbackVerdict;
  note?: string;
  at: string;
}

export function readFeedback(path: string): FeedbackEntry[] {
  if (!existsSync(path)) return [];
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as { entries?: FeedbackEntry[] };
    return Array.isArray(parsed.entries) ? parsed.entries : [];
  } catch {
    return [];
  }
}

/** 同一个 id 只保留最新判定 */
export function writeFeedback(path: string, entry: FeedbackEntry): void {
  const entries = readFeedback(path).filter((existing) => existing.id !== entry.id);
  entries.push(entry);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify({ entries }, null, 2) + '\n', 'utf8');
}

export function feedbackMap(path: string): Record<string, FeedbackVerdict> {
  const map: Record<string, FeedbackVerdict> = {};
  for (const entry of readFeedback(path)) map[entry.id] = entry.verdict;
  return map;
}
