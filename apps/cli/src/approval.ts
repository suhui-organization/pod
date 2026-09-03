/**
 * 文件旁路审批 provider（v0）。
 *
 * 背景：stdio 网关的 stdin/stdout 被 MCP 协议占用，终端交互只能走旁路通道。
 * 机制：
 *   - 挂起请求 → 写 ~/.pod/pending/<id>.json（含工具/参数元数据）
 *   - 用户在另一个终端执行 `pod approve --id <id>` / `pod deny --id <id>`
 *     → 写 <id>.decision.json
 *   - 网关轮询 decision 文件（200ms），超时按拒绝处理（fail-closed）
 * 审计中 approver/reason 来自 decision 文件。
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ApprovalProvider, ApprovalRequest } from '@podsec/gateway';

export interface FileApprovalOptions {
  pendingDir: string;
  /** 超时毫秒，默认 300s；超时 = 拒绝 */
  timeoutMs?: number;
  /** 每次产生新挂起请求时回调（CLI 用它打印提示） */
  onRequest?: (req: ApprovalRequest, pendingFile: string) => void;
}

export interface FileApprovalDecision {
  approved: boolean;
  approver?: string;
  reason?: string;
  decidedAt: string;
}

export function createFileApprovalProvider(opts: FileApprovalOptions): ApprovalProvider {
  const timeoutMs = opts.timeoutMs ?? 300_000;
  mkdirSync(opts.pendingDir, { recursive: true });

  return async (req) => {
    const pendingFile = join(opts.pendingDir, `${req.id}.json`);
    writeFileSync(pendingFile, JSON.stringify({ ...req, pendingSince: new Date().toISOString() }, null, 2), 'utf8');
    opts.onRequest?.(req, pendingFile);

    const deadline = Date.now() + timeoutMs;
    const decisionFile = join(opts.pendingDir, `${req.id}.decision.json`);
    while (Date.now() < deadline) {
      if (existsSync(decisionFile)) {
        const raw = JSON.parse(readFileSync(decisionFile, 'utf8')) as FileApprovalDecision;
        rmSync(pendingFile, { force: true });
        rmSync(decisionFile, { force: true }); // 用后即焚,防止残留决定"毒化"同 id 的未来请求
        return {
          approved: raw.approved,
          approver: raw.approver,
          reason: raw.reason,
        };
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    rmSync(pendingFile, { force: true });
    return {
      approved: false,
      approver: 'system',
      reason: `approval timed out after ${Math.round(timeoutMs / 1000)}s (fail-closed)`,
    };
  };
}

export function decideApproval(
  pendingDir: string,
  id: string,
  decision: { approved: boolean; approver: string; reason?: string },
): { ok: true; pendingFile: string } {
  const pendingFile = join(pendingDir, `${id}.json`);
  if (!existsSync(pendingFile)) {
    throw new Error(`no pending approval "${id}" in ${pendingDir}`);
  }
  const decisionFile = join(pendingDir, `${id}.decision.json`);
  const record: FileApprovalDecision = {
    approved: decision.approved,
    approver: decision.approver,
    reason: decision.reason,
    decidedAt: new Date().toISOString(),
  };
  writeFileSync(decisionFile, JSON.stringify(record, null, 2), 'utf8');
  return { ok: true, pendingFile };
}

/** 列出挂起中的审批请求 */
export function listPendingApprovals(pendingDir: string): Array<{ id: string; server: string; tool: string }> {
  const files = readdirSync(pendingDir).filter((f) => f.endsWith('.json') && !f.endsWith('.decision.json'));
  return files
    .map((f) => {
      try {
        const req = JSON.parse(readFileSync(join(pendingDir, f), 'utf8')) as ApprovalRequest;
        return { id: req.id, server: req.server, tool: req.tool };
      } catch {
        return null;
      }
    })
    .filter((x): x is { id: string; server: string; tool: string } => x !== null);
}
