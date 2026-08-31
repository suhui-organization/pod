#!/usr/bin/env node
/**
 * pod CLI v0 骨架（Phase 0）。
 * 子命令：
 *   pod init                     初始化 ~/.pod（示例策略）
 *   pod serve                    启动网关（MCP stdio 代理）
 *     --agent <name>              agent 身份
 *     --server <name>             server 名（策略求值用）
 *     --policy <path>             策略 JSON 文件
 *     --command <cmd>             真实 MCP server 启动命令
 *     --arg <value>               可重复，传给真实 server 的参数
 *     --audit-dir <path>          审计输出目录（默认 ~/.pod/audit）
 *
 * 注意：网关进程的 stdout 被 MCP 协议占用，所有日志必须走 stderr。
 */
import { parseArgs } from 'node:util';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { AuditLog, appendToAuditFile } from '@podsec/audit';
import type { Policy } from '@podsec/policy';
import { createStdioProxy } from '@podsec/gateway';

const POD_HOME = join(homedir(), '.pod');

function podPath(...parts: string[]): string {
  return join(POD_HOME, ...parts);
}

const EXAMPLE_POLICY: Policy = {
  version: '0.1.0',
  agent: 'openclaw-main',
  defaultDecision: 'deny',
  servers: {
    filesystem: {
      allow: ['read_file', 'list_directory', 'search_files'],
      approve: ['write_file', 'edit_file'],
      deny: ['delete_file'],
    },
    github: {
      allow: ['create_issue'],
    },
  },
};

function log(message: string): void {
  console.error(`[pod] ${message}`);
}

async function cmdInit(): Promise<void> {
  mkdirSync(podPath('policies'), { recursive: true });
  mkdirSync(podPath('audit'), { recursive: true });
  const policyFile = podPath('policies', 'example.json');
  if (!existsSync(policyFile)) {
    writeFileSync(policyFile, JSON.stringify(EXAMPLE_POLICY, null, 2) + '\n', 'utf8');
  }
  log(`initialized ${POD_HOME}`);
  log(`example policy: ${policyFile}`);
}

interface ServeOptions {
  agent: string;
  server: string;
  policy: string;
  command: string;
  args: string[];
  auditDir: string;
}

async function cmdServe(opts: ServeOptions): Promise<void> {
  const policy = JSON.parse(readFileSync(opts.policy, 'utf8')) as Policy;

  const auditDir = opts.auditDir;
  mkdirSync(auditDir, { recursive: true });
  const auditPath = join(auditDir, `${opts.server}.jsonl`);
  const audit = new AuditLog(policy.version, {
    onAppend: (entry) => appendToAuditFile(auditPath, entry),
  });

  const server = await createStdioProxy({
    agent: opts.agent,
    serverName: opts.server,
    policy,
    audit,
    command: opts.command,
    args: opts.args,
  });

  log(`serving "${opts.server}" for agent "${opts.agent}" (audit: ${auditPath})`);
  log(`upstream: ${opts.command} ${opts.args.join(' ')}`);

  const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js');
  await server.connect(new StdioServerTransport());
  log('gateway ready on stdio; waiting for agent…');
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    args: normalizePodArgs(process.argv.slice(2)),
    allowPositionals: true,
    options: {
      agent: { type: 'string' },
      server: { type: 'string' },
      policy: { type: 'string' },
      command: { type: 'string' },
      arg: { type: 'string', multiple: true },
      'audit-dir': { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  const cmd = positionals[0];
  if (values.help || !cmd) {
    console.error(usage());
    process.exit(cmd ? 0 : 1);
  }

  if (cmd === 'init') {
    await cmdInit();
    return;
  }

  if (cmd === 'serve') {
    if (!values.agent || !values.server || !values.policy || !values.command) {
      console.error('pod serve requires --agent --server --policy --command');
      console.error(usage());
      process.exit(1);
    }
    await cmdServe({
      agent: values.agent,
      server: values.server,
      policy: values.policy,
      command: values.command,
      args: values.arg ?? [],
      auditDir: values['audit-dir'] ?? podPath('audit'),
    });
    return;
  }

  console.error(`unknown command: ${cmd}`);
  console.error(usage());
  process.exit(1);
}

/**
 * parseArgs 不允许选项值以 '-' 开头（如 --arg --import 会被判为 ambiguous），
 * 这里把裸 `--arg <v>` 重写为 `--arg=<v>`，两种写法都可用。
 */
function normalizePodArgs(argv: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i]!;
    if (tok === '--arg' && i + 1 < argv.length) {
      out.push(`--arg=${argv[i + 1]!}`);
      i++;
    } else {
      out.push(tok);
    }
  }
  return out;
}

function usage(): string {
  return `pod — AI agent security pod (Phase 0 scaffold)

Usage:
  pod init
  pod serve --agent <name> --server <name> --policy <file> \\
           --command <cmd> [--arg <value> ...] [--audit-dir <dir>]
  pod --help
`;
}

main().catch((err: unknown) => {
  log(`fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
  process.exit(1);
});
