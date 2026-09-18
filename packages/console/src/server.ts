/**
 * `pod ui` 的本地 HTTP 服务：托管控制台静态产物 + 数据接口（读默认开、写显式开）。
 *
 * 安全约束（threat-model.md T8）：
 * - 只绑 127.0.0.1（默认），不对外监听；
 * - 随机 token 鉴权，三种携带方式：`?token=`、`x-pod-token` 头、首次访问后下发的
 *   HttpOnly cookie（浏览器加载 <script>/<link> 时带不了自定义头，cookie 是必须的，
 *   否则静态产物一律 401、页面白屏）；
 * - 默认只读：只接受 GET / HEAD；写操作（纳管/移除）要显式打开 allowWrites，
 *   且必须过同源检查 + JSON content-type（cookie 鉴权下这两条是 CSRF 的主要防线）；
 * - 安全头：CSP self、nosniff、no-referrer（token 不通过 Referer 外泄）。
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { aggregateAgents } from './aggregate.js';
import { enrollAgent, forgetAgent } from './enroll.js';
import { applyEnforcement, applyTakeover, planEnforcement, planTakeover, revertTakeover } from './takeover.js';
import { t } from '@podsec/i18n';

export interface UiServerOptions {
  home: string;
  /** 前端静态产物目录（apps/web/dist）；不存在时接口仍可用，页面提示未构建 */
  webRoot: string;
  podHome?: string;
  port?: number;
  host?: string;
  /** 不传则随机生成 */
  token?: string;
  /**
   * 是否允许写操作（纳管 / 移除）。
   *
   * 默认 **false**：包本身按只读交付，只有 `pod ui`（以及显式打开它的调用方）
   * 才会接受 POST。控制台前端的按钮也据此显示/隐藏。
   */
  allowWrites?: boolean;
  /**
   * 写进 harness 配置的 pod 可执行文件（默认 "pod"，即要求在 PATH 上）。
   *
   * 与 `pod onboard --pod-bin` 同一个旋钮：pod 不在 PATH 上时（比如用绝对路径
   * 启动、或 CI 里），接管会**拒绝执行**——包装命令跑不起来会让该 harness 的
   * MCP server 全部失效。要接管就得给出可执行的绝对路径。
   */
  podBin?: string;
  log?: (msg: string) => void;
}

export interface UiServerHandle {
  url: string;
  token: string;
  port: number;
  close(): Promise<void>;
}

const COOKIE_NAME = 'pod_ui_token';

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
  '.ico': 'image/x-icon',
};

const CSP =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/** 写请求体上限：纳管/移除只有几个字段，超过一定是搞错了 */
const MAX_WRITE_BODY_BYTES = 16 * 1024;

function send(res: ServerResponse, status: number, body: string, type: string): void {
  res.writeHead(status, {
    'Content-Type': type,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  send(res, status, JSON.stringify(payload), MIME['.json']!);
}

/** 读一个 JSON 请求体；超限/非对象/非法 JSON 都抛错（fail-closed，不猜） */
async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    size += buf.byteLength;
    if (size > MAX_WRITE_BODY_BYTES) throw new Error('请求体过大');
    chunks.push(buf);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  if (!text.trim()) return {};
  const parsed: unknown = JSON.parse(text);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('请求体必须是 JSON 对象');
  }
  return parsed as Record<string, unknown>;
}

/**
 * 同源检查。
 *
 * 写操作带 cookie 鉴权，而浏览器会自动带上 cookie，所以必须有 CSRF 防线。
 * 这里用两条：① `Content-Type: application/json`（跨站表单发不出这个类型，
 * 会触发预检而预检不被放行）；② Origin 与 Host 一致（同源请求才会带这个头，
 * 而 curl 之类的本机调用不带 Origin，放行）。
 */
function sameOrigin(req: IncomingMessage): boolean {
  const origin = req.headers.origin;
  if (typeof origin !== 'string' || origin === '') return true;
  const host = req.headers.host;
  if (typeof host !== 'string' || host === '') return false;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

function isJsonContentType(req: IncomingMessage): boolean {
  const type = req.headers['content-type'];
  return typeof type === 'string' && type.split(';')[0]!.trim().toLowerCase() === 'application/json';
}

function readCookie(req: IncomingMessage, name: string): string | null {
  const raw = req.headers.cookie;
  if (!raw) return null;
  for (const part of raw.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    if (part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return null;
}

/** 直接打开没有 token 的页面时，给一个能读的说明，而不是一行 JSON */
function unauthorizedPage(): string {
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>需要 token · pod 控制台</title>
<style>body{font-family:ui-sans-serif,-apple-system,"PingFang SC",sans-serif;max-width:52ch;margin:14vh auto;padding:0 24px;color:#1f2933;line-height:1.7}
code{font-family:ui-monospace,Menlo,monospace;background:#f3f4f6;padding:1px 6px;border-radius:6px}</style></head>
<body><h1 style="font-size:20px">需要 token 才能打开控制台</h1>
<p>pod 控制台只绑在本机，并要求启动时生成的 token。</p>
<p>回到终端，用 <code>pod ui</code> 打印出来的完整 URL 打开（形如 <code>http://127.0.0.1:8787/?token=…</code>）；
打开后 token 会写入本次会话的 cookie，并立即从地址栏移除。</p>
</body></html>`;
}

export function serveConsole(opts: UiServerOptions): Promise<UiServerHandle> {
  const host = opts.host ?? '127.0.0.1';
  const token = opts.token ?? randomBytes(24).toString('base64url');
  const log = opts.log ?? (() => {});
  const webRoot = resolve(opts.webRoot);
  const indexHtml = join(webRoot, 'index.html');

  const authorized = (req: IncomingMessage, url: URL): boolean => {
    const header = req.headers['x-pod-token'];
    if (typeof header === 'string' && header === token) return true;
    const query = url.searchParams.get('token');
    if (query !== null && query === token) return true;
    return readCookie(req, COOKIE_NAME) === token;
  };

  /** 静态文件解析；越界一律拒绝（防路径穿越） */
  const resolveStatic = (pathname: string): string | null => {
    let decoded: string;
    try {
      decoded = decodeURIComponent(pathname);
    } catch {
      return null;
    }
    const candidate = resolve(webRoot, `.${normalize(decoded)}`);
    if (candidate !== webRoot && !candidate.startsWith(webRoot + sep)) return null;
    if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
    return null;
  };

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', `http://${host}`);
    const method = req.method ?? 'GET';

    if (method !== 'GET' && method !== 'HEAD' && method !== 'POST') {
      sendJson(res, 405, { error: 'only GET/HEAD (reads) and POST (enroll/forget) are accepted' });
      return;
    }

    // 从 URL 带 token 进来的，签发一个本次会话的 cookie：
    // 浏览器加载 /assets/*.js 时不带自定义头，没有 cookie 就会白屏。
    if (url.searchParams.get('token') === token) {
      res.setHeader(
        'Set-Cookie',
        `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Strict; Path=/`,
      );
    }

    if (!authorized(req, url)) {
      log(`ui ${method} ${url.pathname} -> 401`);
      const accept = req.headers.accept ?? '';
      if (accept.includes('text/html')) {
        res.writeHead(401, {
          'Content-Type': 'text/html; charset=utf-8',
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'no-referrer',
          'Cache-Control': 'no-store',
        });
        res.end(unauthorizedPage());
        return;
      }
      sendJson(res, 401, { error: 'unauthorized: 需要 token（见启动日志里的 URL）' });
      return;
    }

    // ---------- 写操作（纳管 / 移除） ----------
    if (method === 'POST') {
      if (!opts.allowWrites) {
        sendJson(res, 403, {
          error: '控制台以只读模式启动（pod ui --read-only），不接受写操作',
        });
        return;
      }
      if (!isJsonContentType(req)) {
        sendJson(res, 415, { error: '写操作必须使用 Content-Type: application/json' });
        return;
      }
      if (!sameOrigin(req)) {
        sendJson(res, 403, { error: '拒绝跨站写请求（Origin 与 Host 不一致）' });
        return;
      }
      const writeRoute = url.pathname;
      if (
        writeRoute !== '/api/agents/enroll' &&
        writeRoute !== '/api/agents/forget' &&
        writeRoute !== '/api/agents/takeover' &&
        writeRoute !== '/api/agents/revert' &&
        writeRoute !== '/api/agents/enforce'
      ) {
        sendJson(res, 404, { error: 'not found' });
        return;
      }
      try {
        const body = await readJsonBody(req);
        const agent = typeof body.agent === 'string' ? body.agent : '';
        const podHome = opts.podHome ?? join(opts.home, '.pod');
        const harness = typeof body.harness === 'string' ? body.harness : 'unknown';
        const mode = body.mode === 'record-only' ? 'record-only' : 'enforce';
        const result =
          writeRoute === '/api/agents/enroll'
            ? enrollAgent({ podHome, harness, agent, enrolledBy: 'pod ui' })
            : writeRoute === '/api/agents/forget'
              ? forgetAgent({ podHome, agent, purgeIdentity: body.purgeIdentity === true, actor: 'pod ui' })
              : writeRoute === '/api/agents/takeover'
                ? applyTakeover({
                    home: opts.home,
                    podHome,
                    harness,
                    agent,
                    actor: 'pod ui',
                    ...(opts.podBin ? { podBin: opts.podBin } : {}),
                  })
                : writeRoute === '/api/agents/enforce'
                  ? applyEnforcement({ home: opts.home, podHome, harness, agent, mode, actor: 'pod ui' })
                  : revertTakeover({ home: opts.home, podHome, agent, actor: 'pod ui' });
        log(`ui POST ${writeRoute} agent=${agent || harness} ok`);
        // 一并回新鲜数据：前端不必再发一次 GET，也就不会出现"按钮点了没反应"
        const payload = aggregateAgents({
          home: opts.home,
          podHome: opts.podHome,
          writesEnabled: true,
        });
        sendJson(res, 200, { result, payload });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        log(`ui POST ${writeRoute} -> 400 ${message}`);
        sendJson(res, 400, { error: message });
      }
      return;
    }

    if (url.pathname === '/api/health') {
      sendJson(res, 200, { ok: true, writes: opts.allowWrites === true });
      return;
    }

    // 只扫 harness（不读能力图/毒性链）：扫描按钮用这个，快且不动别的东西
    if (url.pathname === '/api/harnesses') {
      try {
        const payload = aggregateAgents({
          home: opts.home,
          podHome: opts.podHome,
          writesEnabled: opts.allowWrites === true,
        });
        sendJson(res, 200, {
          generatedAt: payload.generatedAt,
          podHome: payload.podHome,
          harnesses: payload.harnesses,
          capabilities: payload.capabilities,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        log(`ui /api/harnesses -> 500 ${message}`);
        sendJson(res, 500, { error: `扫描失败：${message}` });
      }
      return;
    }

    /**
     * 接管计划：只读（只解析配置、不写任何文件），所以走 GET。
     * 前端在弹确认框前先取一次，把"改前 / 改后 / 备份路径"摊开给用户看。
     */
    if (url.pathname === '/api/agents/takeover-plan') {
      const harness = url.searchParams.get('harness') ?? '';
      if (!harness) {
        sendJson(res, 400, { error: '缺少 harness 参数' });
        return;
      }
      try {
        const plan = planTakeover({
          home: opts.home,
          podHome: opts.podHome ?? join(opts.home, '.pod'),
          harness,
          ...(opts.podBin ? { podBin: opts.podBin } : {}),
          ...(url.searchParams.get('agent') ? { agent: url.searchParams.get('agent')! } : {}),
        });
        sendJson(res, 200, { plan, writes: opts.allowWrites === true });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        log(`ui /api/agents/takeover-plan -> 500 ${message}`);
        sendJson(res, 500, { error: `生成接管计划失败：${message}` });
      }
      return;
    }

    /** 切执法 / 回到只录不拦的计划（只读；仍然走 GET） */
    if (url.pathname === '/api/agents/enforce-plan') {
      const harness = url.searchParams.get('harness') ?? '';
      if (!harness) {
        sendJson(res, 400, { error: '缺少 harness 参数' });
        return;
      }
      const mode = url.searchParams.get('mode') === 'record-only' ? 'record-only' : 'enforce';
      try {
        const plan = planEnforcement({
          home: opts.home,
          podHome: opts.podHome ?? join(opts.home, '.pod'),
          harness,
          mode,
          ...(url.searchParams.get('agent') ? { agent: url.searchParams.get('agent')! } : {}),
        });
        sendJson(res, 200, { plan, writes: opts.allowWrites === true });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        log(`ui /api/agents/enforce-plan -> 500 ${message}`);
        sendJson(res, 500, { error: `生成执法计划失败：${message}` });
      }
      return;
    }

    if (url.pathname === '/api/agents') {
      try {
        const payload = aggregateAgents({
          home: opts.home,
          podHome: opts.podHome,
          writesEnabled: opts.allowWrites === true,
        });
        sendJson(res, 200, payload);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        log(`ui /api/agents -> 500 ${message}`);
        sendJson(res, 500, { error: `聚合失败：${message}` });
      }
      return;
    }

    if (url.pathname.startsWith('/api/')) {
      sendJson(res, 404, { error: 'not found' });
      return;
    }

    // 前端未构建：给出可执行的下一步，而不是空白页
    if (!existsSync(indexHtml)) {
      send(
        res,
        503,
        '控制台前端尚未构建。\n\n在仓库根目录执行：\n  pnpm --filter @podsec/web build\n\n然后重新打开本页。\n',
        'text/plain; charset=utf-8',
      );
      return;
    }

    const requested = resolveStatic(url.pathname);
    const file = requested ?? indexHtml; // SPA fallback
    const type = MIME[extname(file).toLowerCase()] ?? 'application/octet-stream';
    try {
      const body = readFileSync(file);
      res.writeHead(200, {
        'Content-Type': type,
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy': CSP,
        'Cache-Control': type === MIME['.html'] ? 'no-store' : 'public, max-age=300',
      });
      res.end(method === 'HEAD' ? undefined : body);
    } catch (err) {
      send(res, 500, `读取 ${file} 失败：${err instanceof Error ? err.message : String(err)}`, 'text/plain; charset=utf-8');
    }
  });

  return new Promise((resolvePromise) => {
    server.listen(opts.port ?? 8787, host, () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : (opts.port ?? 8787);
      const url = `http://${host}:${port}/?token=${token}`;
      log(
        opts.allowWrites
          ? t('pod ui listening on http://{host}:{port}（可写：纳管 / 移除）', { host, port })
          : t('pod ui listening on http://{host}:{port}（只读）', { host, port }),
      );
      resolvePromise({
        url,
        token,
        port,
        close: () =>
          new Promise<void>((done) => {
            server.close(() => done());
          }),
      });
    });
  });
}
