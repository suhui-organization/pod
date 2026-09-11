/**
 * `pod ui` 的本地 HTTP 服务：托管控制台静态产物 + 只读数据接口。
 *
 * 安全约束（threat-model.md T8）：
 * - 只绑 127.0.0.1（默认），不对外监听；
 * - 随机 token 鉴权，三种携带方式：`?token=`、`x-pod-token` 头、首次访问后下发的
 *   HttpOnly cookie（浏览器加载 <script>/<link> 时带不了自定义头，cookie 是必须的，
 *   否则静态产物一律 401、页面白屏）；
 * - 默认只读：只接受 GET / HEAD，其他方法一律 405；
 * - 安全头：CSP self、nosniff、no-referrer（token 不通过 Referer 外泄）。
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { aggregateAgents } from './aggregate.js';

export interface UiServerOptions {
  home: string;
  /** 前端静态产物目录（apps/web/dist）；不存在时接口仍可用，页面提示未构建 */
  webRoot: string;
  podHome?: string;
  port?: number;
  host?: string;
  /** 不传则随机生成 */
  token?: string;
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

function send(res: ServerResponse, status: number, body: string, type: string): void {
  res.writeHead(status, {
    'Content-Type': type,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
  });
  res.end(body);
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

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://${host}`);
    const method = req.method ?? 'GET';

    if (method !== 'GET' && method !== 'HEAD') {
      send(res, 405, JSON.stringify({ error: 'read-only console: only GET/HEAD' }), MIME['.json']!);
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
      send(res, 401, JSON.stringify({ error: 'unauthorized: 需要 token（见启动日志里的 URL）' }), MIME['.json']!);
      return;
    }

    if (url.pathname === '/api/health') {
      send(res, 200, JSON.stringify({ ok: true }), MIME['.json']!);
      return;
    }

    if (url.pathname === '/api/agents') {
      try {
        const payload = aggregateAgents({ home: opts.home, podHome: opts.podHome });
        send(res, 200, JSON.stringify(payload), MIME['.json']!);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        log(`ui /api/agents -> 500 ${message}`);
        send(res, 500, JSON.stringify({ error: `聚合失败：${message}` }), MIME['.json']!);
      }
      return;
    }

    if (url.pathname.startsWith('/api/')) {
      send(res, 404, JSON.stringify({ error: 'not found' }), MIME['.json']!);
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
      log(`pod ui listening on http://${host}:${port} (只读)`);
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
