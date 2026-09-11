/**
 * `pod ui` — 启动本地只读控制台。
 *
 * 定位：把 ~/.pod 下已落盘的策略、审计、能力图渲染成可读的资产视图。
 * 约束（threat-model.md T8）：只绑 127.0.0.1、随机 token 鉴权、只读、前台运行。
 */
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { serveConsole, type UiServerHandle } from '@podsec/console';

export interface UiCommandOptions {
  /** ~/.pod */
  podHome: string;
  port: number;
  token?: string;
  log?: (msg: string) => void;
}

/**
 * 前端产物位置：apps/cli/dist/ui.js → ../../web/dist = apps/web/dist。
 * 若前端未构建，服务仍然可用（接口正常，页面给出构建提示）。
 */
export function resolveWebRoot(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, '../../web/dist');
}

/** 启动控制台并保持前台，直到 Ctrl+C / SIGTERM */
export async function cmdUi(opts: UiCommandOptions): Promise<void> {
  const log = opts.log ?? ((msg: string) => console.log(msg));

  const handle = await serveConsole({
    home: dirname(opts.podHome),
    podHome: opts.podHome,
    webRoot: resolveWebRoot(),
    port: opts.port,
    token: opts.token,
    log,
  });

  log(`pod 控制台（只读）已启动：${handle.url}`);
  log(`数据目录：${opts.podHome}`);
  log('token 只在本机终端出现；页面加载后会从地址栏移除。按 Ctrl+C 停止。');

  await new Promise<void>((resolvePromise) => {
    const stop = (signal: string) => {
      log(`收到 ${signal}，正在停止控制台…`);
      void handle.close().then(resolvePromise);
    };
    process.once('SIGINT', () => stop('SIGINT'));
    process.once('SIGTERM', () => stop('SIGTERM'));
  });
}

export type { UiServerHandle };
