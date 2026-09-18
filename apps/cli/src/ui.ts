/**
 * `pod ui` — 启动本地控制台。
 *
 * 定位：把 ~/.pod 下已落盘的策略、审计、能力图渲染成可读的资产视图。
 * 约束（threat-model.md T8）：只绑 127.0.0.1、随机 token 鉴权、前台运行。
 * 读全部只读；唯一的写操作是纳管/移除 agent（建身份 + 零权限策略 + 审计目录），
 * 可以用 --read-only 整个关掉。
 */
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { serveConsole, type UiServerHandle } from '@podsec/console';
import { t } from '@podsec/i18n';

export interface UiCommandOptions {
  /** ~/.pod */
  podHome: string;
  port: number;
  token?: string;
  /** true = 只读模式：不接受纳管/移除（写操作） */
  readOnly?: boolean;
  /** 写进 harness 配置的 pod 可执行文件（默认 "pod"）；pod 不在 PATH 上时必须给绝对路径 */
  podBin?: string;
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
    allowWrites: opts.readOnly !== true,
    ...(opts.podBin ? { podBin: opts.podBin } : {}),
    log,
  });

  log(
    opts.readOnly === true
      ? t('pod 控制台（只读模式）已启动：{url}', { url: handle.url })
      : t('pod 控制台已启动：{url}', { url: handle.url }),
  );
  log(t('数据目录：{path}', { path: opts.podHome }));
  if (opts.readOnly !== true) {
    log(
      t(
        '写操作已开启（页面上的「加入监控 / 移除监控」）：只写 ~/.pod 下的身份、零权限策略与审计记录，每次都会进哈希链。要关掉用 --read-only。',
      ),
    );
  }
  log(t('token 只在本机终端出现；页面加载后会从地址栏移除。按 Ctrl+C 停止。'));

  await new Promise<void>((resolvePromise) => {
    const stop = (signal: string) => {
      log(t('收到 {signal}，正在停止控制台…', { signal }));
      void handle.close().then(resolvePromise);
    };
    process.once('SIGINT', () => stop('SIGINT'));
    process.once('SIGTERM', () => stop('SIGTERM'));
  });
}

export type { UiServerHandle };
