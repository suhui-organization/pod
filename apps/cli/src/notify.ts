/**
 * 桌面通知（审批请求）。尽力而为：失败绝不影响网关。
 *
 * 无新依赖：macOS 用 osascript display notification，Linux 用 notify-send。
 * 依赖注入便于单测（不会真的弹通知）。
 */
import { execFile } from 'node:child_process';
import { t } from '@podsec/i18n';

export interface ApprovalNotification {
  id: string;
  server: string;
  tool: string;
  agent?: string;
}

export interface NotifyDeps {
  platform?: NodeJS.Platform;
  run?: (cmd: string, args: string[]) => void;
}

function escapeAppleScript(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

export function notifyApproval(n: ApprovalNotification, deps: NotifyDeps = {}): void {
  const platform = deps.platform ?? process.platform;
  const run = deps.run ?? ((cmd, args) => { execFile(cmd, args, () => {}); });
  try {
    const detail = `${n.server}.${n.tool}${n.agent ? ` (agent=${n.agent})` : ''} — id ${n.id}`;
    if (platform === 'darwin') {
      run('osascript', [
        '-e',
        `display notification "${escapeAppleScript(detail)}" with title "${t('pod 需要审批')}"`,
      ]);
    } else if (platform === 'linux') {
      run('notify-send', [t('pod 需要审批'), detail]);
    }
  } catch {
    // 通知是尽力而为
  }
}
