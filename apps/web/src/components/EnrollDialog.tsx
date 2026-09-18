import { useEffect, useRef, useState } from 'react';
import type { HarnessCandidate } from '@podsec/console/types';

/**
 * 纳管确认框。
 *
 * 为什么一定要确认一次：这是控制台唯一的写操作。用户点之前必须知道
 * **会写什么、不会写什么**——"不会改你的 harness 配置"这句尤其重要，
 * 否则没人敢点（谁都怕网页按钮偷偷改了自己的 mcp.json）。
 */
export function EnrollDialog({
  harness,
  busy,
  error,
  onCancel,
  onConfirm,
}: {
  harness: HarnessCandidate;
  busy: boolean;
  error: string | null;
  onCancel: () => void;
  onConfirm: (agent: string) => void;
}) {
  const [agent, setAgent] = useState(harness.suggestedAgent);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
    inputRef.current?.select();
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onCancel();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onCancel]);

  const valid = /^[A-Za-z0-9._-]{1,64}$/.test(agent) && agent !== '.' && agent !== '..';

  return (
    <div className="overlay" role="presentation" onClick={onCancel}>
      <div
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="enroll-title"
        onClick={(event) => event.stopPropagation()}
      >
        <h2 className="dialog__title" id="enroll-title">
          把 {harness.label} 加入监控
        </h2>
        <p className="dialog__lead">
          agent 名会进路径与审计链，用 <code>A-Za-z0-9._-</code>
          ；默认用 harness id（<code>{harness.suggestedAgent}</code>）。
        </p>

        <label className="field">
          <span className="field__label">agent 名</span>
          <input
            ref={inputRef}
            className="field__input"
            value={agent}
            spellCheck={false}
            autoComplete="off"
            onChange={(event) => setAgent(event.target.value.trim())}
          />
        </label>
        {!valid ? <p className="dialog__error">名字不合法：只允许 A-Za-z0-9._-，长度 1-64。</p> : null}

        <div className="dialog__block">
          <div className="dialog__block-title">会写这些（都在 ~/.pod 下）</div>
          <ul className="dialog__list">
            <li>
              <code>identity/{agent || '…'}/</code> —— ed25519 身份（私钥 0600）。有了它才能回答"这次调用是谁做的"
            </li>
            <li>
              <code>policies/{agent || '…'}.json</code> —— <strong>零权限起点</strong>（未登记 server 一律拒绝）；已有策略则不动
            </li>
            <li>
              <code>audit/{agent || '…'}/</code> —— 审计目录
            </li>
            <li>
              控制平面审计一条（<code>kind=identity</code> / <code>config-change</code>）—— 写进 SHA-256 哈希链
            </li>
          </ul>
        </div>

        <div className="dialog__block">
          <div className="dialog__block-title">不会做这些</div>
          <ul className="dialog__list">
            <li>
              <strong>不改动 {harness.label} 的配置</strong>——改写配置是 <code>pod onboard --yes</code> 的事（它有备份与回滚）
            </li>
            <li>
              不拦流量。纳管只是把资产纳入管理；要真正拦，得让 MCP server 经过网关
              {harness.servers.total > harness.servers.behindGateway
                ? `（当前有 ${harness.servers.total - harness.servers.behindGateway} 个 server 直连）`
                : ''}
            </li>
          </ul>
        </div>

        {error ? <p className="dialog__error">{error}</p> : null}

        <div className="dialog__actions">
          <button className="btn" type="button" onClick={onCancel} disabled={busy}>
            取消
          </button>
          <button
            className="btn btn--primary"
            type="button"
            disabled={!valid || busy}
            onClick={() => onConfirm(agent)}
          >
            {busy ? '纳管中…' : '确认纳管'}
          </button>
        </div>
      </div>
    </div>
  );
}
