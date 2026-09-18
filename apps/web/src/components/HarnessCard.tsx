import type { HarnessCandidate } from '@podsec/console/types';
import { useEffect, useState } from 'react';

const MANAGED_BY_LABEL: Record<string, string> = {
  policy: '策略',
  audit: '审计',
  identity: '身份',
};

/**
 * 一张"本机 harness"卡：扫描结果 → 是否已纳管 → 纳管按钮。
 *
 * 与 AgentCard 的分工：AgentCard 讲"已经在管的东西做了什么"，
 * 这张卡讲"这台机器上还有什么没被管起来"。所以它只呈现"纳管需要知道的信息"：
 * 装在哪（证据）、有几个 server、其中几个过了网关、扫出多少漏洞。
 */
export function HarnessCard({
  harness,
  writable,
  busy,
  onEnroll,
  onForget,
  onTakeover,
  onRevert,
  onEnforce,
}: {
  harness: HarnessCandidate;
  writable: boolean;
  busy: boolean;
  onEnroll: (harness: HarnessCandidate) => void;
  onForget: (harness: HarnessCandidate) => void;
  onTakeover: (harness: HarnessCandidate) => void;
  onRevert: (harness: HarnessCandidate) => void;
  onEnforce: (harness: HarnessCandidate, mode: 'record-only' | 'enforce') => void;
}) {
  const { servers, findings } = harness;
  const headingId = `harness-${harness.id}`;
  const gatewayGap = servers.total - servers.behindGateway;
  const [confirming, setConfirming] = useState(false);
  const [confirmingRevert, setConfirmingRevert] = useState(false);
  /**
   * 三种状态，别合并成"已纳管/未纳管"两态：
   * - enrolled：有策略 → 真的被约束了；
   * - partial：只有身份/审计（比如移除纳管后身份刻意保留）→ 还没被约束；
   * - none：什么都没发现。
   */
  const state: 'enrolled' | 'partial' | 'none' = harness.managed && harness.hasPolicy
    ? 'enrolled'
    : harness.managed
      ? 'partial'
      : 'none';

  // 确认态 8 秒后自动收回：避免"点过一次之后按钮一直处于危险状态"
  useEffect(() => {
    if (!confirming) return;
    const timer = window.setTimeout(() => setConfirming(false), 8000);
    return () => window.clearTimeout(timer);
  }, [confirming]);

  useEffect(() => {
    if (!confirmingRevert) return;
    const timer = window.setTimeout(() => setConfirmingRevert(false), 8000);
    return () => window.clearTimeout(timer);
  }, [confirmingRevert]);

  return (
    <article className="card card--harness" aria-labelledby={headingId}>
      <header className="card__head">
        <div className="card__identity">
          <h2 className="card__name" id={headingId}>
            {harness.label}
          </h2>
          <div className="card__badges">
            <span className="pill">{harness.id}</span>
            {state === 'enrolled' ? (
              <span className="pill pill--managed">
                已纳管
                {harness.managedBy.length > 0
                  ? ` · ${harness.managedBy.map((m) => MANAGED_BY_LABEL[m] ?? m).join('/')}`
                  : ''}
              </span>
            ) : state === 'partial' ? (
              <span className="pill pill--partial">
                仅{harness.managedBy.map((m) => MANAGED_BY_LABEL[m] ?? m).join('/') ?? '部分产物'}
              </span>
            ) : (
              <span className="pill">未纳管</span>
            )}
          </div>
        </div>
      </header>

      <hr className="card__rule" />

      <section className="card__section">
        <h3 className="card__section-label">安装证据（只读扫描）</h3>
        <ul className="evidence__list evidence__list--tight">
          {harness.evidence.map((path) => (
            <li key={path}>
              <code>{path}</code>
            </li>
          ))}
        </ul>
        {harness.configFiles.length > 0 ? (
          <p className="card__meta">
            读到配置：{harness.configFiles.map((f) => (
              <code key={f}>{f}</code>
            ))}
          </p>
        ) : (
          <p className="card__meta">没读到可解析的 MCP 配置——纳管后需要先确认它的 server 清单。</p>
        )}
      </section>

      <section className="card__section">
        <h3 className="card__section-label">暴露面</h3>
        <div className="tally">
          <span className="tally__item">
            <span className="tally__label">MCP server</span>
            <span className="tally__value">{servers.total}</span>
          </span>
          <span className={`tally__item${gatewayGap > 0 ? ' tally__item--deny' : ''}`}>
            <span className="tally__label">绕过网关</span>
            <span className="tally__value">{gatewayGap}</span>
          </span>
          <span className={`tally__item${findings.high > 0 ? ' tally__item--deny' : ''}`}>
            <span className="tally__label">high</span>
            <span className="tally__value">{findings.high}</span>
          </span>
          <span className={`tally__item${findings.medium > 0 ? ' tally__item--approve' : ''}`}>
            <span className="tally__label">medium</span>
            <span className="tally__value">{findings.medium}</span>
          </span>
          <span className="tally__item">
            <span className="tally__label">low</span>
            <span className="tally__value">{findings.low}</span>
          </span>
        </div>
        <p className="card__meta">
          漏洞来自 <code>pod guard</code> 的 18 条威胁目录；完整清单用 <code>pod guard scan</code> 看。
        </p>
      </section>

      {/* 第二步：接管（把 MCP server 包进网关）。只有存在直连 server 时才出现 */}
      {servers.total > 0 ? (
        <section className="card__section">
          <h3 className="card__section-label">网关接管</h3>
          {gatewayGap === 0 ? (
            <>
              <div className="takeover takeover--done">
                <span className="pill pill--managed">已接管</span>
                <span className="card__meta">
                  {servers.enforcing > 0
                    ? `${servers.enforcing} 个 server 已在执法（未登记调用一律拒绝）`
                    : `${servers.recordOnly} 个 server 都经过网关，但仍然只录不拦`}
                </span>
                {confirmingRevert ? (
                  <span className="card__actions-group">
                    <span className="card__meta">撤销上一步（从最近的备份恢复）</span>
                    <button className="btn" type="button" onClick={() => setConfirmingRevert(false)}>
                      取消
                    </button>
                    <button
                      className="btn btn--danger"
                      type="button"
                      disabled={busy}
                      onClick={() => {
                        setConfirmingRevert(false);
                        onRevert(harness);
                      }}
                    >
                      确认还原
                    </button>
                  </span>
                ) : (
                  <button
                    className="btn btn--quiet"
                    type="button"
                    disabled={!writable || busy}
                    onClick={() => setConfirmingRevert(true)}
                  >
                    还原配置
                  </button>
                )}
              </div>
              {harness.enforcedPolicy ? (
                <p className="card__meta">
                  {servers.enforcing > 0 ? '执法策略' : '包装策略'}：
                  <code>{harness.enforcedPolicy}</code>
                  {harness.managedBy.includes('policy') && harness.enforcedPolicy.includes('onboard-')
                    ? '（接管时的 record 模板，切执法前应当换成编译好的策略）'
                    : ''}
                </p>
              ) : null}

              {/* 第三步：只录不拦 ↔ 执法。前置条件（有编译好的策略）在计划里检查 */}
              <div className="takeover">
                {servers.recordOnly > 0 ? (
                  <>
                    <span className="card__meta">
                      只录不拦是为采集语料。用 <code>pod policy draft</code> 编译并复核策略后，
                      这里可以切执法。
                    </span>
                    <button
                      className="btn btn--primary"
                      type="button"
                      disabled={!writable || busy}
                      onClick={() => onEnforce(harness, 'enforce')}
                    >
                      {busy ? '处理中…' : '切执法'}
                    </button>
                  </>
                ) : (
                  <>
                    <span className="card__meta">
                      已经在执法：网关按策略判定，未登记的一律拒绝。
                      如果它打断了正常干活，可以先退回只录不拦。
                    </span>
                    <button
                      className="btn"
                      type="button"
                      disabled={!writable || busy}
                      onClick={() => onEnforce(harness, 'record-only')}
                    >
                      {busy ? '处理中…' : '回到只录不拦'}
                    </button>
                  </>
                )}
              </div>
            </>
          ) : (
            <div className="takeover">
              <span className="card__meta">
                还有 <strong>{gatewayGap}</strong> 个 server 直连（不走网关 ⇒ 策略与审计对它们无效）。
                接管会把启动命令改写成经网关的包装命令，<strong>会动这个 harness 的配置文件</strong>。
              </span>
              <button
                className="btn"
                type="button"
                disabled={!writable || busy}
                onClick={() => onTakeover(harness)}
                title={writable ? '先看改写计划，确认后才动配置' : '控制台以只读模式启动（pod ui --read-only）'}
              >
                {busy ? '处理中…' : '接管（包进网关）'}
              </button>
            </div>
          )}
        </section>
      ) : null}

      <footer className="card__actions">
        {state === 'enrolled' && harness.enrolledAt ? (
          <>
            <span className="card__meta">
              agent：<code>{harness.agentNames.join('、') || harness.suggestedAgent}</code>
              {' · 由控制台纳管'}
            </span>
            {confirming ? (
              <span className="card__actions-group">
                <span className="card__meta">删掉纳管创建的策略；身份保留</span>
                <button className="btn" type="button" onClick={() => setConfirming(false)}>
                  取消
                </button>
                <button
                  className="btn btn--danger"
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    setConfirming(false);
                    onForget(harness);
                  }}
                >
                  确认移除
                </button>
              </span>
            ) : (
              <button
                className="btn btn--quiet"
                type="button"
                disabled={!writable || busy}
                onClick={() => setConfirming(true)}
                title={writable ? '移除控制台纳管的内容' : '控制台以只读模式启动（pod ui --read-only）'}
              >
                移除监控
              </button>
            )}
          </>
        ) : state === 'enrolled' ? (
          // 有策略但不是控制台纳管的（例如 pod onboard 写下的包装策略）：
          // 不提供"移除监控"——pod 不删不是自己写的东西
          <span className="card__meta">
            已纳入管理（{harness.managedBy.map((m) => MANAGED_BY_LABEL[m] ?? m).join('/')}），
            但不是控制台纳管的，因此这里不提供移除——用 <code>pod agents revert</code> 或手工处理。
          </span>
        ) : (
          <>
            <span className="card__meta">
              {state === 'partial'
                ? '有身份/审计但没有策略——还没有真正被约束。'
                : '纳管后会有身份、零权限策略与审计目录；'}
              <strong>不会改动 harness 配置</strong>。
            </span>
            <button
              className="btn btn--primary"
              type="button"
              disabled={!writable || busy}
              onClick={() => onEnroll(harness)}
              title={writable ? `纳管为 agent ${harness.suggestedAgent}` : '控制台以只读模式启动（pod ui --read-only）'}
            >
              {busy ? '处理中…' : '加入监控'}
            </button>
          </>
        )}
      </footer>
    </article>
  );
}
