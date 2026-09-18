import { useEffect } from 'react';
import type { EnforcePlan, HarnessCandidate } from '@podsec/console/types';

/**
 * 切执法 / 回到只录不拦的确认框。
 *
 * 这个对话框要挡住一种最糟的失败："看起来生效了，其实没有保护"。
 * 所以它必须显示三件事：
 * 1. 用哪份策略执法，以及这份策略允许什么（server / 工具 / 三态计数）；
 * 2. 改前 → 改后（就是去掉 --record-only，把 --policy 指向那份策略）；
 * 3. 切完会发生什么（approve 会挂起等审批；没跑 pod watch 就等到超时被拒）。
 *
 * 前置条件不满足时不给确认按钮，并把"要跑哪条命令"原样给出来。
 */
export function EnforceDialog({
  harness,
  plan,
  loading,
  error,
  busy,
  onCancel,
  onConfirm,
}: {
  harness: HarnessCandidate;
  plan: EnforcePlan | null;
  loading: boolean;
  error: string | null;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onCancel();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onCancel]);

  const backToRecord = plan?.mode === 'record-only';
  const canApply = plan?.applicable === true && !loading && !busy;

  return (
    <div className="overlay" role="presentation" onClick={onCancel}>
      <div
        className="dialog dialog--wide"
        role="dialog"
        aria-modal="true"
        aria-labelledby="enforce-title"
        onClick={(event) => event.stopPropagation()}
      >
        <h2 className="dialog__title" id="enforce-title">
          {backToRecord ? `让 ${harness.label} 回到只录不拦` : `让 ${harness.label} 开始执法`}
        </h2>
        <p className="dialog__lead">
          {backToRecord ? (
            <>这一步只去掉包装命令里的 <code>--record-only</code>：策略不变，但网关会重新开始拦。</>
          ) : (
            <>
              这一步把包装命令里的 <code>--record-only</code> 去掉，并让它使用你编译好的策略
              ——之后<strong>未登记的调用一律拒绝</strong>。
            </>
          )}
        </p>

        {loading ? <p className="dialog__lead">正在生成计划…</p> : null}
        {error ? <p className="dialog__error">{error}</p> : null}

        {plan ? (
          <>
            {plan.blockedReason ? (
              <div className="dialog__block">
                <div className="dialog__block-title">还不能执行</div>
                <p className="dialog__error">{plan.blockedReason}</p>
                <p className="card__meta">当前审计语料：{plan.corpus} 条</p>
              </div>
            ) : null}

            {plan.policyPath ? (
              <div className="dialog__block">
                <div className="dialog__block-title">执法策略</div>
                <p className="card__meta">
                  <code>{plan.policyLabel}</code>
                </p>
                {plan.policySummary ? (
                  <div className="tally">
                    <span className="tally__item">
                      <span className="tally__label">servers</span>
                      <span className="tally__value">{plan.policySummary.servers}</span>
                    </span>
                    <span className="tally__item">
                      <span className="tally__label">tools</span>
                      <span className="tally__value">{plan.policySummary.tools}</span>
                    </span>
                    <span className="tally__item tally__item--allow">
                      <span className="tally__label">allow</span>
                      <span className="tally__value">{plan.policySummary.allow}</span>
                    </span>
                    <span className="tally__item tally__item--approve">
                      <span className="tally__label">approve</span>
                      <span className="tally__value">{plan.policySummary.approve}</span>
                    </span>
                    <span className="tally__item tally__item--deny">
                      <span className="tally__label">deny</span>
                      <span className="tally__value">{plan.policySummary.deny}</span>
                    </span>
                  </div>
                ) : null}
                <p className="card__meta">
                  这份策略编译时的审计语料：<strong>{plan.corpus}</strong> 条。
                  {plan.corpus === 0 ? ' 还没有语料——策略可能只是一张猜测表。' : ''}
                </p>
              </div>
            ) : null}

            {plan.entries.length > 0 ? (
              <div className="dialog__block">
                <div className="dialog__block-title">会改写的包装命令</div>
                {plan.entries.map((entry) => (
                  <div className="plan" key={entry.configPath}>
                    <div className="plan__file">
                      <code>{entry.configLabel}</code>
                    </div>
                    {entry.servers.map((server) => (
                      <div className="plan__server" key={server.name}>
                        <div className="plan__name">{server.name}</div>
                        <div className="plan__line plan__line--from">
                          <span className="plan__tag">改前</span>
                          <code>{server.from}</code>
                        </div>
                        <div className="plan__line plan__line--to">
                          <span className="plan__tag">改后</span>
                          <code>{server.to}</code>
                        </div>
                      </div>
                    ))}
                    <div className="plan__backup">
                      备份：<code>{entry.backupLabel}</code>
                    </div>
                  </div>
                ))}
              </div>
            ) : null}

            {plan.notes.length > 0 ? (
              <div className="dialog__block">
                <div className="dialog__block-title">切之前要知道的</div>
                <ul className="dialog__list">
                  {plan.notes.map((note) => (
                    <li key={note}>{note}</li>
                  ))}
                </ul>
              </div>
            ) : null}
          </>
        ) : null}

        <div className="dialog__actions">
          <button className="btn" type="button" onClick={onCancel} disabled={busy}>
            取消
          </button>
          <button
            className={`btn ${backToRecord ? '' : 'btn--danger'}`}
            type="button"
            disabled={!canApply}
            onClick={onConfirm}
          >
            {busy ? '改写中…' : backToRecord ? '确认回到只录不拦' : '确认切执法（会改配置）'}
          </button>
        </div>
      </div>
    </div>
  );
}
