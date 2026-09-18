import { useEffect } from 'react';
import type { HarnessCandidate, TakeoverPlan } from '@podsec/console/types';

/**
 * 接管确认框。
 *
 * 这是控制台里**唯一会改写用户配置文件**的操作，所以它比纳管多三样东西：
 * 1. 逐条列出"改前 → 改后"（用户能看懂自己的 mcp.json 会变成什么）；
 * 2. 明确写出备份路径（出事时知道去哪儿找）；
 * 3. 说清"只录不拦"——接管不等于拦住，切执法是后面的事。
 *
 * 计划取不到或不适用（pod 不在 PATH、格式不支持）时不给确认按钮：
 * 一个会把用户所有 MCP server 搞挂的操作，宁可不做。
 */
export function TakeoverDialog({
  harness,
  plan,
  loading,
  error,
  busy,
  onCancel,
  onConfirm,
}: {
  harness: HarnessCandidate;
  plan: TakeoverPlan | null;
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

  const canApply = plan?.applicable === true && !loading && !busy;

  return (
    <div className="overlay" role="presentation" onClick={onCancel}>
      <div
        className="dialog dialog--wide"
        role="dialog"
        aria-modal="true"
        aria-labelledby="takeover-title"
        onClick={(event) => event.stopPropagation()}
      >
        <h2 className="dialog__title" id="takeover-title">
          接管 {harness.label}（把 MCP server 包进网关）
        </h2>
        <p className="dialog__lead">
          这一步会<strong>改写 {harness.label} 的配置文件</strong>：把每个 MCP server 的启动命令
          换成 <code>pod serve --record-only …</code>，让它经过网关（策略 / 审批 / 审计都在网关侧）。
        </p>

        {loading ? <p className="dialog__lead">正在生成计划…</p> : null}
        {error ? <p className="dialog__error">{error}</p> : null}

        {plan ? (
          <>
            {plan.blockedReason ? (
              <div className="dialog__block">
                <div className="dialog__block-title">不能执行</div>
                <p className="dialog__error">{plan.blockedReason}</p>
              </div>
            ) : null}

            {plan.entries.length > 0 ? (
              <div className="dialog__block">
                <div className="dialog__block-title">会改写的配置（{plan.entries.length} 个文件）</div>
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

            <div className="dialog__block">
              <div className="dialog__block-title">包装策略</div>
              <p className="card__meta">
                <code>{plan.policyLabel}</code>
                {plan.reusesExistingPolicy
                  ? '（沿用你已有的策略，不覆盖）'
                  : '（新建的 record 模板；采集语料后再用 pod policy draft 编译真策略）'}
              </p>
            </div>

            {plan.skipped.length > 0 || plan.unsupported.length > 0 ? (
              <div className="dialog__block">
                <div className="dialog__block-title">跳过 / 暂不支持</div>
                <ul className="dialog__list">
                  {plan.unsupported.map((item) => (
                    <li key={item}>⚠️ {item}</li>
                  ))}
                  {plan.skipped.map((item) => (
                    <li key={item}>· {item}</li>
                  ))}
                </ul>
              </div>
            ) : null}

            <div className="dialog__block">
              <div className="dialog__block-title">要知道的三件事</div>
              <ul className="dialog__list">
                <li>
                  <strong>只录不拦</strong>：包装带 <code>--record-only</code>，先采集真实调用。
                  切执法要等策略编译出来（<code>pod policy draft</code>）。
                </li>
                <li>
                  <strong>可回滚</strong>：原配置已备份（路径见上），卡片上的「还原配置」会从最近的备份恢复。
                </li>
                {plan.notes
                  .filter((note) => note.includes('项目级') || note.includes('fail-closed'))
                  .map((note) => (
                    <li key={note}>{note}</li>
                  ))}
              </ul>
            </div>
          </>
        ) : null}

        <div className="dialog__actions">
          <button className="btn" type="button" onClick={onCancel} disabled={busy}>
            取消
          </button>
          <button className="btn btn--danger" type="button" disabled={!canApply} onClick={onConfirm}>
            {busy ? '改写中…' : '确认接管（会改配置文件）'}
          </button>
        </div>
      </div>
    </div>
  );
}
