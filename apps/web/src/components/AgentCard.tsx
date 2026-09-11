import type { AgentAsset } from '@podsec/console/types';
import {
  DecisionPill,
  SignalChip,
  Sparkline,
  StatusBadge,
  absoluteTime,
  relativeTime,
} from './primitives.tsx';

/**
 * 一张 agent 资产卡：身份 → 权限 → 活动 → 风险 → 证据。
 * 顺序刻意与用户的问题顺序一致（"有哪些 → 能碰什么 → 最近做了什么 → 哪里可疑"）。
 */
export function AgentCard({ agent, now }: { agent: AgentAsset; now: Date }) {
  const { permissions: p, activity: a } = agent;
  const headingId = `agent-${agent.id}`;

  return (
    <article className="card" aria-labelledby={headingId}>
      <header className="card__head">
        <div className="card__identity">
          <h2 className="card__name" id={headingId}>
            {agent.label}
          </h2>
          <div className="card__badges">
            <span className="pill">{agent.platform ?? '来源未识别'}</span>
            {agent.policy ? (
              <span className="pill">
                策略 v{agent.policy.version} · 默认 {agent.policy.defaultDecision}
              </span>
            ) : (
              <span className="pill">无策略绑定</span>
            )}
          </div>
        </div>
        <StatusBadge status={agent.status} />
      </header>

      <hr className="card__rule" />

      <section className="card__section">
        <h3 className="card__section-label">权限概况</h3>
        <div className="tally">
          <span className="tally__item">
            <span className="tally__label">servers</span>
            <span className="tally__value">{p.servers}</span>
          </span>
          <span className="tally__item">
            <span className="tally__label">tools</span>
            <span className="tally__value">{p.tools}</span>
          </span>
          <span className="tally__item tally__item--allow">
            <span className="tally__label">allow</span>
            <span className="tally__value">{p.allow}</span>
          </span>
          <span className="tally__item tally__item--approve">
            <span className="tally__label">approve</span>
            <span className="tally__value">{p.approve}</span>
          </span>
          <span className="tally__item tally__item--deny">
            <span className="tally__label">deny</span>
            <span className="tally__value">{p.deny}</span>
          </span>
        </div>
      </section>

      <section className="card__section">
        <h3 className="card__section-label">近 7 天活动</h3>
        <div className="activity">
          <Sparkline values={a.calls7d} />
          <div className="activity__meta">
            <div>
              <strong>{a.calls7dTotal}</strong> 次调用
              {a.deny7d + a.approve7d > 0 ? (
                <>
                  {' · '}
                  <strong>{a.deny7d}</strong> deny / <strong>{a.approve7d}</strong> approve
                </>
              ) : null}
            </div>
            <div>最近 {relativeTime(a.lastCallAt, now)}</div>
          </div>
        </div>
        {a.lastDecision ? (
          <div className="decision">
            <DecisionPill decision={a.lastDecision.decision} />
            <span className="decision__target">
              {a.lastDecision.server}.{a.lastDecision.tool}
            </span>
            <span className="decision__time">
              {relativeTime(a.lastDecision.at, now)}
              {a.lastDecision.enforced ? '' : ' · 仅记录未强制执行'}
            </span>
          </div>
        ) : (
          <div className="decision">
            <span className="decision__time">没有调用记录</span>
          </div>
        )}
      </section>

      <section className="card__section">
        <h3 className="card__section-label">风险信号</h3>
        <div className="signals">
          {agent.risks.length === 0 ? (
            <span className="signal signal--none">未发现风险信号（依据：已读到的策略与审计）</span>
          ) : (
            agent.risks.map((risk) => (
              <SignalChip
                key={risk.kind}
                severity={risk.severity}
                label={risk.label}
                count={risk.count}
                title={risk.detail}
              />
            ))
          )}
        </div>
        <details className="evidence">
          <summary>证据与出处</summary>
          <ul className="evidence__list">
            {agent.risks.map((risk) => (
              <li key={risk.kind}>
                <strong>{risk.label}</strong>：{risk.detail}
              </li>
            ))}
            <li>
              策略文件：<code>{agent.policy ? agent.policy.file : '（无）'}</code> · 审计条目：
              <code>{a.entries}</code>
            </li>
            <li>
              最近一次调用：<code>{absoluteTime(a.lastCallAt)}</code>
            </li>
            {a.lastDecision?.reason ? (
              <li>
                最近一次决策原因：<code>{a.lastDecision.reason}</code>
              </li>
            ) : null}
          </ul>
        </details>
      </section>
    </article>
  );
}
