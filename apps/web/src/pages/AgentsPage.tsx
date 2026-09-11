import { useCallback, useEffect, useState } from 'react';
import type { AgentAssetsPayload } from '@podsec/console/types';
import { ConsoleApiError, fetchAgents, fetchSample } from '../api.ts';
import { AgentCard } from '../components/AgentCard.tsx';
import { absoluteTime } from '../components/primitives.tsx';

type LoadState =
  | { phase: 'loading' }
  | { phase: 'error'; message: string; status: number }
  | { phase: 'ready'; payload: AgentAssetsPayload; source: 'live' | 'sample' };

function SkeletonGrid() {
  return (
    <div className="grid" aria-hidden="true">
      {[0, 1, 2, 3].map((i) => (
        <div className="skeleton-card" key={i}>
          <div className="skeleton-line skeleton-line--title" />
          <div className="skeleton-line" />
          <div className="skeleton-line skeleton-line--short" />
          <div className="skeleton-line" />
        </div>
      ))}
    </div>
  );
}

function errorHint(status: number): string {
  if (status === 401) {
    return '这个页面需要启动时打印的 token。用 `pod ui` 输出的完整 URL 重新打开（token 只在 URL 里出现一次，随后会从地址栏移除）。';
  }
  if (status === 0) {
    return '本地服务没有响应。确认 `pod ui` 仍在运行，并且是通过 127.0.0.1 访问。';
  }
  return '读取 ~/.pod 产物时出错。下面的示例数据可以先用来看界面。';
}

export function AgentsPage() {
  const [state, setState] = useState<LoadState>({ phase: 'loading' });
  const [now, setNow] = useState(() => new Date());

  const load = useCallback(async (mode: 'live' | 'sample') => {
    setState({ phase: 'loading' });
    try {
      const payload = mode === 'live' ? await fetchAgents() : await fetchSample();
      setState({ phase: 'ready', payload, source: mode });
      setNow(new Date());
    } catch (err) {
      const status = err instanceof ConsoleApiError ? err.status : 0;
      const message = err instanceof Error ? err.message : String(err);
      setState({ phase: 'error', message, status });
    }
  }, []);

  useEffect(() => {
    void load('live');
  }, [load]);

  const ready = state.phase === 'ready' ? state : null;
  const payload = ready?.payload ?? null;

  return (
    <main className="main">
      <div className="topbar">
        <div className="topbar__title">
          <h1 className="brand__name">Agent 资产</h1>
          <span className="topbar__sub">
            {payload ? (
              <>
                数据来源 <code className="num">{payload.podHome}</code> · 生成于{' '}
                {absoluteTime(payload.generatedAt)}
                {ready?.source === 'sample' ? ' · 示例数据' : ''}
              </>
            ) : (
              '读取本机 ~/.pod 的策略、审计与能力图'
            )}
          </span>
        </div>
        <div className="topbar__actions">
          <span className="pill pill--readonly">只读</span>
          {ready?.source === 'sample' ? (
            <button className="btn" type="button" onClick={() => void load('live')}>
              返回实时数据
            </button>
          ) : null}
          <button
            className="btn"
            type="button"
            onClick={() => void load(ready?.source ?? 'live')}
            disabled={state.phase === 'loading'}
          >
            刷新
          </button>
        </div>
      </div>

      <div className="content">
        {state.phase === 'loading' ? <SkeletonGrid /> : null}

        {state.phase === 'error' ? (
          <div className="placeholder">
            <h2 className="placeholder__title">读不到数据</h2>
            <div className="placeholder__body">
              <p>{state.message}</p>
              <p>{errorHint(state.status)}</p>
            </div>
            <div className="topbar__actions">
              <button className="btn" type="button" onClick={() => void load('live')}>
                重试
              </button>
              <button className="btn" type="button" onClick={() => void load('sample')}>
                载入示例数据
              </button>
            </div>
          </div>
        ) : null}

        {ready && payload ? (
          <>
            {payload.agents.some((agent) => agent.status === 'unobserved') ? (
              <div className="banner banner--danger">
                <div>
                  <div className="banner__title">有 agent 在未登记策略的情况下产生了真实调用</div>
                  <div>
                    审计里出现的 agent 身份必须能对上一条策略，否则它的权限不受 pod 约束（威胁
                    T6，影子 agent）。
                  </div>
                </div>
              </div>
            ) : null}

            {payload.discovered.length > 0 ? (
              <div className="banner banner--note">
                <div>
                  <div className="banner__title">
                    本机还发现 {payload.discovered.length} 个 agent 平台未纳入管理
                  </div>
                  <div>
                    {payload.discovered.map((item) => item.platform).join('、')}
                    —— 它们没有出现在策略或审计里。用 <code>pod scan</code> 看它们暴露了什么。
                  </div>
                </div>
              </div>
            ) : null}

            {payload.agents.length === 0 ? (
              <div className="placeholder">
                <h2 className="placeholder__title">还没有可展示的 agent 资产</h2>
                <div className="placeholder__body">
                  <p>
                    Agent 资产页直接读本机 <code>~/.pod</code> 的产物：策略、审计、能力图。现在这三处都还是空的。
                  </p>
                  <p>跑一遍这条链路，资产会自动出现：</p>
                  <pre className="codeblock">
                    <code>
                      pod record --agent claude-code --server filesystem --command mcp-server-filesystem
                      {'\n'}pod policy draft --from ~/.pod/audit --agent claude-code
                      {'\n'}pod graph build --out ~/.pod/graph/potential.json
                      {'\n'}pod graph toxic
                    </code>
                  </pre>
                </div>
                <button className="btn" type="button" onClick={() => void load('sample')}>
                  先看示例数据
                </button>
              </div>
            ) : (
              <>
                <div className="summary">
                  <div className="summary__cell">
                    <div className="summary__label">agent</div>
                    <div className="summary__value">{payload.totals.agents}</div>
                  </div>
                  <div className="summary__cell">
                    <div className="summary__label">登记的 MCP server</div>
                    <div className="summary__value">{payload.totals.servers}</div>
                  </div>
                  <div className="summary__cell">
                    <div className="summary__label">受管工具</div>
                    <div className="summary__value">{payload.totals.tools}</div>
                  </div>
                  <div className="summary__cell">
                    <div className="summary__label">近 7 天调用</div>
                    <div className="summary__value">{payload.totals.calls7d}</div>
                  </div>
                  <div
                    className={`summary__cell${
                      payload.totals.deny7d > 0 ? ' summary__cell--alert' : ''
                    }`}
                  >
                    <div className="summary__label">近 7 天 deny</div>
                    <div className="summary__value">{payload.totals.deny7d}</div>
                  </div>
                  <div
                    className={`summary__cell${
                      payload.totals.agentsWithRisks > 0 ? ' summary__cell--alert' : ''
                    }`}
                  >
                    <div className="summary__label">有风险信号的 agent</div>
                    <div className="summary__value">{payload.totals.agentsWithRisks}</div>
                  </div>
                </div>

                <div className="grid">
                  {payload.agents.map((agent) => (
                    <AgentCard key={agent.id} agent={agent} now={now} />
                  ))}
                </div>
              </>
            )}

            {payload.notes.length > 0 ? (
              <section className="notes">
                <h2 className="notes__title">数据说明（缺口照实写）</h2>
                <ul className="notes__list">
                  {payload.notes.map((note) => (
                    <li key={note}>{note}</li>
                  ))}
                </ul>
              </section>
            ) : null}
          </>
        ) : null}
      </div>
    </main>
  );
}
