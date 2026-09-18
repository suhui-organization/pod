import { useCallback, useEffect, useState } from 'react';
import type { AgentAssetsPayload, HarnessCandidate } from '@podsec/console/types';
import type { TakeoverPlan } from '@podsec/console/types';
import type { EnforcePlan } from '@podsec/console/types';
import {
  ConsoleApiError,
  applyTakeover,
  applyEnforcement,
  enrollHarness,
  fetchAgents,
  fetchSample,
  fetchTakeoverPlan,
  fetchEnforcePlan,
  forgetHarness,
  revertTakeover,
  scanHarnesses,
} from '../api.ts';
import { AgentCard } from '../components/AgentCard.tsx';
import { HarnessCard } from '../components/HarnessCard.tsx';
import { EnrollDialog } from '../components/EnrollDialog.tsx';
import { TakeoverDialog } from '../components/TakeoverDialog.tsx';
import { EnforceDialog } from '../components/EnforceDialog.tsx';
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
  const [scanAt, setScanAt] = useState<string | null>(null);
  const [scanBusy, setScanBusy] = useState(false);
  const [enrollTarget, setEnrollTarget] = useState<HarnessCandidate | null>(null);
  const [takeoverTarget, setTakeoverTarget] = useState<HarnessCandidate | null>(null);
  const [takeoverPlan, setTakeoverPlan] = useState<TakeoverPlan | null>(null);
  const [takeoverLoading, setTakeoverLoading] = useState(false);
  const [enforceTarget, setEnforceTarget] = useState<HarnessCandidate | null>(null);
  const [enforceMode, setEnforceMode] = useState<'record-only' | 'enforce'>('enforce');
  const [enforcePlan, setEnforcePlan] = useState<EnforcePlan | null>(null);
  const [enforceLoading, setEnforceLoading] = useState(false);
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [flash, setFlash] = useState<string | null>(null);

  const load = useCallback(async (mode: 'live' | 'sample') => {
    setState({ phase: 'loading' });
    setActionError(null);
    try {
      const payload = mode === 'live' ? await fetchAgents() : await fetchSample();
      setState({ phase: 'ready', payload, source: mode });
      setNow(new Date());
      if (mode === 'live') setScanAt(payload.generatedAt);
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
  // 示例数据里没有 harnesses 字段（它随前端发布，可能比后端旧）→ 回退到空数组
  const harnesses = payload?.harnesses ?? [];
  const installedHarnesses = harnesses.filter((h) => h.installed);
  const writable = payload?.capabilities?.writes === true;

  /** 扫描按钮：只读请求，重新读一遍本机 harness 列表 */
  const rescan = useCallback(async () => {
    setScanBusy(true);
    setActionError(null);
    try {
      const scan = await scanHarnesses();
      setScanAt(scan.generatedAt);
      setState((previous) =>
        previous.phase === 'ready'
          ? {
              ...previous,
              payload: {
                ...previous.payload,
                generatedAt: scan.generatedAt,
                harnesses: scan.harnesses,
                capabilities: scan.capabilities,
              },
            }
          : previous,
      );
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setScanBusy(false);
    }
  }, []);

  const confirmEnroll = useCallback(
    async (agent: string) => {
      if (!enrollTarget) return;
      const harness = enrollTarget;
      setActionBusy(harness.id);
      setActionError(null);
      try {
        const { result, payload: fresh } = await enrollHarness({ harness: harness.id, agent });
        setState({ phase: 'ready', payload: fresh, source: 'live' });
        setNow(new Date());
        setEnrollTarget(null);
        setFlash(
          result.alreadyManaged
            ? `agent ${result.agent} 已在纳管中（本次无改动）。`
            : `已纳管 agent ${result.agent}：身份 ${result.identityFingerprint ?? '—'} · 策略 ${
                result.policyFile ?? '（沿用已有策略）'
              }。下一步用 pod onboard 把 server 包进网关。`,
        );
      } catch (err) {
        setActionError(err instanceof Error ? err.message : String(err));
      } finally {
        setActionBusy(null);
      }
    },
    [enrollTarget],
  );

  const confirmForget = useCallback(async (harness: HarnessCandidate) => {
    const agent = harness.agentNames[0] ?? harness.suggestedAgent;
    setActionBusy(harness.id);
    setActionError(null);
    try {
      const { result, payload: fresh } = await forgetHarness({ agent });
      setState({ phase: 'ready', payload: fresh, source: 'live' });
      setNow(new Date());
      setFlash(
        result.found
          ? `已移除 ${result.agent} 的纳管（策略${result.removed.policy ? '已删' : '保留'} · 身份${
              result.removed.identity ? '已删' : '保留'
            }）。`
          : `${result.agent} 没有纳管记录，未做改动。`,
      );
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setActionBusy(null);
    }
  }, []);

  /** 打开接管确认框：先取计划（只读），把改前/改后摊开给用户看 */
  const openTakeover = useCallback(async (harness: HarnessCandidate) => {
    setTakeoverTarget(harness);
    setTakeoverPlan(null);
    setTakeoverLoading(true);
    setActionError(null);
    try {
      const { plan } = await fetchTakeoverPlan(harness.id, harness.suggestedAgent);
      setTakeoverPlan(plan);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setTakeoverLoading(false);
    }
  }, []);

  const confirmTakeover = useCallback(async () => {
    if (!takeoverTarget) return;
    const harness = takeoverTarget;
    setActionBusy(harness.id);
    setActionError(null);
    try {
      const { result, payload: fresh } = await applyTakeover({
        harness: harness.id,
        agent: harness.suggestedAgent,
      });
      setState({ phase: 'ready', payload: fresh, source: 'live' });
      setNow(new Date());
      setTakeoverTarget(null);
      setTakeoverPlan(null);
      setFlash(
        `已接管 ${harness.label}：${result.changed.length} 个配置文件改写成经网关的启动命令（默认只录不拦）。` +
          '采集几天语料后用 pod policy draft 编译最小权限策略再切执法。',
      );
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setActionBusy(null);
    }
  }, [takeoverTarget]);

  const confirmRevert = useCallback(async (harness: HarnessCandidate) => {
    const agent = harness.takeover ? harness.agentNames[0] ?? harness.suggestedAgent : harness.suggestedAgent;
    setActionBusy(harness.id);
    setActionError(null);
    try {
      const { result, payload: fresh } = await revertTakeover({ agent });
      setState({ phase: 'ready', payload: fresh, source: 'live' });
      setNow(new Date());
      setFlash(
        result.restored.length > 0
          ? `已从最近的备份还原 ${result.restored.length} 个配置。`
          : '没有找到可还原的备份（可能已经还原过）。',
      );
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setActionBusy(null);
    }
  }, []);

  /** 打开执法确认框：先取计划（只读），前置条件不满足时原样显示原因 */
  const openEnforce = useCallback(
    async (harness: HarnessCandidate, mode: 'record-only' | 'enforce') => {
      setEnforceTarget(harness);
      setEnforceMode(mode);
      setEnforcePlan(null);
      setEnforceLoading(true);
      setActionError(null);
      try {
        const { plan } = await fetchEnforcePlan(harness.id, mode, harness.suggestedAgent);
        setEnforcePlan(plan);
      } catch (err) {
        setActionError(err instanceof Error ? err.message : String(err));
      } finally {
        setEnforceLoading(false);
      }
    },
    [],
  );

  const confirmEnforce = useCallback(async () => {
    if (!enforceTarget) return;
    const harness = enforceTarget;
    setActionBusy(harness.id);
    setActionError(null);
    try {
      const { result, payload: fresh } = await applyEnforcement({
        harness: harness.id,
        mode: enforceMode,
        agent: harness.suggestedAgent,
      });
      setState({ phase: 'ready', payload: fresh, source: 'live' });
      setNow(new Date());
      setEnforceTarget(null);
      setEnforcePlan(null);
      setFlash(
        result.mode === 'enforce'
          ? `已让 ${harness.label} 开始执法：策略 ${result.policyPath ?? '—'}，未登记的调用一律拒绝。` +
            '命中 approve 的调用会挂起等审批（没跑 pod watch 就等到超时被拒）。'
          : `已让 ${harness.label} 回到只录不拦（策略不变，不再阻断）。`,
      );
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setActionBusy(null);
    }
  }, [enforceTarget, enforceMode]);

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
          <span className="pill pill--readonly">{writable ? '可纳管' : '只读'}</span>
          {ready?.source === 'sample' ? (
            <button className="btn" type="button" onClick={() => void load('live')}>
              返回实时数据
            </button>
          ) : null}
          <button
            className="btn btn--primary"
            type="button"
            onClick={() => void rescan()}
            disabled={scanBusy || state.phase === 'loading'}
            title="扫描这台机器上装了哪些 agent / harness（只读，不修改任何文件）"
          >
            {scanBusy ? '扫描中…' : '扫描本机 agent'}
          </button>
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

            {/* 扫描结果里已经有更完整的 harness 列表时，不再重复这条粗粒度提示 */}
            {payload.discovered.length > 0 && harnesses.length === 0 ? (
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

            {flash ? (
              <div className="banner banner--ok">
                <div>
                  <div className="banner__title">已生效</div>
                  <div>{flash}</div>
                </div>
                <button className="btn btn--quiet" type="button" onClick={() => setFlash(null)}>
                  知道了
                </button>
              </div>
            ) : null}

            {actionError ? (
              <div className="banner banner--danger">
                <div>
                  <div className="banner__title">操作失败</div>
                  <div>{actionError}</div>
                </div>
                <button className="btn btn--quiet" type="button" onClick={() => setActionError(null)}>
                  关闭
                </button>
              </div>
            ) : null}

            {installedHarnesses.length > 0 ? (
              <section className="section" aria-labelledby="harness-section-title">
                <div className="section__head">
                  <h2 className="section__title" id="harness-section-title">
                    本机 agent（扫描结果）
                  </h2>
                  <span className="section__meta">
                    {installedHarnesses.length} 个已安装 · 扫描于 {absoluteTime(scanAt)}
                  </span>
                </div>
                <p className="section__lead">
                  扫描只读、不联网、不改任何文件。「加入监控」会给这个 agent 建身份与零权限策略并记进哈希链
                  —— 它<strong>不会改动 harness 的配置</strong>；要真正拦住工具调用，还需要
                  {' '}<code>pod onboard</code> 把 MCP server 包进网关。
                  {writable ? null : ' 当前控制台以只读模式启动（pod ui --read-only），按钮不可用。'}
                </p>
                <div className="grid">
                  {installedHarnesses.map((harness) => (
                    <HarnessCard
                      key={harness.id}
                      harness={harness}
                      writable={writable}
                      busy={actionBusy === harness.id}
                      onEnroll={setEnrollTarget}
                      onForget={(target) => void confirmForget(target)}
                      onTakeover={(target) => void openTakeover(target)}
                      onRevert={(target) => void confirmRevert(target)}
                      onEnforce={(target, mode) => void openEnforce(target, mode)}
                    />
                  ))}
                </div>
                {harnesses.length > installedHarnesses.length ? (
                  <details className="evidence">
                    <summary>
                      另外 {harnesses.length - installedHarnesses.length} 个 harness 没检测到（不在此机器上）
                    </summary>
                    <ul className="evidence__list">
                      {harnesses
                        .filter((h) => !h.installed)
                        .map((h) => (
                          <li key={h.id}>
                            <code>{h.label}</code>（{h.id}）
                          </li>
                        ))}
                    </ul>
                  </details>
                ) : null}
              </section>
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

      {enrollTarget ? (
        <EnrollDialog
          harness={enrollTarget}
          busy={actionBusy === enrollTarget.id}
          error={actionError}
          onCancel={() => {
            setEnrollTarget(null);
            setActionError(null);
          }}
          onConfirm={(agent) => void confirmEnroll(agent)}
        />
      ) : null}

      {takeoverTarget ? (
        <TakeoverDialog
          harness={takeoverTarget}
          plan={takeoverPlan}
          loading={takeoverLoading}
          error={actionError}
          busy={actionBusy === takeoverTarget.id}
          onCancel={() => {
            setTakeoverTarget(null);
            setTakeoverPlan(null);
            setActionError(null);
          }}
          onConfirm={() => void confirmTakeover()}
        />
      ) : null}

      {enforceTarget ? (
        <EnforceDialog
          harness={enforceTarget}
          plan={enforcePlan}
          loading={enforceLoading}
          error={actionError}
          busy={actionBusy === enforceTarget.id}
          onCancel={() => {
            setEnforceTarget(null);
            setEnforcePlan(null);
            setActionError(null);
          }}
          onConfirm={() => void confirmEnforce()}
        />
      ) : null}
    </main>
  );
}
