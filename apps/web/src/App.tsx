import { AgentsPage } from './pages/AgentsPage.tsx';

/**
 * 控制台壳：左侧导航 + 主区。
 * 只有「Agent 资产」是可用的第一页；其余入口明确标注未实现，不做假链接。
 */
const NAV = [
  { id: 'agents', label: 'Agent 资产', ready: true },
  { id: 'policies', label: '策略', ready: false },
  { id: 'approvals', label: '审批队列', ready: false },
  { id: 'audit', label: '审计', ready: false },
  { id: 'scan', label: '扫描报告', ready: false },
] as const;

export function App() {
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand__name">pod 控制台</span>
          {/* 只读/可纳管由顶栏的状态 pill 表达（它读的是服务端真实能力），这里不再写死 */}
          <span className="brand__meta">本地</span>
        </div>
        <nav className="nav" aria-label="控制台导航">
          {NAV.map((item) =>
            item.ready ? (
              <button key={item.id} className="nav__item" type="button" aria-current="page">
                {item.label}
              </button>
            ) : (
              <button
                key={item.id}
                className="nav__item"
                type="button"
                aria-disabled="true"
                disabled
                title="尚未实现：控制台 v1 只交付 Agent 资产页"
              >
                {item.label}
                <span className="nav__flag">未实现</span>
              </button>
            ),
          )}
        </nav>
        <div className="sidebar__foot">
          <div>
            数据来自本机 <code>~/.pod</code>，不离开这台机器。
          </div>
          {/* 构建标识：回答"这个页面是哪次构建"。带 + 号 = 构建时工作区有未提交改动 */}
          <div
            className="sidebar__build"
            title={`构建时间 ${new Date(__POD_BUILD__.builtAt).toLocaleString()}${
              __POD_BUILD__.dirty ? '（构建时工作区有未提交改动）' : ''
            }`}
          >
            build <code>{__POD_BUILD__.commit}{__POD_BUILD__.dirty ? '+' : ''}</code>
            <span className="sidebar__build-time">
              {new Date(__POD_BUILD__.builtAt).toLocaleString(undefined, {
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                hour12: false,
              })}
            </span>
          </div>
        </div>
      </aside>
      <AgentsPage />
    </div>
  );
}
