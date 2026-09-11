import type { DecisionState, RiskSeverity } from '@podsec/console/types';

const DECISION_LABEL: Record<DecisionState, string> = {
  allow: 'allow',
  approve: 'approve',
  deny: 'deny',
};

/** 三态决策徽章：颜色 + 文字，颜色从不单独表意 */
export function DecisionPill({
  decision,
  count,
}: {
  decision: DecisionState;
  count?: number;
}) {
  return (
    <span className={`pill pill--${decision}`}>
      {DECISION_LABEL[decision]}
      {typeof count === 'number' ? <span className="num">{count}</span> : null}
    </span>
  );
}

const STATUS_META = {
  active: { label: '活跃', hint: '近 7 天有调用记录' },
  idle: { label: '静默', hint: '已登记策略，近 7 天没有调用' },
  unobserved: { label: '未登记', hint: '有真实调用，但没有策略绑定' },
} as const;

export function StatusBadge({ status }: { status: keyof typeof STATUS_META }) {
  const meta = STATUS_META[status];
  return (
    <span className={`status status--${status}`} title={meta.hint}>
      <span className="status__dot" aria-hidden="true" />
      {meta.label}
    </span>
  );
}

const SEVERITY_LABEL: Record<RiskSeverity, string> = {
  high: '高危',
  medium: '中危',
  low: '提示',
};

export function SignalChip({
  severity,
  label,
  count,
  title,
}: {
  severity: RiskSeverity;
  label: string;
  count: number;
  title?: string;
}) {
  return (
    <span className={`signal signal--${severity}`} title={title}>
      <span className="signal__sev">{SEVERITY_LABEL[severity]}</span>
      {label}
      {count > 0 ? <span className="num">{count}</span> : null}
    </span>
  );
}

/** 近 7 天调用量：7 根静态柱（无动画，因此不需要 reduced-motion 分支） */
export function Sparkline({ values }: { values: number[] }) {
  const max = Math.max(1, ...values);
  const lastIndex = values.length - 1;
  return (
    <div className="spark" aria-hidden="true">
      {values.map((value, index) => {
        const height = value === 0 ? 2 : Math.max(3, Math.round((value / max) * 30));
        const className = [
          'spark__bar',
          value === 0 ? 'spark__bar--zero' : '',
          index === lastIndex && value > 0 ? 'spark__bar--last' : '',
        ]
          .filter(Boolean)
          .join(' ');
        return <span key={index} className={className} style={{ height: `${height}px` }} />;
      })}
    </div>
  );
}

const rtf = new Intl.RelativeTimeFormat('zh-CN', { numeric: 'auto' });

/** 相对时间；null 明确显示"从未"，不是空白 */
export function relativeTime(iso: string | null, now: Date): string {
  if (!iso) return '从未记录';
  const ts = Date.parse(iso);
  if (Number.isNaN(ts)) return '时间无法解析';
  const diffSeconds = Math.round((ts - now.getTime()) / 1000);
  const abs = Math.abs(diffSeconds);
  if (abs < 60) return rtf.format(diffSeconds, 'second');
  if (abs < 3600) return rtf.format(Math.round(diffSeconds / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(diffSeconds / 3600), 'hour');
  if (abs < 86400 * 30) return rtf.format(Math.round(diffSeconds / 86400), 'day');
  return new Intl.DateTimeFormat('zh-CN', { dateStyle: 'medium' }).format(new Date(ts));
}

export function absoluteTime(iso: string | null): string {
  if (!iso) return '无记录';
  const ts = Date.parse(iso);
  if (Number.isNaN(ts)) return iso;
  return new Intl.DateTimeFormat('zh-CN', {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(new Date(ts));
}
