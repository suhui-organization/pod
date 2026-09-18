/**
 * 漏斗：把"扫出一堆问题"折成"现在先做这三件事"，并给出交付入口。
 *
 * 为什么单独一层：`pod guard scan` 的输出如果停在"漏洞清单"，用户拿到的是一份
 * 需要自己做判断的报表——那是扫描器，不是能被用起来的东西。这一步把每条判定
 * 映射成一条**能直接复制的 pod 命令**，并明确三种结局：
 *
 *   - fix     pod 有执行点，做完这类问题就消失（coverage: covered）；
 *   - shrink  只能降低风险或让它变得可发现（coverage: partial）；
 *   - deliver pod 看不到 / 拦不住，需要写进一份可交付的报告（coverage: gap 或结构性）。
 *
 * 排序不是营销排序：先按严重级别，再按"能不能真的解决"，最后按影响面。
 * 免费扫描到此为止，交付入口（`pod harden`）只在最后出现一次。
 */
import type { Severity } from '@podsec/policy';
import { t } from '@podsec/i18n';
import { localizedThreat } from './catalog.js';
import type { GuardReport } from './types.js';
import { SEVERITY_ORDER } from './types.js';

export type NextActionKind = 'enroll' | 'onboard' | 'freeze' | 'tighten' | 'review' | 'deliver';

export interface NextAction {
  /** 1 最先做 */
  priority: number;
  threat: string;
  title: string;
  severity: Severity;
  /** 受影响的 harness；机器级判定为 'machine' */
  harness: string;
  /** 这条命令消掉多少处 finding */
  affects: number;
  kind: NextActionKind;
  /** 一句话说清要做什么 */
  action: string;
  /** 可直接复制执行的 pod 命令 */
  command: string;
  /** 做完怎么确认（同样是 pod 命令） */
  verify: string;
  /** 为什么排在这里 */
  why: string;
  coverage: 'covered' | 'partial' | 'gap';
  /** true = 只能降低风险，不能根治（coverage !== covered 时为 true） */
  residualRisk: boolean;
}

export interface FunnelPlan {
  actions: NextAction[];
  /**
   * 免费扫描之后的那一步：把同一批事实变成一份可交付、可被对方独立校验的报告。
   * 没有发现时也给——"这轮干净"本身需要被证明，而不是靠一句口头结论。
   */
  deliverable: {
    command: string;
    reason: string;
    contains: string[];
  };
  counts: {
    findings: number;
    /** 有执行点、做完就消失的 finding 数 */
    fixable: number;
    /** 能发现但拦不住 / 只能降低风险的 finding 数 */
    review: number;
    /** pod 看不到、只能写进交付物的 finding 数 */
    uncovered: number;
  };
}

/** 一条建议最多展开这么多条命令；再多就不叫"先做这三件事"了 */
const MAX_ACTIONS = 3;

/** harness 名能不能安全地进命令行（防注入：只允许 id 形态） */
export function harnessArg(harness: string): string | null {
  if (!harness || harness === 'machine' || harness === 'unknown') return null;
  return /^[a-z0-9][a-z0-9._-]*$/.test(harness) ? harness : null;
}

/**
 * 威胁 → 下一步命令。
 *
 * 这里的每条命令都必须是**今天就能跑**的 pod 命令，而且只做一件事：
 * 命令能串起来还不够，串起来之后用户不知道自己是停了还是成了。
 * 所以每条都配一个 verify（见 nextVerifyFor）。
 */
export function nextCommandFor(threat: string, harness: string): string | undefined {
  const h = harnessArg(harness);
  switch (threat) {
    case 'AG-03':
      // 接管只是让调用经过网关（默认只录不拦）；切执法是后面的事，写在 why 里
      return h ? `pod agents onboard --harness ${h} --yes` : 'pod onboard --yes';
    case 'AG-11':
    case 'AG-16':
      return h ? `pod agents enroll --harness ${h}` : 'pod agents scan';
    case 'AG-10':
      return h ? `pod identity init --agent ${h}` : 'pod identity init --agent <agent>';
    case 'AG-12':
      return 'pod posture freeze';
    case 'AG-05':
    case 'AG-07':
    case 'AG-13':
    case 'AG-14':
    case 'AG-02':
    case 'AG-06':
    case 'AG-08':
      return 'pod posture freeze && pod posture --strict';
    case 'AG-04':
      // 项目级配置的修复发生在仓库里，pod 能做的是把它冻进基线、之后按漂移报警
      return 'pod posture freeze && pod posture --strict';
    case 'AG-09':
      return 'pod graph build && pod graph toxic';
    case 'AG-15':
    case 'AG-17':
      // 闸门关着这类问题只能通过收紧规则解决；模型只给建议，规则增量要过放宽守卫
      return 'pod guard remediate --llm';
    case 'AG-18':
      return 'pod harden --out ~/pod-audit';
    case 'AG-01':
      // 凭据搬进钥匙串是人工动作；pod 能做的是搬完之后复核一遍
      return 'pod scan';
    default:
      return undefined;
  }
}

/** 命令跑完之后，用什么证明它生效了 */
export function nextVerifyFor(threat: string, harness: string): string {
  const h = harnessArg(harness);
  switch (threat) {
    case 'AG-03':
      return 'pod coverage --strict';
    case 'AG-11':
      return 'pod agents scan';
    case 'AG-16':
      return 'pod verify-audit';
    case 'AG-10':
      return 'pod identity verify';
    case 'AG-12':
    case 'AG-05':
    case 'AG-07':
    case 'AG-13':
    case 'AG-14':
    case 'AG-02':
    case 'AG-06':
    case 'AG-08':
    case 'AG-04':
      return 'pod guard scan';
    case 'AG-09':
      return 'pod graph toxic';
    case 'AG-15':
    case 'AG-17':
      return 'pod guard scan';
    case 'AG-18':
      return 'pod harden --verify ~/pod-audit';
    case 'AG-01':
      return 'pod scan';
    default:
      return h ? `pod guard scan` : 'pod guard scan';
  }
}

/** 排序权重：能根治的排在"只能降险"的前面——用户做完第一件事应该有确定收益 */
function coverageWeight(coverage: 'covered' | 'partial' | 'gap'): number {
  return coverage === 'covered' ? 0 : coverage === 'partial' ? 1 : 2;
}

/**
 * 动作权重：改变状态的（纳管 / 接管 / 冻结 / 收紧）排在"只是复核一遍"的前面。
 * AG-01 这类人工动作只能给复核命令（`pod scan`），把它排第一会让用户跑完
 * 一条什么都不改变的命令，然后以为已经处理过了。
 */
function kindWeight(kind: NextActionKind): number {
  if (kind === 'review') return 2;
  if (kind === 'deliver') return 1;
  return 0;
}

export function buildFunnelPlan(report: GuardReport, now: Date = new Date()): FunnelPlan {
  const byThreatHarness = new Map<string, { threat: string; harness: string; count: number }>();
  for (const finding of report.findings) {
    const key = `${finding.threat}\u0000${finding.harness}`;
    const bucket = byThreatHarness.get(key);
    if (bucket) bucket.count++;
    else byThreatHarness.set(key, { threat: finding.threat, harness: finding.harness, count: 1 });
  }

  const counts = { findings: report.findings.length, fixable: 0, review: 0, uncovered: 0 };
  for (const finding of report.findings) {
    const entry = localizedThreat(finding.threat);
    if (!entry) continue;
    if (entry.coverage === 'covered') counts.fixable++;
    else if (entry.coverage === 'partial') counts.review++;
    else counts.uncovered++;
  }

  const candidates: NextAction[] = [];
  for (const { threat, harness, count } of byThreatHarness.values()) {
    const entry = localizedThreat(threat);
    if (!entry) continue;
    const command = nextCommandFor(threat, harness);
    if (!command) continue;
    const kind: NextActionKind =
      threat === 'AG-03'
        ? 'onboard'
        : threat === 'AG-11' || threat === 'AG-16'
          ? 'enroll'
          : threat === 'AG-10'
            ? 'tighten'
            : threat === 'AG-18'
              ? 'deliver'
              : threat === 'AG-12' || threat === 'AG-05' || threat === 'AG-07' || threat === 'AG-13' || threat === 'AG-14'
                ? 'freeze'
                : threat === 'AG-15' || threat === 'AG-17'
                  ? 'tighten'
                  : 'review';
    candidates.push({
      priority: 0,
      threat,
      title: entry.title,
      severity: entry.severity,
      harness,
      affects: count,
      kind,
      action: entry.remediation.action,
      command,
      verify: nextVerifyFor(threat, harness),
      why: entry.remediation.why,
      coverage: entry.coverage,
      residualRisk: entry.coverage !== 'covered',
    });
  }

  candidates.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      coverageWeight(a.coverage) - coverageWeight(b.coverage) ||
      kindWeight(a.kind) - kindWeight(b.kind) ||
      b.affects - a.affects ||
      a.threat.localeCompare(b.threat) ||
      a.harness.localeCompare(b.harness),
  );

  // 同一条命令只留一次：三个 harness 都要 enroll 时，展开三条会把"三件事"变成"一张表"
  const seen = new Set<string>();
  const actions: NextAction[] = [];
  for (const candidate of candidates) {
    if (seen.has(candidate.command)) continue;
    seen.add(candidate.command);
    candidate.priority = actions.length + 1;
    actions.push(candidate);
    if (actions.length >= MAX_ACTIONS) break;
  }

  const stamp = now.toISOString().slice(0, 10);
  return {
    actions,
    deliverable: {
      command: `pod harden --out ~/pod-audit-${stamp}`,
      reason: t('扫描回答"现在有什么问题"；要把同一批事实变成一份能交给客户/审计方、并且对方自己就能校验的报告，用 pod harden。'),
      contains: [
        t('执行摘要与扫描范围（哪些看到了、哪些没看到）'),
        t('按优先级排序的待办，每条带可执行命令'),
        t('从真实调用编译的最小权限策略草稿'),
        t('证据包 + 逐文件 sha256 清单（对方用 pod harden --verify 独立复验）'),
      ],
    },
    counts,
  };
}
