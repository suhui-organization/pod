/**
 * Agent / Harness 威胁目录（machine-readable）。
 *
 * 这份目录是 `pod guard` 的判定知识库：每一条都对应一个可自动执行的检测器
 * （见 detect.ts），并带上可核查的外部出处。它回答两个问题：
 *   1. 这类攻击长什么样？（summary + refs）
 *   2. pod 现在能不能发现它？（coverage：covered / partial / gap）
 *
 * 出处纪律（与 docs/threat-model.md 同规格）：
 * - 每条都要有 URL，且优先引原始披露方（厂商研究 / CVE / 平台报告），不引二手转述；
 * - `coverage: 'gap'` 必须写清楚缺什么，不假装覆盖；
 * - 编号 `AG-xx` 是 pod 自己的稳定 id，同时映射到仓库威胁模型 T 编号与
 *   OWASP Agentic Top 10 的 ASI 编号，避免又造一套编号。
 *
 * 来源（2026-09 复核）：HackerOne Hacktivity 与年度报告、Bugcrowd AI 研究、
 * 厂商披露（Invariant / Aim / Check Point / Oligo / Tenable / Wiz / Snyk / JFrog /
 * AWS / Microsoft）、vulnerablemcp.info 汇总项目、OWASP Agentic Top 10（2025-12）。
 */
import type { Severity } from '@podsec/policy';
import { t } from '@podsec/i18n';

export type ThreatSourceKind =
  | 'vuln-db'
  | 'vendor-research'
  | 'bug-bounty-platform'
  | 'standards'
  | 'incident';

export interface ThreatRef {
  id: string;
  url: string;
  source: ThreatSourceKind;
  /**
   * 披露方或平台名。必须有——"谁说的"决定这条能不能被当成证据，
   * 只给一条 URL 的目录搬运，读的人无法判断可信度。
   */
  by: string;
}

export type GuardCategory =
  | 'credential'
  | 'supply-chain'
  | 'boundary'
  | 'execution'
  | 'permission'
  | 'memory'
  | 'identity'
  | 'network'
  | 'visibility';

export interface Remediation {
  /** 一句话动作（给人看的） */
  action: string;
  /** 可直接复制执行的命令；没有可自动化的动作时留空 */
  command?: string;
  /** 为什么要这么做 */
  why: string;
  /**
   * 模型能不能替用户做这件事。
   * `proposal` = 模型可以生成建议物（规则包/策略补丁），仍需过放宽守卫；
   * `manual` = 只能人工（例如"把密钥挪进钥匙串"）。
   */
  automation: 'proposal' | 'manual';
}

export interface ThreatEntry {
  /** AG-xx：pod 自己的稳定编号 */
  id: string;
  title: string;
  severity: Severity;
  category: GuardCategory;
  /** 攻击者在做什么（一句话） */
  summary: string;
  /** OWASP Agentic Top 10 映射（ASI01–ASI10） */
  asi: string[];
  /** 本仓库 docs/threat-model.md 的编号 */
  localThreats: string[];
  refs: ThreatRef[];
  /**
   * pod 现在的覆盖程度。诚实标注比"全绿"更值钱：
   * - covered：有确定性判定 + 有执行点（gateway / posture / guard）
   * - partial：能发现，但拦不住（例如钩子跑在 harness 里）
   * - gap：目前看不到
   */
  coverage: 'covered' | 'partial' | 'gap';
  /** coverage !== gap 时说明已有防线在哪 */
  existingControls?: string[];
  /** coverage !== covered 时说明缺口 */
  gap?: string;
  remediation: Remediation;
}

const OWASP_AGENTIC =
  'https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/';

export const THREAT_CATALOG: ThreatEntry[] = [
  {
    id: 'AG-01',
    title: '明文凭据进了 agent / MCP 配置',
    severity: 'high',
    category: 'credential',
    summary:
      'API key、PAT、数据库口令直接写在 mcp.json / settings.json / mcp-manager.json 里。任何能读这些文件的进程（包括它自己要启动的 MCP server、IDE 扩展、同机恶意软件）都拿到了凭据。',
    asi: ['ASI03'],
    localThreats: ['T2'],
    refs: [
      { id: 'CWE-522', url: 'https://cwe.mitre.org/data/definitions/522.html', source: 'standards', by: 'MITRE' },
      { id: 's1ngularity', url: 'https://www.wiz.io/blog/s1ngularity-supply-chain-attack', source: 'incident', by: 'Wiz Research' },
    ],
    coverage: 'covered',
    existingControls: ['pod scan 掩码识别 9 类密钥格式', '策略 secrets.deny_input_paths 拒绝读取敏感路径'],
    remediation: {
      action: '把密钥迁到系统钥匙串 / secret 管理器，配置里只留引用',
      why: '配置文件是分发物，凭据一旦落盘就等于进了版本历史与备份',
      automation: 'manual',
    },
  },
  {
    id: 'AG-02',
    title: 'MCP server 来源未锁定版本',
    severity: 'medium',
    category: 'supply-chain',
    summary:
      'npx -y pkg 或 @latest 让上游每次发布直接进入本机。postmark-mcp 先跑 15 个干净版本、第 16 版才加 BCC 外发——版本不锁，你就没有"我装的那份"这个事实。',
    asi: ['ASI04'],
    localThreats: ['T4'],
    refs: [
      { id: 'postmark-mcp', url: 'https://www.koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft', source: 'incident', by: 'Koi Security' },
      { id: 'snyk-postmark', url: 'https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/', source: 'vendor-research', by: 'Snyk' },
    ],
    coverage: 'partial',
    existingControls: ['pod scan / pod posture packages.requireVersionPin 检查版本锁定'],
    gap: 'pod 不校验 npm 包的签名与发布者；来源真实性要用户自己核对官方仓库',
    remediation: {
      action: '把 npx / @latest 换成官方仓库的固定版本（pkg@x.y.z），或在本地锁 lockfile',
      command: 'pod posture freeze && pod posture --strict',
      why: '版本锁定把"上游今天发了什么"变成可复核的确定事实',
      automation: 'manual',
    },
  },
  {
    id: 'AG-03',
    title: 'MCP server 绕过网关直连',
    severity: 'high',
    category: 'boundary',
    summary:
      'agent 配置里的 server 没走 pod 网关，策略、审批、审计对它全部无效。这是所有"边界完整性"问题的前提——只要有一条绕过，其余防线就只在部分流量上生效。',
    asi: ['ASI02', 'ASI03'],
    localThreats: ['T1', 'T2', 'T3'],
    refs: [
      { id: 'OWASP-ASI', url: OWASP_AGENTIC, source: 'standards', by: 'OWASP GenAI Security Project' },
    ],
    coverage: 'covered',
    existingControls: ['pod scan checkBypass', 'pod coverage --strict', 'pod serve 在 MCP 边界执法'],
    remediation: {
      action: '用 onboarding 把直连的 server 包进网关',
      command: 'pod onboard --yes && pod coverage --strict',
      why: '只有经过的点才能拦；绕过网关的调用连审计记录都不存在',
      automation: 'proposal',
    },
  },
  {
    id: 'AG-04',
    title: '项目级 MCP 配置在打开文件夹时自动执行',
    severity: 'high',
    category: 'execution',
    summary:
      '仓库里的 .mcp.json / .cursor/mcp.json / .vscode/mcp.json 被 clone 下来后，接受"工作区信任"这一个动作就足以让攻击者的命令以开发者权限启动。CurXecute 证明一次外部提示注入就能改写 mcp.json 并在下一次启动执行。',
    asi: ['ASI05', 'ASI04'],
    localThreats: ['T10', 'T4'],
    refs: [
      { id: 'CVE-2025-54135', url: 'https://www.catonetworks.com/blog/curxecute-rce/', source: 'vuln-db', by: 'Cato Networks / Aim Labs' },
      { id: 'CVE-2025-54136', url: 'https://blog.checkpoint.com/research/cursor-ide-persistent-code-execution-via-mcp-trust-bypass/', source: 'vuln-db', by: 'Check Point Research' },
      { id: 'CSA-MCP-autoexec', url: 'https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-auto-execution-20260701/', source: 'standards', by: 'Cloud Security Alliance' },
    ],
    coverage: 'partial',
    existingControls: ['pod onboard 把项目级 server 包进网关后，策略对它有约束'],
    gap: 'pod 不阻断 harness 自己启动项目级 server 这个动作（那是 harness 的行为，不在 MCP 边界内）',
    remediation: {
      action: '把仓库里的 MCP 配置当作不可信输入：进仓库前审一遍，或改用用户级配置',
      command: 'pod guard scan --workspace .',
      why: '打开文件夹不等于同意执行陌生代码；这一步必须显式',
      automation: 'manual',
    },
  },
  {
    id: 'AG-05',
    title: '生命周期钩子携带网络出口 / 持久化 / 编码载荷',
    severity: 'high',
    category: 'execution',
    summary:
      '钩子把 shell 命令绑到 harness 事件上（会话启动、每次提交提示词、文件编辑），以宿主权限运行，且往往在用户和模型都看不见的时机触发。PromptArmor 的攻击链就是"恶意插件 + 钩子改写 permissions 文件"，把人工审批整条摘掉。',
    asi: ['ASI04', 'ASI05', 'ASI09'],
    localThreats: ['T10'],
    refs: [
      { id: 'promptarmor-claude-plugins', url: 'https://www.promptarmor.com/resources/hijacking-claude-code-via-injected-marketplace-plugins', source: 'vendor-research', by: 'PromptArmor' },
      { id: 'lasso-claude-code', url: 'https://www.lasso.security/blog/the-hidden-backdoor-in-claude-coding-assistant', source: 'vendor-research', by: 'Lasso Security' },
    ],
    coverage: 'partial',
    existingControls: ['pod posture 采集钩子并按 rules.hookRisk.riskPatterns 判定', '钩子内容进基线，新增/改动按 freeze 级别报警'],
    gap: 'pod 不执行钩子也不阻断钩子——钩子跑在 harness 里，不经过网关；能力边界是发现 + 取证 + 变更审计',
    remediation: {
      action: '确认钩子来源；给可信钩子加签名，把其余钩子移出风险规则之外',
      command: 'pod posture freeze && pod posture --strict',
      why: '钩子是"配置即代码执行"——它比插件本身更值得冻结',
      automation: 'proposal',
    },
  },
  {
    id: 'AG-06',
    title: 'agent 以"跳过审批"模式运行',
    severity: 'high',
    category: 'permission',
    summary:
      '--dangerously-skip-permissions / --yolo / --trust-all-tools / DANGEROUSLY_OMIT_AUTH 这类开关把人类审批整条拿掉。s1ngularity 供应链攻击正是用这些 flag 把开发者本机的 AI CLI 变成无审批的侦察与打包工具。',
    asi: ['ASI09', 'ASI02'],
    localThreats: ['T9'],
    refs: [
      { id: 's1ngularity', url: 'https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware', source: 'incident', by: 'StepSecurity' },
      { id: 'CVE-2025-8217', url: 'https://aws.amazon.com/security/security-bulletins/AWS-2025-015/', source: 'vuln-db', by: 'AWS Security' },
    ],
    coverage: 'partial',
    existingControls: ['pod serve 的 approve 闸门 + fail-closed 超时', 'pod grant 的 JIT 令牌可替代交互审批'],
    gap: 'agent 自身的 CLI flag 不在 pod 控制范围内；pod 只能发现配置里的放宽项并报警',
    remediation: {
      action: '去掉跳过审批的启动参数；需要自动化时改用 pod grant 签发的限时令牌',
      command: 'pod grant issue --agent <a> --capability <c> --ttl 900',
      why: '跳过审批把"人在回路"换成"任何能影响 agent 的内容都在回路"',
      automation: 'proposal',
    },
  },
  {
    id: 'AG-07',
    title: '长期记忆文件可被写入且未纳管',
    severity: 'high',
    category: 'memory',
    summary:
      'CLAUDE.md / AGENTS.md 之类的长期记忆影响的是之后每一次会话。一次投毒不是一条坏回复，而是一个持续生效的立场。记忆文件和普通数据一样可写，却比普通数据耐用得多。',
    asi: ['ASI06'],
    localThreats: ['T13'],
    refs: [
      { id: 'OWASP-ASI06', url: OWASP_AGENTIC, source: 'standards', by: 'OWASP GenAI Security Project' },
    ],
    coverage: 'partial',
    existingControls: ['pod posture memory.paths 进基线，漂移按 high 报'],
    gap: 'pod 不理解记忆内容语义，只保证"你看到的和上次是不是同一份"；语义级投毒检测不在覆盖范围',
    remediation: {
      action: '把记忆文件纳入基线，并在评审后合并变更',
      command: 'pod posture freeze',
      why: '记忆写入比普通数据更需要人工确认来源——它会影响后续所有决策',
      automation: 'manual',
    },
  },
  {
    id: 'AG-08',
    title: '远程 / HTTP 形态的 MCP 端点未鉴权',
    severity: 'high',
    category: 'network',
    summary:
      'MCP 的 Streamable HTTP / SSE 传输把工具执行暴露成网络接口。MCP Inspector 的 CVE-2025-49596（CVSS 9.4）就是绑定 0.0.0.0 且无鉴权，一次 CSRF 直接变成远程代码执行；oatpp-mcp 的 CVE-2025-6515 则用可预测 session id 做提示词劫持。',
    asi: ['ASI07'],
    localThreats: ['T1'],
    refs: [
      { id: 'CVE-2025-49596', url: 'https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596', source: 'vuln-db', by: 'Oligo Security / Tenable' },
      { id: 'CVE-2025-6515', url: 'https://jfrog.com/blog/mcp-prompt-hijacking-vulnerability/', source: 'vuln-db', by: 'JFrog Security Research' },
    ],
    coverage: 'partial',
    existingControls: ['pod serve --http 绑定 127.0.0.1 + token；网关不暴露 stdio 之外的裸执行面'],
    gap: '第三方 server 自己的监听地址与鉴权策略 pod 看不到，只能从配置里发现线索（0.0.0.0 / 关闭鉴权的开关）',
    remediation: {
      action: '远程端点只绑本地回环并强制鉴权；确需暴露时套在 pod 网关后面',
      command: 'pod serve --agent <a> --server <s> --policy <p>',
      why: '工具执行暴露成网络接口就是 RCE 面；无鉴权等于把执行权挂公网',
      automation: 'proposal',
    },
  },
  {
    id: 'AG-09',
    title: '致命三角：私密数据 + 不可信输入 + 外发通道',
    severity: 'high',
    category: 'boundary',
    summary:
      'Simon Willison 的"致命三角"：同一个 agent 同时能读私密数据、会读到攻击者可控的内容、又能把数据发出去，就一定能被诱导外泄。GitHub MCP 的私有仓库泄露就是标准案例——恶意 issue 让 agent 把私有仓库信息写进公开 PR。',
    asi: ['ASI01', 'ASI02'],
    localThreats: ['T1', 'T5'],
    refs: [
      { id: 'invariant-github-mcp', url: 'https://invariantlabs.ai/blog/mcp-github-vulnerability', source: 'vendor-research', by: 'Invariant Labs' },
      { id: 'willison-lethal-trifecta', url: 'https://simonwillison.net/2025/May/26/github-mcp-exploited/', source: 'vendor-research', by: 'Simon Willison' },
      { id: 'gitlab-duo', url: 'https://www.legitsecurity.com/blog/remote-prompt-injection-in-gitlab-duo', source: 'vendor-research', by: 'Legit Security' },
    ],
    coverage: 'partial',
    existingControls: [
      'pod graph toxic 在能力图上找 source→sink 毒性链',
      'policy deny_output_matching 拦密钥外发',
      'injection.signals 分级阻断已知注入句式',
    ],
    gap: '三角里"不可信输入"这一边在 pod 看不到（server 的响应内容不经过能力判定）；模型对没见过的措辞仍然会中招',
    remediation: {
      action: '拆三角：把私密数据 server 与外发 server 分给不同 agent，或对写入类工具强制 approve',
      command: 'pod graph toxic --policy <p> --diff',
      why: '三条边少一条，攻击链就断；拆权限比检测提示词可靠',
      automation: 'proposal',
    },
  },
  {
    id: 'AG-10',
    title: '多个 agent / server 共用同一份凭据',
    severity: 'medium',
    category: 'identity',
    summary:
      '共享令牌意味着出事时无法回答"是谁做的"，也无法单独吊销。Nx 事件里被偷的 GitHub/npm token 能横向把数千个仓库改成公开，正是因为一份凭据覆盖了远超需要的范围。',
    asi: ['ASI03', 'ASI07'],
    localThreats: ['T12'],
    refs: [
      { id: 's1ngularity-wiz', url: 'https://www.wiz.io/blog/s1ngularity-supply-chain-attack', source: 'incident', by: 'Wiz Research' },
    ],
    coverage: 'covered',
    existingControls: ['pod identity 给每个 agent 一对 ed25519 密钥', 'pod delegate 委托链逐跳收窄', 'pod grant JIT 令牌带 TTL 与作用域'],
    remediation: {
      action: '每个 agent 一份身份；需要共享能力时走签名委托并把范围收窄',
      command: 'pod identity init --agent <a> && pod delegate issue --parent <p> --child <c> --capability <x> --ttl 600',
      why: '归因能力来自身份唯一性；共享凭证让审计链只能证明"某台机器做了"',
      automation: 'proposal',
    },
  },
  {
    id: 'AG-11',
    title: '影子 agent：有 agent 在跑，但没有任何治理记录',
    severity: 'medium',
    category: 'visibility',
    summary:
      '本机同时装了好几个 harness，只有一部分被纳入策略/审计。控制台看到的"全部资产"其实是"愿意露面的资产"，剩下的暴露面既不在策略里也不在证据里。',
    asi: ['ASI10', 'ASI03'],
    localThreats: ['T6'],
    refs: [
      { id: 'OWASP-ASI10', url: OWASP_AGENTIC, source: 'standards', by: 'OWASP GenAI Security Project' },
    ],
    coverage: 'covered',
    existingControls: ['pod scan 发现已安装的 harness', 'pod posture identities 对比策略/审计/身份三个来源'],
    remediation: {
      action: '给每个在用的 harness 建身份并挂策略；不用的直接卸载',
      command: 'pod onboard && pod identity init --agent <a>',
      why: '资产不清时，治理只能覆盖一部分流量，而攻击者只需要那一部分之外的一条路',
      automation: 'proposal',
    },
  },
  {
    id: 'AG-12',
    title: 'agent 配置未冻结，可被静默降级',
    severity: 'high',
    category: 'boundary',
    summary:
      '攻击者不需要创造新的恶意动作，只要改一个参数：把审批关掉、把内部地址换成公开地址、把密钥引用换成明文。agent 仍然"正确"完成任务，安全态势已经被摘掉——这正是 CurXecute 的落点。',
    asi: ['ASI03', 'ASI04'],
    localThreats: ['T11'],
    refs: [
      { id: 'CVE-2025-54135', url: 'https://www.catonetworks.com/blog/curxecute-rce/', source: 'vuln-db', by: 'Cato Networks / Aim Labs' },
    ],
    coverage: 'covered',
    existingControls: ['pod posture freeze 把冻结项记进基线哈希', '漂移写进同一条哈希链（config-change）'],
    remediation: {
      action: '冻结所有 harness 的配置路径，把漂移检查挂进定时任务或 CI',
      command: 'pod posture freeze && pod posture --strict',
      why: '配置漂移是最安静的攻击面：动作合法、意图不在日志里',
      automation: 'proposal',
    },
  },
  {
    id: 'AG-13',
    title: '插件 / 技能市场来源未固定',
    severity: 'medium',
    category: 'supply-chain',
    summary:
      'Agent Skills 这类分发物把提示词、脚本和钩子打包在一起，装进来就等于同时接受了三样东西。Snyk 对某市场数千个 skill 的扫描发现 36% 含提示词注入、1467 个恶意载荷。',
    asi: ['ASI04', 'ASI05'],
    localThreats: ['T4', 'T10'],
    refs: [
      { id: 'snyk-toxicskills', url: 'https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/', source: 'vendor-research', by: 'Snyk' },
      { id: 'promptarmor-claude-plugins', url: 'https://www.promptarmor.com/resources/hijacking-claude-code-via-injected-marketplace-plugins', source: 'vendor-research', by: 'PromptArmor' },
    ],
    coverage: 'partial',
    existingControls: ['hookRisk.watchPaths 覆盖插件目录下的钩子文件', 'hookRisk.trustedSources 决定是否降级'],
    gap: 'pod 不审查插件/skill 正文（提示词注入在自然语言里），只审查它带来的钩子与命令',
    remediation: {
      action: '插件目录纳入钩子与配置冻结范围；升级后必须复核',
      command: 'pod posture freeze && pod posture --strict',
      why: '插件以"更新"的名义换掉钩子，是最难被注意到的持久化方式',
      automation: 'proposal',
    },
  },
  {
    id: 'AG-14',
    title: 'MCP server 启动命令与基线不一致（rug pull）',
    severity: 'high',
    category: 'supply-chain',
    summary:
      '同名 server 被换成另一个包、或参数被改。工具描述可以在安装后被悄悄改写（rug pull），用户第 1 天批准的那个工具，第 7 天已经在做别的事。',
    asi: ['ASI04'],
    localThreats: ['T4'],
    refs: [
      { id: 'invariant-tpa', url: 'https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks', source: 'vendor-research', by: 'Invariant Labs' },
      { id: 'msrc-indirect-injection', url: 'https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp/', source: 'vendor-research', by: 'Microsoft' },
    ],
    coverage: 'covered',
    existingControls: ['pod posture packages.requireIntegrity 比对 command+args 指纹', 'gateway 启动前校验策略 source 白名单'],
    remediation: {
      action: '打开来源完整性检查并冻结当前 server 指纹',
      command: 'pod posture freeze && pod posture --strict',
      why: 'rug pull 攻击的前提是"没人比过上一次的命令行"',
      automation: 'proposal',
    },
  },
  {
    id: 'AG-15',
    title: '注入阻断与 egress 判定未启用，但存在外发能力的 server',
    severity: 'medium',
    category: 'boundary',
    summary:
      '工具响应里带回的内容是间接注入的主要入口（EchoLeak 是零点击版本）；egress 判定是数据出机器前最后一道可判定闸门。两者默认关闭时，防线就只剩"模型自己不被骗"。',
    asi: ['ASI01', 'ASI02'],
    localThreats: ['T1', 'T5'],
    refs: [
      { id: 'CVE-2025-32711', url: 'https://nvd.nist.gov/vuln/detail/cve-2025-32711', source: 'vuln-db', by: 'NVD / Aim Labs' },
      { id: 'bugcrowd-prompt-injection', url: 'https://www.bugcrowd.com/blog/ai-vulnerability-deep-dive-prompt-injection/', source: 'bug-bounty-platform', by: 'Bugcrowd' },
    ],
    coverage: 'partial',
    existingControls: ['rules.injection 分级子串匹配（默认阻断 high）', 'rules.egress allowHosts/denyHosts 判定参数里的主机'],
    gap: '词表只能抓已知措辞；egress 只判定参数里出现的主机，看不到 server 内部自己发的请求',
    remediation: {
      action: '确认 injection.block 与 egress 判定已打开，并按自己的 provider 列表收紧 allowHosts',
      command: 'pod lint --policy <p>',
      why: '这两项是 egress 侧唯一可判定、可复现的闸门；关着等于只剩模型自觉',
      automation: 'proposal',
    },
  },
  {
    id: 'AG-16',
    title: '审计覆盖缺口：harness 在网关之外活动',
    severity: 'medium',
    category: 'visibility',
    summary:
      '"看起来在记、其实没记"比"没记"更危险：链断裂后追加会被拒绝，agent 照常工作、本地一条都不再落。发现了 harness 却没有任何审计链，等价于出事时只能靠回忆。',
    asi: ['ASI10'],
    localThreats: ['T7'],
    refs: [
      { id: 'hackerone-ai-report', url: 'https://www.hackerone.com/press-release/hackerone-report-finds-210-spike-ai-vulnerability-reports-amid-rise-ai-autonomy', source: 'bug-bounty-platform', by: 'HackerOne' },
    ],
    coverage: 'covered',
    existingControls: ['pod posture auditHealth 检查断链与长时间无写入', 'pod verify-audit / export-evidence 可独立校验'],
    remediation: {
      action: '给每个 harness 接上记录通道，并把 auditHealth 期望活跃度按 agent 配好',
      command: 'pod record --agent <a> --server <s>',
      why: '证据的可用性取决于"断的那一刻有没有人告诉你"',
      automation: 'proposal',
    },
  },
  {
    id: 'AG-17',
    title: '工具描述投毒面：server 未走网关时摘除规则不生效',
    severity: 'medium',
    category: 'boundary',
    summary:
      '工具描述是模型直接读的自由文本，也是唯一能"不用被调用就影响行为"的通道。pod 的 toolMetadata 规则会在 tools/list 阶段把命中工具摘掉——但只在流量经过网关时有效。',
    asi: ['ASI02', 'ASI01'],
    localThreats: ['T1'],
    refs: [
      { id: 'invariant-tpa', url: 'https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks', source: 'vendor-research', by: 'Invariant Labs' },
      { id: 'vulnerablemcp', url: 'https://vulnerablemcp.info/', source: 'vendor-research', by: 'Vulnerable MCP Project' },
    ],
    coverage: 'partial',
    existingControls: ['rules.toolMetadata.suspiciousPatterns + 在 tools/list 阶段摘除命中工具（默认 high）'],
    gap: '摘除是启发式的（正则），编码/改写后的恶意描述会漏；且必须有网关在中间',
    remediation: {
      action: '让所有 server 走网关，并保持 toolMetadata.block 打开',
      command: 'pod onboard --yes && pod lint --policy <p>',
      why: '工具描述一旦进了上下文就没有撤回按钮；摘除必须在它进入之前发生',
      automation: 'proposal',
    },
  },
  {
    id: 'AG-18',
    title: 'MCP server 以宿主完整权限运行（无沙箱）',
    severity: 'medium',
    category: 'execution',
    summary:
      'MCP server 是普通进程，拿到的是启动它的用户权限。一次投毒就是一次完整的本地代码执行——这也是 Amazon Q / Nx 事件里"差点删掉整台机器"的原因。',
    asi: ['ASI05', 'ASI04'],
    localThreats: ['T3'],
    refs: [
      { id: 'amazon-q', url: 'https://www.reversinglabs.com/blog/aws-amazonq-ai-incident', source: 'incident', by: 'ReversingLabs' },
      { id: 'CWE-250', url: 'https://cwe.mitre.org/data/definitions/250.html', source: 'standards', by: 'MITRE' },
    ],
    coverage: 'gap',
    gap: 'pod 不做沙箱/容器隔离（明确的非目标）。需要强隔离时用平台原生沙箱或容器，pod 的策略与证据可以叠在上面',
    remediation: {
      action: '把高权限 server 放进容器/沙箱；或者只给它一份最小权限的独立凭据',
      why: '本地优先的取舍是"网关进程内转发"，强隔离必须由外部承担',
      automation: 'manual',
    },
  },
];

export const THREAT_BY_ID: Record<string, ThreatEntry> = Object.fromEntries(
  THREAT_CATALOG.map((entry) => [entry.id, entry]),
);

/**
 * 目录条目的本地化副本（渲染时调用）。
 *
 * 为什么是函数而不是模块级常量：`--lang` / `POD_LANG` 在模块 import **之后**才生效，
 * 模块加载时求值会把文案冻在默认语言上（改完语言，标题还是中文）。
 *
 * 这也是全仓库唯一一处"变量查表"（`t(entry.title)`）——覆盖率脚本按字面量找调用点，
 * 看不见它。所以这些键在 `packages/i18n/data-keys.txt` 里显式声明：脚本据此
 * **既要求它们有英文词条，也不把它们误报成僵尸键**。
 */
export function localizeThreat(entry: ThreatEntry): ThreatEntry {
  const localized: ThreatEntry = {
    ...entry,
    title: t(entry.title),
    summary: t(entry.summary),
    remediation: {
      ...entry.remediation,
      action: t(entry.remediation.action),
      why: t(entry.remediation.why),
    },
  };
  if (entry.gap) localized.gap = t(entry.gap);
  if (entry.existingControls) localized.existingControls = entry.existingControls.map((item) => t(item));
  return localized;
}

/** 本地化后的整份目录（报表、`--json`、模型上下文用） */
export function localizedCatalog(): ThreatEntry[] {
  return THREAT_CATALOG.map(localizeThreat);
}

/** 按编号取本地化条目 */
export function localizedThreat(id: string): ThreatEntry | undefined {
  const raw = THREAT_BY_ID[id];
  return raw ? localizeThreat(raw) : undefined;
}

/**
 * 目录里每条都要能追到至少一个外部出处；这是 CI 里可以断言的纪律。
 * 目录是"我们声称懂的东西"的清单，所以它自己必须可核查。
 */
export function assertCatalogRefs(catalog: ThreatEntry[] = THREAT_CATALOG): void {
  for (const entry of catalog) {
    if (entry.refs.length === 0) throw new Error(`${entry.id} 缺少外部出处（refs）`);
    for (const ref of entry.refs) {
      if (!/^https:\/\//.test(ref.url)) throw new Error(`${entry.id} 的出处 ${ref.id} 不是 https URL`);
      if (!ref.by) throw new Error(`${entry.id} 的出处 ${ref.id} 没写披露方`);
    }
    if (entry.coverage === 'gap' && !entry.gap) {
      throw new Error(`${entry.id} 标了 gap 却没写缺什么`);
    }
    if (entry.coverage === 'covered' && !(entry.existingControls && entry.existingControls.length > 0)) {
      throw new Error(`${entry.id} 标了 covered 却没写已有防线`);
    }
  }
}
