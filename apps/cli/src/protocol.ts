/**
 * 端 A（本机）↔ 端 B（云端控制平面）之间的契约：协议版本 + 健康摘要。
 *
 * 为什么单独一个文件：两端是**分开发布**的——端 A 按 tag 发（用户装完就不动了），
 * 端 B 按镜像滚（随时会更新）。版本错配是必然发生的组合，而现在没有协议版本时，
 * 错配表现为**静默半失效**：老客户端不认 `/sync/quarantine`（只打一行警告）、
 * 新服务端多出来的字段没人读。这种"看起来在同步，其实少了一半"最难排查。
 *
 * 所以：版本号与健康摘要都只从这里出，两端各自只依赖这一个契约
 * （对照文档见 docs/local-cloud-contract.md）。
 */
import { readFileSync } from 'node:fs';

/**
 * 协议版本。**只在破坏性变更时 +1**（改字段含义 / 删字段 / 改语义）；
 * 加可选字段不算破坏性变更，不动这个数。
 */
export const POD_PROTOCOL_VERSION = 1;

/** 服务端能接受的最低客户端协议——低于它就建议升级（缺字段会被当成默认值） */
export const POD_MIN_CLIENT_PROTOCOL = 1;

/**
 * CLI 自身的版本（`pod --version` 与上报给云端的是同一个数）。
 * 来源 apps/cli/package.json——发版时它和 CHANGELOG / install.sh / README 一起改。
 */
export function cliVersion(): string {
  try {
    const pkg = JSON.parse(
      readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
    ) as { version?: string };
    return pkg.version ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

/**
 * 本机健康摘要。**只含计数、布尔与时间戳**：没有路径、没有主机名、没有配置原文、
 * 没有工具参数——与审计同步的口径一致（云端拿到的永远不是内容）。
 *
 * 为什么要上报它：云端现在只知道"这个 agent 30 分钟前在线"。但"在线"和
 * "真的在保护"是两件事——网关可能根本没起、链可能断了、还有 server 绕过了网关。
 * 这三件事恰恰是"部署了但没生效"的典型形态，也是控制台最该报出来的东西。
 */
export interface PodHealth {
  // 字段名即**线上字段名**（与云端 app/routers/sync.py 的 HealthIn 一一对应）。
  // 这里刻意不用 camelCase：契约两端各写一遍，命名不一致会静默丢数据
  // （云端 Pydantic 默认忽略多余字段），而丢的是"链断了没有"这种关键信息。
  audit: {
    /** 本地审计链条数 */
    chains: number;
    /** 校验失败的链数（>0 = 有记录被改过） */
    broken: number;
    /** 最近一次工具调用的时间（网关是否在干活的直接证据） */
    last_call_at: string | null;
  };
  coverage: {
    /** 发现的本机 MCP server 总数 */
    servers: number;
    /** 其中绕过网关的数量（>0 = 拦截与留痕都覆盖不到） */
    unmanaged: number;
  };
  /** 最近一次只读漏洞扫描的计数；跑不动时为 null（并在 errors 里说明） */
  guard: { high: number; medium: number; low: number; scanned_at: string } | null;
  /** 采集过程中解释不了的东西。绝不静默丢弃 */
  errors: string[];
}

/** 协议不匹配时给用户看的提示（服务端回什么，就照什么说） */
export interface ProtocolNotice {
  serverProtocol?: number;
  minClientProtocol?: number;
  /** true = 本机这版客户端已经比服务端支持的最低版本更旧 */
  clientOutdated?: boolean;
  message?: string;
}
