/**
 * 接管本机 MCP server 的实现已移到 `@podsec/onboard`。
 *
 * 原因：控制台的「接管」按钮要走**同一条**写路径（改写 harness 配置 + 备份 + 回滚）。
 * 两处各写一份的后果是"网页改的和 CLI 改的不一致"，而这类不一致只有在复盘时才发现。
 * 这里保留 re-export，既有 import 路径与测试不变。
 */
export {
  applyOnboard,
  buildWrapArgs,
  computeCoverage,
  discoverTargets,
  isPodCommand,
  revertOnboard,
  type ConfigFormat,
  type CoverageEntry,
  type CoverageReport,
  type DiscoverOptions,
  type OnboardApplyOptions,
  type OnboardChange,
  type OnboardResult,
  type OnboardTarget,
  type ServerEntry,
  type ServerLocation,
} from '@podsec/onboard';
