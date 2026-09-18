/**
 * 本次**前端**构建的标识。
 *
 * 来源：deploy/Dockerfile 里的 `ARG BUILD_TAG` → `ENV VITE_BUILD_TAG`，
 * 构建时被打进产物。本地 `npm run dev` 没有注入，显示 'dev'。
 *
 * 与后端 `/api/v1/auth/config` 返回的 `build`（服务器镜像 tag）分开显示：
 * 两者不一致就说明"前端滚上去了、后端没有"（或反过来）——这正是滚动发布
 * 最容易出错、又最难发现的地方（见 docs/rolling-update.md §4.2）。
 */
export const WEB_BUILD_TAG: string =
  (import.meta.env.VITE_BUILD_TAG as string | undefined)?.trim() || 'dev'

/** 前后端是否同一次构建 */
export function sameBuild(serverBuild: string | null): boolean {
  if (!serverBuild) return true // 拿不到后端标识时不报警（可能只是接口旧）
  return serverBuild === WEB_BUILD_TAG
}
