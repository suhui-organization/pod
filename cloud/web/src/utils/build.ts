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

/**
 * 本次**前端**构建来自哪个 commit（deploy/Dockerfile 的 `ARG BUILD_COMMIT`）。
 * 本地 `npm run dev` 没有注入，为空。
 */
export const WEB_BUILD_COMMIT: string =
  (import.meta.env.VITE_BUILD_COMMIT as string | undefined)?.trim() || ''

/**
 * 前后端是否同一次构建。
 *
 * **按 commit 判**：两个镜像的 tag 是各自的内容指纹（`fp-<hash>`，server 与 web
 * 天生不同），拿 tag 比会永远不等、变成假告警；而"前后端是不是同一次发布"这件事，
 * 只有 commit 能回答（新前端 + 旧后端会出现新页面 404，见 docs/rolling-update.md §4.2）。
 *
 * 没有 commit 的情况（旧镜像、本地 dev）退回旧的发布 tag 规则：只在 `main-<sha>`
 * 这种"两个镜像共用同一个 tag"的老形态下才比对。宁可不说，也不制造假告警——
 * 假告警会让人开始忽略这一行，那它就彻底没用了。
 */
export function sameBuild(serverBuild: string | null, serverCommit?: string | null): boolean {
  const server = (serverCommit ?? '').trim()
  if (server && WEB_BUILD_COMMIT) return server === WEB_BUILD_COMMIT
  if (!serverBuild) return true // 拿不到后端标识（旧后端没有该字段）时不报警
  const releaseTag = (tag: string): boolean => /^main-[0-9a-f]{6,}/.test(tag)
  if (!releaseTag(serverBuild) || !releaseTag(WEB_BUILD_TAG)) return true
  return serverBuild === WEB_BUILD_TAG
}
