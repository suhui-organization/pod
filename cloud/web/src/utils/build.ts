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
 * 前后端是否同一次构建。
 *
 * 只在**发布 tag** 下才有意义：`install-server.sh` 给两个镜像打同一个
 * `main-<commit>`，所以 tag 不等 = 有一边没滚上去。
 *
 * 本机 kind 用的是**每镜像独立的内容指纹**（`fp-<hash>`，server/web 各自算），
 * 按设计就永远不相等——拿它报警是误报。宁可不说，也不制造假告警：
 * 假告警会让人开始忽略这一行，那它就彻底没用了。
 */
export function sameBuild(serverBuild: string | null): boolean {
  if (!serverBuild) return true // 拿不到后端标识（旧后端没有该字段）时不报警
  const releaseTag = (tag: string): boolean => /^main-[0-9a-f]{6,}/.test(tag)
  if (!releaseTag(serverBuild) || !releaseTag(WEB_BUILD_TAG)) return true
  return serverBuild === WEB_BUILD_TAG
}
