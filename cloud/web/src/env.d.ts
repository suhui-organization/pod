/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
}

// dsh-genui 独立 chunk(运行时由 vite 构建到 /genui/,类型仅用于 TS 检查)
declare module '/genui/finharness-genui.js' {
  export function install(
    host: { currentSessionId?: () => string | undefined },
    sendAction: (action: string, payload: Record<string, unknown>) => void,
  ): () => void
}
