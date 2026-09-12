import { defineStore } from 'pinia'
import { api } from '../api'
import type { LlmSettings } from '../api/types'

/**
 * AI 可用性的全局状态。
 *
 * 为什么单独有它：AI 入口散在三处（策略中心生成策略、告警页摘要、设置页 AI
 * 日报），如果每个页面各自判断"模型配好了吗"，规则会各写一份、接口也各拉一次，
 * 迟早出现"A 页面拦住了、B 页面照样发请求"。这里只做两件事：拉一次
 * `/settings/llm` 并缓存；把「未配置时怎么说、去哪配」收敛成一处。
 *
 * 判定仍然是服务端权威：页面这层只是提前一步拦住并给出路径，400 的兜底照旧保留。
 */
export const useAiStore = defineStore('ai', {
  state: () => ({
    loaded: false,
    /** 模型当前能否直接调用（服务端 resolve_config 的结论） */
    configured: false,
    /** 不能调用时缺什么，文案与服务端一致，直接给用户看 */
    reason: '',
    settings: null as LlmSettings | null,
  }),
  actions: {
    async ensureLoaded() {
      if (!this.loaded) await this.refresh()
    },
    async refresh() {
      try {
        const s = await api.llmSettings()
        this.settings = s
        this.configured = s.configured
        this.reason = s.reason
      } catch {
        // 读不到配置就当作"未知"，放行到服务端去判定。
        // 反过来把入口锁死更糟：一次网络抖动会让 AI 功能整个不可达。
        this.settings = null
        this.configured = true
        this.reason = ''
      } finally {
        this.loaded = true
      }
    },
  },
})
