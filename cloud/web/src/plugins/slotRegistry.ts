/**
 * 前端 Slot 注册表(P0 宿主协议前端面)
 *
 * 对应 DSH 的 Slot 机制:插件 manifest 声明 ui_slots(type + component),
 * 前端按 component 名从注册表取组件动态渲染。组件注册表是白名单:
 * 只有在此注册过的组件才会被渲染(未注册的 slot 静默跳过)。
 */
import type { Component } from 'vue'

export interface PluginSlot {
  type: string
  component: string
  title?: string
  plugin_id?: string
}

export type SlotComponentMap = Record<string, () => Promise<{ default: Component }>>

/** 内置 slot 组件注册表(hello 插件示例) */
const slotComponents: SlotComponentMap = {
  HelloPanel: () => import('../components/plugin/HelloPanel.vue'),
  HelloBadge: () => import('../components/plugin/HelloBadge.vue'),
}

/** 插件代码(自定义插件)目前不能携带前端代码:前端组件需在发行版内置并在此注册。 */
export function registerSlotComponent(name: string, loader: () => Promise<{ default: Component }>): void {
  slotComponents[name] = loader
}

export function hasSlotComponent(name: string): boolean {
  return name in slotComponents
}

export function resolveSlotComponent(name: string): (() => Promise<{ default: Component }>) | undefined {
  return slotComponents[name]
}
