import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '../api'

/**
 * 部署形态（实例级，不是租户级）：是否私有化、是否启用计费。
 *
 * 一次拉取、全局复用：侧栏订阅入口的显隐、订阅页的形态都依赖它。
 * 计费默认按"关"处理——自托管部署不该看到点了会报错的付费按钮。
 */
export const useDeploymentStore = defineStore('deployment', () => {
  const loaded = ref(false)
  const isPrivate = ref(false)
  const billingEnabled = ref(false)
  const billingProvider = ref('')
  /** 后端镜像的构建标识（来自 /auth/config）。前端自己的标识见 utils/build.ts */
  const buildTag = ref('')

  async function load() {
    if (loaded.value) return
    try {
      const cfg = await api.authConfig()
      isPrivate.value = cfg.is_private
      billingEnabled.value = cfg.billing_enabled === true
      billingProvider.value = cfg.billing_provider ?? ''
      buildTag.value = cfg.build ?? ''
    } catch {
      // 拉不到就按未启用计费处理：少一个入口，好过一个会报错的入口
      billingEnabled.value = false
    } finally {
      loaded.value = true
    }
  }

  return { loaded, isPrivate, billingEnabled, billingProvider, buildTag, load }
})
