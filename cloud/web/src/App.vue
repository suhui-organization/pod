<template>
  <el-config-provider :locale="elLocale">
    <AdminLayout v-if="!isPublic">
      <router-view />
    </AdminLayout>
    <router-view v-else />
  </el-config-provider>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import AdminLayout from './components/layout/AdminLayout.vue'
import { bootstrapLayoutPreferences, applyPreferencesToStore } from './stores/layout'
import { useResponsive } from './composables/useResponsive'
import { useLayoutStore } from './stores/layout'
import { useDeploymentStore } from './stores/deployment'
import { computed as vueComputed } from 'vue'
import { elementLocale, useLocaleRef, type Locale } from './i18n'

// Element Plus 的内置文案（日期选择、分页等）跟着切换
const localeRef = useLocaleRef()
const elLocale = vueComputed(() => elementLocale(localeRef.value as Locale))

const route = useRoute()
const isPublic = computed(() => Boolean(route.meta.public))

// 启动时:迁移老 localStorage + 从后端拉偏好 + 回填到 layout store
onMounted(async () => {
  await useDeploymentStore().load()
  await bootstrapLayoutPreferences()
  applyPreferencesToStore()
  // 移动端:模块面板为全屏覆盖式,默认折叠,避免盖住路由页面内容
  // (必须在 applyPreferencesToStore 之后,否则会被偏好回填覆盖)
  const { mode } = useResponsive()
  if (mode.value === 'mobile') useLayoutStore().setModulesCollapsed(true)
})
</script>
