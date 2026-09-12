<template>
  <div class="admin-layout">
    <aside class="admin-nav">
      <div class="nav-logo" @click="$router.push('/')">
        <span class="logo-mark">PD</span>
        <span class="logo-text">Pod Cloud</span>
      </div>
      <div class="nav-scroll">
        <div
          v-for="item in visibleNavItems"
          :key="item.to"
          class="nav-item"
          :class="{ active: isActive(item.to) }"
          @click="$router.push(item.to)"
        >
          <component :is="item.icon" :size="18" :stroke-width="1.8" class="nav-icon" />
          <span class="nav-label">{{ item.label }}</span>
        </div>
      </div>
      <div class="nav-foot">
        <div class="nav-item" :class="{ active: isActive('/profile') }" @click="$router.push('/profile')">
          <UserRound :size="18" :stroke-width="1.8" class="nav-icon" />
          <span class="nav-label">{{ t('个人资料') }}</span>
        </div>
        <div class="nav-item" :class="{ active: isActive('/settings') }" @click="$router.push('/settings')">
          <Settings :size="18" :stroke-width="1.8" class="nav-icon" />
          <span class="nav-label">{{ t('设置') }}</span>
        </div>
      </div>
    </aside>
    <main class="admin-main">
      <header class="admin-topbar">
        <span class="topbar-title">{{ route.meta.title ? t(route.meta.title as string) : 'Pod Cloud' }}</span>
        <UserMenu />
      </header>
      <div class="admin-content">
        <router-view />
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import {
  LayoutDashboard, Boxes, BellRing, History, Network, ShieldAlert, ShieldCheck, PackageCheck, CreditCard, Users, Settings, UserRound,
  FileCheck2,
} from 'lucide-vue-next'
import UserMenu from './UserMenu.vue'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '../../stores/auth'
import { useDeploymentStore } from '../../stores/deployment'

const route = useRoute()
const { t } = useI18n()
const auth = useAuthStore()

// 定义用中文原文，label 在渲染时过 t()——这样切换语言立刻生效
const navDefs = [
  { to: '/', label: '总览', icon: LayoutDashboard },
  { to: '/agents', label: 'Agent 资产', icon: Boxes },
  { to: '/alerts', label: '告警', icon: BellRing },
  { to: '/timeline', label: '时间线', icon: History },
  { to: '/control-plane', label: '控制平面', icon: ShieldAlert },
  { to: '/traces', label: '调用链', icon: Network },
  { to: '/policies', label: '策略中心', icon: ShieldCheck },
  { to: '/rules', label: '规则包', icon: PackageCheck },
  { to: '/harden', label: '加固报告', icon: FileCheck2 },
  // 计费关闭的部署（自托管默认）不显示订阅入口
  { to: '/subscription', label: '订阅', icon: CreditCard, billing: true },
  { to: '/users', label: '成员管理', icon: Users, admin: true },
]

const deployment = useDeploymentStore()
const allNavItems = computed(() => navDefs.map((i) => ({ ...i, label: t(i.label) })))
const visibleNavItems = computed(() =>
  allNavItems.value.filter((i) => (!i.admin || auth.isAdmin) && (!i.billing || deployment.billingEnabled)),
)

function isActive(to: string): boolean {
  if (to === '/') return route.path === '/'
  return route.path.startsWith(to)
}
</script>

<style scoped>
.admin-layout { display: flex; height: 100vh; overflow: hidden; }
.admin-nav {
  width: 220px; flex-shrink: 0; display: flex; flex-direction: column;
  background: var(--pod-panel-bg, #161a1f); border-right: 1px solid var(--pod-border, #2a2f37);
}
.nav-logo { display: flex; align-items: center; gap: 8px; padding: 16px 18px; cursor: pointer; }
.logo-mark {
  width: 30px; height: 30px; border-radius: 8px; display: flex; align-items: center; justify-content: center;
  background: #4f7cff; color: #fff; font-weight: 700; font-size: 13px;
}
.logo-text { font-weight: 600; font-size: 14px; }
.nav-scroll { flex: 1; overflow-y: auto; padding: 8px 10px; }
.nav-item {
  display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-radius: 8px;
  cursor: pointer; color: var(--pod-text-dim, #9aa3af); margin-bottom: 2px; user-select: none;
}
.nav-item:hover { background: rgba(127, 127, 127, 0.08); color: var(--pod-text, #e8eaed); }
.nav-item.active { background: rgba(79, 124, 255, 0.14); color: #4f7cff; }
.nav-label { font-size: 14px; }
.nav-foot { padding: 8px 10px 14px; border-top: 1px solid var(--pod-border, #2a2f37); }
.admin-main { flex: 1; display: flex; flex-direction: column; min-width: 0; }
.admin-topbar {
  height: 52px; display: flex; align-items: center; justify-content: space-between;
  padding: 0 20px; border-bottom: 1px solid var(--pod-border, #2a2f37); flex-shrink: 0;
}
.topbar-title { font-size: 15px; font-weight: 600; }
.admin-content { flex: 1; overflow-y: auto; padding: 20px; }
</style>
