import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: () => import('../views/LoginView.vue'), meta: { public: true } },
    // 公开：重置链接是从邮件/日志里点进来的，此时用户本来就没登录
    { path: '/reset-password', name: 'reset-password', component: () => import('../views/ResetPasswordView.vue'), meta: { public: true, title: '设置新密码' } },
    { path: '/legal/privacy', name: 'privacy', component: () => import('../views/LegalView.vue'), meta: { public: true, title: '隐私政策' } },
    { path: '/legal/terms', name: 'terms', component: () => import('../views/LegalView.vue'), meta: { public: true, title: '服务条款' } },
    // Paddle 审核收银台域名要求站点链到「服务条款 + 隐私政策 + 退款政策」三份文档
    { path: '/legal/refund', name: 'refund', component: () => import('../views/LegalView.vue'), meta: { public: true, title: '退款政策' } },
    { path: '/', name: 'dashboard', component: () => import('../views/DashboardView.vue'), meta: { title: '总览' } },
    { path: '/agents', name: 'agents', component: () => import('../views/AgentsView.vue'), meta: { title: 'Agent 资产' } },
    { path: '/alerts', name: 'alerts', component: () => import('../views/AlertsView.vue'), meta: { title: '告警' } },
    { path: '/timeline', name: 'timeline', component: () => import('../views/TimelineView.vue'), meta: { title: '时间线' } },
    { path: '/control-plane', name: 'control-plane', component: () => import('../views/ControlPlaneView.vue'), meta: { title: '控制平面' } },
    { path: '/traces', name: 'traces', component: () => import('../views/TracesView.vue'), meta: { title: '调用链' } },
    // 只读成员也要能看（后端 GET 已开放，写操作在页面内按角色隐藏）
    { path: '/policies', name: 'policies', component: () => import('../views/PoliciesView.vue'), meta: { title: '策略中心' } },
    { path: '/rules', name: 'rules', component: () => import('../views/RulesView.vue'), meta: { title: '规则包' } },
    { path: '/harden', name: 'harden', component: () => import('../views/HardenView.vue'), meta: { title: '加固报告' } },
    // 自检会真实调用模型、写审计，且能改状态：只给管理员
    { path: '/selfcheck', name: 'selfcheck', component: () => import('../views/SelfCheckView.vue'), meta: { admin: true, title: '系统自检' } },
    { path: '/subscription', name: 'subscription', component: () => import('../views/SubscriptionView.vue'), meta: { title: '订阅' } },
    { path: '/users', name: 'users', component: () => import('../views/UsersView.vue'), meta: { admin: true, title: '成员管理' } },
    { path: '/profile', name: 'profile', component: () => import('../views/ProfileView.vue'), meta: { title: '个人资料' } },
    { path: '/settings', name: 'settings', component: () => import('../views/SettingsView.vue'), meta: { title: '设置' } },
  ],
})

router.beforeEach((to) => {
  const auth = useAuthStore()
  if (!to.meta.public && !auth.isLoggedIn) {
    return { name: 'login' }
  }
  if (to.name === 'login' && auth.isLoggedIn) {
    return { name: 'dashboard' }
  }
  if (to.meta.admin && !auth.isAdmin) {
    return { name: 'dashboard' }
  }
  return true
})

// 部署滚动更新后旧 hash chunk 可能 404:动态 import 失败时自动整页刷新
router.onError((error) => {
  if (/Failed to fetch dynamically imported module|Importing a module script failed|error loading dynamically imported module/i.test(String(error))) {
    window.location.reload()
  }
})

export default router
