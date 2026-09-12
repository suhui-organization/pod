import { defineStore } from 'pinia'
import { api } from '../api'
import { STORAGE_KEYS } from '../api/client'

interface AuthState {
  token: string
  refreshToken: string
  email: string
  fullName: string
  tenantId: number | null
  tenantName: string
  role: string
}

export const useAuthStore = defineStore('auth', {
  state: (): AuthState => ({
    token: localStorage.getItem(STORAGE_KEYS.token) || '',
    refreshToken: localStorage.getItem(STORAGE_KEYS.refreshToken) || '',
    email: localStorage.getItem(STORAGE_KEYS.email) || '',
    fullName: localStorage.getItem(STORAGE_KEYS.fullName) || '',
    tenantId: null,
    tenantName: '',
    role: localStorage.getItem(STORAGE_KEYS.role) || 'member',
  }),
  getters: {
    isLoggedIn: (s) => Boolean(s.token),
    isAdmin: (s) => s.role === 'admin',
  },
  actions: {
    persistTokens(access: string, refresh?: string) {
      this.token = access
      localStorage.setItem(STORAGE_KEYS.token, access)
      if (refresh) {
        this.refreshToken = refresh
        localStorage.setItem(STORAGE_KEYS.refreshToken, refresh)
      }
    },
    persistProfile(email: string, fullName: string) {
      this.email = email
      this.fullName = fullName
      localStorage.setItem(STORAGE_KEYS.email, email)
      localStorage.setItem(STORAGE_KEYS.fullName, fullName)
    },
    persistRole(role?: string) {
      this.role = role || 'member'
      localStorage.setItem(STORAGE_KEYS.role, this.role)
    },
    async login(email: string, password: string) {
      const resp = await api.login(email, password)
      this.persistTokens(resp.access_token, resp.refresh_token)
      this.persistProfile(resp.email || email, '')
      this.persistRole('admin')
      this.tenantId = null
      await this.loadTenant()
    },
    async register(email: string, password: string, fullName: string) {
      const resp = await api.register(email, password, fullName)
      this.persistTokens(resp.access_token, resp.refresh_token)
      this.persistProfile(resp.email || email, fullName)
      this.persistRole('admin')
      await this.loadTenant()
    },
    async loadTenant() {
      try {
        const me = await api.me()
        this.tenantId = me.tenant_id
        this.persistRole(me.role)
        // 登录响应里没有姓名(只有邮箱),不回填的话菜单和成员列表会各显示各的
        this.persistProfile(me.email, me.full_name || '')
        const tenant = await api.tenantMe()
        this.tenantName = tenant.name
      } catch {
        this.tenantName = '默认租户'
      }
    },
    /** 本人改资料:改完就地回填,菜单/头像不用等下次刷新 */
    async updateProfile(fullName: string) {
      const me = await api.updateProfile(fullName)
      this.persistProfile(me.email, me.full_name)
      return me
    },
    /** 本人改密:后端会把其它会话踢掉,所以必须存下本会话换发的新 token */
    async changePassword(oldPassword: string, newPassword: string) {
      const result = await api.changePassword(oldPassword, newPassword)
      this.persistTokens(result.access_token, result.refresh_token)
      return result
    },
    logout() {
      this.token = ''
      this.refreshToken = ''
      this.email = ''
      this.fullName = ''
      this.tenantId = null
      this.tenantName = ''
      this.role = 'member'
      localStorage.removeItem(STORAGE_KEYS.token)
      localStorage.removeItem(STORAGE_KEYS.refreshToken)
      localStorage.removeItem(STORAGE_KEYS.email)
      localStorage.removeItem(STORAGE_KEYS.fullName)
      localStorage.removeItem(STORAGE_KEYS.role)
    },
  },
})
