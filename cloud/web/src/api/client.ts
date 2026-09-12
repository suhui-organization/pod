import axios from 'axios'
import type { ApiError } from './types'

export const STORAGE_KEYS = {
  token: 'podcloud_token',
  refreshToken: 'podcloud_refresh_token',
  baseUrl: 'podcloud_base_url',
  tenantId: 'podcloud_tenant_id',
  email: 'podcloud_email',
  fullName: 'podcloud_fullname',
  role: 'podcloud_role',
}

export function getBaseUrl(): string {
  return localStorage.getItem(STORAGE_KEYS.baseUrl) || ''
}

export function setBaseUrl(url: string) {
  localStorage.setItem(STORAGE_KEYS.baseUrl, url.replace(/\/+$/, ''))
}

export const http = axios.create({ timeout: 60000 })

http.interceptors.request.use((config) => {
  const base = getBaseUrl()
  config.baseURL = base || undefined
  const token = localStorage.getItem(STORAGE_KEYS.token)
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

let refreshing: Promise<string | null> | null = null

function refreshAccess(): Promise<string | null> {
  if (!refreshing) {
    refreshing = (async () => {
      const rt = localStorage.getItem(STORAGE_KEYS.refreshToken)
      if (!rt) return null
      try {
        const base = getBaseUrl()
        const resp = await axios.post(
          `${base}/api/v1/auth/refresh`,
          { refresh_token: rt },
          { timeout: 15000 },
        )
        const token = resp.data?.access_token
        if (token) localStorage.setItem(STORAGE_KEYS.token, token)
        return token || null
      } catch {
        return null
      } finally {
        refreshing = null
      }
    })()
  }
  return refreshing
}

http.interceptors.response.use(
  (resp) => resp,
  async (error: any) => {
    if (error.response?.status === 401) {
      const config = error.config
      const url: string = config?.url || ''
      const isAuthEndpoint =
        url.includes('/auth/refresh') || url.includes('/auth/login')
      if (config && !config._retried && !isAuthEndpoint) {
        config._retried = true
        const token = await refreshAccess()
        if (token) {
          config.headers.Authorization = `Bearer ${token}`
          return http(config)
        }
      }
      localStorage.removeItem(STORAGE_KEYS.token)
      localStorage.removeItem(STORAGE_KEYS.refreshToken)
      if (window.location.pathname !== '/login') {
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  },
)

export function parseApiError(error: unknown): string {
  const body = (error as { response?: { data?: { error?: ApiError; detail?: string } } })?.response?.data
  if (body?.error?.message) return body.error.message
  if (body?.detail) return body.detail
  return '网络或服务异常,请稍后重试'
}
