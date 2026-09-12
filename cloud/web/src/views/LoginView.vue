<template>
  <div class="login-page">
    <div class="login-card">
      <div class="login-lang"><LangSwitch /></div>
      <div class="login-logo"><img src="/logo.svg" alt="Pod Cloud" /></div>
      <h1 class="title">Pod Cloud</h1>
      <p class="subtitle">{{ t('AI Agent 安全控制平面 · 本地优先，云端可选') }}</p>
      <el-tabs v-if="mode !== 'forgot'" v-model="mode" stretch>
        <el-tab-pane :label="t('登录')" name="login" />
        <el-tab-pane v-if="registerEnabled" :label="t('注册')" name="register" />
      </el-tabs>
      <p v-else class="subtitle subtitle--forgot">{{ t('输入注册时用的邮箱，我们发一条重置链接给你。') }}</p>
      <el-form label-position="top" @submit.prevent>
        <el-form-item v-if="showServer" :label="t('服务地址（私有化实例填写，留空为公有 SaaS）')">
          <el-input v-model="serverUrl" :placeholder="t('如 https://podcloud.your-company.com')" />
        </el-form-item>
        <el-form-item :label="t('邮箱')">
          <el-input v-model="email" type="email" placeholder="you@company.com" />
        </el-form-item>
        <el-form-item v-if="mode !== 'forgot'" :label="t('密码')">
          <el-input v-model="password" type="password" show-password :placeholder="t('请输入密码')" @keyup.enter="submit" />
        </el-form-item>
        <el-form-item v-if="mode === 'register'" :label="t('姓名')">
          <el-input v-model="fullName" :placeholder="t('您的姓名')" />
        </el-form-item>
        <el-button type="primary" class="submit" :loading="loading" @click="submit">
          {{ submitLabel }}
        </el-button>
        <div class="links">
          <el-link v-if="mode === 'login'" type="info" @click="mode = 'forgot'">{{ t('忘记密码？') }}</el-link>
          <el-link v-else-if="mode === 'forgot'" type="info" @click="mode = 'login'">{{ t('返回登录') }}</el-link>
        </div>
        <div v-if="mode === 'register'" class="legal-links">
          {{ t('注册即表示同意') }}
          <router-link to="/legal/terms">{{ t('服务条款') }}</router-link> {{ t('与') }}
          <router-link to="/legal/privacy">{{ t('隐私政策') }}</router-link>
        </div>
        <div class="server-toggle">
          <el-link type="info" @click="showServer = !showServer">{{ showServer ? t('隐藏服务地址') : t('配置私有化实例地址') }}</el-link>
        </div>
      </el-form>
      <!-- 找回密码的受理回执。文案对"账号存不存在"完全一致：这个端点不能当账号枚举器用 -->
      <div v-if="resetSent" class="notice" role="status">
        <div class="notice__title">已受理</div>
        <p class="notice__body">{{ resetNotice }}</p>
      </div>
      <el-alert v-if="errorMsg" :title="errorMsg" type="error" :closable="false" class="error" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { useI18n } from 'vue-i18n'
import LangSwitch from '../components/LangSwitch.vue'

const { t } = useI18n()
import { useAuthStore } from '../stores/auth'
import { parseApiError, setBaseUrl, STORAGE_KEYS } from '../api/client'

const router = useRouter()
const auth = useAuthStore()

const mode = ref<'login' | 'register' | 'forgot'>('login')
const serverUrl = ref(localStorage.getItem(STORAGE_KEYS.baseUrl) || '')
const showServer = ref(Boolean(serverUrl.value))
const email = ref('')
const password = ref('')
const fullName = ref('')
const loading = ref(false)
const errorMsg = ref('')
const registerEnabled = ref(true)
/** 本实例把重置链接投到哪：email=已配 SMTP；log=服务端日志 */
const resetChannel = ref<'email' | 'log' | 'unknown'>('unknown')
const resetMinutes = ref(30)
const resetSent = ref(false)
const resetNotice = ref('')

// 前端预校验仅作用户体验;服务端 pydantic EmailStr 才是安全边界(以后端为准)
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

const submitLabel = computed(() => {
  if (mode.value === 'login') return t('登录')
  if (mode.value === 'register') return t('注册并进入')
  return t('发送重置链接')
})

async function loadAuthConfig() {
  try {
    const cfg = await api.authConfig()
    registerEnabled.value = !cfg.is_private
    resetChannel.value = cfg.password_reset ?? 'unknown'
    resetMinutes.value = cfg.password_reset_minutes ?? 30
  } catch {
    registerEnabled.value = true
  }
}

onMounted(loadAuthConfig)

/** 回执文案必须对"账号存在 / 不存在"完全一致，否则这个页面就成了账号探测器。
 *  措辞统一用"如果该邮箱是本系统的账号"，只在"链接去哪"上区分实例能力。 */
function buildResetNotice(cleanEmail: string): string {
  const head = `如果 ${cleanEmail} 是本系统的账号，重置链接已经发出，${resetMinutes.value} 分钟内有效。`
  if (resetChannel.value === 'email') {
    return `${head}没收到的话，检查一下垃圾邮件，或稍后重新申请。`
  }
  if (resetChannel.value === 'log') {
    return `${head}本实例没有配置邮件服务，链接写在服务端日志里——请联系部署这台机器的人用 kubectl logs 取走。`
  }
  return head
}

async function submit() {
  const cleanEmail = email.value.trim()
  if (!cleanEmail || (mode.value !== 'forgot' && !password.value)) {
    errorMsg.value = mode.value === 'forgot' ? '请输入邮箱' : '请输入邮箱和密码'
    return
  }
  if (!EMAIL_RE.test(cleanEmail)) {
    errorMsg.value = '邮箱格式不正确(如 you@company.com)'
    return
  }
  setBaseUrl(serverUrl.value)
  loading.value = true
  errorMsg.value = ''
  try {
    if (mode.value === 'forgot') {
      // 服务地址可能刚刚才填进来:重新问一次"本实例把链接投到哪",
      // 否则回执会按上一个实例(或公有 SaaS)的能力来写
      await loadAuthConfig()
      await api.forgotPassword(cleanEmail)
      resetSent.value = true
      resetNotice.value = buildResetNotice(cleanEmail)
      return
    }
    if (mode.value === 'login') {
      await auth.login(cleanEmail, password.value)
    } else {
      await auth.register(cleanEmail, password.value, fullName.value)
    }
    ElMessage.success(t('欢迎使用 Pod Cloud'))
    router.push('/')
  } catch (e) {
    errorMsg.value = parseApiError(e)
  } finally {
    loading.value = false
  }
}
</script>

.legal-links { font-size: 12px; color: var(--pod-text-dim, #9aa3af); text-align: center; margin-top: 8px; }
.legal-links a { color: #4f7cff; text-decoration: none; }
<style scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--pod-bg);
}
.login-card {
  width: 400px;
  background: var(--pod-bg-elev);
  border: 1px solid var(--pod-border);
  border-radius: var(--pod-radius-lg);
  padding: 32px;
  position: relative;
}
/* 语言开关放在登录卡右上角：登录前就能切——英文用户第一眼就能读 */
.login-lang { position: absolute; top: 14px; right: 14px; }
.title {
  margin: 0 0 4px;
  color: var(--pod-text);
  font-size: 24px;
  font-weight: 600;
  letter-spacing: 0.5px;
}
.subtitle {
  margin: 0 0 20px;
  color: var(--pod-text-faint);
  font-size: 13px;
}
.submit {
  width: 100%;
  margin-top: 4px;
}
.links {
  margin-top: 10px;
  text-align: center;
}
.subtitle--forgot {
  margin-bottom: 16px;
}
.notice {
  margin-top: 14px;
  padding: 12px 14px;
  border: 1px solid var(--pod-border-strong);
  border-radius: var(--pod-radius);
  background: var(--pod-bg-soft);
}
.notice__title {
  font-size: 13px;
  font-weight: 600;
  color: var(--pod-text);
  margin-bottom: 4px;
}
.notice__body {
  margin: 0;
  font-size: 12px;
  line-height: 1.7;
  color: var(--pod-text-dim);
}
.server-toggle {
  margin-top: 12px;
  text-align: center;
}
.error {
  margin-top: 12px;
}
</style>

.login-logo {
  display: flex;
  justify-content: center;
  margin-bottom: 6px;
}
.login-logo img {
  width: 56px;
  height: 56px;
}
