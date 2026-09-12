<template>
  <div class="reset-page">
    <div class="reset-card">
      <div class="reset-logo"><img src="/logo.svg" alt="Pod Cloud" /></div>
      <h1 class="title">设置新密码</h1>

      <template v-if="!token">
        <p class="subtitle">这个链接缺少重置令牌。请回到登录页重新申请一条。</p>
        <el-button class="submit" @click="$router.push('/login')">回到登录</el-button>
      </template>

      <template v-else-if="done">
        <p class="subtitle">
          密码已更新。该账号在其他设备上的登录已全部失效，需要用新密码重新登录。
        </p>
        <el-button type="primary" class="submit" @click="$router.push('/login')">去登录</el-button>
      </template>

      <template v-else>
        <p class="subtitle">链接只能使用一次，且有时间限制。</p>
        <el-form label-position="top" @submit.prevent>
          <el-form-item label="新密码">
            <el-input
              v-model="password"
              type="password"
              show-password
              autocomplete="new-password"
              placeholder="至少 8 位，含字母和数字"
            />
          </el-form-item>
          <el-form-item label="确认新密码">
            <el-input
              v-model="confirm"
              type="password"
              show-password
              autocomplete="new-password"
              @keyup.enter="submit"
            />
          </el-form-item>
          <el-button type="primary" class="submit" :loading="loading" @click="submit">确定</el-button>
        </el-form>
        <el-alert v-if="error" :title="error" type="error" :closable="false" class="error" />
        <p class="hint">离开这个页面后链接就作废了；万一过期，回登录页重新申请即可。</p>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '../api'
import { parseApiError } from '../api/client'

const route = useRoute()
const token = computed(() => String(route.query.token || ''))

const password = ref('')
const confirm = ref('')
const loading = ref(false)
const error = ref('')
const done = ref(false)

/** 与后端 security.validate_password_strength 同一套规则；前端只做提示，
 *  真正的边界在服务端（前端能被绕过）。 */
function policyError(value: string): string {
  if (value.length < 8) return '新密码至少 8 位'
  if (!/[A-Za-z]/.test(value) || !/[0-9]/.test(value)) return '新密码需同时包含字母和数字'
  return ''
}

async function submit() {
  error.value = ''
  const weak = policyError(password.value)
  if (weak) {
    error.value = weak
    return
  }
  if (password.value !== confirm.value) {
    error.value = '两次输入的新密码不一致'
    return
  }
  loading.value = true
  try {
    await api.resetPassword(token.value, password.value)
    done.value = true
  } catch (e) {
    error.value = parseApiError(e)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.reset-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--pod-bg);
}
.reset-card {
  width: 400px;
  background: var(--pod-bg-elev);
  border: 1px solid var(--pod-border);
  border-radius: var(--pod-radius-lg);
  padding: 32px;
}
.reset-logo {
  display: flex;
  justify-content: center;
  margin-bottom: 6px;
}
.reset-logo img {
  width: 56px;
  height: 56px;
}
.title {
  margin: 0 0 4px;
  color: var(--pod-text);
  font-size: 22px;
  font-weight: 600;
}
.subtitle {
  margin: 0 0 20px;
  color: var(--pod-text-dim);
  font-size: 13px;
  line-height: 1.7;
}
.submit {
  width: 100%;
}
.error {
  margin-top: 12px;
}
.hint {
  margin: 12px 0 0;
  font-size: 12px;
  line-height: 1.6;
  color: var(--pod-text-dim);
}
</style>
