<template>
  <div class="profile">
    <div class="head">
      <h1>个人资料</h1>
      <p>你自己的账号信息与密码。这里的改动只影响你自己，不涉及其他成员。</p>
    </div>

    <!-- 身份在前（只读、可核查），可写的资料在后 -->
    <el-card class="card">
      <template #header>账号</template>
      <el-descriptions :column="2" border>
        <el-descriptions-item label="邮箱">{{ me?.email || auth.email }}</el-descriptions-item>
        <el-descriptions-item label="租户">{{ tenantName || '—' }}</el-descriptions-item>
        <el-descriptions-item label="角色">{{ roleText }}</el-descriptions-item>
        <el-descriptions-item label="上次修改密码">{{ lastChangedText }}</el-descriptions-item>
      </el-descriptions>
      <p class="hint">
        邮箱是登录身份，暂不支持自助修改——换邮箱等于换身份，需要重新验证所有权。
      </p>
    </el-card>

    <el-card class="card">
      <template #header>姓名</template>
      <el-form label-width="90px" @submit.prevent>
        <el-form-item label="姓名">
          <el-input
            v-model="fullName"
            maxlength="128"
            placeholder="显示在成员列表与右上角菜单里"
            style="width: 300px"
            @keyup.enter="saveName"
          />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="nameSaving" :disabled="!nameDirty" @click="saveName">
            保存
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="card">
      <template #header>修改密码</template>
      <el-form label-width="90px" @submit.prevent>
        <el-form-item label="当前密码">
          <el-input
            v-model="oldPassword"
            type="password"
            show-password
            autocomplete="current-password"
            placeholder="用于确认是你本人操作"
            style="width: 300px"
          />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input
            v-model="newPassword"
            type="password"
            show-password
            autocomplete="new-password"
            placeholder="至少 8 位，含字母和数字"
            style="width: 300px"
          />
        </el-form-item>
        <el-form-item label="确认新密码">
          <el-input
            v-model="confirmPassword"
            type="password"
            show-password
            autocomplete="new-password"
            style="width: 300px"
          />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="pwSaving" @click="submitPassword">修改密码</el-button>
        </el-form-item>
      </el-form>

      <el-alert v-if="pwError" :title="pwError" type="error" :closable="false" class="alert" />

      <p class="hint">
        改完密码后，其它设备/浏览器上的登录会立即失效，需要重新登录；当前这个会话保持在线。
      </p>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { parseApiError } from '../api/client'
import { useAuthStore } from '../stores/auth'
import type { MeProfile } from '../api/types'

const auth = useAuthStore()
const me = ref<MeProfile | null>(null)
// 租户名不进 localStorage，刷新后 store 里是空的：这里自己拉一次，
// 免得硬刷新一次就显示成「—」
const tenantName = ref('')

const fullName = ref('')
const nameSaving = ref(false)

const oldPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const pwSaving = ref(false)
const pwError = ref('')

const roleText = computed(() => (auth.role === 'admin' ? '管理员' : '成员'))

const lastChangedText = computed(() => {
  const iso = me.value?.password_changed_at
  if (!iso) return '从未修改'
  const ts = new Date(iso)
  if (Number.isNaN(ts.getTime())) return iso
  return ts.toLocaleString('zh-CN', { dateStyle: 'medium', timeStyle: 'short' })
})

const nameDirty = computed(() => fullName.value.trim() !== (me.value?.full_name || ''))

/** 与后端 security.validate_password_strength 同一套规则；这里只做输入提示，
 *  真正的边界在服务端（前端能被绕过）。 */
function policyError(password: string): string {
  if (password.length < 8) return '新密码至少 8 位'
  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) return '新密码需同时包含字母和数字'
  return ''
}

async function load() {
  try {
    const profile = await api.me()
    me.value = profile
    fullName.value = profile.full_name || ''
  } catch {
    /* 读不到就保持占位，不阻塞页面 */
  }
  try {
    tenantName.value = (await api.tenantMe()).name
  } catch {
    /* 同上 */
  }
}

async function saveName() {
  if (!nameDirty.value) return
  nameSaving.value = true
  try {
    me.value = await auth.updateProfile(fullName.value)
    ElMessage.success('姓名已更新')
  } catch (e) {
    ElMessage.error(parseApiError(e))
  } finally {
    nameSaving.value = false
  }
}

async function submitPassword() {
  pwError.value = ''
  if (!oldPassword.value) {
    pwError.value = '请输入当前密码'
    return
  }
  const weak = policyError(newPassword.value)
  if (weak) {
    pwError.value = weak
    return
  }
  if (newPassword.value !== confirmPassword.value) {
    pwError.value = '两次输入的新密码不一致'
    return
  }
  pwSaving.value = true
  try {
    const result = await auth.changePassword(oldPassword.value, newPassword.value)
    me.value = result.user
    oldPassword.value = ''
    newPassword.value = ''
    confirmPassword.value = ''
    ElMessage.success('密码已更新，其它设备需要重新登录')
  } catch (e) {
    pwError.value = parseApiError(e)
  } finally {
    pwSaving.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.profile {
  max-width: 760px;
}
.head {
  margin-bottom: 16px;
}
.head h1 {
  margin: 0 0 6px;
  font-size: 18px;
  font-weight: 600;
  color: var(--fh-text);
}
.head p {
  margin: 0;
  font-size: var(--fh-size-sm);
  /* 用 dim 而非 faint：--fh-text-faint(#6b7280) 压在暗色卡片上只有 3.85:1，
     够不到 PRODUCT.md 要求的 4.5:1；dim 在两种主题下都 ≥7:1 */
  color: var(--fh-text-dim);
  max-width: 60ch;
  line-height: 1.5;
}
.card {
  margin-bottom: 16px;
}
.alert {
  margin-top: 4px;
}
.hint {
  margin: 12px 0 0;
  font-size: 12px;
  line-height: 1.6;
  color: var(--fh-text-dim);
}
</style>
