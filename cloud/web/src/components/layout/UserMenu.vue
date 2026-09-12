<template>
  <div class="user-menu">
    <LangSwitch />
    <button class="um-icon" :title="isDark ? '切换到亮色' : '切换到暗色'" @click="toggleTheme">
      <component :is="isDark ? Sun : Moon" :size="17" :stroke-width="1.8" />
    </button>
    <el-dropdown trigger="click" @command="onCommand">
      <div class="um-user">
        <span class="um-avatar">{{ avatarText }}</span>
        <span class="um-email">{{ auth.email }}</span>
        <el-tag v-if="auth.isAdmin" size="small" effect="plain" class="um-role">admin</el-tag>
      </div>
      <template #dropdown>
        <el-dropdown-menu>
          <el-dropdown-item disabled>{{ auth.email }}</el-dropdown-item>
          <el-dropdown-item divided command="profile">{{ t('个人资料') }}</el-dropdown-item>
          <el-dropdown-item command="settings">{{ t('设置') }}</el-dropdown-item>
          <el-dropdown-item command="logout">{{ t('退出登录') }}</el-dropdown-item>
        </el-dropdown-menu>
      </template>
    </el-dropdown>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { Moon, Sun } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import LangSwitch from '../LangSwitch.vue'
import { useAuthStore } from '../../stores/auth'

const { t } = useI18n()
const auth = useAuthStore()
const router = useRouter()
const isDark = computed(() => (document.documentElement.dataset.theme || 'dark') === 'dark')

// 有姓名就用姓名首字，没有才退回邮箱首字母
const avatarText = computed(() =>
  (auth.fullName.trim() || auth.email || '?').slice(0, 2).toUpperCase(),
)

function toggleTheme() {
  const next = isDark.value ? 'light' : 'dark'
  document.documentElement.dataset.theme = next
  localStorage.setItem('podcloud_theme', next)
}

function onCommand(cmd: string) {
  if (cmd === 'profile') router.push('/profile')
  if (cmd === 'settings') router.push('/settings')
  if (cmd === 'logout') {
    auth.logout()
    router.push('/login')
  }
}
</script>

<style scoped>
.user-menu { display: flex; align-items: center; gap: 10px; }
.um-icon {
  width: 32px; height: 32px; border-radius: 8px; border: none; background: transparent;
  display: flex; align-items: center; justify-content: center; cursor: pointer; color: var(--pod-text-dim, #9aa3af);
}
.um-icon:hover { background: rgba(127, 127, 127, 0.1); color: var(--pod-text, #e8eaed); }
.um-user { display: flex; align-items: center; gap: 8px; cursor: pointer; padding: 4px 8px; border-radius: 8px; }
.um-user:hover { background: rgba(127, 127, 127, 0.08); }
.um-avatar {
  width: 28px; height: 28px; border-radius: 50%; background: #4f7cff; color: #fff;
  display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 600;
}
.um-email { font-size: 13px; }
.um-role { margin-left: 0; }
</style>
