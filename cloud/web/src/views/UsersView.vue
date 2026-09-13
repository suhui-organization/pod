<template>
  <div class="page">
    
    <main class="content">
      <div class="toolbar">
        <div class="heading">
          <h1>{{ t('用户管理') }}</h1>
          <p>{{ t('管理租户成员、角色与账号状态。管理员负责配置与成员管理，不读取成员的业务数据。') }}</p>
        </div>
        <div class="actions">
          <el-input
            v-model="search"
            class="search"
            :placeholder="t('搜索姓名或邮箱')"
            clearable
            autocomplete="off"
          >
            <template #prefix>
              <span class="search-icon" aria-hidden="true">⌕</span>
            </template>
          </el-input>
          <el-tooltip :content="t('新建用户')" placement="bottom">
            <el-button type="primary" circle @click="openCreate">
              <el-icon><Plus /></el-icon>
            </el-button>
          </el-tooltip>
        </div>
      </div>

      <div class="table-panel" v-loading="loading">
        <el-table :data="filteredUsers" style="width: 100%" row-key="id">
          <template #empty>
            <div class="empty-state">
              <div class="empty-title">{{ search ? t('没有匹配的用户') : t('还没有成员') }}</div>
              <div class="empty-desc">{{ search ? t('换个关键词试试') : t('创建第一个成员，开始分配角色') }}</div>
              <el-tooltip v-if="!search" :content="t('新建用户')" placement="bottom">
                <el-button type="primary" size="small" circle @click="openCreate">
                  <el-icon><Plus /></el-icon>
                </el-button>
              </el-tooltip>
            </div>
          </template>

          <el-table-column :label="t('用户')" min-width="240">
            <template #default="{ row }">
              <div class="user-cell">
                <span class="avatar" :class="{ self: row.email === auth.email }">{{ initials(row) }}</span>
                <div class="user-meta">
                  <div class="name">
                    {{ row.full_name || row.email }}
                    <span v-if="row.email === auth.email" class="self-label">{{ t('你') }}</span>
                  </div>
                  <div class="email">{{ row.email }}</div>
                </div>
              </div>
            </template>
          </el-table-column>

          <el-table-column :label="t('角色')" width="150">
            <template #default="{ row }">
              <el-select
                v-model="row.role"
                size="small"
                :disabled="row.email === auth.email"
                @change="() => changeRole(row)"
              >
                <el-option :label="t('管理员')" value="admin" />
                <el-option :label="t('成员')" value="member" />
              </el-select>
            </template>
          </el-table-column>

          <el-table-column :label="t('状态')" width="110">
            <template #default="{ row }">
              <span class="status" :class="row.is_active ? 'on' : 'off'">
                <span class="dot" />
                {{ row.is_active ? t('启用') : t('已停用') }}
              </span>
            </template>
          </el-table-column>

          <el-table-column :label="t('创建时间')" width="150">
            <template #default="{ row }">
              <span class="created">{{ formatDate(row.created_at) }}</span>
            </template>
          </el-table-column>

          <el-table-column :label="t('操作')" width="110" align="right">
            <template #default="{ row }">
              <el-button
                v-if="row.email !== auth.email"
                link
                :type="row.is_active ? 'danger' : 'primary'"
                @click="toggleActive(row)"
              >
                {{ row.is_active ? t('停用') : t('启用') }}
              </el-button>
              <span v-else class="muted-action">—</span>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </main>

    <el-dialog v-model="dialogVisible" :title="t('新建用户')" width="480px" destroy-on-close>
      <el-form label-position="top" class="create-form">
        <el-form-item :label="t('邮箱')">
          <el-input v-model="form.email" placeholder="name@company.local" autocomplete="off" />
        </el-form-item>
        <el-form-item :label="t('姓名')">
          <el-input v-model="form.full_name" :placeholder="t('如：张三')" autocomplete="off" />
        </el-form-item>
        <el-form-item :label="t('初始密码')">
          <el-input v-model="form.password" type="password" show-password :placeholder="t('至少 8 位')" autocomplete="new-password" />
        </el-form-item>
        <el-form-item :label="t('角色（可选项如下）')">
          <el-radio-group v-model="form.role" class="role-list">
            <el-radio
              v-for="r in ROLE_OPTIONS"
              :key="r.value"
              :value="r.value"
              class="role-card"
              :class="{ 'is-active': form.role === r.value }"
            >
              <span class="role-card__name">{{ r.label }}</span>
              <span class="role-card__desc">{{ r.desc }}</span>
            </el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="dialog-footer">
          <span class="dialog-hint">{{ t('创建后可用该账号登录；成员仅日常使用，管理员可管理配置、数据源与成员。') }}</span>
          <div class="dialog-actions">
            <el-button @click="dialogVisible = false">{{ t('取消') }}</el-button>
            <el-button type="primary" :loading="saving" @click="create">{{ t('创建') }}</el-button>
          </div>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { Plus } from 'lucide-vue-next'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { parseApiError } from '../api/client'
import { useAuthStore } from '../stores/auth'
import type { UserItem } from '../api/types'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const auth = useAuthStore()
const users = ref<UserItem[]>([])
const loading = ref(false)
const saving = ref(false)
const search = ref('')
const dialogVisible = ref(false)
const form = reactive({ email: '', full_name: '', password: '', role: 'member' as 'admin' | 'member' })

/** 可选角色清单：与后端 users.VALID_ROLES 保持一致，明确告知可选择的角色及其权限 */
const ROLE_OPTIONS: { value: 'admin' | 'member'; label: string; desc: string }[] = [
  { value: 'member', label: t('成员'), desc: t('日常使用对话与业务能力，可查询数据；不能修改配置或管理成员。') },
  { value: 'admin', label: t('管理员'), desc: t('拥有成员的全部权限，并管理设置、数据源、能力与成员账号。') },
]

const filteredUsers = computed(() => {
  const q = search.value.trim().toLowerCase()
  if (!q) return users.value
  return users.value.filter(
    (u) => u.email.toLowerCase().includes(q) || (u.full_name || '').toLowerCase().includes(q),
  )
})

function initials(row: UserItem) {
  const source = row.full_name || row.email
  return source.slice(0, 1).toUpperCase()
}

function formatDate(value: string) {
  return new Date(value).toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' })
}

async function load() {
  loading.value = true
  try {
    users.value = await api.users()
  } catch (e) {
    ElMessage.error(parseApiError(e))
  } finally {
    loading.value = false
  }
}

function openCreate() {
  form.email = ''
  form.full_name = ''
  form.password = ''
  form.role = 'member'
  dialogVisible.value = true
}

async function create() {
  if (!form.email.trim() || !form.password) {
    ElMessage.warning(t('请填写邮箱和初始密码'))
    return
  }
  if (form.password.length < 8) {
    ElMessage.warning(t('初始密码至少 8 位'))
    return
  }
  saving.value = true
  try {
    await api.createUser({
      email: form.email.trim(),
      password: form.password,
      full_name: form.full_name.trim(),
      role: form.role,
    })
    ElMessage.success(t('用户已创建'))
    dialogVisible.value = false
    await load()
  } catch (e) {
    ElMessage.error(parseApiError(e))
  } finally {
    saving.value = false
  }
}

async function changeRole(row: UserItem) {
  try {
    await api.updateUser(row.id, { role: row.role })
    ElMessage.success(t('角色已更新'))
  } catch (e) {
    await load()
    ElMessage.error(parseApiError(e))
  }
}

async function toggleActive(row: UserItem) {
  try {
    if (row.is_active) {
      await api.deactivateUser(row.id)
    } else {
      await api.updateUser(row.id, { is_active: true })
    }
    ElMessage.success(row.is_active ? t('已停用') : t('已启用'))
    await load()
  } catch (e) {
    ElMessage.error(parseApiError(e))
  }
}


onMounted(load)
</script>

<style scoped>
.page {
  min-height: 100%;
  height: 100%;
  background: var(--pod-bg);
  display: flex;
  flex-direction: column;
}
.topbar {
  display: flex;
  align-items: center;
  gap: 12px;
  height: 52px;
  padding: 0 24px;
  background: var(--pod-bg-soft);
  border-bottom: 1px solid var(--pod-border);
  flex-shrink: 0;
}
.brand {
  font-size: 15px;
  font-weight: 600;
  cursor: pointer;
  color: var(--pod-text);
}
.back {
  cursor: pointer;
  color: var(--pod-text-dim);
}
.crumb {
  font-size: var(--pod-size-md);
  color: var(--pod-text-dim);
}
.content {
  flex: 1;
  overflow-y: auto;
  padding: 28px 32px;
}
.toolbar {
  max-width: 960px;
  margin: 0 auto 20px;
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 24px;
}
.heading h1 {
  margin: 0 0 6px;
  font-size: 18px;
  font-weight: 600;
  color: var(--pod-text);
  text-wrap: balance;
}
.heading p {
  margin: 0;
  font-size: var(--pod-size-sm);
  color: var(--pod-text-faint);
  max-width: 52ch;
  line-height: 1.5;
}
.actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
}
.search {
  width: 240px;
}
.search-icon {
  color: var(--pod-text-faint);
  font-size: 15px;
  line-height: 1;
}
.table-panel {
  max-width: 960px;
  margin: 0 auto;
  background: var(--pod-bg-elev);
  border: 1px solid var(--pod-border);
  border-radius: var(--pod-radius);
  overflow: hidden;
}
.user-cell {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 0;
}
.avatar {
  width: 32px;
  height: 32px;
  border-radius: var(--pod-radius-sm);
  background: var(--pod-bg-soft);
  color: var(--pod-text-dim);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
  font-weight: 600;
  flex-shrink: 0;
}
.avatar.self {
  background: var(--pod-accent-soft);
  color: var(--pod-accent);
}
.user-meta {
  min-width: 0;
}
.name {
  font-size: var(--pod-size-md);
  color: var(--pod-text);
  font-weight: 500;
  display: flex;
  align-items: center;
  gap: 6px;
}
.self-label {
  font-size: 11px;
  color: var(--pod-accent);
  background: var(--pod-accent-soft);
  border-radius: var(--pod-radius-sm);
  padding: 1px 5px;
}
.email {
  font-size: var(--pod-size-sm);
  color: var(--pod-text-faint);
  margin-top: 2px;
}
.status {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: var(--pod-size-sm);
}
.dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
}
.status.on {
  color: var(--pod-success);
}
.status.off {
  color: var(--pod-danger);
}
.created {
  font-size: var(--pod-size-sm);
  color: var(--pod-text-dim);
}
.muted-action {
  color: var(--pod-text-faint);
}
.empty-state {
  padding: 48px 16px;
  text-align: center;
}
.empty-title {
  font-size: var(--pod-size-md);
  color: var(--pod-text);
  font-weight: 500;
}
.empty-desc {
  margin: 6px 0 16px;
  font-size: var(--pod-size-sm);
  color: var(--pod-text-faint);
}
.create-form {
  padding: 4px 4px 0;
}
.role-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  width: 100%;
}
.role-list .el-radio {
  height: auto;
  margin-right: 0;
}
.role-card {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  width: 100%;
  padding: 10px 12px;
  border: 1px solid var(--pod-border);
  border-radius: var(--pod-radius);
  background: var(--pod-bg-soft);
  cursor: pointer;
  transition: border-color 0.15s ease, background 0.15s ease;
  box-sizing: border-box;
}
.role-card:hover {
  border-color: var(--pod-accent);
}
.role-card.is-active {
  border-color: var(--pod-accent);
  background: var(--pod-accent-soft);
}
.role-card .el-radio__label {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
  white-space: normal;
  line-height: 1.4;
}
.role-card__name {
  font-size: var(--pod-size-md);
  font-weight: 500;
  color: var(--pod-text);
}
.role-card__desc {
  font-size: var(--pod-size-sm);
  color: var(--pod-text-dim);
  line-height: 1.5;
  white-space: normal;
}
.dialog-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.dialog-hint {
  font-size: var(--pod-size-sm);
  color: var(--pod-text-faint);
  max-width: 32ch;
  text-align: left;
}
.dialog-actions {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}

@media (max-width: 720px) {
  .toolbar {
    flex-direction: column;
    align-items: stretch;
  }
  .actions {
    width: 100%;
  }
  .search {
    flex: 1;
    width: auto;
  }
}
</style>
