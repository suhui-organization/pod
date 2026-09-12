<template>
  <div class="rules">
    <div class="head">
      <div class="head__title">
        <h2>{{ t('规则包') }}</h2>
        <p class="head__meta">
          {{ t('订阅式加固：把新的对抗知识（注入词表、钩子风险模式、供应链指纹）作为已签名的包下发给机器。') }}
        </p>
      </div>
      <div v-if="canEdit" class="head__actions">
        <el-button @click="openPublish()">
          <Plus :size="15" aria-hidden="true" />{{ t('发布规则包') }}
        </el-button>
      </div>
    </div>

    <el-alert type="info" :closable="false" show-icon class="hint"
      :title="t('云端只负责存与分发，不做判定：机器拉取后由本地 pod 验签 + 过放宽守卫才生效。放宽已有规则的包默认会被本地拒绝。')" />

    <el-card shadow="never" class="cmd">
      <div class="cmd__label">{{ t('机器侧拉取（用接入时的同一份 sync token）') }}</div>
      <code class="cmd__code">pod rules pull --from-cloud</code>
      <div class="cmd__note">
        {{ t('公钥需在机器的 ~/.pod/cloud.json 里配 rules_public_key（或 policy_public_key）——公钥不与包同路，否则验签形同虚设。') }}
      </div>
    </el-card>

    <p v-if="!canEdit" class="readonly">
      <Info :size="14" aria-hidden="true" />
      {{ t('你是只读成员：可以查看下发过的版本；发布与撤回需要管理员权限。') }}
    </p>

    <div v-if="error" class="state state--error">
      <p>{{ error }}</p>
      <el-button size="small" @click="load()">{{ t('重试') }}</el-button>
    </div>
    <div v-else-if="loading" class="state" aria-busy="true">
      <el-skeleton :rows="3" animated />
    </div>
    <template v-else>
      <el-table :data="rows" stripe style="width: 100%">
        <el-table-column :label="t('版本')" width="160">
          <template #default="{ row }">
            <span class="ver">{{ row.pack_version }}</span>
            <el-tag v-if="row.active" size="small" type="success" effect="dark" class="active-tag">
              {{ t('生效中') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="issued_by" :label="t('签发者')" width="140" />
        <el-table-column :label="t('说明')" min-width="220">
          <template #default="{ row }">
            <span class="note">{{ row.note || '—' }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('发布时间')" width="180">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column :label="t('操作')" width="200">
          <template #default="{ row }">
            <el-button size="small" @click="openDetail(row)">{{ t('查看') }}</el-button>
            <el-button
              v-if="canEdit && !row.active"
              size="small"
              type="primary"
              plain
              @click="activate(row)"
            >{{ t('撤回至此版本') }}</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-empty v-if="!rows.length" :description="t('还没有发布过规则包：机器侧 pod rules pull 会拿到 404。')" />
    </template>

    <el-dialog v-model="publishOpen" :title="t('发布规则包')" width="640">
      <p class="dialog-hint">
        {{ t('把签发好的整包 JSON 粘进来（含 signature）。签发在本机用 pod rules pack 完成——私钥不离开你的机器。') }}
      </p>
      <el-input v-model="draftJson" type="textarea" :rows="12" spellcheck="false"
        :placeholder="t('{\n  &quot;schema&quot;: &quot;pod-rules-pack/v1&quot;,\n  &quot;packVersion&quot;: &quot;2026.09.12&quot;,\n  &quot;signature&quot;: &quot;...&quot;\n}')" />
      <el-input v-model="draftNote" class="note-input" :placeholder="t('说明（可选，写给未来的自己）')" />
      <p v-if="draftError" class="dialog-error">{{ draftError }}</p>
      <template #footer>
        <el-button @click="publishOpen = false">{{ t('取消') }}</el-button>
        <el-button type="primary" :loading="saving" @click="publish()">{{ t('发布并生效') }}</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="detailOpen" :title="t('规则包内容')" width="720">
      <pre class="detail">{{ detailJson }}</pre>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Info, Plus } from 'lucide-vue-next'
import { api } from '../api'
import { parseApiError } from '../api/client'
import type { RulePackItem } from '../api/types'
import { useAuthStore } from '../stores/auth'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
const auth = useAuthStore()
const canEdit = computed(() => auth.isAdmin)

const rows = ref<RulePackItem[]>([])
const loading = ref(false)
const error = ref('')

const publishOpen = ref(false)
const detailOpen = ref(false)
const draftJson = ref('')
const draftNote = ref('')
const draftError = ref('')
const saving = ref(false)
const detailJson = ref('')

function fmtTime(ts: string): string {
  if (!ts) return '—'
  const d = new Date(ts)
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString()
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    rows.value = (await api.rulePacks()).packs
  } catch (e) {
    error.value = parseApiError(e)
  } finally {
    loading.value = false
  }
}

function openPublish() {
  draftJson.value = ''
  draftNote.value = ''
  draftError.value = ''
  publishOpen.value = true
}

function openDetail(row: RulePackItem) {
  detailJson.value = pretty(row.pack_json)
  detailOpen.value = true
}

function pretty(json: string): string {
  try {
    return JSON.stringify(JSON.parse(json), null, 2)
  } catch {
    return json
  }
}

/** 发布前本地先做一次结构检查：让错误当场出现，而不是等服务端 400 */
function localCheck(json: string): string {
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch (e) {
    return t('不是合法 JSON：{err}', { err: e instanceof Error ? e.message : String(e) })
  }
  if (typeof parsed !== 'object' || parsed === null) return t('规则包必须是 JSON 对象')
  const obj = parsed as Record<string, unknown>
  if (obj.schema !== 'pod-rules-pack/v1') return t('schema 必须是 pod-rules-pack/v1')
  if (!obj.signature) return t('缺少 signature：请先用 pod rules pack 签发')
  return ''
}

async function publish() {
  draftError.value = localCheck(draftJson.value)
  if (draftError.value) return
  saving.value = true
  try {
    const res = await api.publishRulePack({ pack_json: draftJson.value, note: draftNote.value })
    ElMessage.success(t('已发布并生效：{v}', { v: res.pack.pack_version }))
    publishOpen.value = false
    await load()
  } catch (e) {
    draftError.value = parseApiError(e)
  } finally {
    saving.value = false
  }
}

async function activate(row: RulePackItem) {
  await ElMessageBox.confirm(
    t('将 {v} 设为生效版本？机器下次拉取时会换成这一版（本地仍会验签 + 过放宽守卫）。', { v: row.pack_version }),
    t('撤回确认'),
    { confirmButtonText: t('撤回至此版本'), cancelButtonText: t('取消') },
  )
  try {
    await api.activateRulePack(row.id)
    ElMessage.success(t('已切回 {v}', { v: row.pack_version }))
    await load()
  } catch (e) {
    ElMessage.error(parseApiError(e))
  }
}

onMounted(load)
</script>

<style scoped>
.head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 16px;
}
.head__title h2 {
  margin: 0 0 4px;
}
.head__meta {
  margin: 0;
  color: var(--el-text-color-secondary);
  font-size: 13px;
}
.hint {
  margin-bottom: 12px;
}
.cmd {
  margin-bottom: 16px;
}
.cmd__label {
  font-size: 13px;
  color: var(--el-text-color-secondary);
  margin-bottom: 6px;
}
.cmd__code {
  display: inline-block;
  padding: 6px 10px;
  background: var(--el-fill-color-light);
  border-radius: 4px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 13px;
}
.cmd__note {
  margin-top: 8px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.readonly {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--el-text-color-secondary);
  font-size: 13px;
}
.state {
  padding: 24px 0;
}
.state--error {
  color: var(--el-color-danger);
}
.ver {
  font-weight: 600;
}
.active-tag {
  margin-left: 8px;
}
.note,
.detail {
  font-size: 12px;
}
.detail {
  max-height: 420px;
  overflow: auto;
  background: var(--el-fill-color-light);
  padding: 12px;
  border-radius: 4px;
  white-space: pre-wrap;
  word-break: break-all;
}
.dialog-hint {
  margin: 0 0 8px;
  font-size: 13px;
  color: var(--el-text-color-secondary);
}
.note-input {
  margin-top: 8px;
}
.dialog-error {
  margin: 8px 0 0;
  color: var(--el-color-danger);
  font-size: 13px;
}
</style>
