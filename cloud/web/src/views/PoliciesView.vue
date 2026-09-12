<template>
  <div class="pol">
    <div class="head">
      <div class="head__title">
        <h2>策略中心</h2>
        <p class="head__meta">
          网关同构 JSON · deny &gt; approve &gt; allow · 未登记的 server 与工具一律拒绝
        </p>
      </div>
      <div v-if="canEdit" class="head__actions">
        <el-button @click="openAi">
          <Sparkles :size="15" aria-hidden="true" />AI 生成策略
        </el-button>
        <el-button type="primary" @click="openEdit()">
          <Plus :size="15" aria-hidden="true" />新建策略
        </el-button>
      </div>
    </div>

    <p v-if="!canEdit" class="readonly">
      <Info :size="14" aria-hidden="true" />
      你是只读成员：可以查看策略内容、适用范围与修改历史；编辑需要管理员权限。
    </p>

    <div v-if="error" class="state state--error">
      <p>{{ error }}</p>
      <el-button size="small" @click="load()">重试</el-button>
    </div>

    <div v-else-if="loading" class="state" aria-busy="true" aria-label="正在读取策略">
      <el-skeleton :rows="3" animated />
    </div>

    <template v-else>
      <section v-if="rows.length" class="list" aria-label="策略列表">
        <div class="list__head" aria-hidden="true">
          <span>策略 / 适用范围</span>
          <span>决策姿态</span>
          <span>工具规则</span>
          <span>密钥防线</span>
          <span>版本</span>
          <span>操作</span>
        </div>

        <article v-for="row in rows" :key="row.id" class="pr">
          <div class="cell pr__main">
            <span class="cell__k">策略</span>
            <div class="pr__name">{{ row.name }}</div>
            <div class="pr__scope">
              <ShieldCheck :size="13" aria-hidden="true" />
              {{ row.scope }}
            </div>
            <p v-if="row.note" class="pr__note">{{ row.note }}</p>
          </div>

          <div class="cell pr__posture">
            <span class="cell__k">决策姿态</span>
            <span class="badge" :class="`badge--${row.posture.tone}`">{{ row.posture.label }}</span>
            <p class="pr__why">{{ row.posture.note }}</p>
          </div>

          <div class="cell pr__rules">
            <span class="cell__k">工具规则</span>
            <p class="pr__counts">
              <span>放行 <b>{{ row.summary.allow }}</b></span>
              <span>审批 <b>{{ row.summary.approve }}</b></span>
              <span>拒绝 <b>{{ row.summary.deny }}</b></span>
            </p>
            <p class="pr__sub">
              {{ row.summary.servers.length }} 个 server · 默认
              <code>{{ row.summary.defaultDecision }}</code>
            </p>
          </div>

          <div class="cell pr__guard">
            <span class="cell__k">密钥防线</span>
            <p class="pr__counts">
              <span v-if="row.summary.secretPaths">敏感路径 <b>{{ row.summary.secretPaths }}</b></span>
              <span v-if="row.summary.secretPatterns">密钥模式 <b>{{ row.summary.secretPatterns }}</b></span>
              <span v-if="!row.summary.secretPaths && !row.summary.secretPatterns" class="muted">未登记</span>
            </p>
            <p class="pr__sub">熵检测 {{ row.summary.entropy ? '已开启' : '未开启' }}</p>
          </div>

          <div class="cell pr__version">
            <span class="cell__k">版本</span>
            <p class="pr__v">v{{ row.version }}</p>
            <p class="pr__sub">{{ formatTime(row.created_at) }}</p>
          </div>

          <div class="cell pr__actions">
            <button
              class="link"
              type="button"
              :aria-expanded="expandedId === row.id"
              :aria-controls="`policy-detail-${row.id}`"
              @click="toggleDetail(row.id)"
            >
              {{ expandedId === row.id ? '收起' : '明细' }}
            </button>
            <!-- 历史是读操作，后端 GET 对成员开放：只读成员也要能核对"谁在什么时候改了什么" -->
            <button class="link" type="button" @click="openHistory(row.raw)">历史</button>
            <template v-if="canEdit">
              <button class="link" type="button" @click="openEdit(row.raw)">编辑</button>
              <el-popconfirm
                title="删除后网关将回落到默认拒绝，确认删除？"
                confirm-button-text="删除"
                cancel-button-text="取消"
                @confirm="remove(row.raw)"
              >
                <template #reference>
                  <button class="link link--danger" type="button">删除</button>
                </template>
              </el-popconfirm>
            </template>
          </div>

          <div v-if="expandedId === row.id" :id="`policy-detail-${row.id}`" class="pr__detail">
            <div v-if="!row.summary.readable" class="detail__broken">
              这份策略不是合法 JSON（{{ row.summary.reason }}），无法展示明细。
              网关侧按默认拒绝处理，建议用「编辑」修正后保存。
            </div>
            <template v-else>
              <div v-if="!row.summary.servers.length" class="detail__broken">
                没有登记任何 server —— 所有调用都会落到默认拒绝（fail-closed）。
              </div>
              <div v-for="srv in row.summary.servers" :key="srv.name" class="srv">
                <div class="srv__head">
                  <code class="srv__name">{{ srv.name }}</code>
                  <span v-if="srv.source" class="srv__src">{{ srv.source }}</span>
                  <span v-if="srv.sourceUnpinned" class="srv__warn">未锁版本</span>
                  <span v-if="!srv.source" class="srv__warn">未声明启动来源</span>
                </div>
                <div class="srv__rules">
                  <div v-if="srv.allowedTools.length" class="srv__group">
                    <span class="srv__k">放行 {{ srv.allowedTools.length }}</span>
                    <span class="chip-list">
                      <code v-for="t in srv.allowedTools" :key="t" class="chip chip--allow">{{ t }}</code>
                    </span>
                  </div>
                  <div v-if="srv.approvedTools.length" class="srv__group">
                    <span class="srv__k">审批 {{ srv.approvedTools.length }}</span>
                    <span class="chip-list">
                      <code v-for="t in srv.approvedTools" :key="t" class="chip chip--approve">{{ t }}</code>
                    </span>
                  </div>
                  <div v-if="srv.deniedTools.length" class="srv__group">
                    <span class="srv__k">拒绝 {{ srv.deniedTools.length }}</span>
                    <span class="chip-list">
                      <code v-for="t in srv.deniedTools" :key="t" class="chip chip--deny">{{ t }}</code>
                    </span>
                  </div>
                </div>
              </div>
            </template>
          </div>
        </article>
      </section>

      <div v-else class="state empty">
        <p class="empty__title">还没有策略</p>
        <p class="empty__body">
          网关对未登记的工具一律拒绝，所以这里为空时，agent 的调用都会被挡下。
          <template v-if="canEdit">
            从模板开始最省事——模板是一份写好的策略 JSON，应用后可以直接改。
          </template>
          <template v-else> 让管理员从模板或 AI 生成一份。 </template>
        </p>
        <el-button v-if="canEdit" type="primary" @click="openTemplates">从模板开始</el-button>
      </div>

      <section v-if="canEdit" class="tpl">
        <button
          class="tpl__toggle"
          type="button"
          :aria-expanded="tplOpen"
          aria-controls="template-panel"
          @click="tplOpen = !tplOpen"
        >
          <ChevronRight
            :size="15"
            class="tpl__caret"
            :class="{ 'tpl__caret--open': tplOpen }"
            aria-hidden="true"
          />
          从模板开始
          <span class="tpl__hint">一键生成一份可改的策略，覆盖目标现有的整份策略</span>
        </button>

        <div v-if="tplOpen" id="template-panel" class="tpl__body">
          <div class="tpl__target">
            <label for="tpl-agent">应用到</label>
            <el-select
              id="tpl-agent"
              v-model="tplAgent"
              clearable
              placeholder="租户模板（全部 Agent）"
              class="tpl__select"
            >
              <el-option
                v-for="a in agents"
                :key="a.id"
                :label="`仅 ${a.name}（#${a.id}）`"
                :value="a.id"
              />
            </el-select>
            <span class="tpl__danger">应用会覆盖目标现有的整份策略，且立即影响网关行为。</span>
          </div>

          <div class="tpl__grid">
            <button
              v-for="t in templates"
              :key="t.id"
              type="button"
              class="tpl__item"
              :class="{ 'tpl__item--active': tplPick === t.id }"
              :aria-pressed="tplPick === t.id"
              @click="tplPick = t.id"
            >
              <span class="tpl__name">{{ t.name }}</span>
              <span class="tpl__desc">{{ t.desc }}</span>
              <span class="tpl__stats">
                <span
                  class="badge badge--mini"
                  :class="t.default_decision === 'deny' ? 'badge--strict' : 'badge--loose'"
                >
                  默认 {{ t.default_decision }}
                </span>
                <span class="tpl__stat">拒绝 {{ t.deny.length }} 条</span>
                <span class="tpl__stat">敏感路径 {{ t.sensitive_paths }} 条</span>
              </span>
            </button>
          </div>

          <div class="tpl__actions">
            <el-popconfirm
              :title="`将覆盖${tplAgent ? '该 Agent' : '租户模板'}的现有策略，确认应用？`"
              confirm-button-text="应用"
              cancel-button-text="取消"
              :disabled="!tplPick"
              @confirm="applyTemplate"
            >
              <template #reference>
                <el-button type="primary" :disabled="!tplPick">应用模板</el-button>
              </template>
            </el-popconfirm>
          </div>
        </div>
      </section>
    </template>

    <el-dialog v-model="histOpen" :title="historyTitle" width="880px" class="hist-dialog">
      <div class="hist">
        <div class="hist__versions" role="list">
          <button
            v-for="v in histVersions"
            :key="v.version"
            type="button"
            role="listitem"
            class="ver"
            :class="{ 'ver--active': histPickVersion === v.version }"
            @click="pickHistVersion(v)"
          >
            <span class="ver__no">v{{ v.version }}</span>
            <span class="ver__time">{{ formatTime(v.created_at) }}</span>
            <span class="ver__note">{{ v.note || '（无备注）' }}</span>
          </button>
        </div>

        <div class="hist__diff">
          <template v-if="histDiff.length">
            <div class="diff__head">
              <span class="diff__legend diff__legend--del">
                − 当前 v{{ histCurrent }} 有、目标版本没有
              </span>
              <span class="diff__legend diff__legend--add">+ 目标版本 v{{ histPickVersion }} 新增</span>
            </div>
            <pre class="diff"><span
              v-for="(l, idx) in histDiff"
              :key="idx"
              :class="`diff__line diff__line--${l.type}`"
            >{{ l.type === 'add' ? '+' : l.type === 'del' ? '−' : ' ' }} {{ l.text }}
</span></pre>
          </template>
          <p v-else class="hist__placeholder">选择左侧任一版本，查看它与当前版本的逐行差异。</p>
        </div>
      </div>

      <template v-if="canEdit" #footer>
        <span class="hist__foot-hint">回滚会把目标版本写成新版本，原内容保留在历史里。</span>
        <el-popconfirm
          :title="`确认回滚到 v${histPickVersion}？网关行为将随之改变。`"
          confirm-button-text="回滚"
          cancel-button-text="取消"
          :disabled="!histPickVersion"
          @confirm="revertPolicy"
        >
          <template #reference>
            <el-button type="danger" :disabled="!histPickVersion">
              回滚到 v{{ histPickVersion || '—' }}
            </el-button>
          </template>
        </el-popconfirm>
      </template>
    </el-dialog>

    <el-dialog v-model="aiOpen" title="AI 生成策略" width="720px">
      <p class="dlg__lead">
        用一句话描述你的安全要求，生成一份策略 JSON 草稿。草稿不会自动生效——核对后点「保存策略」才会写入，
        保存动作进审计。
      </p>
      <AiNotice v-if="aiConfigIssue" :message="aiConfigIssue" />
      <el-input
        v-model="aiDesc"
        type="textarea"
        :rows="3"
        placeholder="例如：禁止 agent 访问生产服务器、密钥文件和任何删除操作；日常读写需要审批"
      />

      <template v-if="aiResult">
        <div class="preview">
          <div class="preview__head">
            <span class="badge" :class="`badge--${aiPreview.posture.tone}`">
              {{ aiPreview.posture.label }}
            </span>
            <span class="preview__why">{{ aiPreview.posture.note }}</span>
          </div>
          <p class="preview__counts">
            <span>放行 <b>{{ aiPreview.summary.allow }}</b></span>
            <span>审批 <b>{{ aiPreview.summary.approve }}</b></span>
            <span>拒绝 <b>{{ aiPreview.summary.deny }}</b></span>
            <span>敏感路径 <b>{{ aiPreview.summary.secretPaths }}</b></span>
            <span>密钥模式 <b>{{ aiPreview.summary.secretPatterns }}</b></span>
          </p>
        </div>

        <div v-if="aiExplanation" class="preview__explain">
          <span class="preview__explain-k">设计说明</span>
          <p>{{ aiExplanation }}</p>
        </div>

        <button
          class="disclose"
          type="button"
          :aria-expanded="aiJsonOpen"
          @click="aiJsonOpen = !aiJsonOpen"
        >
          {{ aiJsonOpen ? '收起 JSON' : '查看和修改 JSON' }}
        </button>
        <el-input v-if="aiJsonOpen" v-model="aiPolicyJson" type="textarea" :rows="14" class="mono" />
      </template>

      <template #footer>
        <el-button v-if="aiResult" :loading="aiGenLoading" @click="genPolicy">重新生成</el-button>
        <el-button v-else :loading="aiGenLoading" @click="genPolicy">生成草稿</el-button>
        <el-button type="primary" :disabled="!aiResult" :loading="aiSaving" @click="saveAiPolicy">
          保存策略
        </el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="editOpen" :title="editing ? '编辑策略' : '新建策略'" width="680px">
      <el-form label-width="84px">
        <el-form-item label="名称">
          <el-input v-model="form.name" placeholder="如：claude-code 生产只读" />
        </el-form-item>
        <el-form-item label="绑定 Agent">
          <el-select
            v-model="form.agent_id"
            clearable
            placeholder="租户模板（全部 Agent）"
            class="form__select"
          >
            <el-option
              v-for="a in agents"
              :key="a.id"
              :label="`仅 ${a.name}（#${a.id}）`"
              :value="a.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="备注">
          <el-input
            v-model="form.note"
            type="textarea"
            :rows="2"
            placeholder="记下这份策略为什么这么设——半年后你会需要它"
          />
        </el-form-item>
        <el-form-item label="策略 JSON">
          <el-input v-model="form.policy_json" type="textarea" :rows="12" class="mono" />
        </el-form-item>
      </el-form>

      <div class="preview preview--form">
        <div class="preview__head">
          <span class="badge" :class="`badge--${formPreview.posture.tone}`">
            {{ formPreview.posture.label }}
          </span>
          <span class="preview__why">{{ formPreview.posture.note }}</span>
        </div>
        <p class="preview__counts">
          <span>放行 <b>{{ formPreview.summary.allow }}</b></span>
          <span>审批 <b>{{ formPreview.summary.approve }}</b></span>
          <span>拒绝 <b>{{ formPreview.summary.deny }}</b></span>
          <span>{{ formPreview.summary.servers.length }} 个 server</span>
        </p>
      </div>

      <template #footer>
        <el-button @click="editOpen = false">取消</el-button>
        <el-button type="primary" @click="save">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { ChevronRight, Info, Plus, ShieldCheck, Sparkles } from 'lucide-vue-next'
import { api } from '../api'
import { parseApiError } from '../api/client'
import type { AgentItem, PolicyItem } from '../api/types'
import AiNotice from '../components/AiNotice.vue'
import { useAiStore } from '../stores/ai'
import { useAuthStore } from '../stores/auth'
import { diffLines, type DiffLine } from '../utils/diff'
import { policyPosture, summarizePolicy } from '../utils/policySummary'

interface TemplateItem {
  id: string
  name: string
  desc: string
  default_decision: string
  allow: string[]
  deny: string[]
  approve: string[]
  sensitive_paths: number
}

const auth = useAuthStore()
const ai = useAiStore()
/** 只读成员看同一页，写操作整块隐藏——不留点不动的按钮 */
const canEdit = computed(() => auth.isAdmin)

const policies = ref<PolicyItem[]>([])
const agents = ref<AgentItem[]>([])
const templates = ref<TemplateItem[]>([])
const loading = ref(true)
const error = ref('')
const expandedId = ref<number | null>(null)

const agentName = computed(() => new Map(agents.value.map((a) => [a.id, a.name])))

/** 列表行 = 原始记录 + 语义摘要 + 姿态判断（模板里不再做任何计算） */
const rows = computed(() =>
  policies.value.map((p) => {
    const summary = summarizePolicy(p.policy_json)
    return {
      id: p.id,
      raw: p,
      name: p.name,
      note: p.note,
      version: p.version,
      created_at: p.created_at,
      scope:
        p.agent_id === null
          ? '租户模板 · 适用于全部 Agent'
          : `仅 ${agentName.value.get(p.agent_id) ?? `#${p.agent_id}`}`,
      summary,
      posture: policyPosture(summary),
    }
  }),
)

function formatTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function toggleDetail(id: number) {
  expandedId.value = expandedId.value === id ? null : id
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [p, a] = await Promise.all([api.policies(), api.agents()])
    policies.value = p.policies
    agents.value = a.agents
    // 模板只用于写操作，只读成员不必拉
    if (canEdit.value) templates.value = (await api.policyTemplates()).templates
  } catch (e) {
    error.value = parseApiError(e)
  } finally {
    loading.value = false
  }
}

/* ---------- 模板 ---------- */
const tplOpen = ref(false)
const tplPick = ref<string | null>(null)
const tplAgent = ref<number | null>(null)

function openTemplates() {
  tplOpen.value = true
}

async function applyTemplate() {
  if (!tplPick.value) return
  try {
    await api.applyPolicyTemplate(tplPick.value, tplAgent.value ?? null)
    ElMessage.success('模板已应用；网关侧 pod pull-policy 拉取后生效')
    tplPick.value = null
    await load()
  } catch (e) {
    ElMessage.error(parseApiError(e))
  }
}

/* ---------- 新建 / 编辑 ---------- */
const editOpen = ref(false)
const editing = ref<PolicyItem | null>(null)
const form = ref({ name: '', agent_id: null as number | null, policy_json: '', note: '' })

const TEMPLATE = JSON.stringify(
  {
    version: '0.1.0',
    defaultDecision: 'deny',
    servers: {
      filesystem: {
        allow: ['read_file', 'list_directory'],
        approve: ['write_file'],
        deny: ['delete_file'],
      },
    },
  },
  null,
  2,
)

const formSummary = computed(() => summarizePolicy(form.value.policy_json))
const formPreview = computed(() => ({
  summary: formSummary.value,
  posture: policyPosture(formSummary.value),
}))

function openEdit(row?: PolicyItem) {
  editing.value = row ?? null
  form.value = row
    ? { name: row.name, agent_id: row.agent_id, policy_json: row.policy_json, note: row.note ?? '' }
    : { name: '', agent_id: null, policy_json: TEMPLATE, note: '' }
  editOpen.value = true
}

async function save() {
  if (!form.value.name.trim()) return ElMessage.warning('请填写名称')
  let parsed: unknown
  try {
    parsed = JSON.parse(form.value.policy_json)
  } catch (e) {
    return ElMessage.error(`策略 JSON 不是合法 JSON：${e instanceof Error ? e.message : ''}`)
  }
  const body = {
    ...form.value,
    name: form.value.name.trim(),
    policy_json: JSON.stringify(parsed, null, 2),
  }
  try {
    if (editing.value) await api.updatePolicy(editing.value.id, body)
    else await api.createPolicy(body)
    editOpen.value = false
    ElMessage.success('已保存')
    await load()
  } catch (e) {
    ElMessage.error(parseApiError(e))
  }
}

async function remove(row: PolicyItem) {
  try {
    await api.deletePolicy(row.id)
    ElMessage.success('已删除')
    await load()
  } catch (e) {
    ElMessage.error(parseApiError(e))
  }
}

/* ---------- AI 生成 ---------- */
const aiOpen = ref(false)
const aiDesc = ref('')
const aiResult = ref(false)
const aiGenLoading = ref(false)
const aiSaving = ref(false)
const aiJsonOpen = ref(false)
const aiPolicyJson = ref('')
const aiExplanation = ref('')
/** 模型未配置时的文案：留在对话框里（带跳转），不要只闪一条 toast */
const aiConfigIssue = ref('')

const aiSummary = computed(() => summarizePolicy(aiPolicyJson.value))
const aiPreview = computed(() => ({
  summary: aiSummary.value,
  posture: policyPosture(aiSummary.value),
}))

function openAi() {
  // 打开的瞬间就把"没配模型"说清楚，别让用户先写一段需求再被挡
  aiConfigIssue.value = ai.configured ? '' : ai.reason
  aiOpen.value = true
}

async function genPolicy() {
  if (!aiDesc.value.trim()) return ElMessage.warning('请先描述安全需求')
  if (!ai.configured) {
    aiConfigIssue.value = ai.reason
    return
  }
  aiGenLoading.value = true
  aiConfigIssue.value = ''
  try {
    const r = await api.generatePolicy(aiDesc.value.trim())
    aiResult.value = true
    aiPolicyJson.value = r.policy_json
    aiExplanation.value = r.explanation ?? ''
  } catch (e) {
    const msg = parseApiError(e)
    // 400 = 模型还没配好（可能是别处刚把配置清掉）：留在对话框里给一条去配置的路
    if ((e as { response?: { status?: number } })?.response?.status === 400) {
      aiConfigIssue.value = msg
      void ai.refresh()
    } else {
      ElMessage.error(msg)
    }
  } finally {
    aiGenLoading.value = false
  }
}

async function saveAiPolicy() {
  let parsed: unknown
  try {
    parsed = JSON.parse(aiPolicyJson.value)
  } catch {
    return ElMessage.error('策略 JSON 格式错误，请修正后再保存')
  }
  aiSaving.value = true
  try {
    await api.createPolicy({
      name: aiDesc.value.trim().slice(0, 30),
      policy_json: JSON.stringify(parsed, null, 2),
      agent_id: null,
      note: aiExplanation.value || `AI 生成（需求：${aiDesc.value.trim().slice(0, 120)}）`,
    })
    aiOpen.value = false
    aiDesc.value = ''
    aiResult.value = false
    aiJsonOpen.value = false
    aiExplanation.value = ''
    ElMessage.success('策略已保存（含审计记录）')
    await load()
  } catch (e) {
    ElMessage.error(parseApiError(e))
  } finally {
    aiSaving.value = false
  }
}

/* ---------- 历史与差异 ---------- */
const histOpen = ref(false)
const historyTitle = ref('')
const histPolicy = ref<PolicyItem | null>(null)
const histVersions = ref<
  Array<{ version: number; policy_json: string; note: string; created_at: string }>
>([])
const histCurrent = ref('')
const histPickVersion = ref(0)
const histDiff = ref<DiffLine[]>([])

async function openHistory(row: PolicyItem) {
  try {
    const r = await api.policyVersions(row.id)
    histPolicy.value = row
    histVersions.value = r.versions
    histCurrent.value = row.version
    histPickVersion.value = 0
    histDiff.value = []
    historyTitle.value = `策略历史 · ${row.name}`
    histOpen.value = true
  } catch (e) {
    ElMessage.error(parseApiError(e))
  }
}

function pickHistVersion(row: { version: number; policy_json: string }) {
  if (!histPolicy.value) return
  histPickVersion.value = row.version
  histDiff.value = diffLines(pretty(histPolicy.value.policy_json), pretty(row.policy_json))
}

function pretty(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}

async function revertPolicy() {
  if (!histPolicy.value || !histPickVersion.value) return
  try {
    await api.revertPolicy(histPolicy.value.id, histPickVersion.value)
    ElMessage.success(`已回滚到 v${histPickVersion.value}（原内容保留在历史里）`)
    histOpen.value = false
    await load()
  } catch (e) {
    ElMessage.error(parseApiError(e))
  }
}

onMounted(async () => {
  await Promise.all([load(), ai.ensureLoaded()])
})
</script>

<style scoped>
.pol { display: flex; flex-direction: column; gap: 16px; }

.head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
.head h2 { margin: 0; }
.head__meta {
  margin: 4px 0 0; font-size: var(--pod-size-sm, 12px); line-height: 1.6;
  color: var(--pod-text-dim, #9aa3b1);
}
.head__actions { display: flex; flex-wrap: nowrap; gap: 8px; flex-shrink: 0; }
.head__actions :deep(.el-button) { display: inline-flex; align-items: center; gap: 6px; margin-left: 0; }

/* 只读成员：说清权限，不做得像警告 */
.readonly {
  display: flex; align-items: center; gap: 8px; margin: 0;
  padding: 10px 14px; border-radius: 10px;
  font-size: var(--pod-size-md, 13px); color: var(--pod-text-dim, #9aa3b1);
  background: var(--pod-panel-elev, #1c2128);
  border: 1px solid var(--pod-border, rgba(255, 255, 255, 0.07));
}

.state {
  padding: 20px 22px; border-radius: 12px;
  background: var(--pod-panel-bg, #161a1f);
  border: 1px solid var(--pod-border, rgba(255, 255, 255, 0.07));
}
.state--error {
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
  font-size: var(--pod-size-md, 13px); color: var(--pod-text-dim, #9aa3b1);
}
.state--error p { margin: 0; }
.empty__title { margin: 0 0 6px; font-size: 15px; font-weight: 600; color: var(--pod-text, #e6e8ec); }
.empty__body {
  margin: 0 0 14px; max-width: 62ch;
  font-size: var(--pod-size-md, 13px); line-height: 1.7; color: var(--pod-text-dim, #9aa3b1);
}

/* ── 策略列表：台账式网格，宽屏对齐列、窄屏降级成卡片行 ── */
.list { display: flex; flex-direction: column; gap: 8px; }
.list__head,
.pr {
  display: grid;
  grid-template-columns:
    minmax(220px, 1.6fr) minmax(150px, 1.1fr) minmax(150px, 1fr)
    minmax(120px, 0.9fr) 92px auto;
  gap: 10px 18px;
  align-items: start;
}
.list__head {
  padding: 0 18px; font-size: var(--pod-size-sm, 12px); color: var(--pod-text-faint, #6b7280);
}
.list__head > span:last-child { text-align: right; }

.pr {
  padding: 14px 18px; border-radius: 12px;
  background: var(--pod-panel-bg, #161a1f);
  border: 1px solid var(--pod-border, rgba(255, 255, 255, 0.07));
  transition: border-color 150ms ease-out;
}
.pr:hover { border-color: var(--pod-border-strong, rgba(255, 255, 255, 0.12)); }
.cell { min-width: 0; }
.cell__k { display: none; font-size: var(--pod-size-sm, 12px); color: var(--pod-text-faint, #6b7280); }

.pr__name { font-size: 14px; font-weight: 600; overflow-wrap: anywhere; }
.pr__scope {
  display: flex; align-items: center; gap: 5px; margin-top: 4px;
  font-size: var(--pod-size-sm, 12px); color: var(--pod-text-dim, #9aa3b1);
}
.pr__note {
  margin: 6px 0 0; font-size: var(--pod-size-sm, 12px); line-height: 1.6;
  color: var(--pod-text-faint, #6b7280);
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;
}
.pr__why {
  margin: 6px 0 0; font-size: var(--pod-size-sm, 12px); line-height: 1.6;
  color: var(--pod-text-dim, #9aa3b1);
}
.pr__counts {
  display: flex; flex-wrap: wrap; gap: 4px 12px; margin: 0;
  font-size: var(--pod-size-md, 13px); color: var(--pod-text-dim, #9aa3b1);
  font-variant-numeric: tabular-nums;
}
.pr__counts b { color: var(--pod-text, #e6e8ec); font-weight: 600; }
.pr__sub { margin: 4px 0 0; font-size: var(--pod-size-sm, 12px); color: var(--pod-text-faint, #6b7280); }
.pr__sub code { font-family: var(--pod-font-mono); font-size: 11px; }
.pr__v { margin: 0; font-size: var(--pod-size-md, 13px); font-weight: 600; font-variant-numeric: tabular-nums; }
.muted { color: var(--pod-text-faint, #6b7280); }

.pr__actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 4px 12px; }
.link {
  padding: 0; border: 0; background: none; cursor: pointer;
  font: inherit; font-size: var(--pod-size-md, 13px); color: var(--pod-accent, #6ea4f9);
}
.link:hover { color: var(--pod-accent-hover, #8ab1fa); }
.link--danger { color: var(--pod-danger, #cc3e44); }
.link:focus-visible { outline: 2px solid var(--pod-accent, #6ea4f9); outline-offset: 2px; border-radius: 3px; }

/* 决策姿态：颜色 + 文字双通道，不靠颜色单独表意 */
.badge {
  display: inline-block; padding: 2px 9px; border-radius: 999px;
  font-size: var(--pod-size-sm, 12px); font-weight: 600; white-space: nowrap;
}
.badge--mini { padding: 1px 7px; font-weight: 500; }
/* 徽章是这一页的主信号，12px/600 必须在两种主题下都过 4.5:1。
   纯 token 色压在 tint 底上只有 4.0（浅色 accent）/ 3.2（深色 danger），
   所以文字色向正文色混一档：浅色变深、深色变亮，方向由 --pod-text 自动决定。 */
.badge--strict {
  background: var(--pod-accent-soft, rgba(110, 164, 249, 0.14));
  color: color-mix(in srgb, var(--pod-accent, #6ea4f9) 68%, var(--pod-text, #e6e8ec));
}
.badge--balanced {
  background: rgba(227, 121, 51, 0.14);
  color: color-mix(in srgb, var(--pod-warning, #e37933) 64%, var(--pod-text, #e6e8ec));
}
.badge--loose {
  background: rgba(204, 62, 68, 0.14);
  color: color-mix(in srgb, var(--pod-danger, #cc3e44) 60%, var(--pod-text, #e6e8ec));
}
.badge--unreadable {
  background: transparent; color: var(--pod-text-dim, #9aa3b1);
  box-shadow: inset 0 0 0 1px var(--pod-border-strong, rgba(255, 255, 255, 0.12));
}

/* ── 明细：server 逐个摊开，工具名与启动来源都摆出来 ── */
.pr__detail {
  grid-column: 1 / -1; margin-top: 6px; padding-top: 12px;
  border-top: 1px solid var(--pod-divider, rgba(255, 255, 255, 0.05));
  display: flex; flex-direction: column; gap: 12px;
}
.detail__broken {
  padding: 10px 12px; border-radius: 8px; max-width: 82ch;
  font-size: var(--pod-size-sm, 12px); line-height: 1.7;
  color: var(--pod-text-dim, #9aa3b1); background: var(--pod-panel-elev, #1c2128);
}
.srv { display: flex; flex-direction: column; gap: 8px; }
.srv__head { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
.srv__name { font-family: var(--pod-font-mono); font-size: 12px; color: var(--pod-text, #e6e8ec); }
.srv__src {
  padding: 1px 7px; border-radius: 999px; font-family: var(--pod-font-mono); font-size: 11px;
  color: var(--pod-text-dim, #9aa3b1); background: var(--pod-panel-elev, #1c2128);
}
.srv__warn {
  padding: 1px 7px; border-radius: 999px; font-size: 11px;
  color: var(--pod-warning, #e37933); background: rgba(227, 121, 51, 0.14);
}
.srv__rules { display: flex; flex-direction: column; gap: 6px; }
.srv__group { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.srv__k {
  flex: none; width: 72px; font-size: var(--pod-size-sm, 12px);
  color: var(--pod-text-faint, #6b7280); font-variant-numeric: tabular-nums;
}
.chip-list { display: flex; flex-wrap: wrap; gap: 4px; }
.chip {
  padding: 1px 7px; border-radius: var(--pod-radius-sm, 4px);
  font-family: var(--pod-font-mono); font-size: 11px; color: var(--pod-text-dim, #9aa3b1);
  background: var(--pod-panel-elev, #1c2128);
}
.chip--approve { color: var(--pod-warning, #e37933); }
.chip--deny { color: var(--pod-danger, #cc3e44); }

/* ── 模板：默认收起，别把主内容挤到折叠线以下 ── */
.tpl {
  border-radius: 12px;
  background: var(--pod-panel-bg, #161a1f);
  border: 1px solid var(--pod-border, rgba(255, 255, 255, 0.07));
}
.tpl__toggle {
  display: flex; align-items: center; gap: 8px; width: 100%;
  padding: 12px 18px; border: 0; background: none; cursor: pointer; text-align: left;
  font: inherit; font-size: var(--pod-size-base, 14px); color: var(--pod-text, #e6e8ec);
}
.tpl__caret { transition: transform 150ms ease-out; flex: none; }
.tpl__caret--open { transform: rotate(90deg); }
.tpl__hint { font-size: var(--pod-size-sm, 12px); color: var(--pod-text-faint, #6b7280); }
.tpl__toggle:focus-visible { outline: 2px solid var(--pod-accent, #6ea4f9); outline-offset: -2px; border-radius: 12px; }
.tpl__body {
  display: flex; flex-direction: column; gap: 14px;
  padding: 14px 18px 18px;
  border-top: 1px solid var(--pod-divider, rgba(255, 255, 255, 0.05));
}
.tpl__target { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.tpl__target label { font-size: var(--pod-size-md, 13px); color: var(--pod-text-dim, #9aa3b1); }
.tpl__select { width: 240px; }
.tpl__danger { font-size: var(--pod-size-sm, 12px); color: var(--pod-text-dim, #9aa3b1); }
.tpl__grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 10px; }
.tpl__item {
  display: flex; flex-direction: column; gap: 6px; padding: 12px 14px; text-align: left; cursor: pointer;
  border-radius: 10px; font: inherit; color: var(--pod-text, #e6e8ec);
  background: var(--pod-panel-elev, #1c2128); border: 1px solid transparent;
  transition: border-color 150ms ease-out;
}
.tpl__item:hover { border-color: var(--pod-border-strong, rgba(255, 255, 255, 0.12)); }
.tpl__item--active { border-color: var(--pod-accent, #6ea4f9); }
.tpl__item:focus-visible { outline: 2px solid var(--pod-accent, #6ea4f9); outline-offset: 2px; }
.tpl__name { font-size: 14px; font-weight: 600; }
.tpl__desc { font-size: var(--pod-size-sm, 12px); line-height: 1.6; color: var(--pod-text-dim, #9aa3b1); }
.tpl__stats { display: flex; align-items: center; flex-wrap: wrap; gap: 4px 8px; margin-top: 2px; }
.tpl__stat { font-size: var(--pod-size-sm, 12px); color: var(--pod-text-faint, #6b7280); }
.tpl__actions { display: flex; justify-content: flex-end; }

/* ── 预览：AI 草稿与编辑中都能立刻看到语义 ── */
.preview {
  margin-top: 14px; padding: 12px 14px; border-radius: 10px;
  background: var(--pod-panel-elev, #1c2128);
  border: 1px solid var(--pod-border, rgba(255, 255, 255, 0.07));
}
.preview--form { margin-top: 0; }
.preview__head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.preview__why {
  margin: 0; font-size: var(--pod-size-sm, 12px); line-height: 1.6; color: var(--pod-text-dim, #9aa3b1);
}
.preview__counts {
  display: flex; flex-wrap: wrap; gap: 4px 14px; margin: 8px 0 0;
  font-size: var(--pod-size-sm, 12px); color: var(--pod-text-dim, #9aa3b1);
  font-variant-numeric: tabular-nums;
}
.preview__counts b { color: var(--pod-text, #e6e8ec); }
.preview__explain { margin-top: 12px; }
.preview__explain-k { font-size: var(--pod-size-sm, 12px); color: var(--pod-text-faint, #6b7280); }
.preview__explain p {
  margin: 4px 0 0; max-width: 70ch; white-space: pre-wrap;
  font-size: var(--pod-size-md, 13px); line-height: 1.7; color: var(--pod-text-dim, #9aa3b1);
}
.dlg__lead {
  margin: 0 0 12px; max-width: 70ch;
  font-size: var(--pod-size-md, 13px); line-height: 1.7; color: var(--pod-text-dim, #9aa3b1);
}
.disclose {
  margin: 12px 0 8px; padding: 0; border: 0; background: none; cursor: pointer;
  font: inherit; font-size: var(--pod-size-md, 13px); color: var(--pod-accent, #6ea4f9);
}
.mono :deep(textarea) { font-family: var(--pod-font-mono); font-size: 12px; line-height: 1.6; }
.form__select { width: 100%; }

/* ── 历史与差异 ── */
.hist { display: grid; grid-template-columns: minmax(200px, 0.8fr) minmax(0, 1.4fr); gap: 16px; }
.hist__versions { display: flex; flex-direction: column; gap: 6px; max-height: 420px; overflow-y: auto; }
.ver {
  display: grid; grid-template-columns: auto 1fr; gap: 2px 10px; padding: 8px 10px; text-align: left;
  border-radius: 8px; font: inherit; cursor: pointer;
  background: var(--pod-panel-elev, #1c2128); border: 1px solid transparent;
}
.ver:hover { border-color: var(--pod-border-strong, rgba(255, 255, 255, 0.12)); }
.ver--active { border-color: var(--pod-accent, #6ea4f9); }
.ver:focus-visible { outline: 2px solid var(--pod-accent, #6ea4f9); outline-offset: 2px; }
.ver__no { font-size: var(--pod-size-md, 13px); font-weight: 600; font-variant-numeric: tabular-nums; }
.ver__time { font-size: var(--pod-size-sm, 12px); color: var(--pod-text-faint, #6b7280); text-align: right; }
.ver__note {
  grid-column: 1 / -1; font-size: var(--pod-size-sm, 12px); line-height: 1.6;
  color: var(--pod-text-dim, #9aa3b1);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.hist__diff { min-width: 0; }
.hist__placeholder {
  margin: 0; padding: 24px 0; text-align: center;
  font-size: var(--pod-size-md, 13px); color: var(--pod-text-faint, #6b7280);
}
.diff__head { display: flex; flex-wrap: wrap; gap: 6px 14px; margin-bottom: 8px; }
.diff__legend { font-size: var(--pod-size-sm, 12px); color: var(--pod-text-dim, #9aa3b1); }
.diff__legend--add { color: var(--pod-success, #8dc149); }
.diff__legend--del { color: var(--pod-danger, #cc3e44); }
.diff {
  margin: 0; padding: 10px 12px; border-radius: 8px; max-height: 380px; overflow: auto;
  background: var(--pod-panel-elev, #1c2128);
  font-family: var(--pod-font-mono); font-size: 12px; line-height: 1.6;
}
.diff__line { display: block; color: var(--pod-text-dim, #9aa3b1); }
.diff__line--same { opacity: 0.65; }
.diff__line--add {
  color: var(--pod-success, #8dc149);
  background: color-mix(in srgb, var(--pod-success, #8dc149) 12%, transparent);
}
.diff__line--del {
  color: var(--pod-danger, #cc3e44);
  background: color-mix(in srgb, var(--pod-danger, #cc3e44) 12%, transparent);
}
.hist__foot-hint { margin-right: auto; font-size: var(--pod-size-sm, 12px); color: var(--pod-text-faint, #6b7280); }
:deep(.hist-dialog .el-dialog__footer) { display: flex; align-items: center; gap: 12px; }

/* ── 响应式：<1240 收成一屏两列，<760 单列 ── */
@media (max-width: 1240px) {
  .list__head { display: none; }
  .pr { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }
  .cell__k { display: block; margin-bottom: 4px; }
  .pr__actions { grid-column: 1 / -1; justify-content: flex-start; }
}
@media (max-width: 760px) {
  .pr { grid-template-columns: minmax(0, 1fr); }
  .tpl__select { width: 100%; }
  .hist { grid-template-columns: minmax(0, 1fr); }
  .hist__versions { max-height: 200px; }
}

@media (prefers-reduced-motion: reduce) {
  .pr, .tpl__caret, .tpl__item { transition: none; }
}
</style>
