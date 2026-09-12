<template>
  <div>
    <div class="head">
      <div>
        <h2>{{ t('Agent 资产') }}</h2>
        <p class="head__sub">
          {{ t('接入的 agent 会用本地 pod 网关把审计推到这里。状态每 5 秒自动刷新。') }}
        </p>
      </div>
      <div class="head__actions">
        <span v-if="lastLoadedAt" class="head__stamp">
          {{ t('更新于') }} {{ lastLoadedAt.toLocaleTimeString('zh-CN') }}
        </span>
        <el-button :loading="loading" @click="load()">{{ t('刷新') }}</el-button>
        <el-button type="primary" @click="openRegister">{{ t('+ 添加 Agent') }}</el-button>
      </div>
    </div>

    <!-- 读不到数据时必须说清楚，而不是显示一个"还没有 Agent"的空壳 -->
    <el-alert v-if="loadError" type="error" :closable="false" show-icon class="alert">
      <template #title>{{ t('读不到 Agent 列表：') }}{{ loadError.message }}</template>
      <p class="alert__hint">{{ loadError.hint }}</p>
    </el-alert>

    <div v-if="agents.length" class="agent-grid">
      <article v-for="a in agents" :key="a.id" class="agent-card">
        <header class="agent-head">
          <div class="agent-name">{{ a.name }}</div>
          <el-tag :type="a.status === 'online' ? 'success' : 'info'" size="small" effect="plain">
            {{ a.status === 'online' ? t('在线') : t('未接入') }}
          </el-tag>
        </header>

        <dl class="agent-meta">
          <div>
            <dt>{{ t('平台') }}</dt>
            <dd>{{ a.platform || '—' }}</dd>
          </div>
          <div>
            <dt>{{ t('审计事件') }}</dt>
            <dd class="num">{{ a.event_count }}</dd>
          </div>
          <div class="span2">
            <dt>{{ t('最近同步') }}</dt>
            <dd>
              {{ a.last_seen_at ? new Date(a.last_seen_at).toLocaleString('zh-CN') : '从未接入' }}
            </dd>
          </div>
        </dl>

        <!-- 未接入的 agent 给出下一步，而不是让用户对着"离线"发呆 -->
        <p v-if="!a.last_seen_at" class="agent-tip">
          {{ t('还没收到过它的同步。点「接入命令」拿一条命令，在跑 agent 的机器上执行； 执行完这里会自动变成「在线」。') }}
        </p>
        <p v-else-if="a.event_count === 0" class="agent-tip">
          {{ t('已接入，但还没有审计上云。先确认本地网关跑过（pod serve / pod record），再确认接入命令里的名字与本地 agent 名一致——不一致时命令会列出本机实际的 agent 名，用 LOCAL_AGENT=<名字> 重跑即可。') }}
        </p>

        <footer class="agent-actions">
          <el-button link size="small" @click="startConnect(a)">{{ t('接入命令') }}</el-button>
          <el-popconfirm :title="t('删除该 Agent 及其审计？')" @confirm="remove(a)">
            <template #reference><el-button link type="danger" size="small">{{ t('删除') }}</el-button></template>
          </el-popconfirm>
        </footer>
      </article>
    </div>
    <div v-else-if="!loadError" class="empty">
      {{ t('还没有 Agent —— 点右上角「+ 添加 Agent」接入第一个。') }}
    </div>

    <!-- 一个弹窗走完：填名称 → 拿命令 → 自动等它上线 -->
    <el-dialog
      v-model="dialogOpen"
      :title="phase === 'form' ? '添加 Agent' : '接入 Agent'"
      width="640px"
      @closed="stopWaiting"
    >
      <template v-if="phase === 'form'">
        <el-form @submit.prevent="register">
          <el-form-item>
            <el-input v-model="form.name" size="large" autofocus
              :placeholder="t('给它起个名字，如 openclaw-main')" @keyup.enter="register" />
          </el-form-item>
          <p class="hint">
            {{ t('只需填名称，平台类型自动识别、令牌自动生成。名字建议与本地网关的 agent 名一致 （') }}<code>{{ t('pod serve --agent &lt;名字&gt;') }}</code>{{ t('）——不一致时接入命令会提示并对齐。') }}
          </p>
        </el-form>
        <el-alert v-if="formError" type="error" :closable="false" show-icon class="alert">
          <template #title>{{ formError.message }}</template>
          <p class="alert__hint">{{ formError.hint }}</p>
          <el-button v-if="formError.action" link type="primary" size="small" @click="go(formError.action.to)">
            {{ formError.action.label }}
          </el-button>
        </el-alert>
      </template>

      <template v-else>
        <p class="step">
          {{ t('在') }}<strong>{{ t('跑这个 agent 的机器') }}</strong>{{ t('上执行下面这条命令。它会写好配置、清掉失效的旧绑定， 并回报是否真的接入成功：') }}
        </p>
        <div class="token-box">
          <code>{{ setupCommand }}</code>
          <el-button size="small" @click="copy(setupCommand)">{{ t('复制命令') }}</el-button>
        </div>
        <p class="hint">
          {{ t('令牌只显示这一次（服务端只存哈希）。若已经关掉或换了机器，点任意 agent 上的 「接入命令」会重新生成一条——旧令牌随即失效。') }}
        </p>

        <!-- 实时等待：不用手动刷新，也不需要用户猜有没有成功 -->
        <div class="wait" :class="connected ? 'wait--ok' : 'wait--pending'" role="status">
          <template v-if="connected">
            <div class="wait__title">{{ t('✅ 已接入') }}</div>
            <div class="wait__body">
              {{ t('收到了') }} {{ createdAgent?.name }} {{ t('的同步，审计正在上云。') }}
            </div>
          </template>
          <template v-else>
            <div class="wait__title">{{ t('等待接入…') }}</div>
            <div class="wait__body">
              {{ t('还没收到这台 agent 的同步（每 5 秒检查一次）。命令执行完这里会自动变成已接入； 如果命令最后一行报了 ❌，按它给的下一步处理。') }}
            </div>
          </template>
        </div>

        <el-button link size="small" @click="showRawToken = !showRawToken">
          {{ showRawToken ? '收起' : '查看' }}{{ t('同步令牌') }}
        </el-button>
        <div v-if="showRawToken" class="token-box">
          <code>{{ syncToken }}</code>
          <el-button size="small" @click="copy(syncToken)">{{ t('复制') }}</el-button>
        </div>
      </template>

      <template #footer>
        <el-button v-if="phase === 'form'" @click="dialogOpen = false">{{ t('取消') }}</el-button>
        <el-button type="primary" @click="dialogOpen = false">
          {{ connected ? '完成' : '我知道了' }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { parseApiError } from '../api/client'
import type { AgentItem } from '../api/types'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const router = useRouter()
const agents = ref<AgentItem[]>([])
const loading = ref(false)
const lastLoadedAt = ref<Date | null>(null)
const loadError = ref<{ message: string; hint: string } | null>(null)

const dialogOpen = ref(false)
const phase = ref<'form' | 'connect'>('form')
const form = ref({ name: '' })
const formError = ref<{ message: string; hint: string; action?: { label: string; to: string } } | null>(null)
const createdAgent = ref<AgentItem | null>(null)
const syncToken = ref('')
const showRawToken = ref(false)
const connected = ref(false)

const setupCommand = computed(() =>
  createdAgent.value
    ? `curl -fsSL ${window.location.origin}/api/v1/agent-setup/${createdAgent.value.id}/${syncToken.value} | bash`
    : '',
)

/** 把 HTTP 状态翻译成"我该怎么办"，而不是把原始错误丢给用户。 */
function hintFor(err: unknown): string {
  const status = (err as { response?: { status?: number } })?.response?.status ?? 0
  if (status === 401) return t('登录态已失效，请重新登录后再试。')
  if (status === 402) return t('这是套餐额度限制：升级计划，或先删掉不用的 agent。')
  if (status === 403) return t('只有租户管理员能管理 agent；让管理员来操作，或改用管理员账号。')
  if (status === 0) return t('连不上控制台后端：确认服务在运行、地址可访问、网络没被挡。')
  return t('可以重试一次；若持续失败，请把这条错误发给管理员看服务端日志。')
}

async function load() {
  loading.value = true
  try {
    agents.value = (await api.agents()).agents
    lastLoadedAt.value = new Date()
    loadError.value = null
  } catch (e) {
    // 保留上一次的列表：读失败不代表资产没了，别用空列表误导用户
    loadError.value = { message: parseApiError(e), hint: hintFor(e) }
  } finally {
    loading.value = false
  }
}

function openRegister() {
  form.value = { name: '' }
  formError.value = null
  createdAgent.value = null
  syncToken.value = ''
  showRawToken.value = false
  connected.value = false
  phase.value = 'form'
  dialogOpen.value = true
}

async function register() {
  const name = form.value.name.trim()
  if (!name) {
    formError.value = { message: t('请填写名称'), hint: t('名称只是给你自己看的标识，如 openclaw-main。') }
    return
  }
  formError.value = null
  try {
    const res = await api.registerAgent({ name })
    createdAgent.value = res.agent
    syncToken.value = res.sync_token
    phase.value = 'connect'
    connected.value = false
    startWaiting()
    await load()
  } catch (e) {
    const status = (e as { response?: { status?: number } })?.response?.status
    formError.value = {
      message: parseApiError(e),
      hint: hintFor(e),
      action: status === 402 ? { label: t('去看看套餐'), to: '/subscription' } : undefined,
    }
  }
}

/** 已有 agent 重新生成接入命令：轮换令牌后旧命令立即失效。 */
async function startConnect(agent: AgentItem) {
  try {
    const res = await api.rotateToken(agent.id)
    createdAgent.value = agent
    syncToken.value = res.sync_token
    showRawToken.value = false
    connected.value = Boolean(agent.last_seen_at)
    phase.value = 'connect'
    dialogOpen.value = true
    startWaiting()
  } catch (e) {
    ElMessage.error(`${parseApiError(e)}（${hintFor(e)}）`)
  }
}

async function remove(agent: AgentItem) {
  try {
    await api.removeAgent(agent.id)
    ElMessage.success(`已删除 ${agent.name}`)
    await load()
  } catch (e) {
    ElMessage.error(`${parseApiError(e)}（${hintFor(e)}）`)
  }
}

// ── 实时等待:弹窗开着时每 5 秒问一次,接入成功立刻反映到界面上 ──
let timer: ReturnType<typeof setInterval> | null = null

function startWaiting() {
  stopWaiting()
  timer = setInterval(async () => {
    const id = createdAgent.value?.id
    if (!id) return
    try {
      const fresh = (await api.agents()).agents.find((a) => a.id === id)
      if (fresh) {
        createdAgent.value = fresh
        connected.value = Boolean(fresh.last_seen_at)
        agents.value = agents.value.map((a) => (a.id === id ? fresh : a))
      }
    } catch {
      /* 轮询失败静默：下一次再试，不要每 5 秒弹一次错误 */
    }
  }, 5000)
}

function stopWaiting() {
  if (timer !== null) {
    clearInterval(timer)
    timer = null
  }
}

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success(t('已复制'))
  } catch {
    // 非 https / 非 localhost 环境下 clipboard API 不可用:提醒手动复制
    ElMessage.warning(t('浏览器不允许自动复制，请手动选中上面的命令复制'))
  }
}

function go(to: string) {
  dialogOpen.value = false
  router.push(to)
}

onMounted(async () => {
  await load()
  timer = setInterval(load, 5000)
})
onUnmounted(stopWaiting)
</script>

<style scoped>
.head { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 16px; }
.head h2 { margin: 0 0 4px; }
.head__sub { margin: 0; font-size: 12px; color: var(--pod-text-dim); }
.head__actions { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
.head__stamp { font-size: 12px; color: var(--pod-text-dim); }
.alert { margin-bottom: 16px; }
.alert__hint { margin: 4px 0 0; font-size: 12px; line-height: 1.6; }
.hint { color: var(--pod-text-dim); font-size: 12px; margin: 0; line-height: 1.7; }
.agent-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 16px;
}
.agent-card {
  display: flex; flex-direction: column; gap: 12px;
  padding: 16px 18px; border-radius: 12px;
  background: var(--pod-panel-bg, #161a1f); border: 1px solid var(--pod-border, #2a2f37);
}
.agent-card:hover { border-color: var(--pod-border-strong, #2a2f37); }
.agent-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.agent-name { font-size: 14px; font-weight: 600; overflow-wrap: anywhere; }
.agent-meta {
  display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px 12px; margin: 0;
}
.agent-meta > .span2 { grid-column: span 2; }
.agent-meta dt { margin-bottom: 2px; font-size: 11px; color: var(--pod-text-dim, #9aa3af); }
.agent-meta dd { margin: 0; font-size: 13px; color: var(--pod-text, #e6e8ec); overflow-wrap: anywhere; }
.agent-meta dd.num { font-variant-numeric: tabular-nums; font-weight: 600; }
.agent-tip {
  margin: 0; padding: 8px 10px; border-radius: 8px;
  font-size: 12px; line-height: 1.7;
  color: var(--pod-text-dim); background: var(--pod-bg-soft);
}
.agent-actions {
  display: flex; justify-content: flex-end; gap: 4px;
  margin-top: auto; padding-top: 10px; border-top: 1px solid var(--pod-divider, rgba(255, 255, 255, 0.05));
}
.empty { padding: 40px 0; text-align: center; font-size: 13px; color: var(--pod-text-dim, #9aa3af); }
.step { margin: 0 0 8px; font-size: 13px; line-height: 1.7; color: var(--pod-text); }
.step code { background: rgba(127, 127, 127, 0.12); padding: 1px 6px; border-radius: 4px; }
.token-box { display: flex; gap: 10px; margin: 8px 0; align-items: center; }
.token-box code {
  flex: 1; padding: 10px; border-radius: 8px; background: rgba(127, 127, 127, 0.12);
  word-break: break-all; font-size: 13px;
}
.wait {
  margin: 14px 0 10px; padding: 12px 14px; border-radius: 8px;
  border: 1px solid var(--pod-border-strong, #2a2f37);
}
.wait--pending { background: var(--pod-bg-soft); }
.wait--ok { background: var(--pod-accent-soft); border-color: var(--pod-accent); }
.wait__title { font-size: 13px; font-weight: 600; color: var(--pod-text); }
.wait__body { margin-top: 4px; font-size: 12px; line-height: 1.7; color: var(--pod-text-dim); }
</style>
