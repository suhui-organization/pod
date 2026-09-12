<template>
  <div class="sub">
    <div class="head">
      <h2>{{ t('订阅') }}</h2>
      <span class="head__mode">
        {{ billingEnabled
          ? (billingConfigured ? t('{provider} 在线支付已接入', { provider: providerLabel }) : t('在线支付未开通'))
          : t('本部署未启用计费（自托管）') }}
      </span>
    </div>

    <!-- 自托管部署：没有付费能力，也不受套餐限制。把这件事说清楚，
         而不是展示一堆点了会报错的升级按钮。 -->
    <el-alert
      v-if="!billingEnabled"
      type="success"
      :closable="false"
      show-icon
      class="selfhost"
      :title="t('本部署未启用计费：所有功能可用，agent 数量不限')"
      :description="t('自托管部署默认关闭计费。需要收费能力时，在部署配置里设置 PODCLOUD_BILLING_ENABLED=on 并填好支付平台凭据（如 Paddle 的 PADDLE_API_KEY / PADDLE_PRICE_PRO / PADDLE_WEBHOOK_SECRET），重启后这里会出现订阅入口。详见 docs/deploy-cloud.md。')"
    />

    <div v-if="error" class="state state--error">
      <p>{{ error }}</p>
      <el-button size="small" @click="load()">{{ t('重试') }}</el-button>
    </div>

    <div v-else-if="!info" class="state" aria-busy="true" :aria-label="t('正在读取订阅状态')">
      <el-skeleton :rows="2" animated />
    </div>

    <template v-else-if="billingEnabled">
      <!-- 当前状态：一眼回答“我在哪个套餐、用了几个席位、什么时候续费” -->
      <section class="status" :class="statusClass">
        <div class="status__plan">
          <span class="status__label">{{ t('当前套餐') }}</span>
          <div class="status__row">
            <strong class="status__name">{{ currentPlan.name }}</strong>
            <span v-if="currentPlan.price" class="status__price">{{ currentPlan.price }}{{ currentPlan.unit }}</span>
          </div>
          <p class="status__renew">{{ renewText }}</p>
        </div>

        <div class="status__usage">
          <div class="usage__head">
            <span class="status__label">{{ t('Agent 席位') }}</span>
            <span class="usage__count"><b>{{ used }}</b> / {{ limitText }}</span>
          </div>
          <div
            class="meter"
            role="progressbar"
            :aria-valuenow="used"
            aria-valuemin="0"
            :aria-valuemax="limit === UNLIMITED ? 100 : limit"
            :aria-label="t('Agent 席位已用 {used} / {limit}', { used, limit: limitText })"
          >
            <i class="meter__fill" :style="{ width: `${pct}%` }"></i>
          </div>
          <p v-if="full" class="usage__note">{{ t('席位已满，升级可加至') }} {{ proSeats }}</p>
          <p v-else-if="warn" class="usage__note">{{ t('已用') }} {{ pct }}{{ t('%，接近上限') }}</p>
        </div>
      </section>

      <!-- 套餐对比：当前套餐不做成可点按钮，避免假控件 -->
      <section class="plans">
        <article
          v-for="p in plans"
          :key="p.id"
          class="plan"
          :class="{ 'plan--current': p.id === info.plan }"
        >
          <header class="plan__head">
            <h3>{{ p.name }}</h3>
            <span v-if="p.id === info.plan" class="plan__badge">{{ t('当前计划') }}</span>
          </header>
          <div class="plan__price">{{ p.price }}<span v-if="p.unit">{{ p.unit }}</span></div>
          <p class="plan__seats">{{ p.seatsText }}</p>
          <ul class="plan__features">
            <li v-for="f in p.features" :key="f">{{ f }}</li>
          </ul>
          <div class="plan__action">
            <el-button
              v-if="p.id !== info.plan && p.id === 'pro'"
              type="primary"
              :loading="checkoutLoading"
              @click="upgrade"
            >{{ t('升级到专业版') }}</el-button>
            <el-button
              v-else-if="p.id !== info.plan"
              :loading="planLoading === p.id"
              @click="switchPlan(p.id)"
            >{{ t('降级到免费版') }}</el-button>
          </div>
        </article>
      </section>

      <p v-if="upgradeNotice" class="upgrade-notice">
        {{ upgradeNotice }}
        <a class="upgrade-notice__link" href="mailto:support@podcloud.dev">{{ t('联系我们开通') }}</a>
      </p>
      <!-- 从收银台跳回来：先说清楚"钱付了、权限还在同步"，
           因为订阅状态是 webhook 到了才变，中间有几秒差 -->
      <p v-if="checkoutStatus === 'success'" class="checkout-status">
        {{ t('支付已完成。订阅状态由支付平台回调同步，通常几秒内生效 —— 下面没变的话刷新一次。') }}
      </p>
      <p v-else-if="checkoutStatus === 'cancelled'" class="checkout-status">
        {{ t('这次结账取消了，没有扣款。') }}
      </p>
      <p class="foot">{{ billingNote }}</p>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { parseApiError } from '../api/client'
import type { SubscriptionInfo } from '../api/types'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

/**
 * Paddle.js 的全局对象。Paddle Billing 的收银台是**跑在我们自己页面上**的
 * overlay（不是 Stripe 那种托管页），所以必须加载它的脚本并 Initialize。
 * 只有在 provider=paddle 时才需要。
 */
declare global {
  interface Window {
    Paddle?: {
      Environment: { set: (env: 'sandbox' | 'production') => void }
      Initialize: (opts: { token: string }) => void
      Checkout: { open: (opts: { transactionId: string; settings?: { successUrl?: string } }) => void }
    }
  }
}

const PADDLE_JS = 'https://cdn.paddle.com/paddle/v2/paddle.js'

function loadScript(src: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const el = document.createElement('script')
    el.src = src
    el.async = true
    el.onload = () => resolve()
    el.onerror = () => reject(new Error(t('加载失败：{src}', { src })))
    document.head.appendChild(el)
  })
}

/** 套餐目录（agent 限额与文案都写在这里，避免散落在模板中） */
const plans = [
  {
    id: 'free',
    name: t('基础版'),
    price: t('免费'),
    unit: '',
    seats: 3,
    seatsText: t('最多 3 个 Agent'),
    features: [t('SHA-256 哈希链审计（不可篡改）'), t('策略闸门 + 审批'), t('审计同步与总览')],
  },
  {
    id: 'pro',
    name: t('专业版'),
    price: '$19',
    unit: t('/月'),
    seats: 100,
    seatsText: t('最多 100 个 Agent'),
    features: [
      t('跨 Agent 证据链：完整时间线，篡改即报错'),
      t('合规报告（GDPR，Art.30 处理活动记录）'),
      t('云端告警（密钥拦截 / 注入信号 / Deny 突增）'),
      t('优先支持'),
    ],
  },
] as const

const info = ref<SubscriptionInfo | null>(null)
/** 本部署是否启用计费（自托管默认关闭：不限量、无入口） */
const billingEnabled = ref(true) // 加载完成前按"启用"渲染，避免闪一下自托管提示
/** 支付通道是否已开通（后端 billing_configured；旧字段名 stripe_configured 兼容保留） */
const billingConfigured = ref(false)
/** 当前计费平台 id（stripe / paddle / creem / waffo） */
const billingProvider = ref('')
/** 升级被挡下时留在页面上的提示（比一闪而过的 toast 更容易照着做） */
const upgradeNotice = ref('')
/** Paddle.js 是否已加载并 Initialize 完成 */
const paddleReady = ref(false)
/** 从收银台跳回来时的状态（?status=success / cancelled） */
const checkoutStatus = ref('')
const checkoutLoading = ref(false)
const planLoading = ref<string | null>(null)
const error = ref('')

const proSeats = plans[1].seats

const currentPlan = computed(() => {
  const id = info.value?.plan
  return plans.find((p) => p.id === id) ?? { name: id || t('未知套餐'), price: '', unit: '' }
})
const used = computed(() => info.value?.agent_count ?? 0)
const limit = computed(() => info.value?.agent_limit ?? 0)
/** 后端在计费关闭时返回不限量口径；界面上要把这个数字翻译成"不限" */
const UNLIMITED = 1_000_000
const limitText = computed(() => (limit.value >= UNLIMITED ? t('不限') : String(limit.value)))
const pct = computed(() => (limit.value > 0 ? Math.min(100, Math.round((used.value / limit.value) * 100)) : 0))
const full = computed(() => limit.value > 0 && used.value >= limit.value)
const warn = computed(() => !full.value && pct.value >= 80)
const statusClass = computed(() => ({ 'status--warn': warn.value, 'status--full': full.value }))

const renewText = computed(() => {
  const i = info.value
  if (!i) return ''
  if (i.plan !== 'pro') return t('免费版 · 不自动续费')
  if (!i.renews_at) return t('专业版 · 未设置续费日期')
  return t('续费日期 {date}', { date: new Date(i.renews_at).toLocaleDateString() })
})

/** 支付平台展示名：后端只给 id，文案在这里映射 */
const PROVIDER_LABELS: Record<string, string> = {
  stripe: 'Stripe',
  paddle: 'Paddle',
  creem: 'Creem',
  waffo: 'Waffo',
}
const providerLabel = computed(
  () => PROVIDER_LABELS[billingProvider.value] ?? billingProvider.value ?? '',
)

// 通道没开通时不能承诺"能升级"：以前这里写的是"升级走开发模式免支付切换"，
// 但那个路径在生产已关闭（且前端从未接过它），点按钮只会拿到 503
const billingNote = computed(() =>
  billingConfigured.value
    ? t('升级会在这里打开 {provider} 的收银台完成订阅，可随时取消；发票与税费由支付平台处理。', {
        provider: providerLabel.value,
      })
      : t('在线支付通道尚未开通：点「升级」会提示联系方式。当前版本能力不受影响；审计只存参数哈希、不存原文，同步需显式开启，数据默认不出本机。'),
)

async function switchPlan(plan: string) {
  planLoading.value = plan
  try {
    const r = await api.updatePlan(plan as 'free' | 'pro')
    ElMessage.success(t('已切换到 {plan}（Agent 限额 {limit}）', { plan, limit: r.agent_limit }))
    await load()
  } catch (e) {
    ElMessage.error(parseApiError(e))
  } finally {
    planLoading.value = null
  }
}

async function upgrade() {
  if (!billingConfigured.value) {
    // 通道没开通就别发这次注定 503 的请求，直接把下一步说清楚
    upgradeNotice.value = t('在线支付通道尚未开通，升级需要先联系我们。')
    return
  }
  checkoutLoading.value = true
  upgradeNotice.value = ''
  try {
    const r = await api.checkout('pro')
    // Paddle：收银台跑在我们自己的页面上（Paddle.js overlay），所以直接开 overlay。
    // successUrl 用当前 origin —— 必须落在 Paddle 已审核的域名上，
    // 拿后端配置里的地址可能对不上（比如本地 vs 隧道域名）。
    const paddle = window.Paddle
    if (billingProvider.value === 'paddle' && r.transaction_id && paddleReady.value && paddle) {
      paddle.Checkout.open({
        transactionId: r.transaction_id,
        settings: { successUrl: `${window.location.origin}/subscription?status=success` },
      })
    } else {
      // Stripe：托管收银台，跳过去即可
      window.location.href = r.checkout_url
    }
  } catch (e) {
    const msg = parseApiError(e)
    if ((e as { response?: { status?: number } })?.response?.status === 503) upgradeNotice.value = msg
    else ElMessage.error(msg)
  } finally {
    checkoutLoading.value = false
  }
}

async function load() {
  error.value = ''
  try {
    info.value = await api.subscription()
    billingEnabled.value = info.value.billing_enabled !== false
    const raw = info.value as unknown as {
      billing_configured?: boolean
      stripe_configured?: boolean
      billing_provider?: string
      paddle_client_token?: string
      paddle_environment?: string
    }
    billingConfigured.value = Boolean(raw.billing_configured ?? raw.stripe_configured)
    billingProvider.value = raw.billing_provider ?? ''
    if (billingProvider.value === 'paddle') {
      await setupPaddle(raw.paddle_client_token ?? '', raw.paddle_environment ?? 'sandbox')
    }
  } catch (e) {
    error.value = parseApiError(e)
  }
}

/**
 * 加载并初始化 Paddle.js。
 *
 * 顺序有讲究：**Environment.set 必须在 Initialize 之前**，否则 sandbox 的
 * client token 会被当成 live 去初始化，收银台打不开。
 * 初始化完成后，如果 URL 里带 `?_ptxn=`（Paddle 生成的收银台链接就是这个形状），
 * Paddle.js 会自己把收银台弹出来 —— 我们不需要再做什么。
 */
async function setupPaddle(token: string, environment: string) {
  if (!token) {
        upgradeNotice.value = t('支付通道缺少 client token，请联系我们（Paddle 后台可重新生成）。')
    return
  }
  try {
    if (!window.Paddle) await loadScript(PADDLE_JS)
    if (!window.Paddle) throw new Error(t('Paddle.js 加载后仍未就绪'))
    window.Paddle.Environment.set(environment === 'live' ? 'production' : 'sandbox')
    window.Paddle.Initialize({ token })
    paddleReady.value = true
  } catch (e) {
    upgradeNotice.value = t('收银台初始化失败：{error}', { error: e instanceof Error ? e.message : String(e) })
  }
}

onMounted(() => {
  // 从收银台跳回来的标记：?status=success|cancelled（Paddle 会带上）
  checkoutStatus.value = new URL(window.location.href).searchParams.get('status') ?? ''
  void load()
})
</script>

<style scoped>
.sub { display: flex; flex-direction: column; gap: 16px; }
.head { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; }
.head h2 { margin: 0; }
.head__mode { font-size: var(--pod-size-sm, 12px); color: var(--pod-text-dim, #9aa3af); }

.state {
  padding: 20px 22px; border-radius: 12px;
  background: var(--pod-panel-bg, #161a1f); border: 1px solid var(--pod-border, #2a2f37);
}
.state--error {
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
  font-size: var(--pod-size-md, 13px); color: var(--pod-text-dim, #9aa3af);
}
.state--error p { margin: 0; }

/* 状态区：页面第一眼要回答“在哪个套餐 / 用了几个席位 / 何时续费” */
.status {
  display: flex; flex-wrap: wrap; gap: 24px 32px;
  padding: 20px 22px; border-radius: 12px;
  background: var(--pod-panel-bg, #161a1f); border: 1px solid var(--pod-border, #2a2f37);
}
.status--full { border-color: var(--pod-danger, #cc3e44); }
.status__plan { flex: 1 1 200px; }
.status__usage { flex: 1 1 260px; max-width: 420px; }
.status__label { font-size: var(--pod-size-sm, 12px); color: var(--pod-text-dim, #9aa3af); }
.status__row { display: flex; align-items: baseline; gap: 8px; margin-top: 4px; }
.status__name { font-size: 20px; font-weight: 600; }
.status__price { font-size: var(--pod-size-md, 13px); color: var(--pod-text-dim, #9aa3af); }
.status__renew { margin: 4px 0 0; font-size: var(--pod-size-md, 13px); color: var(--pod-text-dim, #9aa3af); }

.usage__head { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
.usage__count { font-size: var(--pod-size-md, 13px); color: var(--pod-text-dim, #9aa3af); font-variant-numeric: tabular-nums; }
.usage__count b { font-size: 16px; color: var(--pod-text, #e6e8ec); }
.meter {
  height: 6px; margin-top: 8px; border-radius: 999px; overflow: hidden;
  background: var(--pod-hover, rgba(255, 255, 255, 0.04));
}
.meter__fill {
  display: block; height: 100%; border-radius: inherit;
  background: var(--pod-accent, #6ea4f9); transition: width 200ms ease-out;
}
/* 提示文字保持正文灰度、用色点承载告警语义：彩色小字在亮色主题下对比度不达标 */
.usage__note {
  display: flex; align-items: center; gap: 6px; margin: 8px 0 0;
  font-size: var(--pod-size-sm, 12px); color: var(--pod-text-dim, #9aa3af);
}
.usage__note::before { content: ''; flex: none; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.status--warn .meter__fill { background: var(--pod-warning, #e37933); }
.status--warn .usage__note::before { background: var(--pod-warning, #e37933); }
.status--full .meter__fill { background: var(--pod-danger, #cc3e44); }
.status--full .usage__note::before { background: var(--pod-danger, #cc3e44); }

.plans { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
.plan {
  display: flex; flex-direction: column; gap: 12px;
  padding: 20px 22px; border-radius: 12px;
  background: var(--pod-panel-bg, #161a1f); border: 1px solid var(--pod-border, #2a2f37);
}
.plan--current { border-color: var(--pod-accent, #6ea4f9); }
.plan__head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.plan__head h3 { margin: 0; font-size: 15px; }
.plan__badge {
  padding: 1px 8px; border-radius: 999px; font-size: var(--pod-size-sm, 12px);
  background: var(--pod-accent-soft, rgba(110, 164, 249, 0.14)); color: var(--pod-accent, #6ea4f9);
}
.plan__price { font-size: 28px; font-weight: 700; letter-spacing: -0.01em; font-variant-numeric: tabular-nums; }
.plan__price span { font-size: var(--pod-size-md, 13px); font-weight: 400; color: var(--pod-text-dim, #9aa3af); }
.plan__seats { margin: -4px 0 0; font-size: var(--pod-size-md, 13px); color: var(--pod-text-dim, #9aa3af); }
.plan__features {
  display: flex; flex-direction: column; gap: 8px; margin: 4px 0 0; padding: 0;
  list-style: none; font-size: var(--pod-size-md, 13px); color: var(--pod-text-dim, #9aa3af);
}
.plan__features li { display: flex; gap: 8px; }
.plan__features li::before {
  content: ''; flex: none; width: 4px; height: 4px; margin-top: 7px; border-radius: 50%;
  background: var(--pod-text-faint, #6b7280);
}
.plan__action { margin-top: auto; padding-top: 4px; }
.plan__action :deep(.el-button) { width: 100%; }
.foot { margin: 0; font-size: var(--pod-size-sm, 12px); line-height: 1.6; color: var(--pod-text-dim, #9aa3af); }

/* 升级被挡下时的提示：留在页面上，别一闪而过 */
.upgrade-notice {
  display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px;
  margin: 0; padding: 10px 14px; border-radius: 10px;
  font-size: 13px; line-height: 1.7; color: var(--pod-text-dim, #9aa3b1);
  background: var(--pod-panel-elev, #1c2128);
  border: 1px solid var(--pod-border, rgba(255, 255, 255, 0.07));
}
.upgrade-notice__link {
  color: color-mix(in srgb, var(--pod-accent, #6ea4f9) 82%, var(--pod-text, #e6e8ec));
  text-decoration: none;
}
.upgrade-notice__link:hover { text-decoration: underline; }

.checkout-status {
  margin: 0; padding: 10px 14px; border-radius: 10px;
  font-size: 13px; line-height: 1.7; color: var(--pod-text-dim, #9aa3b1);
  background: var(--pod-panel-elev, #1c2128);
  border: 1px solid var(--pod-border, rgba(255, 255, 255, 0.07));
}

@media (prefers-reduced-motion: reduce) {
  .meter__fill { transition: none; }
}
</style>
