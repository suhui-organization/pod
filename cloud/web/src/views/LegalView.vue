<template>
  <div class="legal">
    <h2>{{ title }}</h2>
    <div class="legal-body"><pre>{{ body }}</pre></div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'

const { t, locale } = useI18n()

const route = useRoute()
const PRIVACY = `Pod Cloud 隐私政策（初稿）

1. 我们收集什么
   - 账号信息：邮箱、密码哈希、租户名称
   - Agent 元数据：名称、平台、同步令牌哈希（不存明文）
   - 审计事件元数据：工具名、服务器名、时间、决策、审批人、参数/输出的 SHA-256 哈希
     —— 不含参数/输出原文
   - 告警记录：由审计事件自动生成
   - 支付信息：由 Paddle 处理（它是这笔交易的法律卖家），我们不存储卡号

2. 我们不收集什么
   - 工具调用的参数原文、输出原文、文件内容、代码内容、会话文本、密钥明文

3. 如何使用与共享
   - 仅用于提供服务（仪表盘/策略/合规报告/告警）与安全维护
   - 不出售个人数据；除法律要求、必要子处理者（托管/Paddle）、经你同意外不共享

4. 数据保留
   - 账号删除请求 30 天内处理；审计事件保留期限见发布版

5. 你的权利（GDPR/CCPA）
   - 访问、更正、删除、可携带性、撤回同意；联系方式见发布版

6. 安全
   - TLS 传输加密；审计哈希链防篡改；令牌只存哈希；最小权限访问控制

（完整版见仓库 docs/legal/privacy-policy.md；正式发布前经法律审核）`

const TERMS = `Pod Cloud 服务条款（初稿）

1. 服务：AI Agent 安全 SaaS（审计聚合/策略/告警/合规报告）。
   本地网关 pod CLI 为独立开源软件，本条款仅适用于云服务。

2. 账号：注册需有效邮箱；你对账号下所有活动负责；
   付费计划通过 Paddle 计费，可随时取消。

3. 可接受使用：不得违法、攻击第三方、上传恶意内容。

4. 数据：你拥有你的数据；服务依赖你正确配置本地网关，
   错误配置导致的安全事件由你承担。

5. 可用性：目标 99.5%（按月）；维护窗口提前通知。

6. 免责与责任限制：服务按"现状"提供，不保证防止一切安全事件；
   累计责任不超过你过去 12 个月支付的费用；
   服务不构成法律/合规意见，合规报告仅供参考。

7. 终止：你可随时删除账号；违反条款可被暂停/终止。

8. 变更：重大变更提前 30 天通知。

（完整版见仓库 docs/legal/terms-of-service.md；正式发布前经法律审核）`

// 退款政策写双语：Paddle 审核收银台域名时会逐条看这三份文档，
// 中文版对审核方不够用；中英并排放在一页里，谁都不用"另行索取"。
const REFUND = `Pod Cloud 退款政策（初稿 · 待你方确认）

生效日期：2026-09-15

1. 谁在处理你的付款
   Pod Cloud 的订阅通过 Paddle 收款。Paddle 是这笔交易的「记录商家」(Merchant of Record)，
   也是你信用卡账单上出现的收款方；发票、税费（VAT/GST）与退款都由 Paddle 处理。
   本政策说明我们的退款口径，不改变你依法享有的权利。

2. 订阅如何计费
   - 付费计划按月自动续费，价格以下单时收银台显示为准（当前为 US$19.00/月）。
   - 可随时在控制台「订阅」页取消；取消后不再续费，当前已付周期内继续可用至周期结束。
   - 免费计划不涉及任何付款。

3. 什么时候可以退款
   - 首次订阅 14 天内：未使用因付费计划新增的权益，可申请全额退款。
   - 续费 14 天内：忘记取消而被扣款，可申请该笔续费的全额退款。
   - 重复扣款或误扣：无论多久，核实后全额退回。
   - 服务不可用：因我方原因导致付费功能在计费周期内长时间不可用，按未使用天数比例退款。
   - 超过 14 天的正常使用周期原则上不退款；特殊情况可联系我们协商。

4. 怎么申请
   发邮件到 iverson.wuwei@gmail.com，附上 Paddle 订单号或注册邮箱，并说明退款原因。
   我们会在 3 个工作日内答复；批准的退款由 Paddle 原路退回，通常 5–10 个工作日到账
   （具体取决于发卡行）。

5. 拒付（Chargeback）
   请先联系我们。直接发起拒付会进入 Paddle 的争议流程，可能冻结相关订阅；
   多数情况下我们直接退款会比争议流程更快解决。

6. 变更
   本政策调整会更新在本页并标注生效日期，对已发生的订单不溯及既往。

（正式发布前经法律审核）

────────────────────────────────────────

Refund Policy (draft)

Effective date: 2026-09-15

1. Who processes your payment
   Subscriptions to Pod Cloud are sold through Paddle. Paddle is the Merchant of Record:
   it appears on your card statement and handles invoicing, taxes (VAT/GST) and refunds.
   This policy describes our refund practice and does not affect your statutory rights.

2. Billing
   - Paid plans renew monthly. The price shown at checkout applies (currently US$19.00/month).
   - You can cancel any time from the Subscription page in the console: no further charges,
     and you keep access until the end of the period you already paid for.
   - The free plan involves no payment.

3. When you can get a refund
   - Within 14 days of your first purchase, if you have not used the paid features: full refund.
   - Within 14 days of a renewal you forgot to cancel: full refund of that renewal.
   - Duplicate or erroneous charges: full refund regardless of timing.
   - Prolonged unavailability caused by us: pro-rated refund for the unused days.
   - Beyond 14 days of normal use we generally do not refund; contact us for special cases.

4. How to request
   Email iverson.wuwei@gmail.com with your Paddle order id or the account email and the reason.
   We reply within 3 business days. Approved refunds are issued by Paddle to the original
   payment method, typically within 5–10 business days depending on your bank.

5. Chargebacks
   Please contact us first. A chargeback goes through Paddle's dispute process and may freeze
   the subscription; a direct refund usually resolves things faster.

6. Changes
   Updates are published on this page with an effective date and do not apply retroactively.

（正式发布前经法律审核 — subject to legal review before public release）`

const title = computed(() =>
  route.name === 'privacy' ? t('隐私政策') : route.name === 'refund' ? t('退款政策') : t('服务条款'),
)
// 法律文本暂以中文为准：不机翻（中英不一致时以哪版为准是法律问题，不是文案问题）。
// 英文界面加一行说明，免得读者以为这是英文正式版。
const body = computed(() => {
  const text = route.name === 'privacy' ? PRIVACY : route.name === 'refund' ? REFUND : TERMS
  if (!locale.value.startsWith('en')) return text
  // 退款政策本身就带英文版，不用再加"可向我们索取"那句
  if (route.name === 'refund') return text
  return `${t('（以下为中文正式版本；英文译本可向我们索取，正式发布前经法律审核。）')}\n\n${text}`
})
</script>

<style scoped>
.legal { max-width: 760px; margin: 0 auto; }
.legal h2 { margin-bottom: 16px; }
.legal-body { padding: 20px; border-radius: 12px; background: var(--pod-panel-bg, #161a1f); border: 1px solid var(--pod-border, #2a2f37); }
pre { white-space: pre-wrap; font-family: inherit; font-size: 13px; line-height: 1.7; color: var(--pod-text-dim, #9aa3af); }
</style>
