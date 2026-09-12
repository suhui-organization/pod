<template>
  <div class="legal">
    <h2>{{ title }}</h2>
    <div class="legal-body"><pre>{{ body }}</pre></div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()
const PRIVACY = `Pod Cloud 隐私政策（初稿）

1. 我们收集什么
   - 账号信息：邮箱、密码哈希、租户名称
   - Agent 元数据：名称、平台、同步令牌哈希（不存明文）
   - 审计事件元数据：工具名、服务器名、时间、决策、审批人、参数/输出的 SHA-256 哈希
     —— 不含参数/输出原文
   - 告警记录：由审计事件自动生成
   - 支付信息：由 Stripe 处理，我们不存储卡号

2. 我们不收集什么
   - 工具调用的参数原文、输出原文、文件内容、代码内容、会话文本、密钥明文

3. 如何使用与共享
   - 仅用于提供服务（仪表盘/策略/合规报告/告警）与安全维护
   - 不出售个人数据；除法律要求、必要子处理者（托管/Stripe）、经你同意外不共享

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
   付费计划通过 Stripe 计费，可随时取消。

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

const title = computed(() => (route.name === 'privacy' ? '隐私政策' : '服务条款'))
const body = computed(() => (route.name === 'privacy' ? PRIVACY : TERMS))
</script>

<style scoped>
.legal { max-width: 760px; margin: 0 auto; }
.legal h2 { margin-bottom: 16px; }
.legal-body { padding: 20px; border-radius: 12px; background: var(--fh-panel-bg, #161a1f); border: 1px solid var(--fh-border, #2a2f37); }
pre { white-space: pre-wrap; font-family: inherit; font-size: 13px; line-height: 1.7; color: var(--fh-text-dim, #9aa3af); }
</style>
