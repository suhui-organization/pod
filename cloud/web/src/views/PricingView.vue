<template>
  <div class="pricing-page">
    <div class="pricing-lang"><LangSwitch /></div>
    <header class="hero">
      <img class="logo" src="/logo.svg" alt="Pod Cloud" />
      <h1 class="hero__title">Pod Cloud</h1>
      <p class="hero__sub">{{ t('AI Agent 安全控制平面 · 本地优先，云端可选') }}</p>
      <p class="hero__lead">{{ t('按 Agent 席位订阅，随时可取消。') }}</p>
    </header>

    <section class="plans">
      <article
        v-for="p in plans"
        :key="p.id"
        class="plan"
        :class="{ 'plan--pro': p.id === 'pro' }"
      >
        <header class="plan__head">
          <h2 class="plan__name">{{ p.name }}</h2>
          <span v-if="p.id === 'pro'" class="plan__badge">{{ t('推荐') }}</span>
        </header>
        <div class="plan__price">
          {{ p.price }}<span v-if="p.unit" class="plan__unit">{{ p.unit }}</span>
        </div>
        <p class="plan__seats">{{ p.seatsText }}</p>
        <ul class="plan__features">
          <li v-for="f in p.features" :key="f">{{ f }}</li>
        </ul>
        <router-link class="plan__cta" :class="{ 'plan__cta--pro': p.id === 'pro' }" to="/login">
          {{ p.cta }}
        </router-link>
      </article>
    </section>

    <!-- 这句是给 Paddle 审核和用户看的同一件事：价格以收银台为准，
         收款方是 Paddle（Merchant of Record），退款口径见退款政策。 -->
    <p class="note">
      {{ t('价格以下单时收银台显示为准，币种为美元。订阅通过 Paddle 收款——Paddle 是这笔交易的记录商家，负责开票、代缴税费（VAT/GST）与退款。可随时在控制台取消，取消后当前已付周期继续可用。') }}
    </p>
    <p class="note note--dim">
      {{ t('所有计划都包含本地开源网关（pod CLI）、审计哈希链、策略闸门与告警；付费计划增加跨 Agent 证据链、合规报告和更多 Agent 席位。') }}
    </p>

    <footer class="pricing-foot">
      <router-link to="/legal/terms">{{ t('服务条款') }}</router-link> ·
      <router-link to="/legal/privacy">{{ t('隐私政策') }}</router-link> ·
      <router-link to="/legal/refund">{{ t('退款政策') }}</router-link>
      <div class="contact">
        {{ t('联系我们：') }}<a href="mailto:iverson.wuwei@gmail.com">iverson.wuwei@gmail.com</a>
      </div>
    </footer>
  </div>
</template>

<script setup lang="ts">
// 公开定价页：Paddle 审核收银台域名时要求站点有一个能打开、能看清卖什么的定价页
// （`/subscription` 在登录态里，审核方看不到）。这里的套餐与席位上限跟
// SubscriptionView 共用同一套口径，改价格时两个地方一起改。
import { useI18n } from 'vue-i18n'
import LangSwitch from '../components/LangSwitch.vue'

const { t } = useI18n()

const plans = [
  {
    id: 'free',
    name: t('基础版'),
    price: t('免费'),
    unit: '',
    seatsText: t('最多 3 个 Agent'),
    features: [t('SHA-256 哈希链审计（不可篡改）'), t('策略闸门 + 审批'), t('审计同步与总览')],
    cta: t('免费开始'),
  },
  {
    id: 'pro',
    name: t('专业版'),
    price: '$19',
    unit: t('/月'),
    seatsText: t('最多 100 个 Agent'),
    features: [
      t('跨 Agent 证据链：完整时间线，篡改即报错'),
      t('合规报告（GDPR，Art.30 处理活动记录）'),
      t('云端告警（密钥拦截 / 注入信号 / Deny 突增）'),
      t('优先支持'),
    ],
    cta: t('登录后订阅'),
  },
] as const
</script>

<style scoped>
.pricing-page {
  max-width: 880px;
  margin: 0 auto;
  padding: 56px 20px 40px;
  color: var(--pod-text);
  position: relative;
}
/* 语言开关放右上角：登录前的访客也要能切到自己读得懂的语言 */
.pricing-lang { position: absolute; top: 16px; right: 20px; }
.hero { text-align: center; margin-bottom: 32px; }
.logo { width: 48px; height: 48px; }
.hero__title {
  margin: 8px 0 4px;
  font-size: 26px;
  font-weight: 600;
  letter-spacing: 0.5px;
}
.hero__sub { margin: 0 0 6px; color: var(--pod-text-faint); font-size: 13px; }
.hero__lead { margin: 0; color: var(--pod-text-dim); font-size: 14px; }

.plans {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 16px;
  align-items: start;
}
.plan {
  border: 1px solid var(--pod-border-strong, #2a2f37);
  border-radius: var(--pod-radius, 10px);
  background: var(--pod-bg-soft, #171a20);
  padding: 20px;
  display: flex;
  flex-direction: column;
}
.plan--pro { border-color: #4f7cff; }
.plan__head { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.plan__name { margin: 0; font-size: 16px; font-weight: 600; }
.plan__badge {
  font-size: 11px;
  color: #4f7cff;
  border: 1px solid #4f7cff;
  border-radius: 999px;
  padding: 1px 8px;
}
.plan__price { font-size: 30px; font-weight: 700; line-height: 1.2; }
.plan__unit { font-size: 14px; font-weight: 400; color: var(--pod-text-dim); }
.plan__seats { margin: 6px 0 14px; font-size: 13px; color: var(--pod-text-dim); }
.plan__features { margin: 0 0 18px; padding-left: 18px; flex: 1; }
.plan__features li { font-size: 13px; line-height: 1.9; color: var(--pod-text-dim); }
.plan__cta {
  display: block;
  text-align: center;
  padding: 9px 12px;
  border: 1px solid var(--pod-border-strong, #2a2f37);
  border-radius: var(--pod-radius, 10px);
  color: var(--pod-text);
  text-decoration: none;
  font-size: 14px;
}
.plan__cta:hover { border-color: #4f7cff; }
.plan__cta--pro { background: #4f7cff; border-color: #4f7cff; color: #fff; }

.note {
  margin: 22px 0 0;
  font-size: 12px;
  line-height: 1.8;
  color: var(--pod-text-dim);
}
.note--dim { color: var(--pod-text-faint); }

.pricing-foot {
  margin-top: 28px;
  padding-top: 14px;
  border-top: 1px solid var(--pod-border, #2a2f37);
  font-size: 12px;
  color: var(--pod-text-faint);
  text-align: center;
}
.pricing-foot a { color: var(--pod-text-dim); text-decoration: none; }
.pricing-foot a:hover { color: #4f7cff; text-decoration: underline; }
.contact { margin-top: 6px; }
</style>
