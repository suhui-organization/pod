<template>
  <div class="product-page">
    <div class="product-lang"><LangSwitch /></div>
    <header class="hero">
      <img class="logo" src="/logo.svg" alt="Pod Cloud" />
      <h1 class="hero__title">Pod Cloud</h1>
      <p class="hero__sub">{{ t('AI Agent 安全控制平面 · 本地优先，云端可选') }}</p>
    </header>

    <p class="lead">
      {{ t('Pod Cloud 是给「跑 AI Agent 的团队」用的安全控制平面：把本地 Agent 的工具调用统一收口，留下不可篡改的审计记录，并用策略与审批拦下危险操作。') }}
    </p>

    <section class="block">
      <h2>{{ t('核心能力') }}</h2>
      <ul>
        <li>{{ t('SHA-256 哈希链审计：每次工具调用都留证，改一个字节就能验出来') }}</li>
        <li>{{ t('策略闸门与审批：按工具、路径、参数决定放行 / 审批 / 拒绝') }}</li>
        <li>{{ t('跨 Agent 证据链：完整时间线，支持事后追溯') }}</li>
        <li>{{ t('合规报告：GDPR Art.30 处理活动记录') }}</li>
        <li>{{ t('云端告警：密钥读取、注入信号、拒绝突增') }}</li>
      </ul>
    </section>

    <section class="block">
      <h2>{{ t('交付方式') }}</h2>
      <ul>
        <li>{{ t('云端 SaaS：浏览器打开控制台即可使用，无需安装') }}</li>
        <li>{{ t('本地网关：开源 CLI（pod），跑在用户自己的机器上；同一套代码也支持私有化部署') }}</li>
      </ul>
    </section>

    <section class="block">
      <h2>{{ t('适用对象') }}</h2>
      <p class="block__p">{{ t('使用 AI 编码与自动化 Agent 的工程团队和安全团队。') }}</p>
    </section>

    <section class="block">
      <h2>{{ t('价格与交付') }}</h2>
      <p class="block__p">
        {{ t('基础版免费；专业版 $19/月，按月订阅、随时可取消。') }}
        <router-link to="/pricing">{{ t('查看定价') }}</router-link>
      </p>
    </section>

    <footer class="product-foot">
      <router-link to="/pricing">{{ t('定价') }}</router-link> ·
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
// 公开产品介绍页：支付平台审核收银台域名时会索要「Product page」直链，
// 而我们原来只有定价页和登录页 —— 审核方看不到到底在卖什么。
import { useI18n } from 'vue-i18n'
import LangSwitch from '../components/LangSwitch.vue'

const { t } = useI18n()
</script>

<style scoped>
.product-page {
  max-width: 760px;
  margin: 0 auto;
  padding: 56px 20px 40px;
  color: var(--pod-text);
  position: relative;
}
.product-lang { position: absolute; top: 16px; right: 20px; }
.hero { text-align: center; margin-bottom: 24px; }
.logo { width: 48px; height: 48px; }
.hero__title { margin: 8px 0 4px; font-size: 26px; font-weight: 600; letter-spacing: 0.5px; }
.hero__sub { margin: 0; color: var(--pod-text-faint); font-size: 13px; }
.lead { font-size: 14px; line-height: 1.9; color: var(--pod-text-dim); margin: 0 0 24px; }
.block { margin-bottom: 22px; }
.block h2 { font-size: 15px; font-weight: 600; margin: 0 0 8px; }
.block ul { margin: 0; padding-left: 18px; }
.block li { font-size: 13px; line-height: 2; color: var(--pod-text-dim); }
.block__p { margin: 0; font-size: 13px; line-height: 1.9; color: var(--pod-text-dim); }
.product-foot {
  margin-top: 28px;
  padding-top: 14px;
  border-top: 1px solid var(--pod-border, #2a2f37);
  font-size: 12px;
  color: var(--pod-text-faint);
  text-align: center;
}
.product-foot a { color: var(--pod-text-dim); text-decoration: none; }
.product-foot a:hover { color: #4f7cff; text-decoration: underline; }
.contact { margin-top: 6px; }
</style>
