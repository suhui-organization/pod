<template>
  <div class="product-page">
    <div class="product-lang"><LangSwitch /></div>
    <header class="hero">
      <img class="logo" src="/logo.svg" alt="Pod Cloud" />
      <h1 class="hero__title">Pod Cloud</h1>
      <p class="hero__sub">{{ t('本地执行，云端汇总：AI Agent 的安全控制平面') }}</p>
    </header>

    <p class="lead">
      {{ t('Pod 分两端：机器上的开源 CLI（pod）负责判定、拦截与留证——真的在干活；Pod Cloud 负责汇总、展示与持久化，并为以后的模型训练积累语料。两端之间只传哈希与摘要，不传你的内容。') }}
    </p>

    <section class="block">
      <h2>{{ t('在 Agent 机器上（开源 CLI，Apache-2.0）') }}</h2>
      <ul>
        <li>{{ t('从真实行为编译策略：pod record 只录不拦采几天真实调用，pod policy draft 编译出最小权限策略（读放行 / 写审批 / 破坏性拒绝），并与基线 diff 出收紧与放宽') }}</li>
        <li>{{ t('策略闸门与审批：按工具、路径、参数判定放行 / 审批 / 拒绝；未登记的 server 与工具一律拒绝（fail-closed），审批超时即拒') }}</li>
        <li>{{ t('密钥防线：敏感路径拒读、输出侧密钥正则、高熵兜底（未知格式的密钥也拦得住）') }}</li>
        <li>{{ t('漏洞扫描：16 类 harness（Claude Code / Codex / Cursor / …）与项目级配置，按 18 条威胁目录出清单——每条带外部出处，并写明我们覆盖到哪（覆盖 / 只能发现 / 看不到）') }}</li>
        <li>{{ t('哈希链审计与证据：每次工具调用进 SHA-256 哈希链，pod verify-audit 指出第一处断裂；证据包可导出、可独立校验') }}</li>
        <li>{{ t('可交付的加固报告：pod harden 一次生成执行摘要、范围与方法、按优先级排序的待办、覆盖边界与逐文件 sha256；接收方用 pod harden --verify 自己验，不需要信任我们') }}</li>
      </ul>
    </section>

    <section class="block">
      <h2>{{ t('在控制台上（Pod Cloud）') }}</h2>
      <ul>
        <li>{{ t('跨机器总览：每台机器最近同步时间、装的是哪一版') }}</li>
        <li>{{ t('健康状态：审计链是否完整、网关最近有没有活动、还有多少个 MCP server 绕过网关（按机器去重，不是按绑定累加）') }}</li>
        <li>{{ t('资产清单：每台机器上有哪些 harness、哪些已纳管，哪些 server 经过网关') }}</li>
        <li>{{ t('发现汇总：漏洞扫描与控制平面姿态的结果，按威胁与级别聚合；修好后自动消失') }}</li>
        <li>{{ t('分发与响应：策略下发、规则包订阅（本地验签 + 放宽守卫）、远程熔断（机器下次同步时收敛）') }}</li>
      </ul>
    </section>

    <section class="block">
      <h2>{{ t('数据边界') }}</h2>
      <ul>
        <li>{{ t('只上哈希与摘要：工具参数与输出只留哈希；资产与发现只出标识与计数——没有路径、没有配置原文') }}</li>
        <li>{{ t('云端不在调用路径上：判定与拦截全在本机，云端不可用不影响 Agent 工作') }}</li>
        <li>{{ t('判定口径归你：风险模式、阈值、可信来源都在本机的 rules.json；写错会 fail-closed 报错，不静默回退默认值') }}</li>
      </ul>
    </section>

    <section class="block">
      <h2>{{ t('明确不做的') }}</h2>
      <ul>
        <li>{{ t('不做沙箱或进程隔离：需要强隔离时用平台原生沙箱或容器，我们负责策略与证据') }}</li>
        <li>{{ t('看不到 harness 原生工具路径的全部动作：MCP 边界与已接 hook 之外的部分只能发现与取证') }}</li>
        <li>{{ t('不做模型对话的内容审查：我们判定的是行为，不是语义') }}</li>
      </ul>
    </section>

    <section class="block">
      <h2>{{ t('交付方式') }}</h2>
      <ul>
        <li>{{ t('本地：开源 CLI（pod，Apache-2.0），跑在你自己的机器上；pod --version 可自查版本') }}</li>
        <li>{{ t('云端 SaaS：浏览器打开控制台即可使用，无需安装；同一套代码也支持私有化部署（Docker Compose / Kubernetes）') }}</li>
      </ul>
    </section>

    <section class="block">
      <h2>{{ t('适用对象') }}</h2>
      <p class="block__p">{{ t('使用 AI 编码与自动化 Agent、需要向客户或审计方交代「Agent 能碰什么、做过什么」的团队。') }}</p>
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
