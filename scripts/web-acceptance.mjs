#!/usr/bin/env node
/**
 * 控制台「真机逐页验收」的浏览器驱动（零依赖）。
 *
 * 由 scripts/web-acceptance.sh 调用：那个脚本负责端口转发、起 dev server、
 * 结束后清理；这里只做三件事——开一个无头 Chrome、登录、把每个页面点一遍并断言。
 *
 * 断言两条（缺一不可，见 README 的说明）：
 *   1. 页面**真的渲染出内容**了（行数 ≥ --min-lines）——否则"空白页"也会被当成"没有中文"；
 *   2. 页面上**没有非数据的中文**（数据 = 登录账号自己的名字、机器同步上云的审计原文）。
 *
 * 为什么不用 Playwright：仓库不想为一个验收脚本引入浏览器依赖。Node ≥22 自带
 * 全局 WebSocket，直接讲 CDP 就够，Chrome 用系统装好的那个。
 */
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const args = new Map()
for (let i = 2; i < process.argv.length; i += 2) {
  args.set(process.argv[i].replace(/^--/, ''), process.argv[i + 1])
}
const BASE = (args.get('base') ?? 'http://127.0.0.1:15199').replace(/\/+$/, '')
const EMAIL = args.get('email') ?? ''
const PASSWORD = args.get('password') ?? ''
const TOKEN = args.get('token') ?? ''
const LOCALE = args.get('locale') ?? 'en-US'
// 默认 8 行：曾经设成 4，结果 /settings 只渲染出 5 行（模型面板的接口挂了、页面半空）
// 也算"通过"——空白/半渲染页面本来就没有中文，正是最容易骗过验收的形态。
const MIN_LINES = Number(args.get('min-lines') ?? 8)
const CHROME = args.get('chrome') ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'

const ROUTES = ['/', '/agents', '/alerts', '/timeline', '/control-plane', '/traces', '/policies', '/rules', '/harden', '/subscription', '/users', '/profile', '/settings']

// 允许保留中文的"数据"：账号自己的名字 + 机器同步上云的审计原文（进过哈希链，按设计不翻）
const DATA_PATTERNS = [
  /^posture:/, /^quarantine:/, /^anomaly:/, /^delegation:/, /^grant:/, /^llm-call:/,
  /^\d{4}年/, // 审计原文里的中文日期
]

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// ---------- 最小 CDP 客户端 ----------
class Cdp {
  constructor(ws) {
    this.ws = ws
    this.id = 0
    this.pending = new Map()
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data)
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id)
        this.pending.delete(msg.id)
        msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result)
      }
    })
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
      this.ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }))
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id)
          reject(new Error(`CDP 超时: ${method}`))
        }
      }, 20000)
    })
  }
}

function launchChrome(userDataDir) {
  const child = spawn(
    CHROME,
    [
      '--headless=new',
      '--remote-debugging-port=0',
      `--user-data-dir=${userDataDir}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-gpu',
      '--window-size=1440,900',
    ],
    { stdio: ['ignore', 'ignore', 'pipe'] },
  )
  return new Promise((resolve, reject) => {
    let buf = ''
    const onData = (chunk) => {
      buf += String(chunk)
      const m = buf.match(/ws:\/\/127\.0\.0\.1:\d+\/devtools\/browser\/[a-f0-9-]+/)
      if (m) {
        child.stderr.off('data', onData)
        resolve({ child, wsUrl: m[0] })
      }
    }
    child.stderr.on('data', onData)
    child.on('exit', (code) => reject(new Error(`Chrome 退出，code=${code}`)))
    setTimeout(() => reject(new Error('等待 Chrome 的 DevTools 端口超时')), 20000)
  })
}

// ---------- 页面操作 ----------
const evalJs = async (cdp, sid, expression) => {
  const r = await cdp.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, sid)
  if (r.exceptionDetails) throw new Error(`页面脚本报错: ${r.exceptionDetails.text}`)
  return r.result.value
}

async function waitFor(cdp, sid, expression, timeoutMs = 15000, label = '') {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await evalJs(cdp, sid, expression)) return true
    await sleep(250)
  }
  throw new Error(`等待超时${label ? `（${label}）` : ''}: ${expression}`)
}

async function goto(cdp, sid, path, settleMs = 1400) {
  await cdp.send('Page.navigate', { url: `${BASE}${path}` }, sid)
  await waitFor(cdp, sid, `document.readyState === 'complete'`, 15000, 'load')
  await sleep(settleMs) // 等接口回来 + 图表渲染
}

/**
 * 页面里非数据的中文行（只看 <main>，侧边栏是导航不需要每页重复断言）。
 *
 * 头像会取姓名首字（"管理员" → "管"），所以**名字的前缀**也算数据：
 * 判定规则是"这一行是某个账号名的前缀，且不超过 3 个字"。
 */
const collectChinese = (names) =>
  `(() => {
    const main = document.querySelector('main') || document.body
    const lines = main.innerText.split('\\n').map((s) => s.trim()).filter(Boolean)
    const names = ${JSON.stringify(names)}
    return {
      total: lines.length,
      chinese: lines
        .filter((s) => /[\\u4e00-\\u9fa5]/.test(s))
        .filter((s) => !names.some((n) => n && (s.includes(n) || (s.length <= 3 && n.startsWith(s))))),
    }
  })()`

// ---------- 主流程 ----------
let chrome
let userDataDir
let cdp
try {
  userDataDir = mkdtempSync(join(tmpdir(), 'pod-web-accept-'))
  const launched = await launchChrome(userDataDir)
  chrome = launched.child
  const ws = new WebSocket(launched.wsUrl)
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve, { once: true })
    ws.addEventListener('error', () => reject(new Error('连接 Chrome DevTools 失败')), { once: true })
  })
  cdp = new Cdp(ws)
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' })
  const { sessionId: sid } = await cdp.send('Target.attachToTarget', { targetId, flatten: true })
  await cdp.send('Page.enable', {}, sid)
  await cdp.send('Runtime.enable', {}, sid)

  // 每个新文档生效前，把界面语言钉死（顺带注入 token，如果有）
  const bootstrap = [
    `localStorage.setItem('podcloud_locale', ${JSON.stringify(LOCALE)})`,
    TOKEN ? `localStorage.setItem('podcloud_token', ${JSON.stringify(TOKEN)})` : '',
  ].filter(Boolean).join(';')
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: bootstrap }, sid)

  // ---- 登录 ----
  await goto(cdp, sid, '/login', 800)
  if (!TOKEN) {
    if (!EMAIL || !PASSWORD) throw new Error('缺少 --email/--password（或用 --token）')
    const filled = await evalJs(
      cdp,
      sid,
      `(() => {
        const inputs = [...document.querySelectorAll('input')]
        const email = inputs.find((i) => i.type === 'email' || /邮箱|email/i.test(i.placeholder || ''))
        const pwd = inputs.find((i) => i.type === 'password')
        if (!email || !pwd) return false
        const set = (el, v) => { el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); el.dispatchEvent(new Event('change', { bubbles: true })) }
        set(email, ${JSON.stringify(EMAIL)}); set(pwd, ${JSON.stringify(PASSWORD)})
        const btn = [...document.querySelectorAll('button')].find((b) => /sign in|登录/i.test(b.innerText || ''))
        if (!btn) return false
        btn.click(); return true
      })()`,
    )
    if (!filled) throw new Error('登录表单没找到（选择器变了？）')
    await waitFor(cdp, sid, `location.pathname !== '/login'`, 15000, '登录完成')
  } else {
    await goto(cdp, sid, '/', 1200)
  }
  const account = await evalJs(cdp, sid, `localStorage.getItem('podcloud_email') || ''`)
  // 账号名（自己 + 同租户成员）都要算"数据"：头像会取首字，页面上就剩一两个汉字
  const names = await evalJs(
    cdp,
    sid,
    `(async () => {
      const out = []
      for (const k of ['podcloud_fullname', 'podcloud_email']) {
        const v = localStorage.getItem(k); if (v) out.push(v)
      }
      try {
        const r = await fetch('/api/v1/users', { headers: { Authorization: 'Bearer ' + (localStorage.getItem('podcloud_token') || '') } })
        if (r.ok) {
          const data = await r.json()
          for (const u of (Array.isArray(data) ? data : (data.items || data.users || []))) {
            for (const k of ['full_name', 'display_name', 'name', 'email']) if (u && u[k]) out.push(String(u[k]))
          }
        }
      } catch {}
      return [...new Set(out.filter(Boolean))]
    })()`,
  )
  console.log(`\n已登录：${account}（语言 ${LOCALE}），账号名白名单 ${names.length} 条\n`)

  // ---- 逐页断言 ----
  const failures = []
  const isData = (s) =>
    DATA_PATTERNS.some((re) => re.test(s)) ||
    names.some((n) => n && (s.includes(n) || (s.length <= 3 && n.startsWith(s))))
  for (const route of ROUTES) {
    await goto(cdp, sid, route)
    // 页面侧自己再过一遍白名单（脚本侧的 isData 只用于弹窗那一段）
    const got = await evalJs(cdp, sid, collectChinese(names))
    const toFix = (got.chinese || []).filter((s) => !isData(s))
    const ok = got.total >= MIN_LINES && toFix.length === 0
    console.log(`${ok ? '✅' : '❌'} ${route.padEnd(16)} 内容 ${String(got.total).padStart(3)} 行${toFix.length ? `  中文：${toFix.slice(0, 2).join(' | ').slice(0, 120)}` : ''}`)
    if (!ok) failures.push({ route, total: got.total, toFix })
  }

  // ---- 弹窗（接入命令那条，历史上最容易漏）----
  await goto(cdp, sid, '/agents')
  const opened = await evalJs(
    cdp,
    sid,
    `(() => { const b = [...document.querySelectorAll('button')].find((x) => /add agent|添加/i.test(x.innerText || '')); if (!b) return false; b.click(); return true })()`,
  )
  if (opened) {
    await sleep(1200)
    const dlg = await evalJs(
      cdp,
      sid,
      `(() => { const d = [...document.querySelectorAll('.el-dialog, [role=dialog]')].find((x) => (x.innerText || '').trim().length > 0); return d ? d.innerText : '' })()`,
    )
    const cn = dlg.split('\n').map((s) => s.trim()).filter((s) => s && /[\u4e00-\u9fa5]/.test(s)).filter((s) => !isData(s))
    const ok = dlg.trim().length > 0 && cn.length === 0
    console.log(`${ok ? '✅' : '❌'} ${'弹窗 /agents'.padEnd(16)} ${dlg.trim() ? '有内容' : '没渲染出来'}${cn.length ? `  中文：${cn.slice(0, 2).join(' | ')}` : ''}`)
    if (!ok) failures.push({ route: '弹窗 /agents', total: 0, toFix: cn })
  } else {
    console.log('⚠️  弹窗 /agents      没找到入口按钮，跳过')
  }

  console.log()
  if (failures.length === 0) {
    console.log(`验收通过：${ROUTES.length + 1} 项全绿（内容足够 + 无非数据中文）`)
    process.exitCode = 0
  } else {
    console.log(`验收未通过：${failures.length} 项待处理`)
    process.exitCode = 1
  }
} catch (err) {
  console.error(`\n验收脚本自身出错：${err instanceof Error ? err.message : String(err)}`)
  process.exitCode = 2
} finally {
  try { chrome?.kill() } catch {}
  await sleep(300)
  try { userDataDir && rmSync(userDataDir, { recursive: true, force: true }) } catch {}
}
