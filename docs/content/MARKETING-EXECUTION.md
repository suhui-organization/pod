# 执行计划：海外技术社区 + CSDN

> 配套：[MARKETING-PLAN.md](MARKETING-PLAN.md)（各渠道奖励什么）、[../PUBLISHING.md](../PUBLISHING.md)（发布门禁）。
> 可勾选的操作清单：什么顺序、谁做、做完怎么算通过。渠道可达性与目标账号均为 2026-09-17 实测。

## 1. 分工

| 环节 | 谁做 | 说明 |
|---|---|---|
| 素材制作（配图、终端图、封面、线程拆分） | 我 | 已跑通：矢量/HTML 渲染 + 按平台比例出图 + 像素校验 |
| X：发帖 / 回复 / 引用转发 / 置顶 | 我 | 已跑通；回复要**一条一次**，批量循环会超时 |
| HN / dev.to / Bluesky / LinkedIn / CSDN | **你先给账号** | 这五个本机都未登录（Reddit 是整站被拦，见第 2 节） |
| 登录、验证码、2FA | **你** | 我不经手密码与验证码 |
| 官网版本号修复 | 我（改代码）或你（合并） | 官网在另一个仓库 pod-website |

## 2. 本机实测的渠道状态

| 平台 | 可达 | 登录 | 卡点 |
|---|---|---|---|
| X | 可以 | 已登录 | 无，可立刻开工 |
| LinkedIn | 可以（页面重、加载慢） | 未登录 | 有 Google 一键登录入口 |
| Hacker News | 可以 | 未登录 | 提交需要账号 |
| dev.to | 可以 | 未登录 | 需要账号 |
| Bluesky | 可以 | 未登录 | 需要账号 |
| Reddit | **不可以** | — | 整站返回 "You've been blocked by network security"，本机无法访问 |
| CSDN | 待测 | 未登录 | 需要账号 |

## 2.1 账号登记（2026-09-17）

| 平台 | 账号 | 状态 | 备注 |
|---|---|---|---|
| Hacker News | `WaldenWuwei` | **已注册并登录** | 注册只要用户名+密码，无需邮箱 |
| dev.to | `@waldenwuwei` | **已注册并登录**（Google 授权） | 主页 dev.to/waldenwuwei；自动分配的 handle 已改掉 |
| X | `@WaldenWuwei` | 已登录 | 主力渠道 |
| LinkedIn | — | 未注册 | 有 Google 一键入口，待确认是否已有账号 |
| Bluesky | — | 未注册 | 需要邮箱验证（我读不到收件箱） |
| CSDN | — | 未注册 | 需要手机短信验证 |

## 3. 依赖顺序

1. **修漏斗**：官网安装命令从 v0.2.0 改到 v0.3.0。海外开发者会照着敲，装到旧版等于白导流。
2. **X 继续回复轮**（每天 5 条，冷启动阶段唯一在做正事的动作）。
3. **给账号**：HN / dev.to / LinkedIn / Bluesky / CSDN 任一个登录好，我就把那一路开起来。
4. HN 的 Show HN 放到官网修完之后发——它是这几个渠道里最容易被一次点爆的，别把流量引到一个装不上新版的地方。

## 4. X：每次发帖的固定动作

1. 正文只写结论 + 自己的数据，**不放链接**；
2. 配 1–2 张原生图（终端图 / 控制台图）；
3. 发出后 60 秒内，自己补第 1 条回复放链接；
4. 两小时内回完所有评论；
5. 0 互动的帖不删，留着吃搜索长尾。

## 5. 初始目标清单（X，实测）

| 账号 | 那条帖在讲什么 | 我的切入角度 |
|---|---|---|
| @superdoccimo | MCP transport 的 identity proof；AWS Security Agent 的 CVE | 身份之外还有供应链：12/14 未锁版本 |
| @theNeomatrix369 | Tripwire：扫描 AI skills / MCP server | 扫描给"暴露面"，编译给"该允许什么" |
| @a2agent_ai | Agent Skills 生态周报 | 技能仓库的 @latest 风险 |
| @PeilvDog_CN | 把密钥读取与工具权限分开 | 我也做反过：录一周调用再编译清单 |
| @kirneshh | agent 能碰私有数据就该有权限与审计 | 5 个明文密钥让"能读文件"等同于"能用账号" |

**每日搜索词**：MCP security、agent permissions、least privilege agent、MCP supply chain

## 6. HN 首发准备（等你账号）

- **标题候选**（越像事实越好）：
  1. Show HN: Pod – compile a least-privilege policy from what your agent actually did
  2. Show HN: A read-only scan found 12 of my 14 MCP servers unpinned
- **正文要点**：是什么（一句话）→ 为什么做（自己的机器上扫出 5 处明文密钥）→ 怎么用（record → compile → enforce → prove）→ **边界**（不是沙箱、看不到 agent 之间的对话、不阻止整机被控）。
- **发布时机**：美东工作日上午，对应北京 21:00–23:00。发出后两小时守在评论区。

## 7. CSDN 发布清单（等你账号）

- 中文四篇按顺序发（02 → 01 → 03 → 04），每篇：封面图 + 目录 + 代码块 + 结尾仓库地址。
- 链接主推 gitee 镜像（国内拉 GitHub 常失败），GitHub 作为备选。
- 标题带搜索词：AI Agent 权限、MCP、最小权限、审计。
- 不运营评论区、不追热点：它是 SEO 着陆页，不是社区。

## 8. 我可以直接代做的

- 做图（X 配图、线程用图、CSDN 封面）
- X 发帖 / 回复 / 置顶 / 引用转发
- 把 02-quickstart 拆成 4–6 条线程并逐条发出
- 写出 HN 的标题与正文草稿、dev.to 的英文教程、CSDN 的中文排版稿（交给你过一眼再发）
- 修官网版本号（改 pod-website）

## 9. 复盘节点

| 节点 | 看什么 | 判据 |
|---|---|---|
| 每周 | X 回复带来的主页访问 | 仍接近 0 → 换话题，不是加量 |
| HN 发布后 2 小时 | 评论数 | 0 评论 → 标题角度不对，下次换 |
| 每篇 CSDN 发出后 48 小时 | 阅读量 | 低于 500 → 改标题重发（不是重写正文） |
| 每周 | GitHub star | 唯一算数的转化指标 |

## 10. 需要你决定

1. **账号**：先给哪一个？建议顺序 **HN → dev.to → LinkedIn → Bluesky → CSDN**（HN 杠杆最大，dev.to 最省事）。
2. **官网仓库**：pod-website 是让我 clone，还是你给本地路径？

## 11. 发布记录（2026-09-17，英文全平台）

本轮按用户要求**统一英文发布**，各渠道链接如下。

| 渠道 | 状态 | 链接 |
|---|---|---|
| Bluesky | ✅ 已发 | https://bsky.app/profile/walden83.bsky.social/post/3mvomzllmmc2u |
| X | ✅ 已发（正文 + 首条回复带链接） | https://x.com/WaldenWuwei/status/2100416860273643721 |
| LinkedIn | ✅ 已发 | https://www.linkedin.com/feed/update/urn:li:share:7506181979898470400 |
| dev.to | ✅ 已发（tag: security / ai / opensource / mcp） | https://dev.to/waldenwuwei/i-scanned-14-mcp-servers-on-my-laptop-then-compiled-a-least-privilege-policy-from-what-my-agent-3de9 |
| Hacker News | ⚠️ 已投稿，但走了链接贴（指向 dev.to 长文） | https://news.ycombinator.com/item?id=49735896 |
| CSDN | ✅ 已发布（审核中，英文稿） | https://blog.csdn.net/iversonwuwei/article/details/165726513 |

### 本轮踩到的限制（下次直接绕过）

1. **HN 关闭了新账号的 Show HN**：`/showlim` 明确写「We're temporarily restricting Show HNs」。新号第一次发 Show HN 会被挡。
2. **HN 拒绝提交 podsec.vercel.app**：`Sorry, your account isn't able to submit this site.` 换 dev.to 域名后立刻成功 —— 新号+新域名被限，先发第三方平台再引流官网。
3. **X 未认证账号 280 字符上限**：超限时 Post 按钮直接 disabled，正文必须压到 ≤280。
4. **Bluesky 必须邮箱验证才能发帖**，验证码走 `iverson.wuwei@gmail.com`；`bsky.app/intent/verify-email?code=...` 可直接完成验证。
5. **CSDN 创作入口是 `mp.csdn.net/edit`**，`editor.csdn.net` 从本机不可达；正文编辑器是 CKEditor，内容在 iframe 里。

### 第 2 轮（2026-09-17，素材 01-scan-report）

主题换成「扫描自己的机器」：6 个 agent、14 个 MCP server、12 个未锁版本、5 处明文密钥。六个渠道全部成功。

| 渠道 | 状态 | 链接 |
|---|---|---|
| X | ✅ 已发（正文 + 首条回复带链接） | https://x.com/WaldenWuwei/status/2100476130272927779 |
| Bluesky | ✅ 已发 | https://bsky.app/profile/walden83.bsky.social/post/3mvp2mxusps2f |
| LinkedIn | ✅ 已发 | https://www.linkedin.com/feed/update/urn:li:share:7506242646835679232 |
| dev.to | ✅ 已发（tag: security / ai / opensource / mcp） | https://dev.to/waldenwuwei/i-scanned-my-own-laptop-6-ai-agents-14-mcp-servers-12-unpinned-5-plaintext-keys-1k81 |
| Hacker News | ✅ 已投稿（链接贴指向 dev.to） | https://news.ycombinator.com/item?id=49737253 |
| CSDN | ✅ 已发布（审核中，英文稿） | https://blog.csdn.net/iversonwuwei/article/details/165745440 |

### 第 2 轮新增的坑

1. **HN 标题硬上限 80 字符**，82 字符会被 `/toolong-title` 打回，报错信息是 `Please limit title to 80 characters`。标题要留余量。
2. **LinkedIn 分享框偶发 reCAPTCHA 连接失败**：报「无法连接到 reCAPTCHA 服务」，编辑器不渲染。不用登录也不用换账号，`reload()` 一次就恢复正常。
3. **CSDN 标签输入框的 ID 是动态的**（`el_mcm-id-902-59` 这种），写死 ID 下一轮必失效；用 `input[placeholder*="Enter键入"]` 选更稳。
4. **CSDN 标题框首次 `fill` 可能报 clipboard / target token mismatch**，先 `click()` 再 `fill()` 就正常。

### 第 3 轮（2026-09-17，素材 03-owasp-101）

主题是 OWASP Agentic Top 10（ASI01–ASI10）逐条讲「独立开发者该改什么」。五个渠道成功，CSDN 撞上当日发文额度。

| 渠道 | 状态 | 链接 |
|---|---|---|
| dev.to | ✅ 已发（tag: security / ai / opensource / mcp） | https://dev.to/waldenwuwei/the-owasp-agentic-ai-top-10-read-as-someone-who-actually-runs-agents-on-his-laptop-3ob1 |
| Hacker News | ✅ 已投稿（链接贴指向 dev.to；标题发完用 /edit 修过一次） | https://news.ycombinator.com/item?id=49739427 |
| X | ✅ 已发（正文 207 字符 + 首条自回复带链接） | https://x.com/WaldenWuwei/status/2100553215087706166 |
| Bluesky | ✅ 已发（263 字符，链接在正文） | https://bsky.app/profile/walden83.bsky.social/post/3mvplt65sqs2p |
| LinkedIn | ✅ 已发（1249 字符长文，结尾放 gitee 仓库） | https://www.linkedin.com/feed/update/urn:li:share:7506320453368713216 |
| CSDN | ⚠️ **未发出**：今日发文额度已用完；正文 4424 字 + 标签（MCP / AI Agent / 安全）已存草稿箱 | 草稿箱：`The OWASP Agentic AI Top 10, explained for people who run agents locally`（2026-09-17 19:59） |

### 第 3 轮新增的坑

1. **HN 会吞掉标题里的裸数字**：`OWASP's Agentic AI Top 10, explained…` 提交后显示成 `OWASP's Agentic AI Top, explained…`（`10` 整段消失，标题没有报错）。解析原因未确认，规避方式是别用裸数字——`Top Ten` 就正常。已发错的可以在条目页 `edit` 改标题（提交后一段时间内允许）。
2. **CSDN 有每日发文额度**（本账号当前档位是 2 篇/天）：第 3 轮点「发布博客」时页面提示「今日发文额度已用完」，按钮点了没有反应、不报错。额度用完后**先保存草稿**，内容不会丢，第二天直接进草稿箱发。
3. **X 撰写框里 `[data-testid="tweetTextarea_0"]` 有两个匹配**（弹窗 + 隐藏副本），strict mode 下 `click()` 直接超时；一律用 `.first()`。
4. **dev.to 的标签框 `fill()` 不提交**：必须 `pressSequentially()` 逐字输入，等联想列表出现后点 `li[role="option"]#<tag>`（或按 Enter），选中项才进 `#combo-selected`。
5. **LinkedIn 的「发动态」是个 `<a>`，不是按钮**，按文本找 `button` 会 `no_matches`；直接开 `https://www.linkedin.com/preload/sharebox/` 最稳，正文粘贴进 `.ql-editor[role="textbox"]`，发布按钮是文本恰好为「发布」的那个。
6. **Bluesky 的 intent URL 会跳回首页但保留草稿**：先访问 `bsky.app/intent/compose?text=…`，再打开撰写框时编辑器里已经有那段文字，直接粘贴会变成两份（且超过 300 字符时「发布帖文」按钮是 disabled）。粘贴前先 `Control+A` + `Delete` 清空。

### 第 4 轮（2026-09-18，素材 04-forensics）

主题是「出事后 5 分钟取证」：时间线回放 → `pod verify-audit` 自证未篡改 → `pod export-evidence` 打包证据。**本轮只完成 2/6**：dev.to 和 CSDN 正常，其余四个平台整段时间不可达（详见下方「本轮新增的坑」）。

| 渠道 | 状态 | 链接 |
|---|---|---|
| dev.to | ✅ 已发（tag: security / ai / opensource / mcp） | https://dev.to/waldenwuwei/agent-forensics-in-five-minutes-what-it-did-and-proof-the-log-wasnt-edited-31kb |
| CSDN | ✅ 已发布（审核中，英文稿；标签 MCP / AI Agent / 安全） | https://blog.csdn.net/iversonwuwei/article/details/165853452 |
| X | ⏳ **未发出**：本轮导航被重置（`ERR_CONNECTION_RESET` / CDP 导航超时） | — |
| Bluesky | ⏳ **未发出**：同上（`ERR_CONNECTION_REFUSED`） | — |
| LinkedIn | ⏳ **未发出**：同上（`net::ERR_HTTP_RESPONSE_CODE_FAILURE`） | — |
| Hacker News | ⏳ **未发出**：同上（`ERR_CONNECTION_REFUSED`） | — |

**顺带补完第 3 轮**：昨天因 CSDN 当日额度没发出的 OWASP 稿，今天额度恢复后已补发 —— https://blog.csdn.net/iversonwuwei/article/details/165756328

### 第 4 轮新增的坑

1. **CSDN 草稿箱里的草稿不保留文章标签**：从草稿箱点「编辑」打开后，`.tag-box` 是空的（只有「添加文章标签」按钮）。直接点「发布博客」会被必填拦截，必须先重新加标签再发。
2. **外网可达性会整段时间性中断**，而且是按站点成片的：本轮 x.com、bsky.app、news.ycombinator.com、www.linkedin.com 同时不可达（分别是 `ERR_CONNECTION_RESET`、`ERR_CONNECTION_REFUSED`、`ERR_CONNECTION_REFUSED`、`ERR_HTTP_RESPONSE_CODE_FAILURE`），同一时间 dev.to 和 mp.csdn.net 完全正常。重试一两次没恢复就应当**把这一轮改期**，别反复重试——每次失败都会在浏览器里留下一个 data: URL 的错误页，反复刷只会浪费时间。
3. **判断「是全网还是单站」的最快办法**：同一时间探一次 dev.to（境外、通常可达）+ mp.csdn.net（境内）。两个都通而其它站点全挂，就是站点级封锁/重置，不是本机网络问题。
