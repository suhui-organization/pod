# 发布流程（每次发版 / 发内容都走这份）

> 这份文件是**流程本身**，不是某次发布的记录。任何一次对外动作（发版本、发文章、
> 发公告）之前，按下面的顺序执行；顺序不是偏好，是转化路径决定的。

## 一、发布顺序（固定）

### 阶段 A：发版（产品）

| # | 步骤 | 完成标准 |
|---|---|---|
| A1 | 跑全量门禁 | 本地 `pnpm test`、云端 `pytest`、前端 `npm run build` 全绿 |
| A2 | 跑 `bash scripts/preflight-publish.sh` | 26 项全过（含干净环境安装 + 主路径冒烟） |
| A3 | 更新 `CHANGELOG.md` | 新增版本条目：做了什么 / 已知边界 |
| A4 | 三处版本号一起改 | `CHANGELOG.md`、`scripts/install.sh` 的默认 `POD_VERSION`、`README.md` 的 `raw/<tag>` 链接 |
| A5 | 版本号改动走 PR 合并，再打 tag 推双远端 | 分支上改完 → 开 PR → CI 全绿 → 合并；`git tag -a vX.Y.Z` → `git push github vX.Y.Z` + `git push gitee vX.Y.Z` |
| A6 | 建 Release | GitHub 用 `gh release create`（正文取 CHANGELOG 该节）；Gitee 手动建或给令牌 |
| A7 | 验证钉版本安装链接 | `bash scripts/preflight-publish.sh` 第 5 项已覆盖；或手动 curl 一次 |
| A8 | 看一眼仓库页的 Sponsor 按钮 | 右上角出现 **Sponsor**（`.github/FUNDING.yml` 指向的账号已开通 GitHub Sponsors 并有公开档位；文件必须在默认分支 main 上——三条缺一条就是**静默不显示**，不会报错） |

**为什么 A4 必须是三处一起改**：`install.sh` 决定克隆哪份代码，README 决定用哪份
脚本。只改一处 = "旧脚本 + 新代码" 或 "新链接 + 老代码"，发布版形同虚设。

**为什么 A5 不能直接推 main**：`main` 开了分支保护——必须走 PR、必须 CI 四项
（`test` / `local-smoke` / `cloud-server` / `cloud-web`）全绿、禁止强推与删除，
而且对管理员同样生效（`enforce_admins`）。实测被拒的样子：

```
remote: - Changes must be made through a pull request.
remote: - 4 of 4 required status checks are expected.
! [remote rejected] main -> main (protected branch hook declined)
```

tag 不受分支保护影响，所以"发版"这一步照旧一条命令推上去。

**维护者也不走例外**。这条保护对管理员同样生效（`enforce_admins`），是刻意的：
门禁对谁软，谁就是绕过门禁的那条路。真要直推（比如线上炸了等不了 CI），按这个
顺序做，**留痕优先于速度**：

1. 先在 GitHub 开一个 issue 写清"为什么不能等 CI"（哪怕一句话）；
2. Settings → Branches → 临时 Disable；
3. 推完**立刻开回来**，并在那个 issue 里补上 commit 链接与恢复时间。

开着的这几分钟等于没有闸门——所以第 3 步不是可选项。

### 阶段 B：发内容（固定顺序 02 → 01 → 03 → 04）

顺序就是读者的认知路径：**先给能立刻上手的东西，再给恐惧感，再给框架，最后给深度**。

| 顺位 | 文件 | 渠道 | 为什么排这个位置 |
|---|---|---|---|
| 1 | [02-quickstart.md](content/02-quickstart.md) | GitHub / 即刻 / V2EX | 门槛最低：五分钟能跑出第一条审计记录。**先发它**，评论区和转发都接得住"我也装了"。转化锚点：`pod scan` 的输出截图 |
| 2 | [01-scan-report.md](content/01-scan-report.md) | GitHub / 即刻 / V2EX / HN | 有具体数字的"我扫了自己的机器"，自带传播性（恐惧 + 可复现）。把上一批装过的人的注意力推回 `scan` |
| 3 | [03-owasp-101.md](content/03-owasp-101.md) | GitHub / 即刻 / V2EX / HN | 承接 OWASP 的长期搜索流量：框架解释 + 每条给一个动作。**长尾资产**，晚发但寿命最长 |
| 4 | [04-forensics.md](content/04-forensics.md) | GitHub / 即刻 / V2EX / HN | 面向已装用户展示深度（取证/证据包），也是把本地用户引向云端控制平面的自然位置 |

每篇发布前逐条过下面的检查（`preflight-publish.sh` 已自动化大部分）：

1. **安装命令**：必须是钉在发布版上的链接；不能用未发布的 npm 包。
2. **每条命令真跑过一遍**：在干净环境里执行，不是"看起来对"。
3. **外部事实去源头核**：OWASP 编号、链接、版本号。仓库里抄了两遍的错误最像对的。
4. **样例输出逐字对齐真实输出**：审批 id、timestamps、字段名都不许凭印象写。
5. **数据可复现**：文章里的数字要能在当前机器上重扫出来（注明采集时间）。
6. **边界说清楚**：不做什么（协议本体/沙箱）要写出来，别让读者自己发现。

### 阶段 C：发渠道适配（每篇按渠道改写，不复制粘贴）

| 渠道 | 改写要求 |
|---|---|
| GitHub（仓库/Release） | 保留完整命令与输出样例；链接用相对路径互链 |
| HN / Reddit | 英文；去掉营销形容词，第一段就说"这是什么、解决什么问题"；准备好被问"和 X 有什么区别"（答案是 README 的对比表） |
| 即刻 / V2EX | 短；一张图 + 三行结论 + 安装命令；把长文链接放最后 |
| X / 微博 | 只发一条结论 + 一条命令 + 一张截图 |

## 二、发布后必做

| 项 | 为什么 |
|---|---|
| 记录发布时间与渠道 | 下个版本要看"哪篇带来了 star/安装" |
| 抽样跑一次读者路径 | 从文章里的链接开始，完整走一遍安装——链接失效、tag 被删、脚本改动都会在这一步暴露 |
| 看一次 Sponsor 转化 | 有没有人真的点（Sponsors 后台的 views → sponsors）。按钮存在 ≠ 有人看见：入口只在仓库页右上角，文章里也要给一次文字链接 |
| 收集失败案例到本文件 | 读者踩到的坑写进"每篇发布前逐条过"的清单，下次自动被 `preflight-publish.sh` 覆盖 |

## 三、这套顺序的来历

每一条检查都对应一次真实翻车（2026-09-12 那次内容校订）：

- 四篇文章都写着 `npm i -g @podsec/cli` —— **该包在 npm 上不存在（404）**；
- OWASP 编号写成自编的 `AG-01..AG-10` —— 官方是 `ASI01–ASI10`；
- 链接指向 `github.com/podsec/pod` —— 不存在的仓库；
- `pod serve` 示例用 `npx` 起，被策略的来源白名单拦下（T4 正常工作）；
- 审批 id 样例写成 `filesystem-3` —— 真实格式是 `<server>-<pid>-<序号>`。

所以 `scripts/preflight-publish.sh` 检查的不是"代码风格"，而是**"读者照着做会不会失败"**。
