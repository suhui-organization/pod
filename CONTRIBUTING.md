# 贡献指南 / Contributing

谢谢愿意花时间。请先读这一页——它主要讲**怎么提**，也就是**不要直接往 `main` 推**。

## 一、改代码的路径：fork → 分支 → PR

`main` 开了分支保护：**只有通过 Pull Request 才能合并**，并且必须等 CI 全绿。
直接 `git push` 到 `main` 会被拒绝（连维护者自己也被同一条规则拦，避免手滑）。

```bash
# 1. 在 GitHub/Gitee 上点 Fork，然后克隆你自己的 fork
git clone https://github.com/<你>/pod.git && cd pod

# 2. 开一条分支
git checkout -b fix/gateway-timeout

# 3. 改 → 本地跑门禁（见下一节）→ 提交

# 4. 推到你的 fork，然后开 PR 指向 main
git push origin fix/gateway-timeout
```

PR 描述里请写清：**做了什么 / 为什么 / 怎么验证的**。仓库里有 PR 模板，照着填就行。

> **合并后分支不删（仓库约定）**：PR 合进来之后，源分支留在远端不清理。
> 因为合并用的是 **squash**——main 上只留一个提交，而分支上的**增量提交**是这段
> 开发过程的唯一记录（谁在哪一步改了什么、中间试过什么）。删掉就再也拼不回来。
> 维护者整理仓库时别顺手清它们；远端出现一堆"看着已合并"的分支是**预期状态**。

## 二、提交前跑什么

按改动范围跑，全绿再提 PR（CI 也会跑同样的东西）：

```bash
pnpm test                                  # 本地 CLI / 网关 / 库（vitest）
cd cloud/server && uv run pytest           # 云端后端（pytest）
cd cloud/web && npm run build              # 控制台前端（vue-tsc + vite）
```

改到这些面时，另有专门的检查：

| 改了什么 | 多跑一条 |
|---|---|
| 文案 / 界面 / 中英切换 | `bash scripts/i18n-coverage.sh`（词表齐不齐） |
| 控制台页面 | `bash scripts/web-acceptance.sh`（真机逐页验收，需要 k8s 后端与账号） |
| 安装脚本 / README / 版本号 | `bash scripts/preflight-publish.sh --quick` |

两条硬规矩：

1. **不要提交密钥、审计数据、个人机器路径**。仓库是公开的——`~/.pod/` 下的任何东西都不要粘进来。
2. **不要放宽既有拦截规则**（策略默认值、密钥正则、出口白名单）。要放宽请单独开 issue 说明理由。

## 三、提交信息

中英混合，type/scope 用英文、描述用中文：

```
<类型>(<范围>): <中文描述>

<body：动机与取舍，回答"为什么这样改">
```

常用类型：`feat` / `fix` / `docs` / `refactor` / `test` / `chore`。范围如 `cli`、`gateway`、`cloud`、`web`、`i18n`。

## 四、安全漏洞：**不要开公开 issue**

发现可被利用的漏洞（绕过网关判定、审计链可篡改、凭证泄露等），请按 [SECURITY.md](SECURITY.md) 里写的方式私密联系维护者。公开 issue 会在修复前把利用方式告诉所有人。

## 五、语言 / Language

仓库文档以中文为主，代码注释与对外输出的英文按需补。控制台与 CLI 都支持中英切换（见 README 的「中文 / English」一节）——**新增文案请同时给两边**，否则英文界面会露出中文，覆盖率脚本会报出来。

If you prefer English: issues and PRs in English are welcome. The project ships bilingual (zh-CN / en-US) output; please keep both sides updated when you add user-facing text.
