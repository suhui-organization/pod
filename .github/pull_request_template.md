## 做了什么


## 为什么


## 怎么验证的

- [ ] `pnpm test`
- [ ] `cd cloud/server && uv run pytest`
- [ ] `cd cloud/web && npm run build`
- [ ] 改到界面/文案时：`bash scripts/i18n-coverage.sh`（必要时 `bash scripts/web-acceptance.sh`）

> 只勾真正跑过的。没跑的那条写一句原因比空着好。

## 检查

- [ ] 没有提交密钥、审计数据、个人机器路径（仓库是公开的）
- [ ] 没有放宽既有的拦截规则（策略默认值 / 密钥正则 / 出口白名单）
- [ ] 新增的用户可见文案中英两边都有（否则英文界面会露出中文）
