# Pod Cloud Web — AI Agent 安全舱 · 控制平面前端

Vue 3 + Vite + TypeScript + Element Plus + Pinia + Vue Router + Axios + ECharts。

## 功能

- **总览**：审计事件趋势、决策分布、agent 健康度（ECharts）
- **Agent 资产**：一步添加 agent（只填名称），一键接入命令自动生成
- **时间线**：全量审计事件流（敏感内容仅显示哈希）
- **策略中心**：per-agent 策略查看与编辑
- **告警 / 订阅 / 成员管理 / 设置**

## 开发

```bash
pnpm install
pnpm dev
```

## 构建

```bash
pnpm build          # dist/ 产物
docker build -f deploy/Dockerfile -t podcloud-web:<tag> .
```

镜像内 nginx 反代 `/api/` 到后端，upstream 由环境变量注入：
`PODCLOUD_SERVER_UPSTREAM=podcloud-server:8000`

## 配套仓库

- [pod](https://gitee.com/suhuisoftwares/pod) — 本地网关 + CLI（开源核心）
- [podcloud-server](https://gitee.com/suhuisoftwares/podcloud-server) — SaaS 后端
