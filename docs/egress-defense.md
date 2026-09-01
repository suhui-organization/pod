# Egress（数据外泄，T5）防线说明

## 架构事实（为什么网关层做不了完整 egress）

MCP server 是本地进程，它的出网流量（如 github server 调 API、文件 server 无出网）
**不经过 pod 网关**——网关只站在 agent 与 server 之间，看不见 server 的网络行为。

## 现实防线（按覆盖顺序）

1. **输出侧拦截（已实现，P0）**：`secrets.deny_output_matching` 在工具响应回到
   agent 前拦截密钥——覆盖"agent 把敏感内容带回 LLM 上下文"的主泄露路径。
2. **敏感路径拒绝（已实现，P0）**：`secrets.deny_input_paths` 阻止 agent 读取
   ~/.ssh、.env 等敏感文件——从源头减少可泄露内容。
3. **告警（已实现，P2）**：secret_leak / injection_suspect / deny_burst /
   approval_timeout → Webhook 通知（可接企业微信/钉钉/Slack）。
4. **网络层隔离（未内置，依赖部署环境）**：容器/VM 内对 MCP server 做 egress
   限制（如 k8s NetworkPolicy、macOS pf/socketfilter），仅允许必要域名出网。
   参考 DeepThinkHarness 的 fluvia-datasource-isolation 先例。
5. **LLM 调用层（产品边界外）**：agent 发送给 LLM 提供商的 prompt 内容，
   pod 看不到——若该场景是核心威胁（T5 高风险），需要 agent 侧插件或
   LLM 网关（如 Cloudflare AI Gateway）配合，属路线图外。

## 审计中的标记

- `secret_leak`：输出被拦截（HIGH 告警）
- `injection_suspect`：疑似提示注入（MEDIUM 告警，不阻断）
