# 自动化（macOS launchd）

两个 LaunchAgent 让链路全自动：

| Label | 作用 | 频率 |
|-------|------|------|
| `com.podcloud.sync` | `pod sync` 推送审计到 Pod Cloud | 每 30 分钟 + 登录时 |
| `com.podcloud.port-forward` | 常驻转发 k8s `podcloud-web` → 127.0.0.1:18088 | 常驻（KeepAlive）|

## 管理命令

```bash
# 状态
launchctl list | grep podcloud

# 手动跑一次 sync（不等待定时器）
bash ~/.pod/pod-sync.sh

# 日志
tail -20 ~/.pod/logs/sync.log          # sync 结果
tail -20 ~/.pod/logs/port-forward.err.log  # 转发错误

# 停止/启动
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.podcloud.sync.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.podcloud.sync.plist
# port-forward 同理

# 卸载（删 plist + bootout）
```

## 依赖

- `pod` 全局命令（`npm link` 于 apps/cli；代码更新后 `pnpm -r build` 即可，链接不变）
- `kubectl` 在 PATH（plist 内写死 `/opt/homebrew/bin/kubectl`）
- k8s `podcloud` namespace 存在（部署见 DeepThinkHarness deploy/k8s/podcloud）

## 故障排查

- sync 日志 `fetch failed`：18088 不通 → 检查 `launchctl list | grep port-forward` 是否 exit 非 0、`kubectl get pods -n podcloud`
- 手动转发与常驻转发冲突：先 `pkill -f "port-forward svc/podcloud"` 再 bootstrap
