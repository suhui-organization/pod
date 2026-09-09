#!/usr/bin/env python3
"""Codex PostToolUse hook -> pod ingest.

背景：Codex（deepseek provider + exec 模式）不加载 MCP 工具，内置 shell/exec
调用不经过 pod 网关，Pod Cloud 里 Codex 活跃度一直是 0。

这个 hook 把每次 Codex 工具调用追加进本地哈希链（agent=codex,
server=codex-tools），再由 pod sync 推到云端。MCP 工具（已经过网关）跳过，
避免重复计数。

设计：绝不阻塞/破坏 agent——解析失败、pod 不可用、超时都静默退出。
"""
import json
import os
import subprocess
import sys


def _find_pod_bin() -> str:
    """定位真正的 pod CLI，跳过 PATH 里同名的 CocoaPods。

    CocoaPods 的 pod 是 bash 脚本，podsec CLI 的 shebang 是 node。
    """
    override = os.environ.get("POD_BIN")
    if override and os.path.exists(override):
        return override
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, "pod")
        if not (os.path.exists(candidate) and os.access(candidate, os.X_OK)):
            continue
        try:
            with open(os.path.realpath(candidate), "rb") as fh:
                first_line = fh.readline()
        except OSError:
            continue
        if b"node" in first_line:
            return candidate
    return "pod"


def main() -> int:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw)
    except Exception:
        return 0

    tool = event.get("tool_name") or "unknown"
    # 已经过 pod 网关的 MCP 工具跳过，避免重复审计
    if tool.startswith("pod-filesystem") or tool.startswith("mcp-server-"):
        return 0

    args = event.get("tool_input") or {}
    session = event.get("session_id") or "codex"
    reason = "codex-hook session=%s cwd=%s model=%s" % (
        session,
        event.get("cwd") or "",
        event.get("model") or "",
    )

    pod_bin = _find_pod_bin()
    cmd = [
        pod_bin, "ingest",
        "--agent", os.environ.get("POD_CODEX_AGENT", "codex"),
        "--server", os.environ.get("POD_CODEX_SERVER", "codex-tools"),
        "--tool", tool,
        "--decision", "allow",
        "--outcome", "ok",
        "--args", json.dumps(args, ensure_ascii=False),
        "--reason", reason,
        "--session", session,
    ]
    env = dict(os.environ)
    # pod 的 shebang 是 `#!/usr/bin/env node`；node 通常与 npm 安装的 pod 同目录
    if os.path.isabs(pod_bin):
        env["PATH"] = os.path.dirname(pod_bin) + os.pathsep + env.get(
            "PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
        )
    try:
        subprocess.run(
            cmd,
            check=False,
            timeout=10,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
