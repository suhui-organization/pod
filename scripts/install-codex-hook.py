#!/usr/bin/env python3
"""安装并信任 Codex PostToolUse hook（幂等）。

为什么需要这一步：Codex 对非托管 hook 有 trust gate。只把命令写进
~/.codex/hooks.json 是不够的——Codex 会静默跳过未信任的 hook，表现为
Pod Cloud 里 Codex 活跃度一直是 0。

信任状态存在 ~/.codex/config.toml 的 [hooks.state."<key>"]，值是 Codex
内部计算的 currentHash。这里不自己复刻哈希算法，而是通过 Codex 官方的
app-server JSON-RPC（hooks/list + config/batchWrite）读写，保证与 Codex
版本同步、命令一变就能自动重新信任。

用法:
  python3 scripts/install-codex-hook.py            # 安装 + 信任（幂等）
  python3 scripts/install-codex-hook.py --status   # 只报告当前信任状态
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_HOOK_SCRIPT = SCRIPT_DIR / "codex-post-tool-hook.py"
DEFAULT_HOOKS_FILE = Path.home() / ".codex" / "hooks.json"


class AppServer:
    """最小 codex app-server stdio 客户端（line-delimited JSON-RPC）。"""

    def __init__(self, codex_bin: str):
        self.proc = subprocess.Popen(
            [codex_bin, "app-server", "--listen", "stdio://"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self._q: queue.Queue = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()
        self._id = 0

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._q.put(line)
        self._q.put(None)

    def _send(self, method: str, params: dict | None) -> int:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        return self._id

    def request(self, method: str, params: dict | None = None, timeout: float = 30.0):
        want = self._send(method, params)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = self._q.get(timeout=1.0)
            except queue.Empty:
                continue
            if line is None:
                raise RuntimeError("codex app-server 提前退出")
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == want:
                if "error" in msg:
                    raise RuntimeError(f"{method} 失败: {msg['error']}")
                return msg.get("result")
        raise RuntimeError(f"{method} 超时")

    def initialize(self) -> None:
        self.request(
            "initialize",
            {
                "clientInfo": {"name": "pod-install-codex-hook", "version": "0.1.0"},
                "capabilities": {"experimentalApi": True},
            },
        )
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "initialized", "params": {}}) + "\n")
        self.proc.stdin.flush()
        time.sleep(0.3)

    def close(self) -> None:
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


def hook_command(script: Path) -> str:
    return f'python3 "{script}"'


def ensure_hook_installed(hooks_file: Path, command: str) -> bool:
    """把 PostToolUse hook 合并进 hooks.json，返回是否发生了修改。"""
    data: dict = {}
    if hooks_file.exists():
        try:
            data = json.loads(hooks_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{hooks_file} 不是合法 JSON: {exc}")
    hooks = data.setdefault("hooks", {})
    groups = hooks.setdefault("PostToolUse", [])

    for group in groups:
        for handler in group.get("hooks", []):
            if handler.get("command") == command:
                return False

    if groups and isinstance(groups[0].get("hooks"), list):
        groups[0]["hooks"].append({"type": "command", "command": command})
    else:
        groups.append({"hooks": [{"type": "command", "command": command}]})

    hooks_file.parent.mkdir(parents=True, exist_ok=True)
    if hooks_file.exists():
        backup = hooks_file.with_suffix(
            hooks_file.suffix + time.strftime(".bak-%Y%m%d-%H%M%S")
        )
        shutil.copy2(hooks_file, backup)
    hooks_file.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return True


def find_hook(server: AppServer, cwd: str, hooks_file: Path, command: str) -> dict | None:
    result = server.request("hooks/list", {"cwds": [cwd]})
    for entry in result.get("data", []):
        for hook in entry.get("hooks", []):
            if hook.get("command") == command and Path(hook.get("sourcePath", "")).resolve() == hooks_file.resolve():
                return hook
    return None


def trust_hook(server: AppServer, hook: dict) -> None:
    key_path = f'hooks.state."{hook["key"]}".trusted_hash'
    server.request(
        "config/batchWrite",
        {
            "edits": [
                {"keyPath": key_path, "mergeStrategy": "upsert", "value": hook["currentHash"]}
            ],
            "reloadUserConfig": True,
        },
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="安装并信任 Codex PostToolUse hook（幂等）")
    ap.add_argument("--status", action="store_true", help="只报告信任状态，不修改任何文件")
    ap.add_argument("--codex-bin", default=os.environ.get("CODEX_BIN", "codex"))
    ap.add_argument("--hooks-file", default=str(DEFAULT_HOOKS_FILE))
    ap.add_argument("--script", default=str(DEFAULT_HOOK_SCRIPT), help="PostToolUse hook 脚本路径")
    ap.add_argument("--cwd", default=os.getcwd(), help="解析 hook 配置的工作目录")
    args = ap.parse_args()

    hooks_file = Path(args.hooks_file).expanduser().resolve()
    script = Path(args.script).expanduser().resolve()
    if not script.exists():
        raise SystemExit(f"hook 脚本不存在: {script}")
    if not shutil.which(args.codex_bin) and not Path(args.codex_bin).exists():
        raise SystemExit(f"找不到 codex CLI: {args.codex_bin}")

    command = hook_command(script)
    if not args.status:
        if ensure_hook_installed(hooks_file, command):
            print(f"[pod] 已写入 hook: {hooks_file}")
        else:
            print(f"[pod] hook 已存在: {hooks_file}")

    server = AppServer(args.codex_bin)
    try:
        server.initialize()
        hook = find_hook(server, args.cwd, hooks_file, command)
        if hook is None:
            raise SystemExit("hooks/list 未返回目标 hook，检查 hooks.json 与 --cwd")

        status = hook.get("trustStatus")
        if args.status:
            print(f"[pod] {status:<10} {hook['eventName']}  {hook['key']}")
            return 0 if status in ("trusted", "managed") else 1

        if status in ("trusted", "managed"):
            print(f"[pod] 已信任（无需修改）: {hook['key']}")
            return 0

        trust_hook(server, hook)
        print(f"[pod] 已信任: {hook['key']}")
        print(f"[pod] trusted_hash = {hook['currentHash']}")
        return 0
    finally:
        server.close()


if __name__ == "__main__":
    sys.exit(main())
