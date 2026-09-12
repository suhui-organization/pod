"""私有化 bootstrap 脚本测试:subprocess 指向临时 SQLite 库(不污染开发库)。"""

import os
import subprocess
import sys

SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_bootstrap(db_path):
    env = dict(os.environ, FINHARNESS_DB_URL=f"sqlite:///{db_path}")
    return subprocess.run(
        [sys.executable, "-m", "scripts.bootstrap_admin", "--email", "admin@x.com", "--password", "secret123"],
        capture_output=True, text=True, cwd=SERVER_DIR, env=env, timeout=60,
    )


def test_bootstrap_admin_cli(tmp_path):
    # N4:私有化实例通过 CLI 创建首个管理员;重复执行幂等
    db_path = tmp_path / "boot.db"
    proc = _run_bootstrap(db_path)
    assert proc.returncode == 0, proc.stderr
    assert "管理员创建完成" in proc.stdout
    proc2 = _run_bootstrap(db_path)
    assert proc2.returncode == 0, proc2.stderr
    assert "已存在" in proc2.stdout
