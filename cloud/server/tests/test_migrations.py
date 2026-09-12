"""列迁移的并发安全性。

滚动更新时新旧 Pod 会重叠（replicas=1 + maxUnavailable=0 时新 Pod 先起、旧 Pod 还活着），
两个进程可能同时判定"列不存在"并各自 ALTER，后到的那个会报 duplicate column。
这段代码必须把这种情况当成成功——否则新 Pod 启动即崩，而 maxUnavailable=0 又拦着
旧 Pod 不被替换，整个滚动更新会卡死。
"""

from sqlalchemy import create_engine, inspect, text

from app import migrations
from app.migrations import migrate


def _fresh_engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/m.db")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY, email VARCHAR(64))"))
    return engine


def test_migrate_adds_missing_column(tmp_path):
    engine = _fresh_engine(tmp_path)
    migrations._COLUMN_MIGRATIONS  # noqa: B018  (读一眼常量，保持与真实表一致)
    original = migrations._COLUMN_MIGRATIONS
    migrations._COLUMN_MIGRATIONS = {
        "users": {"nickname": "ALTER TABLE users ADD COLUMN nickname VARCHAR(32) DEFAULT ''"}
    }
    try:
        migrate(engine)
        assert "nickname" in {c["name"] for c in inspect(engine).get_columns("users")}
        # 幂等：再跑一次不报错
        migrate(engine)
    finally:
        migrations._COLUMN_MIGRATIONS = original


def test_migrate_tolerates_concurrent_duplicate_column(tmp_path, monkeypatch):
    """模拟并发同伴抢先建列：存在性检查骗过一次，ALTER 必然撞 duplicate。"""
    engine = _fresh_engine(tmp_path)
    original_map = migrations._COLUMN_MIGRATIONS
    migrations._COLUMN_MIGRATIONS = {
        "users": {"email": "ALTER TABLE users ADD COLUMN email VARCHAR(64) DEFAULT ''"}
    }
    real_check = migrations._column_exists
    calls = {"n": 0}

    def flaky(insp, table, col):
        calls["n"] += 1
        if calls["n"] == 1:
            return False  # 第一次假装不存在 → 触发 ALTER → duplicate
        return real_check(insp, table, col)

    monkeypatch.setattr(migrations, "_column_exists", flaky)
    try:
        migrate(engine)  # 不应抛异常
        assert calls["n"] >= 2, "应该走了异常分支并重新检查一次"
    finally:
        migrations._COLUMN_MIGRATIONS = original_map


def test_migrate_still_raises_real_errors(tmp_path, monkeypatch):
    """列真的不存在、DDL 又是错的 → 必须抛出，不能把真错误吞掉。"""
    engine = _fresh_engine(tmp_path)
    original_map = migrations._COLUMN_MIGRATIONS
    migrations._COLUMN_MIGRATIONS = {"users": {"ghost": "ALTER TABLE nonexistent_table ADD COLUMN ghost INT"}}
    try:
        try:
            migrate(engine)
        except Exception as e:  # noqa: BLE001
            assert "nonexistent_table" in str(e)
        else:
            raise AssertionError("DDL 失败且列不存在时应当抛出")
    finally:
        migrations._COLUMN_MIGRATIONS = original_map
