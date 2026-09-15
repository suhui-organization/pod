"""列迁移的并发安全性。

滚动更新时新旧 Pod 会重叠（replicas=1 + maxUnavailable=0 时新 Pod 先起、旧 Pod 还活着），
两个进程可能同时判定"列不存在"并各自 ALTER，后到的那个会报 duplicate column。
这段代码必须把这种情况当成成功——否则新 Pod 启动即崩，而 maxUnavailable=0 又拦着
旧 Pod 不被替换，整个滚动更新会卡死。
"""

from sqlalchemy import create_engine, inspect, text

from app import migrations
from app.config import settings
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


def _legacy_alerts_engine(tmp_path):
    """造一个"老库"：agent_id 还是 NOT NULL（平台级告警加不进去的那种）。"""
    engine = create_engine(f"sqlite:///{tmp_path}/alerts.db")
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE pod_alerts (id INTEGER NOT NULL, tenant_id INTEGER NOT NULL, "
                "agent_id INTEGER NOT NULL, kind VARCHAR(32) NOT NULL, severity VARCHAR(8) NOT NULL, "
                "message TEXT NOT NULL, event_seq INTEGER NOT NULL, state VARCHAR(16) NOT NULL, "
                "created_at DATETIME NOT NULL, PRIMARY KEY (id), "
                "FOREIGN KEY(tenant_id) REFERENCES tenants (id), "
                "FOREIGN KEY(agent_id) REFERENCES pod_agents (id))"
            )
        )
        conn.execute(text("CREATE INDEX ix_pod_alerts_agent_id ON pod_alerts (agent_id)"))
        conn.execute(
            text(
                "INSERT INTO pod_alerts (id, tenant_id, agent_id, kind, severity, message, event_seq, state, created_at) "
                "VALUES (1, 7, 3, 'deny_burst', 'high', '老数据', 42, 'open', '2026-09-01 00:00:00')"
            )
        )
    return engine


def test_migrate_makes_alert_agent_id_nullable_and_keeps_rows(tmp_path):
    engine = _legacy_alerts_engine(tmp_path)
    assert not inspect(engine).get_columns("pod_alerts")[2]["nullable"]  # 迁移前：NOT NULL

    migrate(engine)

    insp = inspect(engine)
    cols = {c["name"]: c for c in insp.get_columns("pod_alerts")}
    assert cols["agent_id"]["nullable"] is True
    # 老数据一条不少、值也没串位
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT id, tenant_id, agent_id, kind, message, event_seq, state FROM pod_alerts")
        ).one()
        assert tuple(row) == (1, 7, 3, "deny_burst", "老数据", 42, "open")
        # 平台级告警（agent_id 为空）现在写得进去
        conn.execute(
            text(
                "INSERT INTO pod_alerts (id, tenant_id, agent_id, kind, severity, message, event_seq, state, created_at) "
                "VALUES (2, 7, NULL, 'selfcheck', 'high', '平台级', 0, 'open', '2026-09-15 00:00:00')"
            )
        )
        assert conn.execute(text("SELECT COUNT(*) FROM pod_alerts")).scalar() == 2

    # 索引没丢（重建表最容易漏的就是这个）
    idx = {i["name"] for i in insp.get_indexes("pod_alerts")}
    assert "ix_pod_alerts_agent_id" in {n for n in idx if n}

    # 幂等：再跑一次不该再重建
    migrate(engine)
    assert inspect(engine).get_columns("pod_alerts")[2]["nullable"] is True

    # 动过数据的那次迁移要留下备份文件（确认无误后由运维删）
    backups = list(tmp_path.glob("*.bak-*-pre-structural-migration"))
    assert len(backups) == 1, "结构性迁移前必须先留一份原样备份"


def test_structural_migration_rolls_back_when_row_count_mismatches(tmp_path, monkeypatch):
    """对账不通过 → 整笔回滚：旧表、旧数据、索引都得原样还在。"""
    engine = _legacy_alerts_engine(tmp_path)
    calls = {"n": 0}
    real = migrations._row_count

    def lying(conn, table):
        calls["n"] += 1
        return real(conn, table) + (99 if calls["n"] == 2 else 0)  # 只把"新表"的计数算错

    monkeypatch.setattr(migrations, "_row_count", lying)
    try:
        migrate(engine)
    except RuntimeError as e:
        assert "行数对不上" in str(e) and "已回滚" in str(e)
    else:
        raise AssertionError("行数对不上时必须抛出并回滚")

    cols = {c["name"]: c for c in inspect(engine).get_columns("pod_alerts")}
    assert cols["agent_id"]["nullable"] is False  # 没改成半成品
    with engine.begin() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM pod_alerts")).scalar() == 1
        assert conn.execute(text("SELECT message FROM pod_alerts WHERE id=1")).scalar() == "老数据"
    # 备份已经先落了，出问题时手里有原始文件
    assert list(tmp_path.glob("*.bak-*-pre-structural-migration"))


def test_structural_migration_backup_can_be_disabled(tmp_path, monkeypatch):
    engine = _legacy_alerts_engine(tmp_path)
    monkeypatch.setattr(settings, "migrate_backup", "off")
    migrate(engine)
    assert inspect(engine).get_columns("pod_alerts")[2]["nullable"] is True
    assert not list(tmp_path.glob("*.bak-*-pre-structural-migration"))
