"""SQLite 并发：线上真实故障的回归护栏。

事故形态：自检请求里要出网调模型（最长 20 秒），期间一直开着读事务；同一时刻
机器的同步心跳在做高频写 —— 收尾 INSERT 直接 `database is locked`，用户看到
「自检失败：Request failed with status code 500」。

两条护栏：引擎级别切到 WAL + busy_timeout；慢调用之前必须把读事务收掉。
"""

from sqlalchemy import create_engine, text


from app.database import Base, install_sqlite_concurrency
from app.services import selfcheck as selfcheck_service

from tests.conftest import register_and_login


def _file_engine(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path}/conc.db", connect_args={"check_same_thread": False, "timeout": 15})
    install_sqlite_concurrency(eng)
    Base.metadata.create_all(bind=eng)
    return eng


def test_sqlite_engine_uses_wal_and_busy_timeout():
    """默认部署就是 SQLite：WAL 让读写不互斥，busy_timeout 让写者排队而不是当场失败。"""
    from app.database import engine

    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar().lower() == "wal"
        assert int(conn.execute(text("PRAGMA busy_timeout")).scalar()) >= 15000


def test_file_engine_gets_the_same_pragmas(tmp_path):
    """换库（换机器/换数据卷）时护栏跟着走 —— 靠的是同一段安装代码。"""
    eng = _file_engine(tmp_path)
    with eng.connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar().lower() == "wal"
        assert int(conn.execute(text("PRAGMA busy_timeout")).scalar()) >= 15000


def test_wal_lets_readers_and_writers_coexist(tmp_path):
    """WAL 下：一个连接开着写事务时，另一个连接仍能读，不会互相卡死。"""
    eng = _file_engine(tmp_path)
    with eng.connect() as writer, eng.connect() as reader:
        writer.execute(
            text(
                "INSERT INTO pod_selfcheck_runs "
                "(tenant_id, \"trigger\", started_at, finished_at, summary_json, checks_json, repairs_json) "
                "VALUES (1, 'daily', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '{}', '[]', '[]')"
            )
        )
        # 读连接不等待写事务提交（默认 journal 模式下这里会阻塞到超时）
        assert reader.execute(text("SELECT COUNT(*) FROM pod_selfcheck_runs")).scalar() is not None
        writer.rollback()


def test_llm_probe_runs_without_holding_a_transaction(client, db, monkeypatch):
    """出网调用那一刻，DB 事务必须已经收掉 —— 就是这条把线上 500 修掉的。"""
    from app.models import TenantSettings

    db.add(
        TenantSettings(
            tenant_id=1, provider="custom", base_url="http://127.0.0.1:9/v1", model="m", api_key="k"
        )
    )
    db.commit()
    token = register_and_login(client)
    seen: dict = {}

    def fake_test_connection(cfg):
        seen["in_transaction"] = db.in_transaction()
        return {
            "ok": True,
            "provider": cfg.provider,
            "model": cfg.model,
            "endpoint": cfg.endpoint,
            "latency_ms": 1,
            "error": "",
            "sample": "OK",
        }

    monkeypatch.setattr(selfcheck_service.llm, "test_connection", fake_test_connection)

    r = client.post(
        "/api/v1/selfcheck/run",
        json={"repair": False},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert seen, "应当真的走到模型连通性检查"
    assert seen["in_transaction"] is False, "出网调用期间仍开着 DB 事务（SQLite 会 database is locked）"
    # 收掉事务不影响结果：整轮自检照常落库
    assert r.json()["summary"]["pass"] >= 1
