"""数据库引擎与会话;测试通过依赖覆盖注入内存库。

SQLite 并发（默认部署形态，别删这段）：控制平面里**写是高频**的——每台机器
30 秒一次心跳、每 5 分钟一次 pod sync，而有些请求是**慢的**（自检要出网调模型，
最长 20 秒）。SQLite 默认的 journal 模式下，两个"先读后写"的事务会互相把对方
锁死，慢请求必然吃到 `database is locked`（线上真实故障：自检点一次 500 一次）。

所以连接建立时统一切到 WAL + 让写者排队：
- `journal_mode=WAL`：读不阻塞写、写不阻塞读（写与写仍互斥，但窗口极短）；
- `busy_timeout=15s`：写锁被占时排队等待，而不是当场报错；
- `synchronous=NORMAL`：WAL 下的安全档位，兼顾落盘与性能。
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings


class Base(DeclarativeBase):
    pass


_IS_SQLITE = settings.db_url.startswith("sqlite")

engine = create_engine(
    settings.db_url,
    # timeout 是 pysqlite 的 busy timeout（秒）：与下面的 PRAGMA 一起，双保险
    connect_args={"check_same_thread": False, "timeout": 15} if _IS_SQLITE else {},
)


def install_sqlite_concurrency(eng) -> None:
    """给 SQLite 引擎装上 WAL + busy_timeout（独立成函数，便于测试挂到临时库上）。"""

    @event.listens_for(eng, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        try:
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.execute("PRAGMA busy_timeout=15000")
        finally:
            cur.close()


if _IS_SQLITE:
    install_sqlite_concurrency(engine)


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
