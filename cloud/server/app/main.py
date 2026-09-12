"""Pod Cloud 控制平面后端入口。

职责：agent 资产注册、审计同步（数据平面 + 控制平面两套事件流）、策略中心、
告警、时间线、合规报告、订阅（可选）。本地 pod 网关不依赖它——云端挂了，
本地执法与审计照常。
"""
import logging

from fastapi import FastAPI, HTTPException
from app.database import get_db
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.database import Base, engine
from app.i18n import resolve_locale, translate_detail
from app.migrations import migrate
from app.routers import admin, agents, alerts, auth, control_events, dashboard, harden, policies, reports, rules, settings, subscription, sync, tenants, timeline, traces, users

Base.metadata.create_all(bind=engine)
migrate(engine)  # 轻量列迁移(幂等,为已有库补新列)

app = FastAPI(title="Pod Cloud", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # MVP;生产按域名收紧
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """统一错误信封：{"error": {"code", "message"}}（N1 规范）。

    出口统一翻译：路由继续写中文文案，这里按请求语言（Accept-Language / ?lang=）
    换成对应语言。一处收口，胜过改 60+ 个 raise 点。
    """
    locale = resolve_locale(request.headers.get("accept-language"), request.query_params.get("lang"))
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.status_code, "message": translate_detail(exc.detail, locale)}},
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_handler(request, exc: RequestValidationError):
    """422 校验错误：统一信封 + 简洁字段信息，不泄漏内部细节。"""
    locale = resolve_locale(request.headers.get("accept-language"), request.query_params.get("lang"))
    msgs = []
    for e in exc.errors():
        loc = ".".join(str(x) for x in e.get("loc", []) if x != "body")
        msgs.append(f"{loc or 'body'}: {e.get('msg', 'invalid')}")
    return JSONResponse(
        status_code=422,
        content={"error": {"code": 422, "message": translate_detail("; ".join(msgs), locale)}},
    )


# agent 失联巡检（后台线程，30 分钟一轮；单副本部署）
try:
    from app.services.silence_watch import start_silence_watch

    start_silence_watch(get_db)
except Exception as e:  # noqa: BLE001 巡检启动失败不影响服务
    print(f"[podcloud] silence watch failed to start: {e}", flush=True)

try:
    from app.services.digest_scheduler import start_digest_scheduler

    start_digest_scheduler(get_db)
except Exception as e:  # noqa: BLE001 日报调度启动失败不影响服务
    print(f"[podcloud] digest scheduler failed to start: {e}", flush=True)


API = "/api/v1"
app.include_router(auth.router, prefix=API)
app.include_router(admin.router, prefix=API)
app.include_router(tenants.router, prefix=API)
app.include_router(users.router, prefix=API)
app.include_router(settings.router, prefix=API)
app.include_router(agents.router, prefix=API)
app.include_router(agents.setup_router, prefix=API)  # /api/v1/agent-setup/{id}/{token}：一键接入脚本（token 即凭证）
app.include_router(sync.router, prefix=API)
app.include_router(policies.router, prefix=API)
app.include_router(rules.router, prefix=API)  # /api/v1/rules: 规则包（订阅式加固的分发）
app.include_router(harden.router, prefix=API)  # /api/v1/harden: 加固审计报告（交付物上传与查看）
app.include_router(dashboard.router, prefix=API)
app.include_router(subscription.router, prefix=API)
app.include_router(reports.router, prefix=API)
app.include_router(alerts.router, prefix=API)
app.include_router(timeline.router, prefix=API)
app.include_router(control_events.router, prefix=API)  # /api/v1/control-events: 控制平面事件（钩子/身份/委托/熔断）
app.include_router(traces.router, prefix=API)  # /api/v1/traces: 调用链追踪(任务→调用图谱)
