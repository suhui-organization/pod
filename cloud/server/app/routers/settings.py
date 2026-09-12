"""Pod Cloud：租户设置（Provider/模型/工具审批策略）。

租户级设置：告警渠道、工具审批策略、AI 摘要模型、找回密码等。
已删除功能，保留基础租户设置与工具审批策略。
"""

import json
import logging
import types

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.models import AuditLog, TenantSettings
from app.schemas import LlmSettingsIn, LlmTestIn, TenantSettingsIn, TenantSettingsOut
from app.security import get_current_tenant_id, get_current_user
from app.services import llm
from app.services.audit import record_audit

logger = logging.getLogger("podcloud.server")

router = APIRouter(prefix="/settings", tags=["settings"])

VALID_PROVIDERS = {"auto", *llm.PROVIDERS}


def _get_or_create(db: Session, tenant_id: int) -> TenantSettings:
    row = db.query(TenantSettings).filter(TenantSettings.tenant_id == tenant_id).first()
    if row is None:
        row = TenantSettings(tenant_id=tenant_id)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


@router.get("")
def get_settings(db: Session = Depends(get_db), tenant_id: int = Depends(get_current_tenant_id)):
    row = _get_or_create(db, tenant_id)
    db.commit()
    try:
        tool_policy = json.loads(row.tool_policy_json or "{}")
    except json.JSONDecodeError:
        tool_policy = {}
    try:
        wh = json.loads(row.alert_webhook_json or "{}")
    except json.JSONDecodeError:
        wh = {}
    if not isinstance(wh, dict):
        wh = {}
    # url 含敏感信息：只回显是否已配置
    wh_out = {
        "enabled": bool(wh.get("enabled")),
        "channel": wh.get("channel", "generic"),
        "url_set": bool(wh.get("url")),
        "min_severity": wh.get("min_severity", "medium"),
    }
    try:
        smtp = json.loads(row.alert_smtp_json or "{}")
    except json.JSONDecodeError:
        smtp = {}
    if not isinstance(smtp, dict):
        smtp = {}
    smtp_out = {
        "enabled": bool(smtp.get("enabled")),
        "host": smtp.get("host", ""),
        "port": smtp.get("port", 465),
        "user_set": bool(smtp.get("user")),
        "from_addr": smtp.get("from_addr", ""),
        "to_addrs": smtp.get("to_addrs", ""),
        "tls": smtp.get("tls", True),
    }
    try:
        rules = json.loads(row.alert_rules_json or "{}")
    except json.JSONDecodeError:
        rules = {}
    if not isinstance(rules, dict):
        rules = {}
    return TenantSettingsOut(
        provider=row.provider,
        api_key_set=bool(row.api_key),
        model=row.model or "",
        base_url=row.base_url or "",
        mcp_commands=row.mcp_commands or "",
        datasources={},  # 数据源已从 Pod Cloud 移除
        tool_policy=tool_policy,
        alert_webhook=wh_out,
        alert_smtp=smtp_out,
        alert_rules=rules,
        ai_digest={"enabled": bool((json.loads(row.ai_digest_json or "{}") if row.ai_digest_json else {}).get("enabled"))} if row.ai_digest_json else {"enabled": False},
    )


@router.put("")
def update_settings(
    body: TenantSettingsIn,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
    tenant_id: int = Depends(get_current_tenant_id),
):
    require_admin(db, tenant_id, user)
    row = _get_or_create(db, tenant_id)
    # 模型四项一律 None = 不修改：默认值会覆盖已存配置，
    # 前端保存 webhook/SMTP 时发的是 partial body，曾把模型打回 auto + 空模型。
    if body.provider is not None:
        if body.provider not in VALID_PROVIDERS:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="未知 Provider")
        row.provider = body.provider
    if body.api_key is not None:
        row.api_key = body.api_key.strip()
    if body.model is not None:
        row.model = body.model.strip()
    if body.base_url is not None:
        row.base_url = _clean_base_url(body.base_url)
    if body.mcp_commands is not None:
        row.mcp_commands = body.mcp_commands.strip()
    if body.tool_policy is not None:
        # 工具审批策略:校验并归一(非法 mode 拒绝,避免脏配置)
        from app.services.tool_policy import load_policy

        policy = load_policy(json.dumps(body.tool_policy, ensure_ascii=False))
        row.tool_policy_json = json.dumps(policy, ensure_ascii=False)
    if body.alert_webhook is not None:
        # 告警通知渠道:只允许白名单 channel；url 留空 = 关闭
        from app.services.alert_notify import CHANNELS

        wh = dict(body.alert_webhook)
        channel = wh.get("channel", "generic")
        if channel not in CHANNELS:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"未知通知渠道: {channel}")
        url = (wh.get("url") or "").strip()
        if url and not url.startswith(("http://", "https://")):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="webhook URL 需以 http(s):// 开头")
        if wh.get("min_severity") not in (None, "low", "medium", "high"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="min_severity 需为 low/medium/high")
        row.alert_webhook_json = json.dumps({
            "enabled": bool(wh.get("enabled")),
            "channel": channel,
            "url": url,
            "secret": (wh.get("secret") or "").strip(),
            "min_severity": wh.get("min_severity") or "medium",
        }, ensure_ascii=False)
    if body.alert_smtp is not None:
        # 邮件通知:SMTP 自设;密码留空 = 不修改已存
        smtp = dict(body.alert_smtp)
        existing = json.loads(row.alert_smtp_json or "{}") if row.alert_smtp_json else {}
        if not isinstance(existing, dict):
            existing = {}
        host = (smtp.get("host") or "").strip()
        if not host and smtp.get("enabled"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="启用邮件通知需填写 SMTP 主机")
        try:
            port = int(smtp.get("port") or existing.get("port") or 465)
        except (TypeError, ValueError):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="SMTP 端口需为数字")
        password = (smtp.get("password") or "").strip()
        if not password:
            password = existing.get("password", "")
        row.alert_smtp_json = json.dumps({
            "enabled": bool(smtp.get("enabled")),
            "host": host,
            "port": port,
            "user": (smtp.get("user") or "").strip(),
            "password": password,
            "from_addr": (smtp.get("from_addr") or "").strip(),
            "to_addrs": (smtp.get("to_addrs") or "").strip(),
            "tls": bool(smtp.get("tls", True)),
        }, ensure_ascii=False)
    if body.alert_rules is not None:
        # 规则阈值：数值范围校验，缺省回落默认
        from app.routers.sync import BURST_THRESHOLD, BURST_WINDOW, SPIKE_THRESHOLD
        from app.services.silence_watch import SILENCE_HOURS

        rules = dict(body.alert_rules)
        out: dict = {}
        for key, default, lo, hi in (
            ("deny_burst_threshold", BURST_THRESHOLD, 1, 1000),
            ("burst_window_seconds", BURST_WINDOW, 10, 86400),
            ("spike_threshold", SPIKE_THRESHOLD, 2, 100000),
            ("silence_hours", SILENCE_HOURS, 1, 720),
        ):
            try:
                val = int(rules.get(key, default))
            except (TypeError, ValueError):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{key} 需为整数")
            if not (lo <= val <= hi):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{key} 需在 {lo}~{hi} 之间")
            out[key] = val
        row.alert_rules_json = json.dumps(out, ensure_ascii=False)
    if body.ai_digest is not None:
        # AI 日报开关（last_sent_date 保留）
        digest = dict(body.ai_digest)
        existing = json.loads(row.ai_digest_json or "{}") if row.ai_digest_json else {}
        if not isinstance(existing, dict):
            existing = {}
        existing["enabled"] = bool(digest.get("enabled"))
        row.ai_digest_json = json.dumps(existing, ensure_ascii=False)
    record_audit(db, tenant_id=tenant_id, user_id=user["id"], action="settings", detail={"provider": body.provider})
    db.commit()
    try:
        tool_policy = json.loads(row.tool_policy_json or "{}")
    except json.JSONDecodeError:
        tool_policy = {}
    try:
        wh = json.loads(row.alert_webhook_json or "{}")
    except json.JSONDecodeError:
        wh = {}
    try:
        smtp = json.loads(row.alert_smtp_json or "{}")
    except json.JSONDecodeError:
        smtp = {}
    return TenantSettingsOut(
        provider=row.provider,
        api_key_set=bool(row.api_key),
        model=row.model or "",
        base_url=row.base_url or "",
        mcp_commands=row.mcp_commands or "",
        datasources={},
        tool_policy=tool_policy,
        alert_webhook={
            "enabled": bool(wh.get("enabled")),
            "channel": wh.get("channel", "generic"),
            "url_set": bool(wh.get("url")),
            "min_severity": wh.get("min_severity", "medium"),
        },
        alert_smtp={
            "enabled": bool(smtp.get("enabled")),
            "host": smtp.get("host", ""),
            "port": smtp.get("port", 465),
            "user_set": bool(smtp.get("user")),
            "from_addr": smtp.get("from_addr", ""),
            "to_addrs": smtp.get("to_addrs", ""),
            "tls": smtp.get("tls", True),
        },
        alert_rules=json.loads(row.alert_rules_json or "{}") if row.alert_rules_json else {},
        ai_digest={"enabled": bool((json.loads(row.ai_digest_json or "{}") if row.ai_digest_json else {}).get("enabled"))} if row.ai_digest_json else {"enabled": False},
    )


# ---- AI 模型（/settings/llm）：provider / 端点 / key 的唯一配置面 ----


def _clean_base_url(raw: str) -> str:
    """归一 OpenAI 兼容端点：只接受 http(s)，去掉尾部斜杠。"""
    url = (raw or "").strip().rstrip("/")
    if url and not url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Base URL 需以 http:// 或 https:// 开头"
        )
    return url


def _masked_key_hint(raw: str) -> str:
    key = (raw or "").strip()
    if not key:
        return ""
    return f"…{key[-4:]}" if len(key) > 8 else "已配置"


def _llm_payload(db: Session, row: TenantSettings) -> dict:
    """给设置页的模型面板：当前值 + 是否可用 + 为什么不可用 + 依赖清单。

    界面要能回答"现在到底能不能用 AI"，所以这里把 resolve_config 的结论
    （而不是让前端自己拼规则）一并返回。
    """
    configured = True
    reason = ""
    effective: dict = {}
    try:
        cfg = llm.resolve_config(row)
        effective = {
            "provider": cfg.provider,
            "model": cfg.model,
            "endpoint": cfg.endpoint,
            "key_source": cfg.key_source,
            "key_hint": cfg.key_hint,
        }
    except llm.LlmConfigError as e:
        configured = False
        reason = str(e)
    return {
        "provider": row.provider or "auto",
        "model": row.model or "",
        "base_url": row.base_url or "",
        "api_key_set": bool(row.api_key),
        "api_key_hint": _masked_key_hint(row.api_key),
        "configured": configured,
        "reason": reason,
        "effective": effective,
        "providers": llm.providers_public(),
        "features": llm.AI_FEATURES,
    }


@router.get("/llm")
def get_llm_settings(
    db: Session = Depends(get_db), tenant_id: int = Depends(get_current_tenant_id)
):
    """读取模型配置（不回显 key 本体）。只读成员也能看：他们需要知道 AI 为什么不可用。"""
    row = _get_or_create(db, tenant_id)
    return _llm_payload(db, row)


@router.put("/llm")
def update_llm_settings(
    body: LlmSettingsIn,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
    tenant_id: int = Depends(get_current_tenant_id),
):
    """保存模型配置。字段为 None = 不修改（避免把已存配置覆盖成默认值）。"""
    require_admin(db, tenant_id, user)
    row = _get_or_create(db, tenant_id)
    if body.provider is not None:
        provider = body.provider.strip() or "auto"
        if provider not in VALID_PROVIDERS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"未知 Provider：{provider}（可选 {' / '.join(sorted(VALID_PROVIDERS))}）",
            )
        row.provider = provider
    if body.model is not None:
        row.model = body.model.strip()
    if body.base_url is not None:
        row.base_url = _clean_base_url(body.base_url)
    if body.api_key is not None:
        row.api_key = body.api_key.strip()
    # 审计只记"改了什么形状"，不记 key 本体
    record_audit(
        db,
        tenant_id=tenant_id,
        user_id=user["id"],
        action="settings.llm",
        detail={
            "provider": row.provider,
            "model": row.model,
            "base_url_set": bool(row.base_url),
            "api_key_set": bool(row.api_key),
        },
    )
    db.commit()
    return _llm_payload(db, row)


@router.post("/llm/test")
def test_llm_settings(
    body: LlmTestIn,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
    tenant_id: int = Depends(get_current_tenant_id),
):
    """连通性自检：可以先用未保存的草稿试，成了再存。

    这是一次**真实出网调用**，所以同样进审计（feature=settings.llm_test）。
    """
    require_admin(db, tenant_id, user)
    row = _get_or_create(db, tenant_id)
    draft = types.SimpleNamespace(
        provider=body.provider if body.provider is not None else row.provider,
        model=body.model if body.model is not None else row.model,
        base_url=body.base_url if body.base_url is not None else row.base_url,
        # key 是只写的：表单留空表示"用已保存的那把"
        api_key=(body.api_key or "").strip() or row.api_key,
    )
    try:
        cfg = llm.resolve_config(draft)
    except llm.LlmConfigError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    result = llm.test_connection(cfg)
    record_audit(
        db,
        tenant_id=tenant_id,
        user_id=user["id"],
        action="llm.call",
        detail={
            "feature": "settings.llm_test",
            "provider": cfg.provider,
            "model": cfg.model,
            "endpoint": cfg.endpoint,
            "ok": result["ok"],
            "duration_ms": result["latency_ms"],
            "error": (result["error"] or "")[:300],
        },
    )
    db.commit()
    return result
