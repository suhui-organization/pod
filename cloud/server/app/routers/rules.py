"""Pod Cloud：规则包（订阅式加固的分发单元，对应本地 `pod rules`）。

两条通道，鉴权方式刻意不同：
- **管理面**（`/rules/packs`）：租户 JWT + 管理员角色，给 web 用——发布、列版本、撤回；
- **分发面**（`/rules/pack`）：`X-Sync-Token`，给本地机器用——和 `/sync/policies` 同一套凭证，
  这样接入脚本只需要一份 token 就能既推事件又拉规则。

云端不验签、不判定是否放宽：公钥与守卫都在客户端。云端只负责"存 / 标 active / 记审计"。
"""

import json

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.models import Agent, AuditLog, PodRulePack
from app.security import get_current_tenant_id, get_current_user

router = APIRouter(prefix="/rules", tags=["rules"])

PACK_SCHEMA = "pod-rules-pack/v1"


class RulePackPublishRequest(BaseModel):
    # 整包原文（含 signature）。上限比策略大一些：规则包里有模式表。
    pack_json: str = Field(min_length=2, max_length=500_000)
    note: str = Field(default="", max_length=2000)


def _parse_pack(pack_json: str) -> dict:
    """只做"是不是一个可分发的规则包"的结构校验——这是卫生，不是信任。

    真正的验证在客户端：Ed25519 验签 + 放宽守卫。这里拦下来只是为了不让
    明显损坏的东西进库、并且让发布者当场看到错误。
    """
    try:
        parsed = json.loads(pack_json)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"pack_json 不是合法 JSON：{e}") from e
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="规则包必须是 JSON 对象")
    if parsed.get("schema") != PACK_SCHEMA:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"规则包 schema 必须是 {PACK_SCHEMA}",
        )
    for field in ("packVersion", "issuedBy"):
        if not isinstance(parsed.get(field), str) or not parsed[field]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"规则包缺少 {field}")
    if not isinstance(parsed.get("signature"), str) or not parsed["signature"]:
        # 未签名的包不接收：分发面是公网可达的，一个能被中间人替换的包比没有包更危险
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="规则包缺少 signature：云端只分发已签名的包（签名由签发方在本地完成）",
        )
    return parsed


def _out(row: PodRulePack, with_body: bool = False) -> dict:
    data = {
        "id": row.id,
        "pack_version": row.pack_version,
        "issued_by": row.issued_by,
        "note": row.note,
        "active": row.active,
        "created_at": row.created_at.isoformat() if row.created_at else "",
    }
    if with_body:
        data["pack_json"] = row.pack_json
    return data


@router.get("/packs")
def list_packs(
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
):
    """版本列表（新→旧）。带 pack_json 供页面详情/对比，规则包本来就是要下发给客户机器的。"""
    rows = (
        db.query(PodRulePack)
        .filter(PodRulePack.tenant_id == tenant_id)
        .order_by(PodRulePack.id.desc())
        .all()
    )
    return {"packs": [_out(r, with_body=True) for r in rows]}


@router.post("/packs", status_code=201)
def publish_pack(
    body: RulePackPublishRequest,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    """发布并立即激活：把上一版全部置为 inactive。"""
    require_admin(db, tenant_id, user)
    parsed = _parse_pack(body.pack_json)
    db.query(PodRulePack).filter(
        PodRulePack.tenant_id == tenant_id, PodRulePack.active.is_(True)
    ).update({"active": False})
    row = PodRulePack(
        tenant_id=tenant_id,
        pack_version=parsed["packVersion"],
        issued_by=parsed["issuedBy"],
        note=body.note or str(parsed.get("note") or ""),
        pack_json=body.pack_json,
        active=True,
    )
    db.add(row)
    db.flush()
    db.add(
        AuditLog(
            tenant_id=tenant_id,
            user_id=user["id"],
            action="rulepack.publish",
            detail_json=json.dumps(
                {"id": row.id, "pack_version": row.pack_version, "issued_by": row.issued_by}
            ),
        )
    )
    db.commit()
    return {"pack": _out(row, with_body=True)}


@router.post("/packs/{pack_id}/activate")
def activate_pack(
    pack_id: int,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    """撤回/回滚：把指定版本设为 active。比删除好——历史还在，"换过什么"可查。"""
    require_admin(db, tenant_id, user)
    row = (
        db.query(PodRulePack)
        .filter(PodRulePack.id == pack_id, PodRulePack.tenant_id == tenant_id)
        .first()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="规则包不存在")
    db.query(PodRulePack).filter(
        PodRulePack.tenant_id == tenant_id, PodRulePack.active.is_(True)
    ).update({"active": False})
    row.active = True
    db.add(
        AuditLog(
            tenant_id=tenant_id,
            user_id=user["id"],
            action="rulepack.activate",
            detail_json=json.dumps({"id": row.id, "pack_version": row.pack_version}),
        )
    )
    db.commit()
    return {"pack": _out(row)}


@router.get("/pack")
def get_active_pack(
    db: Session = Depends(get_db),
    x_sync_token: str = Header(default=""),
):
    """分发面：本地 `pod rules pull --from-cloud` 拉当前 active 的包。

    鉴权与 /sync/policies 一致（X-Sync-Token），让接入脚本只需要一份凭证。
    """
    if not x_sync_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少 X-Sync-Token")
    from hashlib import sha256

    token_hash = sha256(x_sync_token.encode("utf-8")).hexdigest()
    agent = db.query(Agent).filter(Agent.sync_token_hash == token_hash).first()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="sync token 无效")
    row = (
        db.query(PodRulePack)
        .filter(PodRulePack.tenant_id == agent.tenant_id, PodRulePack.active.is_(True))
        .order_by(PodRulePack.id.desc())
        .first()
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="该租户还没有发布任何规则包（在「规则包」页发布后再拉取）",
        )
    return {
        "agent_id": agent.id,
        "pack_version": row.pack_version,
        "issued_by": row.issued_by,
        "published_at": row.created_at.isoformat() if row.created_at else "",
        # 整包原文直接返回：客户端自己验签，云端不代劳
        "pack_json": row.pack_json,
    }
