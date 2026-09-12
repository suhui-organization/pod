"""Pod Cloud：加固审计报告（`pod harden` 的交付物）。

两条通道：
- **上传**（`POST /harden/reports`）：`X-Sync-Token`，机器侧 `pod harden --upload` 调用；
- **查看**（`GET /harden/reports*`）：租户 JWT，web 用。

只收交付物（report.md + findings.json），**不收 evidence.json**（原始审计链）：
后者是"本地优先"承诺的核心，客户端也不会传。
"""

import json

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Agent, PodHardenReport
from app.security import get_current_tenant_id

router = APIRouter(prefix="/harden", tags=["harden"])

# 报告里内嵌了三份子报告，比普通 JSON 大；给足空间但仍设上限，避免把库写爆
MAX_REPORT_CHARS = 800_000


class HardenReportIn(BaseModel):
    generated_at: str = Field(min_length=1, max_length=64)
    rules_version: str = Field(default="", max_length=64)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    mcp_servers: int = Field(default=0, ge=0)
    exposed_secrets: int = Field(default=0, ge=0)
    broken_chains: int = Field(default=0, ge=0)
    report_md: str = Field(min_length=1, max_length=MAX_REPORT_CHARS)
    findings_json: str = Field(default="{}", max_length=MAX_REPORT_CHARS)


def _summary_out(row: PodHardenReport) -> dict:
    """列表用：不带 report_md（一页几十份报告时那是几百 KB 的无用负载）。"""
    return {
        "id": row.id,
        "agent_id": row.agent_id,
        "generated_at": row.generated_at,
        "uploaded_at": row.created_at.isoformat() if row.created_at else "",
        "high": row.high,
        "medium": row.medium,
        "low": row.low,
        "mcp_servers": row.mcp_servers,
        "exposed_secrets": row.exposed_secrets,
        "broken_chains": row.broken_chains,
        "rules_version": row.rules_version,
    }


@router.post("/reports", status_code=201)
def upload_report(
    body: HardenReportIn,
    db: Session = Depends(get_db),
    x_sync_token: str = Header(default=""),
):
    """机器侧上传（X-Sync-Token）：报告归属到该 token 对应的 agent。"""
    if not x_sync_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少 X-Sync-Token")
    from hashlib import sha256

    token_hash = sha256(x_sync_token.encode("utf-8")).hexdigest()
    agent = db.query(Agent).filter(Agent.sync_token_hash == token_hash).first()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="sync token 无效")
    if body.findings_json:
        try:
            json.loads(body.findings_json)
        except json.JSONDecodeError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"findings_json 不是合法 JSON：{e}"
            ) from e
    row = PodHardenReport(
        tenant_id=agent.tenant_id,
        agent_id=agent.id,
        generated_at=body.generated_at,
        high=body.high,
        medium=body.medium,
        low=body.low,
        mcp_servers=body.mcp_servers,
        exposed_secrets=body.exposed_secrets,
        broken_chains=body.broken_chains,
        rules_version=body.rules_version,
        report_md=body.report_md,
        findings_json=body.findings_json,
    )
    db.add(row)
    db.commit()
    return {"report": _summary_out(row)}


@router.get("/reports")
def list_reports(
    agent_id: int | None = None,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
):
    """报告列表（新→旧）。带 agent 名字，web 直接可用。"""
    q = db.query(PodHardenReport).filter(PodHardenReport.tenant_id == tenant_id)
    if agent_id:
        q = q.filter(PodHardenReport.agent_id == agent_id)
    rows = q.order_by(PodHardenReport.id.desc()).limit(200).all()
    names = {a.id: a.name for a in db.query(Agent).filter(Agent.tenant_id == tenant_id).all()}
    return {
        "reports": [
            {**_summary_out(r), "agent_name": names.get(r.agent_id, f"#{r.agent_id}")} for r in rows
        ]
    }


@router.get("/reports/{report_id}")
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
):
    row = (
        db.query(PodHardenReport)
        .filter(PodHardenReport.id == report_id, PodHardenReport.tenant_id == tenant_id)
        .first()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="报告不存在")
    payload = _summary_out(row)
    payload["report_md"] = row.report_md
    payload["findings_json"] = row.findings_json
    return {"report": payload}
