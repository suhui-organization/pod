"""Pod Cloud：策略中心（模板库 + 按 agent 绑定下发）。

对应商业计划「智能风险引擎/一键合规」的策略承载：云端保存 YAML/JSON 策略，
网关侧 `pod pull-policy` 拉取后本地执行。v0 仅存储与版本管理。
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.models import AuditLog, PodPolicy, PodPolicyVersion
from app.security import SECRET_PATTERNS, get_current_tenant_id, get_current_user

router = APIRouter(prefix="/policies", tags=["policies"])


class PolicyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    policy_json: str = Field(min_length=2, max_length=20000)  # 与 pod 策略 JSON 同构
    agent_id: int | None = None  # None = 租户模板
    note: str = Field(default="", max_length=2000)  # 设计说明/备注（为什么这么设）


def _snapshot(db: Session, p: PodPolicy) -> None:
    """保存当前策略为版本快照（每次变更前调用，存"变更后"内容并递增版本号）。"""
    last = (
        db.query(PodPolicyVersion)
        .filter(PodPolicyVersion.policy_id == p.id)
        .order_by(PodPolicyVersion.version.desc())
        .first()
    )
    ver = (last.version + 1) if last else 1
    p.version = str(ver)
    db.add(PodPolicyVersion(
        tenant_id=p.tenant_id, policy_id=p.id, version=ver,
        policy_json=p.policy_json, note=p.note,
    ))


def policy_out(p: PodPolicy) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "agent_id": p.agent_id,
        "policy_json": p.policy_json,
        "note": p.note,
        "version": p.version,
        "created_at": p.created_at.isoformat(),
    }


@router.get("")
def list_policies(db: Session = Depends(get_db), tenant_id: int = Depends(get_current_tenant_id)):
    policies = db.query(PodPolicy).filter(PodPolicy.tenant_id == tenant_id).order_by(PodPolicy.id).all()
    return {"policies": [policy_out(p) for p in policies]}


@router.post("", status_code=201)
def create_policy(
    body: PolicyCreateRequest,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    require_admin(db, tenant_id, user)
    p = PodPolicy(tenant_id=tenant_id, name=body.name, policy_json=body.policy_json,
                  agent_id=body.agent_id, note=body.note)
    db.add(p)
    db.flush()
    _snapshot(db, p)  # v1
    db.add(AuditLog(tenant_id=tenant_id, user_id=user["id"], action="policy.create", detail_json=f'{{"policy_id": {p.id}}}'))
    db.commit()
    return {"policy": policy_out(p)}


@router.put("/{policy_id}")
def update_policy(
    policy_id: int,
    body: PolicyCreateRequest,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    require_admin(db, tenant_id, user)
    p = db.query(PodPolicy).filter(PodPolicy.id == policy_id, PodPolicy.tenant_id == tenant_id).first()
    if p is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="策略不存在")
    p.name = body.name
    p.policy_json = body.policy_json
    p.agent_id = body.agent_id
    p.note = body.note
    _snapshot(db, p)
    db.add(AuditLog(tenant_id=tenant_id, user_id=user["id"], action="policy.update", detail_json=f'{{"policy_id": {p.id}}}'))
    db.commit()
    return {"policy": policy_out(p)}


@router.delete("/{policy_id}")
def delete_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    require_admin(db, tenant_id, user)
    p = db.query(PodPolicy).filter(PodPolicy.id == policy_id, PodPolicy.tenant_id == tenant_id).first()
    if p is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="策略不存在")
    db.add(AuditLog(tenant_id=tenant_id, user_id=user["id"], action="policy.delete", detail_json=f'{{"policy_id": {p.id}}}'))
    db.delete(p)
    db.commit()
    return {"removed": policy_id}


# ---- 策略模板（一键应用） ----

SENSITIVE_PATHS = [
    "~/.ssh", ".env", "credentials", "id_rsa", "id_ed25519", ".aws", ".git-credentials",
    "known_hosts", "id_dsa", "id_ecdsa", "*.pem", "*.key", "secrets", "token",
]

POLICY_TEMPLATES = {
    "balanced": {
        "name": "均衡模式（推荐）",
        "desc": "日常开发：读文件/列目录/搜索放行，写入需审批，删除一律拒绝，拦截常见敏感路径与密钥输出。",
        "policy": {
            "version": "0.1.0",
            "defaultDecision": "deny",
            "servers": {
                "filesystem": {
                    "allow": ["read_file", "list_directory", "search_files"],
                    "approve": ["write_file", "edit_file"],
                    "deny": ["delete_file"],
                    "source": {"command": "mcp-server-filesystem"},
                }
            },
            "secrets": {
                "deny_input_paths": SENSITIVE_PATHS,
                "deny_output_matching": SECRET_PATTERNS,
            },
        },
    },
    "high-security": {
        "name": "高安全模式",
        "desc": "只读环境：仅允许读/列/搜索，一切写入与删除直接拒绝，敏感路径与密钥输出全量拦截。",
        "policy": {
            "version": "0.1.0",
            "defaultDecision": "deny",
            "servers": {
                "filesystem": {
                    "allow": ["read_file", "list_directory", "search_files"],
                    "approve": [],
                    "deny": ["write_file", "edit_file", "delete_file"],
                    "source": {"command": "mcp-server-filesystem"},
                }
            },
            "secrets": {
                "deny_input_paths": SENSITIVE_PATHS,
                "deny_output_matching": SECRET_PATTERNS,
            },
        },
    },
    "audit-only": {
        "name": "只审计模式",
        "desc": "不拦截任何调用，只记录审计链（配合 pod record / 评估期观察 agent 行为）。",
        "policy": {
            "version": "0.1.0",
            "defaultDecision": "allow",
            "servers": {},
            "secrets": {"deny_input_paths": [], "deny_output_matching": []},
        },
    },
    "locked-down": {
        "name": "锁死模式",
        "desc": "禁止一切工具调用（default deny + 无放行列表），用于隔离风险 agent。",
        "policy": {
            "version": "0.1.0",
            "defaultDecision": "deny",
            "servers": {
                "filesystem": {
                    "allow": [],
                    "approve": [],
                    "deny": ["*"],
                    "source": {"command": "mcp-server-filesystem"},
                }
            },
            "secrets": {
                "deny_input_paths": SENSITIVE_PATHS,
                "deny_output_matching": SECRET_PATTERNS,
            },
        },
    },
}


class TemplateApplyRequest(BaseModel):
    template: str = Field(min_length=1, max_length=32)
    agent_id: int | None = None  # None = 覆盖租户模板


@router.get("/templates")
def list_templates():
    """预置策略模板清单（含描述，不含完整 JSON——预览用 summary）。"""
    return {
        "templates": [
            {"id": tid, "name": t["name"], "desc": t["desc"],
             "default_decision": t["policy"]["defaultDecision"],
             "allow": t["policy"]["servers"].get("filesystem", {}).get("allow", []),
             "deny": t["policy"]["servers"].get("filesystem", {}).get("deny", []),
             "approve": t["policy"]["servers"].get("filesystem", {}).get("approve", []),
             "sensitive_paths": len(t["policy"].get("secrets", {}).get("deny_input_paths", []))}
            for tid, t in POLICY_TEMPLATES.items()
        ]
    }


@router.post("/apply-template")
def apply_template(
    body: TemplateApplyRequest,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    """一键应用模板：覆盖该 agent 的现有策略（无则创建），agent_id 为空 = 租户模板。"""
    require_admin(db, tenant_id, user)
    if body.template not in POLICY_TEMPLATES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"未知模板: {body.template}")
    tpl = POLICY_TEMPLATES[body.template]
    import json
    import copy

    # 注入目标 agent 名（策略引擎按 policy.agent 校验调用方身份）
    from app.models import Agent as PodAgentModel

    policy_body = copy.deepcopy(tpl["policy"])
    if body.agent_id is not None:
        agent_row = db.query(PodAgentModel).filter(
            PodAgentModel.id == body.agent_id, PodAgentModel.tenant_id == tenant_id
        ).first()
        if agent_row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="agent 不存在")
        policy_body["agent"] = agent_row.name
    else:
        policy_body.pop("agent", None)  # 租户模板不绑 agent

    # 同 agent 已有策略 → 覆盖；否则新建
    existing = (
        db.query(PodPolicy)
        .filter(
            PodPolicy.tenant_id == tenant_id,
            PodPolicy.agent_id == body.agent_id,
        )
        .first()
    )
    policy_json = json.dumps(policy_body, ensure_ascii=False, indent=2)
    if existing is not None:
        existing.name = f"{tpl['name']}（模板）"
        existing.policy_json = policy_json
        existing.note = tpl["desc"]
        _snapshot(db, existing)
        action = "policy.apply_template_update"
    else:
        existing = PodPolicy(
            tenant_id=tenant_id, agent_id=body.agent_id,
            name=f"{tpl['name']}（模板）", policy_json=policy_json,
            note=tpl["desc"], version="0.1.0",
        )
        db.add(existing)
        db.flush()
        _snapshot(db, existing)
        action = "policy.apply_template"
    db.flush()
    db.add(AuditLog(tenant_id=tenant_id, user_id=user["id"], action=action,
                    detail_json=f'{{"template": "{body.template}", "agent_id": {body.agent_id}}}'))
    db.commit()
    return {"policy": policy_out(existing), "template": body.template, "applied": True}


class PolicyGenerateRequest(BaseModel):
    description: str = Field(min_length=2, max_length=500)


@router.post("/generate")
def generate_policy_from_text(
    body: PolicyGenerateRequest,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    """自然语言 → 策略 JSON（AI 生成辅助）。

    铁律：生成结果**不落库**，仅返回前端预览；用户确认后走 POST /policies 保存
    （保存动作进审计链）。未配置模型返回 400。
    """
    from app.models import TenantSettings
    from app.services import llm
    from app.services.ai_summary import generate_policy

    row = db.query(TenantSettings).filter(TenantSettings.tenant_id == tenant_id).first()
    try:
        cfg = llm.resolve_config(row)
    except llm.LlmConfigError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    try:
        result = generate_policy(
            cfg, body.description, db=db, tenant_id=tenant_id, user_id=user["id"]
        )
        db.commit()  # 提交调用留痕；生成的策略仍不落库
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"策略生成失败: {e}") from e
    import json as _json

    return {
        "policy": result["policy"],
        "policy_json": _json.dumps(result["policy"], ensure_ascii=False, indent=2),
        "model": result["model"],
        "explanation": result.get("explanation", ""),
        "saved": False,  # 仅预览，等待人工确认保存
        "hint": "AI 生成仅供预览——请核对后保存，保存动作将写入审计",
    }


@router.get("/{policy_id}/versions")
def list_policy_versions(
    policy_id: int,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
):
    """策略版本历史（旧→新），含每次变更的 JSON 与备注，供 diff/回滚。"""
    p = db.query(PodPolicy).filter(PodPolicy.id == policy_id, PodPolicy.tenant_id == tenant_id).first()
    if p is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="策略不存在")
    versions = (
        db.query(PodPolicyVersion)
        .filter(PodPolicyVersion.policy_id == policy_id)
        .order_by(PodPolicyVersion.version)
        .all()
    )
    return {
        "policy_id": policy_id,
        "current_version": p.version,
        "versions": [
            {
                "version": v.version,
                "policy_json": v.policy_json,
                "note": v.note,
                "created_at": v.created_at.isoformat(),
            }
            for v in versions
        ],
    }


class PolicyRevertRequest(BaseModel):
    version: int = Field(ge=1)


@router.post("/{policy_id}/revert")
def revert_policy(
    policy_id: int,
    body: PolicyRevertRequest,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    """回滚到历史版本（当前内容先存为新版本再覆盖）。"""
    require_admin(db, tenant_id, user)
    p = db.query(PodPolicy).filter(PodPolicy.id == policy_id, PodPolicy.tenant_id == tenant_id).first()
    if p is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="策略不存在")
    target = (
        db.query(PodPolicyVersion)
        .filter(PodPolicyVersion.policy_id == policy_id, PodPolicyVersion.version == body.version)
        .first()
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"版本 v{body.version} 不存在")
    _snapshot(db, p)  # 当前内容入历史
    p.policy_json = target.policy_json
    p.note = target.note
    db.add(AuditLog(tenant_id=tenant_id, user_id=user["id"], action="policy.revert",
                    detail_json=f'{{"policy_id": {p.id}, "version": {body.version}}}'))
    db.commit()
    return {"policy": policy_out(p), "reverted_to": body.version}


@router.get("/{policy_id}/versions")
def list_policy_versions(
    policy_id: int,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
):
    """策略版本历史（旧→新），含每次变更的 JSON 与备注，供 diff/回滚。"""
    p = db.query(PodPolicy).filter(PodPolicy.id == policy_id, PodPolicy.tenant_id == tenant_id).first()
    if p is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="策略不存在")
    versions = (
        db.query(PodPolicyVersion)
        .filter(PodPolicyVersion.policy_id == policy_id)
        .order_by(PodPolicyVersion.version)
        .all()
    )
    return {
        "policy_id": policy_id,
        "current_version": p.version,
        "versions": [
            {
                "version": v.version,
                "policy_json": v.policy_json,
                "note": v.note,
                "created_at": v.created_at.isoformat(),
            }
            for v in versions
        ],
    }


class PolicyRevertRequest(BaseModel):
    version: int = Field(ge=1)


@router.post("/{policy_id}/revert")
def revert_policy(
    policy_id: int,
    body: PolicyRevertRequest,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    """回滚到历史版本（当前内容先存为新版本再覆盖）。"""
    require_admin(db, tenant_id, user)
    p = db.query(PodPolicy).filter(PodPolicy.id == policy_id, PodPolicy.tenant_id == tenant_id).first()
    if p is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="策略不存在")
    target = (
        db.query(PodPolicyVersion)
        .filter(PodPolicyVersion.policy_id == policy_id, PodPolicyVersion.version == body.version)
        .first()
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"版本 v{body.version} 不存在")
    _snapshot(db, p)  # 当前内容入历史
    p.policy_json = target.policy_json
    p.note = target.note
    db.add(AuditLog(tenant_id=tenant_id, user_id=user["id"], action="policy.revert",
                    detail_json=f'{{"policy_id": {p.id}, "version": {body.version}}}'))
    db.commit()
    return {"policy": policy_out(p), "reverted_to": body.version}
