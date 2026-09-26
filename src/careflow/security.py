"""角色权限、诊所隔离与患者敏感字段访问边界。"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from .errors import Forbidden, NotFound, Unauthorized

ROLE_PERMISSIONS = {
    "owner": {"clinic:manage", "staff:manage", "patient:read", "patient:write", "clinical:read", "clinical:write",
              "consent:write", "appointment:write", "incident:manage", "audit:read", "billing:read", "export:read", "data:export"},
    "clinician": {"patient:read", "clinical:read", "clinical:write", "consent:read", "consent:write", "appointment:read",
                  "appointment:write", "incident:report", "incident:manage", "followup:manage", "audit:patient"},
    "nurse": {"patient:read", "clinical:read", "clinical:write", "consent:read", "appointment:read", "appointment:write",
              "incident:report", "incident:manage", "followup:manage", "audit:patient"},
    "coordinator": {"patient:read", "patient:write", "consent:read", "appointment:read", "appointment:write", "followup:manage"},
    "auditor": {"audit:read", "patient:read", "clinical:read", "billing:read", "data:export"},
}


@dataclass(frozen=True)
class Principal:
    staff_id: str
    clinic_id: str
    role: str
    active: bool = True


def authorize(principal: Principal, permission: str, *, clinic_id: str | None = None) -> None:
    if not principal.active:
        raise Unauthorized("账号已停用")
    if clinic_id is not None and principal.clinic_id != clinic_id:
        # 不泄露另一诊所资源是否存在。
        raise NotFound("记录不存在")
    if permission not in ROLE_PERMISSIONS.get(principal.role, set()):
        raise Forbidden("当前岗位无权执行此操作", details={"permission": permission})


def principal_for(connection, staff_id: str, clinic_id: str) -> Principal:
    row = connection.execute(
        "SELECT id,clinic_id,role,active FROM staff WHERE id=? AND clinic_id=?", (staff_id, clinic_id)
    ).fetchone()
    if row is None:
        raise Unauthorized("账号不存在或不属于当前诊所")
    return Principal(row["id"], row["clinic_id"], row["role"], bool(row["active"]))


def make_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt, 180_000)


def verify_token(token: str, salt: bytes, expected: bytes) -> bool:
    return hmac.compare_digest(hash_token(token, salt), expected)
