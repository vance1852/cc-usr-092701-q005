"""诊所运营用例与跨域事务。"""

from __future__ import annotations

from datetime import timedelta
import hashlib
import secrets
from typing import Any

from . import audit
from .clock import Clock, SystemClock
from .db import Database, decode_json, encode_json
from .errors import Conflict, Forbidden, NotFound, ValidationError
from .ids import new_id, require_id, require_idempotency_key
from .security import Principal, authorize, hash_token, principal_for, verify_token
from .validation import (
    calendar_date,
    choice,
    decimal_value,
    object_value,
    parsed_timestamp,
    request_digest,
    require_match,
    text,
    timestamp,
)


class Careflow:
    """应用服务。公开方法是业务边界，直接接收已解析 JSON 值。"""

    def __init__(self, database: Database | str, clock: Clock | None = None):
        self.db = database if isinstance(database, Database) else Database(database)
        self.clock = clock or SystemClock()
        from .supplies import SupplyService
        from .reports import ReportService
        from .exports import PatientExportService
        from .milestones import MilestoneService
        from .clinical_flags import ClinicalFlagService
        self.supplies = SupplyService(self.db, self.clock)
        self.reports = ReportService(self.db, self.clock)
        self.exports = PatientExportService(self.db, self.clock)
        self.milestones = MilestoneService(self.db, self.clock)
        self.clinical_flags = ClinicalFlagService(self.db, self.clock)

    def now(self) -> str:
        return timestamp(self.clock.now())

    def create_clinic(self, name: str, timezone: str) -> dict[str, Any]:
        import zoneinfo

        name = text(name, "诊所名称", maximum=160)
        timezone = text(timezone, "时区", maximum=80)
        try:
            zoneinfo.ZoneInfo(timezone)
        except zoneinfo.ZoneInfoNotFoundError as exc:
            raise ValidationError("时区无效") from exc
        clinic_id = new_id("cln")
        now = self.now()
        with self.db.transaction() as connection:
            connection.execute("INSERT INTO clinics(id,name,timezone,state,created_at) VALUES(?,?,?,'active',?)",
                               (clinic_id, name, timezone, now))
        return {"id": clinic_id, "name": name, "timezone": timezone, "state": "active", "version": 1}

    def initialize_clinic(self, name: str, timezone: str, owner_name: str, password: str) -> dict[str, Any]:
        """首次配置为一个原子操作；失败时不留下无负责人的空诊所。"""
        import hashlib
        import secrets
        import zoneinfo

        name = text(name, "诊所名称", maximum=160)
        timezone = text(timezone, "时区", maximum=80)
        owner_name = text(owner_name, "负责人姓名", maximum=120)
        if not isinstance(password, str) or len(password) < 12 or len(password) > 200 or len(set(password)) < 5:
            raise ValidationError("负责人密码须为 12 至 200 个字符，并包含足够多的不同字符")
        try:
            zoneinfo.ZoneInfo(timezone)
        except zoneinfo.ZoneInfoNotFoundError as exc:
            raise ValidationError("时区无效") from exc
        clinic_id, owner_id, now = new_id("cln"), new_id("stf"), self.now()
        salt = secrets.token_bytes(24)
        password_hash = hash_token(password, salt)
        with self.db.transaction() as connection:
            if connection.execute("SELECT 1 FROM clinics LIMIT 1").fetchone():
                raise Conflict("服务已完成初始配置；不能重复创建首个诊所")
            connection.execute("INSERT INTO clinics(id,name,timezone,state,created_at) VALUES(?,?,?,'active',?)",
                               (clinic_id, name, timezone, now))
            connection.execute("INSERT INTO staff(id,clinic_id,display_name,role,created_at) VALUES(?,?,?,'owner',?)",
                               (owner_id, clinic_id, owner_name, now))
            connection.execute("INSERT INTO staff_credentials(staff_id,salt,password_hash,changed_at) VALUES(?,?,?,?)",
                               (owner_id, salt, password_hash, now))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=owner_id, patient_id=None,
                               aggregate_type="clinic", aggregate_id=clinic_id, action="clinic.initialized",
                               occurred_at=now, payload={"timezone": timezone})
        return {"clinic_id": clinic_id, "owner_id": owner_id, "created_at": now}

    def create_staff(self, clinic_id: str, name: str, role: str, *, actor_id: str | None = None) -> dict[str, Any]:
        clinic_id = require_id(clinic_id, "诊所编号")
        name = text(name, "员工姓名", maximum=120)
        role = choice(role, "岗位", {"owner", "clinician", "nurse", "coordinator", "auditor"})
        staff_id = new_id("stf")
        now = self.now()
        with self.db.transaction() as connection:
            clinic = connection.execute("SELECT id,state FROM clinics WHERE id=?", (clinic_id,)).fetchone()
            if clinic is None:
                raise NotFound("诊所不存在")
            if actor_id:
                authorize(principal_for(connection, actor_id, clinic_id), "staff:manage", clinic_id=clinic_id)
            elif role != "owner":
                raise Forbidden("创建首位负责人后才能添加其他岗位")
            connection.execute("INSERT INTO staff(id,clinic_id,display_name,role,created_at) VALUES(?,?,?,?,?)",
                               (staff_id, clinic_id, name, role, now))
            if actor_id:
                audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                                   aggregate_type="staff", aggregate_id=staff_id, action="staff.created",
                                   occurred_at=now, payload={"role": role})
        return {"id": staff_id, "clinic_id": clinic_id, "display_name": name, "role": role, "active": True}

    def set_password(self, clinic_id: str, actor_id: str, staff_id: str, password: str) -> dict[str, Any]:
        if not isinstance(password, str) or len(password) < 12 or len(password) > 200:
            raise ValidationError("密码长度必须为 12 至 200 个字符")
        if len(set(password)) < 5:
            raise ValidationError("密码需要包含足够多的不同字符")
        now = self.now()
        salt = secrets.token_bytes(24)
        hashed = hash_token(password, salt)
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            if actor_id != staff_id:
                authorize(principal, "staff:manage", clinic_id=clinic_id)
            target = connection.execute("SELECT id FROM staff WHERE id=? AND clinic_id=? AND active=1", (staff_id, clinic_id)).fetchone()
            if target is None:
                raise NotFound("员工不存在或已停用")
            connection.execute(
                "INSERT INTO staff_credentials(staff_id,salt,password_hash,changed_at) VALUES(?,?,?,?) "
                "ON CONFLICT(staff_id) DO UPDATE SET salt=excluded.salt,password_hash=excluded.password_hash, "
                "changed_at=excluded.changed_at,credential_version=staff_credentials.credential_version+1",
                (staff_id, salt, hashed, now))
            connection.execute("UPDATE access_sessions SET revoked_at=? WHERE staff_id=? AND revoked_at IS NULL", (now, staff_id))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                               aggregate_type="staff", aggregate_id=staff_id, action="staff.password_changed",
                               occurred_at=now, payload={"sessions_revoked": True})
        return {"staff_id": staff_id, "changed_at": now, "sessions_revoked": True}

    def login(self, clinic_id: str, staff_id: str, password: str, *, lifetime_hours: int = 8) -> dict[str, Any]:
        if not 1 <= lifetime_hours <= 24:
            raise ValidationError("登录时长必须为 1 至 24 小时")
        now = self.now()
        with self.db.transaction() as connection:
            staff = connection.execute("SELECT * FROM staff WHERE id=? AND clinic_id=? AND active=1", (staff_id, clinic_id)).fetchone()
            credential = connection.execute("SELECT * FROM staff_credentials WHERE staff_id=?", (staff_id,)).fetchone()
            if staff is None or credential is None or not verify_token(password, credential["salt"], credential["password_hash"]):
                # 认证错误不区分账号不存在、停用或密码错误。
                raise Forbidden("员工编号或密码不正确")
            token = secrets.token_urlsafe(40)
            token_hash = hashlib.sha256(token.encode("utf-8")).digest()
            expires = timestamp(parsed_timestamp(now) + timedelta(hours=lifetime_hours))
            connection.execute("INSERT INTO access_sessions(token_hash,staff_id,clinic_id,created_at,expires_at) VALUES(?,?,?,?,?)",
                               (token_hash, staff_id, clinic_id, now, expires))
            return {"access_token": token, "token_type": "Bearer", "staff_id": staff_id,
                    "clinic_id": clinic_id, "role": staff["role"], "expires_at": expires}

    def staff_for_token(self, clinic_id: str, token: str) -> str:
        if not isinstance(token, str) or len(token) < 24 or len(token) > 256:
            from .errors import Unauthorized
            raise Unauthorized("访问凭据无效")
        token_hash = hashlib.sha256(token.encode("utf-8")).digest()
        now = self.now()
        with self.db.transaction(write=False) as connection:
            row = connection.execute(
                "SELECT s.staff_id FROM access_sessions s JOIN staff p ON p.id=s.staff_id "
                "WHERE s.token_hash=? AND s.clinic_id=? AND s.revoked_at IS NULL AND s.expires_at>? AND p.active=1",
                (token_hash, clinic_id, now)).fetchone()
            if row is None:
                from .errors import Unauthorized
                raise Unauthorized("访问凭据无效或已过期")
            return row["staff_id"]

    def logout(self, clinic_id: str, actor_id: str, token: str) -> dict[str, Any]:
        token_hash = hashlib.sha256(token.encode("utf-8")).digest()
        now = self.now()
        with self.db.transaction() as connection:
            row = connection.execute("SELECT * FROM access_sessions WHERE token_hash=? AND clinic_id=?", (token_hash, clinic_id)).fetchone()
            if row is None or row["staff_id"] != actor_id:
                raise NotFound("登录会话不存在")
            if row["revoked_at"] is None:
                connection.execute("UPDATE access_sessions SET revoked_at=? WHERE token_hash=?", (now, token_hash))
                audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                                   aggregate_type="session", aggregate_id=token_hash.hex()[:24], action="session.revoked",
                                   occurred_at=now, payload={})
        return {"revoked": True, "revoked_at": now}

    def disable_staff(self, clinic_id: str, actor_id: str, staff_id: str, expected_version: int) -> dict[str, Any]:
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "staff:manage", clinic_id=clinic_id)
            target = connection.execute("SELECT * FROM staff WHERE id=? AND clinic_id=?", (staff_id, clinic_id)).fetchone()
            if target is None:
                raise NotFound("员工不存在")
            require_match(target["version"], expected_version, "员工记录")
            if target["role"] == "owner":
                others = connection.execute("SELECT count(*) FROM staff WHERE clinic_id=? AND role='owner' AND active=1", (clinic_id,)).fetchone()[0]
                if others <= 1:
                    raise Conflict("诊所必须保留至少一位负责人")
            connection.execute("UPDATE staff SET active=0,version=version+1 WHERE id=?", (staff_id,))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                               aggregate_type="staff", aggregate_id=staff_id, action="staff.disabled",
                               occurred_at=now, payload={"previous_role": target["role"]})
        return {"id": staff_id, "active": False, "version": expected_version + 1}

    def create_patient(self, clinic_id: str, actor_id: str, external_ref: str, name: str,
                       *, birth_date: str | None = None, phone_ciphertext: str | None = None) -> dict[str, Any]:
        external_ref = text(external_ref, "患者外部编号", maximum=100)
        name = text(name, "患者姓名", maximum=120)
        birth = calendar_date(birth_date) if birth_date else None
        if phone_ciphertext is not None and (not isinstance(phone_ciphertext, str) or len(phone_ciphertext) > 1024):
            raise ValidationError("联系方式密文无效")
        patient_id = new_id("pat")
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "patient:write", clinic_id=clinic_id)
            connection.execute(
                "INSERT INTO patients(id,clinic_id,external_ref,display_name,birth_date,phone_ciphertext,state,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,'active',?,?)", (patient_id, clinic_id, external_ref, name, birth, phone_ciphertext, now, now))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=patient_id,
                               aggregate_type="patient", aggregate_id=patient_id, action="patient.created",
                               occurred_at=now, payload={"external_ref": external_ref})
        return {"id": patient_id, "clinic_id": clinic_id, "external_ref": external_ref,
                "display_name": name, "birth_date": birth, "state": "active", "version": 1}

    def get_patient(self, clinic_id: str, actor_id: str, patient_id: str, *, include_contact: bool = False) -> dict[str, Any]:
        with self.db.transaction(write=False) as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            authorize(principal, "patient:read", clinic_id=clinic_id)
            row = connection.execute("SELECT * FROM patients WHERE id=? AND clinic_id=?", (patient_id, clinic_id)).fetchone()
            if row is None:
                raise NotFound("患者不存在")
            result = {"id": row["id"], "clinic_id": row["clinic_id"], "external_ref": row["external_ref"],
                      "display_name": row["display_name"], "birth_date": row["birth_date"],
                      "state": row["state"], "version": row["version"], "created_at": row["created_at"]}
            if include_contact:
                authorize(principal, "clinical:read", clinic_id=clinic_id)
                result["phone_ciphertext"] = row["phone_ciphertext"]
            return result

    def merge_patients(self, clinic_id: str, actor_id: str, source_id: str, target_id: str,
                       *, expected_source: int, expected_target: int, reason: str) -> dict[str, Any]:
        reason = text(reason, "合并原因", maximum=600)
        if source_id == target_id:
            raise ValidationError("不能将患者合并到自身")
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "patient:write", clinic_id=clinic_id)
            source = connection.execute("SELECT * FROM patients WHERE id=? AND clinic_id=?", (source_id, clinic_id)).fetchone()
            target = connection.execute("SELECT * FROM patients WHERE id=? AND clinic_id=?", (target_id, clinic_id)).fetchone()
            if source is None or target is None:
                raise NotFound("患者不存在")
            require_match(source["version"], expected_source, "源患者")
            require_match(target["version"], expected_target, "目标患者")
            if source["state"] != "active" or target["state"] != "active":
                raise Conflict("只有在诊患者可以合并")
            if connection.execute("SELECT 1 FROM patients WHERE merged_into=?", (source_id,)).fetchone():
                raise Conflict("该患者已作为其他合并记录的目标")
            connection.execute("UPDATE patients SET state='merged',merged_into=?,updated_at=?,version=version+1 WHERE id=?",
                               (target_id, now, source_id))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=target_id,
                               aggregate_type="patient", aggregate_id=target_id, action="patient.merged",
                               occurred_at=now, payload={"source_id": source_id, "reason": reason,
                                                         "source_version": source["version"], "target_version": target["version"]})
        return {"source_id": source_id, "target_id": target_id, "state": "merged", "merged_at": now}

    def grant_consent(self, clinic_id: str, actor_id: str, patient_id: str, purpose: str,
                      revision: int, text_digest: str, *, expires_at: str | None = None) -> dict[str, Any]:
        purpose = choice(purpose, "授权用途", {"clinical_care", "aesthetic_procedure", "weight_program", "followup_contact", "data_export"})
        if not isinstance(revision, int) or revision < 1:
            raise ValidationError("授权版本必须为正整数")
        if len(text_digest) != 64 or any(c not in "0123456789abcdef" for c in text_digest):
            raise ValidationError("授权文本摘要必须为 SHA-256")
        now = self.now()
        expires = timestamp(expires_at, "到期时间") if expires_at else None
        if expires and parsed_timestamp(expires) <= parsed_timestamp(now):
            raise ValidationError("授权到期时间必须晚于当前时间")
        consent_id = new_id("cns")
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            authorize(principal, "consent:write", clinic_id=clinic_id)
            patient = connection.execute("SELECT id,state FROM patients WHERE id=? AND clinic_id=?", (patient_id, clinic_id)).fetchone()
            if patient is None:
                raise NotFound("患者不存在")
            if patient["state"] != "active":
                raise Conflict("已合并或关闭的患者不能签署新授权")
            previous = connection.execute(
                "SELECT * FROM consents WHERE patient_id=? AND purpose=? ORDER BY revision DESC LIMIT 1", (patient_id, purpose)
            ).fetchone()
            if previous and revision <= previous["revision"]:
                raise Conflict("新授权版本必须高于当前版本")
            if previous and previous["state"] == "granted":
                connection.execute("UPDATE consents SET state='expired' WHERE id=?", (previous["id"],))
            connection.execute(
                "INSERT INTO consents(id,patient_id,purpose,revision,text_digest,state,effective_at,expires_at,recorded_by,supersedes,created_at) "
                "VALUES(?,?,?,?,?,'granted',?,?,?,?,?)",
                (consent_id, patient_id, purpose, revision, text_digest, now, expires, actor_id,
                 previous["id"] if previous else None, now))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=patient_id,
                               aggregate_type="consent", aggregate_id=consent_id, action="consent.granted",
                               occurred_at=now, payload={"purpose": purpose, "revision": revision, "digest": text_digest})
        return {"id": consent_id, "patient_id": patient_id, "purpose": purpose, "revision": revision,
                "text_digest": text_digest, "state": "granted", "effective_at": now, "expires_at": expires}

    def withdraw_consent(self, clinic_id: str, actor_id: str, consent_id: str, reason: str) -> dict[str, Any]:
        reason = text(reason, "撤回原因", maximum=600)
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "consent:write", clinic_id=clinic_id)
            row = connection.execute(
                "SELECT c.* FROM consents c JOIN patients p ON p.id=c.patient_id WHERE c.id=? AND p.clinic_id=?",
                (consent_id, clinic_id)).fetchone()
            if row is None:
                raise NotFound("授权不存在")
            if row["state"] == "withdrawn":
                return {"id": consent_id, "state": "withdrawn", "withdrawn_at": now, "replayed": True}
            if row["state"] != "granted":
                raise Conflict("只有当前有效授权可以撤回")
            connection.execute("UPDATE consents SET state='withdrawn' WHERE id=?", (consent_id,))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=row["patient_id"],
                               aggregate_type="consent", aggregate_id=consent_id, action="consent.withdrawn",
                               occurred_at=now, payload={"purpose": row["purpose"], "reason": reason})
            self._pause_plans_for_withdrawal(connection, row, now, actor_id)
        return {"id": consent_id, "state": "withdrawn", "withdrawn_at": now, "replayed": False}

    def _pause_plans_for_withdrawal(self, connection, consent, now: str, actor_id: str) -> int:
        dependent_kind = "aesthetic" if consent["purpose"] == "aesthetic_procedure" else "weight" if consent["purpose"] == "weight_program" else None
        if not dependent_kind:
            return 0
        rows = connection.execute(
            "SELECT * FROM plans WHERE patient_id=? AND kind=? AND state IN ('proposed','active') AND consent_id=?",
            (consent["patient_id"], dependent_kind, consent["id"])).fetchall()
        for plan in rows:
            connection.execute("UPDATE plans SET state='paused',updated_at=?,version=version+1 WHERE id=?", (now, plan["id"]))
            self._record_plan_revision(connection, plan["id"], plan["version"] + 1, actor_id, "关联授权已撤回", now)
            audit.append_event(connection, clinic_id=plan["clinic_id"], actor_id=actor_id, patient_id=plan["patient_id"],
                               aggregate_type="plan", aggregate_id=plan["id"], action="plan.paused.consent_withdrawn",
                               occurred_at=now, payload={"consent_id": consent["id"], "previous_version": plan["version"]})
        return len(rows)

    def consent_history(self, clinic_id: str, actor_id: str, patient_id: str, purpose: str | None = None) -> list[dict[str, Any]]:
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "consent:read", clinic_id=clinic_id)
            if connection.execute("SELECT 1 FROM patients WHERE id=? AND clinic_id=?", (patient_id, clinic_id)).fetchone() is None:
                raise NotFound("患者不存在")
            if purpose:
                rows = connection.execute("SELECT * FROM consents WHERE patient_id=? AND purpose=? ORDER BY revision", (patient_id, purpose)).fetchall()
            else:
                rows = connection.execute("SELECT * FROM consents WHERE patient_id=? ORDER BY purpose,revision", (patient_id,)).fetchall()
            return [dict(row) for row in rows]

    def create_assessment(self, clinic_id: str, actor_id: str, patient_id: str, kind: str,
                          measurements: dict, answers: dict, *, source: str = "clinician") -> dict[str, Any]:
        kind = choice(kind, "评估类型", {"aesthetic", "weight", "wellbeing", "screening"})
        source = choice(source, "记录来源", {"patient", "clinician", "device_import"})
        measurements = object_value(measurements, "测量值")
        answers = object_value(answers, "问卷")
        if len(measurements) > 80 or len(answers) > 120:
            raise ValidationError("评估条目数量超出限制")
        normalized_measurements = {}
        for key, value in measurements.items():
            key = text(key, "测量项目", maximum=80)
            normalized_measurements[key] = decimal_value(value, key, minimum="0", maximum="100000")
        normalized_answers = {}
        for key, value in answers.items():
            key = text(key, "评估项目", maximum=80)
            if isinstance(value, str):
                normalized_answers[key] = text(value, key, minimum=0, maximum=2000)
            elif isinstance(value, (bool, int, float)) or value is None:
                normalized_answers[key] = value
            else:
                raise ValidationError(f"{key}答案格式无效")
        assessment_id = new_id("asm")
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:write", clinic_id=clinic_id)
            patient = connection.execute("SELECT id,state FROM patients WHERE id=? AND clinic_id=?", (patient_id, clinic_id)).fetchone()
            if patient is None:
                raise NotFound("患者不存在")
            if patient["state"] != "active":
                raise Conflict("非在诊患者不能新增评估")
            connection.execute(
                "INSERT INTO assessments(id,patient_id,clinic_id,kind,captured_at,captured_by,measurements_json,answers_json,source,status,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,'draft',?)",
                (assessment_id, patient_id, clinic_id, kind, now, actor_id, encode_json(normalized_measurements),
                 encode_json(normalized_answers), source, now))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=patient_id,
                               aggregate_type="assessment", aggregate_id=assessment_id, action="assessment.created",
                               occurred_at=now, payload={"kind": kind, "source": source})
        return {"id": assessment_id, "patient_id": patient_id, "kind": kind, "status": "draft",
                "measurements": normalized_measurements, "answers": normalized_answers, "captured_at": now}

    def sign_assessment(self, clinic_id: str, actor_id: str, assessment_id: str, *, expected_version: int) -> dict[str, Any]:
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:write", clinic_id=clinic_id)
            row = connection.execute("SELECT * FROM assessments WHERE id=? AND clinic_id=?", (assessment_id, clinic_id)).fetchone()
            if row is None:
                raise NotFound("评估不存在")
            require_match(row["version"], expected_version, "评估")
            if row["status"] != "draft":
                raise Conflict("只有草稿评估可以签署")
            connection.execute("UPDATE assessments SET status='signed',signed_at=?,version=version+1 WHERE id=?", (now, assessment_id))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=row["patient_id"],
                               aggregate_type="assessment", aggregate_id=assessment_id, action="assessment.signed",
                               occurred_at=now, payload={"kind": row["kind"], "version": expected_version + 1})
        return {"id": assessment_id, "status": "signed", "signed_at": now, "version": expected_version + 1}

    def list_assessments(self, clinic_id: str, actor_id: str, patient_id: str, *, kind: str | None = None) -> list[dict[str, Any]]:
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            if connection.execute("SELECT 1 FROM patients WHERE id=? AND clinic_id=?", (patient_id, clinic_id)).fetchone() is None:
                raise NotFound("患者不存在")
            if kind:
                rows = connection.execute("SELECT * FROM assessments WHERE patient_id=? AND kind=? ORDER BY captured_at DESC", (patient_id, kind)).fetchall()
            else:
                rows = connection.execute("SELECT * FROM assessments WHERE patient_id=? ORDER BY captured_at DESC", (patient_id,)).fetchall()
            return [{"id": row["id"], "kind": row["kind"], "captured_at": row["captured_at"],
                     "captured_by": row["captured_by"], "measurements": decode_json(row["measurements_json"]),
                     "answers": decode_json(row["answers_json"]), "source": row["source"],
                     "status": row["status"], "signed_at": row["signed_at"], "version": row["version"]} for row in rows]

    def create_plan(self, clinic_id: str, actor_id: str, patient_id: str, kind: str, clinical_owner: str,
                    goal: dict, risk: dict, start_date: str, *, target_date: str | None = None,
                    assessment_id: str | None = None, consent_id: str | None = None) -> dict[str, Any]:
        kind = choice(kind, "计划类型", {"aesthetic", "weight", "wellbeing"})
        goal = object_value(goal, "目标", allowed={"description", "measure", "target", "review_interval_days"})
        risk = object_value(risk, "风险摘要", allowed={"screening", "contraindications", "review_required", "notes"})
        start = calendar_date(start_date, "开始日期")
        target = calendar_date(target_date, "目标日期") if target_date else None
        if target and target < start:
            raise ValidationError("目标日期不能早于开始日期")
        if "description" not in goal:
            raise ValidationError("目标需要包含说明")
        goal["description"] = text(goal["description"], "目标说明", maximum=1000)
        if "review_interval_days" in goal:
            goal["review_interval_days"] = int(decimal_value(goal["review_interval_days"], "复核间隔", minimum="1", maximum="365"))
        plan_id = new_id("pln")
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:write", clinic_id=clinic_id)
            patient = connection.execute("SELECT * FROM patients WHERE id=? AND clinic_id=?", (patient_id, clinic_id)).fetchone()
            owner = connection.execute("SELECT * FROM staff WHERE id=? AND clinic_id=? AND active=1", (clinical_owner, clinic_id)).fetchone()
            if patient is None:
                raise NotFound("患者不存在")
            if patient["state"] != "active":
                raise Conflict("非在诊患者不能建立新计划")
            if owner is None or owner["role"] not in {"clinician", "owner"}:
                raise ValidationError("临床负责人必须是有效的医生或负责人")
            if assessment_id:
                assessment = connection.execute("SELECT * FROM assessments WHERE id=? AND patient_id=?", (assessment_id, patient_id)).fetchone()
                if assessment is None or assessment["status"] != "signed":
                    raise Conflict("计划引用的评估不存在或尚未签署")
            required_purpose = {"aesthetic": "aesthetic_procedure", "weight": "weight_program"}.get(kind)
            if required_purpose:
                consent = connection.execute(
                    "SELECT * FROM consents WHERE id=? AND patient_id=? AND purpose=? AND state='granted'",
                    (consent_id, patient_id, required_purpose)).fetchone() if consent_id else None
                if consent is None or (consent["expires_at"] and parsed_timestamp(consent["expires_at"]) <= parsed_timestamp(now)):
                    raise Conflict("计划需要当前有效的对应授权")
            connection.execute(
                "INSERT INTO plans(id,patient_id,clinic_id,kind,state,created_by,clinical_owner,assessment_id,consent_id,goal_json,risk_json,start_date,target_date,created_at,updated_at) "
                "VALUES(?,?,?,?,'draft',?,?,?,?,?,?,?,?,?,?)",
                (plan_id, patient_id, clinic_id, kind, actor_id, clinical_owner, assessment_id, consent_id,
                 encode_json(goal), encode_json(risk), start, target, now, now))
            self._record_plan_revision(connection, plan_id, 1, actor_id, "首次建立", now)
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=patient_id,
                               aggregate_type="plan", aggregate_id=plan_id, action="plan.created", occurred_at=now,
                               payload={"kind": kind, "assessment_id": assessment_id, "consent_id": consent_id})
        return {"id": plan_id, "patient_id": patient_id, "kind": kind, "state": "draft", "version": 1,
                "goal": goal, "risk": risk, "start_date": start, "target_date": target}

    def _record_plan_revision(self, connection, plan_id: str, revision: int, actor_id: str, reason: str, now: str) -> None:
        row = connection.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
        snapshot = {key: row[key] for key in ("kind", "state", "clinical_owner", "assessment_id", "consent_id", "goal_json", "risk_json", "start_date", "target_date", "version")}
        connection.execute("INSERT INTO plan_revisions(plan_id,revision,snapshot_json,changed_by,change_reason,created_at) VALUES(?,?,?,?,?,?)",
                           (plan_id, revision, encode_json(snapshot), actor_id, reason, now))

    def transition_plan(self, clinic_id: str, actor_id: str, plan_id: str, expected_version: int,
                        action: str, *, reason: str | None = None) -> dict[str, Any]:
        transitions = {"propose": ("draft", "proposed"), "activate": ("proposed", "active"),
                       "pause": ("active", "paused"), "resume": ("paused", "active"),
                       "complete": ("active", "completed"), "cancel": (("draft", "proposed", "paused"), "cancelled")}
        if action not in transitions:
            raise ValidationError("计划操作无效")
        if action in {"pause", "cancel"}:
            reason = text(reason or "", "操作原因", maximum=600)
        now = self.now()
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            authorize(principal, "clinical:write", clinic_id=clinic_id)
            plan = connection.execute("SELECT * FROM plans WHERE id=? AND clinic_id=?", (plan_id, clinic_id)).fetchone()
            if plan is None:
                raise NotFound("诊疗计划不存在")
            require_match(plan["version"], expected_version, "诊疗计划")
            before, after = transitions[action]
            if plan["state"] not in ((before,) if isinstance(before, str) else before):
                raise Conflict("诊疗计划当前状态不允许此操作", details={"state": plan["state"], "action": action})
            if action in {"activate", "resume"} and plan["consent_id"]:
                consent = connection.execute("SELECT state,expires_at FROM consents WHERE id=?", (plan["consent_id"],)).fetchone()
                if consent is None or consent["state"] != "granted" or (consent["expires_at"] and parsed_timestamp(consent["expires_at"]) <= parsed_timestamp(now)):
                    raise Conflict("计划授权已撤回或过期")
            new_version = plan["version"] + 1
            connection.execute("UPDATE plans SET state=?,updated_at=?,version=? WHERE id=?", (after, now, new_version, plan_id))
            self._record_plan_revision(connection, plan_id, new_version, actor_id, reason or action, now)
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=plan["patient_id"],
                               aggregate_type="plan", aggregate_id=plan_id, action=f"plan.{action}", occurred_at=now,
                               payload={"from": plan["state"], "to": after, "reason": reason, "version": new_version})
        return {"id": plan_id, "state": after, "version": new_version, "updated_at": now}

    def plan_history(self, clinic_id: str, actor_id: str, plan_id: str) -> list[dict[str, Any]]:
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            plan = connection.execute("SELECT id FROM plans WHERE id=? AND clinic_id=?", (plan_id, clinic_id)).fetchone()
            if plan is None:
                raise NotFound("诊疗计划不存在")
            rows = connection.execute("SELECT * FROM plan_revisions WHERE plan_id=? ORDER BY revision", (plan_id,)).fetchall()
            return [{"revision": row["revision"], "snapshot": decode_json(row["snapshot_json"]),
                     "changed_by": row["changed_by"], "reason": row["change_reason"], "created_at": row["created_at"]} for row in rows]

    def create_appointment(self, clinic_id: str, actor_id: str, patient_id: str, kind: str,
                           starts_at: str, ends_at: str, idempotency_key: str, *,
                           staff_id: str | None = None, plan_id: str | None = None,
                           hold_minutes: int = 10) -> dict[str, Any]:
        starts = timestamp(starts_at, "开始时间")
        ends = timestamp(ends_at, "结束时间")
        if parsed_timestamp(ends) <= parsed_timestamp(starts):
            raise ValidationError("结束时间必须晚于开始时间")
        if parsed_timestamp(starts) <= parsed_timestamp(self.now()):
            raise ValidationError("不能预约已过去的时间")
        if not isinstance(hold_minutes, int) or not 1 <= hold_minutes <= 60:
            raise ValidationError("预约占位时间必须为 1 至 60 分钟")
        key = require_idempotency_key(idempotency_key)
        kind = text(kind, "预约类型", maximum=100)
        body = {"clinic_id": clinic_id, "patient_id": patient_id, "kind": kind, "starts_at": starts,
                "ends_at": ends, "staff_id": staff_id, "plan_id": plan_id}
        body_hash = request_digest(body)
        now = self.now()
        appointment_id = new_id("apt")
        expires = timestamp(parsed_timestamp(now) + timedelta(minutes=hold_minutes))
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "appointment:write", clinic_id=clinic_id)
            existing = connection.execute("SELECT * FROM appointments WHERE clinic_id=? AND idempotency_key=?", (clinic_id, key)).fetchone()
            if existing:
                if existing["patient_id"] != patient_id or existing["starts_at"] != starts or existing["ends_at"] != ends or existing["kind"] != kind or existing["staff_id"] != staff_id or existing["plan_id"] != plan_id:
                    raise Conflict("幂等编号已被不同预约内容使用")
                return self._appointment_result(existing, replayed=True)
            patient = connection.execute("SELECT state FROM patients WHERE id=? AND clinic_id=?", (patient_id, clinic_id)).fetchone()
            if patient is None:
                raise NotFound("患者不存在")
            if patient["state"] != "active":
                raise Conflict("非在诊患者不能预约")
            if staff_id:
                staff = connection.execute("SELECT active FROM staff WHERE id=? AND clinic_id=?", (staff_id, clinic_id)).fetchone()
                if staff is None or not staff["active"]:
                    raise ValidationError("预约人员不存在或已停用")
                overlap = connection.execute(
                    "SELECT id FROM appointments WHERE clinic_id=? AND staff_id=? AND state IN ('held','booked','arrived','in_service') "
                    "AND starts_at<? AND ends_at>? AND (hold_expires_at IS NULL OR hold_expires_at>?)",
                    (clinic_id, staff_id, ends, starts, now)).fetchone()
                if overlap:
                    raise Conflict("工作人员在该时段已有预约", details={"appointment_id": overlap["id"]})
            if plan_id:
                plan = connection.execute("SELECT state,patient_id FROM plans WHERE id=? AND clinic_id=?", (plan_id, clinic_id)).fetchone()
                if plan is None or plan["patient_id"] != patient_id or plan["state"] not in {"proposed", "active"}:
                    raise Conflict("预约关联的计划不存在或当前不可履约")
            connection.execute(
                "INSERT INTO appointments(id,clinic_id,patient_id,plan_id,staff_id,kind,starts_at,ends_at,state,hold_expires_at,idempotency_key,created_by,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,'held',?,?,?,?)",
                (appointment_id, clinic_id, patient_id, plan_id, staff_id, kind, starts, ends, expires, key, actor_id, now))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=patient_id,
                               aggregate_type="appointment", aggregate_id=appointment_id, action="appointment.held",
                               occurred_at=now, payload={"starts_at": starts, "ends_at": ends, "hold_expires_at": expires})
            row = connection.execute("SELECT * FROM appointments WHERE id=?", (appointment_id,)).fetchone()
        return self._appointment_result(row, replayed=False)

    @staticmethod
    def _appointment_result(row, *, replayed: bool) -> dict[str, Any]:
        return {"id": row["id"], "patient_id": row["patient_id"], "kind": row["kind"],
                "starts_at": row["starts_at"], "ends_at": row["ends_at"], "state": row["state"],
                "hold_expires_at": row["hold_expires_at"], "version": row["version"], "replayed": replayed}

    def transition_appointment(self, clinic_id: str, actor_id: str, appointment_id: str,
                               expected_version: int, action: str, *, reason: str | None = None) -> dict[str, Any]:
        transitions = {"book": ("held", "booked"), "arrive": ("booked", "arrived"),
                       "start": ("arrived", "in_service"), "complete": ("in_service", "completed"),
                       "cancel": (("held", "booked", "arrived"), "cancelled"), "no_show": ("booked", "no_show")}
        if action not in transitions:
            raise ValidationError("预约操作无效")
        if action in {"cancel", "no_show"}:
            reason = text(reason or "", "原因", maximum=600)
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "appointment:write", clinic_id=clinic_id)
            appointment = connection.execute("SELECT * FROM appointments WHERE id=? AND clinic_id=?", (appointment_id, clinic_id)).fetchone()
            if appointment is None:
                raise NotFound("预约不存在")
            require_match(appointment["version"], expected_version, "预约")
            before, after = transitions[action]
            allowed = (before,) if isinstance(before, str) else before
            if appointment["state"] not in allowed:
                raise Conflict("预约当前状态不允许此操作", details={"state": appointment["state"], "action": action})
            if action == "book" and appointment["hold_expires_at"] and parsed_timestamp(appointment["hold_expires_at"]) <= parsed_timestamp(now):
                raise Conflict("预约占位已过期")
            if action == "complete" and parsed_timestamp(appointment["ends_at"]) > parsed_timestamp(now):
                raise Conflict("预约尚未到结束时间")
            version = appointment["version"] + 1
            connection.execute("UPDATE appointments SET state=?,version=? WHERE id=?", (after, version, appointment_id))
            if action == "start":
                encounter_id = new_id("enc")
                connection.execute("INSERT INTO encounters(id,appointment_id,patient_id,clinic_id,state,opened_by,opened_at) VALUES(?,?,?,?,'open',?,?)",
                                   (encounter_id, appointment_id, appointment["patient_id"], clinic_id, actor_id, now))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=appointment["patient_id"],
                               aggregate_type="appointment", aggregate_id=appointment_id, action=f"appointment.{action}",
                               occurred_at=now, payload={"from": appointment["state"], "to": after, "reason": reason, "version": version})
        return {"id": appointment_id, "state": after, "version": version, "updated_at": now}

    def encounter_for_appointment(self, clinic_id: str, actor_id: str, appointment_id: str) -> dict[str, Any]:
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            row = connection.execute(
                "SELECT e.* FROM encounters e JOIN appointments a ON a.id=e.appointment_id "
                "WHERE a.id=? AND a.clinic_id=?", (appointment_id, clinic_id)).fetchone()
            if row is None:
                raise NotFound("该预约尚无就诊记录")
            return {"id": row["id"], "appointment_id": row["appointment_id"], "patient_id": row["patient_id"],
                    "state": row["state"], "opened_by": row["opened_by"], "opened_at": row["opened_at"],
                    "signed_by": row["signed_by"], "signed_at": row["signed_at"], "version": row["version"]}

    def add_encounter_note(self, clinic_id: str, actor_id: str, encounter_id: str, section: str,
                           body: str, *, expected_version: int, amendment_reason: str | None = None) -> dict[str, Any]:
        section = choice(section, "病历章节", {"chief_complaint", "history", "examination", "assessment", "plan", "instructions", "followup"})
        body = text(body, "病历内容", maximum=10000)
        if amendment_reason is not None:
            amendment_reason = text(amendment_reason, "补充说明原因", maximum=800)
        now = self.now()
        note_id = new_id("note")
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:write", clinic_id=clinic_id)
            encounter = connection.execute("SELECT * FROM encounters WHERE id=? AND clinic_id=?", (encounter_id, clinic_id)).fetchone()
            if encounter is None:
                raise NotFound("就诊记录不存在")
            require_match(encounter["version"], expected_version, "就诊记录")
            if encounter["state"] in {"void", "amended"}:
                raise Conflict("当前就诊记录不可继续编辑")
            current = connection.execute(
                "SELECT * FROM encounter_notes WHERE encounter_id=? AND section=? ORDER BY revision DESC LIMIT 1",
                (encounter_id, section)).fetchone()
            if encounter["state"] == "signed" and not amendment_reason:
                raise Conflict("已签署记录只能通过有原因的补充条目修订")
            if current and encounter["state"] == "signed" and current["body"] == body:
                raise Conflict("补充条目不能重复原文")
            revision = current["revision"] + 1 if current else 1
            connection.execute(
                "INSERT INTO encounter_notes(id,encounter_id,section,body,author_id,revision,created_at,supersedes) VALUES(?,?,?,?,?,?,?,?)",
                (note_id, encounter_id, section, body, actor_id, revision, now, current["id"] if current else None))
            version = encounter["version"] + 1
            new_state = "amended" if encounter["state"] == "signed" else encounter["state"]
            connection.execute("UPDATE encounters SET state=?,version=? WHERE id=?", (new_state, version, encounter_id))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=encounter["patient_id"],
                               aggregate_type="encounter", aggregate_id=encounter_id,
                               action="encounter.note_added" if revision == 1 else "encounter.note_revised",
                               occurred_at=now, payload={"section": section, "revision": revision,
                                                         "supersedes": current["id"] if current else None,
                                                         "amendment_reason": amendment_reason})
        return {"id": note_id, "encounter_id": encounter_id, "section": section, "revision": revision,
                "state": new_state, "version": version, "created_at": now}

    def sign_encounter(self, clinic_id: str, actor_id: str, encounter_id: str, expected_version: int) -> dict[str, Any]:
        now = self.now()
        required_sections = {"chief_complaint", "assessment", "plan"}
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            authorize(principal, "clinical:write", clinic_id=clinic_id)
            if principal.role not in {"clinician", "owner"}:
                raise Forbidden("只有临床负责人可以签署就诊记录")
            encounter = connection.execute("SELECT * FROM encounters WHERE id=? AND clinic_id=?", (encounter_id, clinic_id)).fetchone()
            if encounter is None:
                raise NotFound("就诊记录不存在")
            require_match(encounter["version"], expected_version, "就诊记录")
            if encounter["state"] != "open":
                raise Conflict("只有未签署就诊记录可以完成签署")
            sections = {row[0] for row in connection.execute(
                "SELECT section FROM encounter_notes WHERE encounter_id=? AND revision=(SELECT MAX(n2.revision) FROM encounter_notes n2 WHERE n2.encounter_id=encounter_notes.encounter_id AND n2.section=encounter_notes.section)",
                (encounter_id,)).fetchall()}
            missing = required_sections - sections
            if missing:
                raise Conflict("病历章节未填写完整", details={"missing_sections": sorted(missing)})
            version = encounter["version"] + 1
            connection.execute("UPDATE encounters SET state='signed',signed_by=?,signed_at=?,version=? WHERE id=?",
                               (actor_id, now, version, encounter_id))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=encounter["patient_id"],
                               aggregate_type="encounter", aggregate_id=encounter_id, action="encounter.signed",
                               occurred_at=now, payload={"sections": sorted(sections), "version": version})
        return {"id": encounter_id, "state": "signed", "signed_by": actor_id, "signed_at": now, "version": version}

    def encounter_notes(self, clinic_id: str, actor_id: str, encounter_id: str) -> dict[str, Any]:
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            encounter = connection.execute("SELECT * FROM encounters WHERE id=? AND clinic_id=?", (encounter_id, clinic_id)).fetchone()
            if encounter is None:
                raise NotFound("就诊记录不存在")
            rows = connection.execute("SELECT * FROM encounter_notes WHERE encounter_id=? ORDER BY section,revision", (encounter_id,)).fetchall()
            return {"encounter_id": encounter_id, "state": encounter["state"], "version": encounter["version"],
                    "notes": [{"id": row["id"], "section": row["section"], "body": row["body"],
                               "author_id": row["author_id"], "revision": row["revision"],
                               "created_at": row["created_at"], "supersedes": row["supersedes"]} for row in rows]}

    def void_encounter(self, clinic_id: str, actor_id: str, encounter_id: str,
                       expected_version: int, reason: str) -> dict[str, Any]:
        reason = text(reason, "作废原因", maximum=1000)
        now = self.now()
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            authorize(principal, "clinical:write", clinic_id=clinic_id)
            if principal.role != "owner":
                raise Forbidden("只有诊所负责人可以作废就诊记录")
            encounter = connection.execute("SELECT * FROM encounters WHERE id=? AND clinic_id=?", (encounter_id, clinic_id)).fetchone()
            if encounter is None:
                raise NotFound("就诊记录不存在")
            require_match(encounter["version"], expected_version, "就诊记录")
            if encounter["state"] == "void":
                raise Conflict("就诊记录已作废")
            version = encounter["version"] + 1
            connection.execute("UPDATE encounters SET state='void',version=? WHERE id=?", (version, encounter_id))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=encounter["patient_id"],
                               aggregate_type="encounter", aggregate_id=encounter_id, action="encounter.voided",
                               occurred_at=now, payload={"reason": reason, "previous_state": encounter["state"]})
        return {"id": encounter_id, "state": "void", "version": version, "voided_at": now}

    def expire_holds(self, clinic_id: str, *, limit: int = 200) -> dict[str, Any]:
        if not 1 <= limit <= 1000:
            raise ValidationError("处理数量必须为 1 至 1000")
        now = self.now()
        with self.db.transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM appointments WHERE clinic_id=? AND state='held' AND hold_expires_at<=? ORDER BY hold_expires_at,id LIMIT ?",
                (clinic_id, now, limit)).fetchall()
            for row in rows:
                connection.execute("UPDATE appointments SET state='cancelled',version=version+1 WHERE id=? AND state='held'", (row["id"],))
                audit.append_event(connection, clinic_id=clinic_id, actor_id=None, patient_id=row["patient_id"],
                                   aggregate_type="appointment", aggregate_id=row["id"], action="appointment.hold_expired",
                                   occurred_at=now, payload={"hold_expires_at": row["hold_expires_at"]})
        return {"expired": len(rows), "as_of": now}

    def schedule_followup(self, clinic_id: str, actor_id: str, patient_id: str, due_at: str,
                          reason: str, key: str, *, plan_id: str | None = None,
                          channel: str = "phone", assigned_to: str | None = None) -> dict[str, Any]:
        due = timestamp(due_at, "随访时间")
        reason = text(reason, "随访原因", maximum=600)
        channel = choice(channel, "随访方式", {"phone", "message", "in_person"})
        key = require_idempotency_key(key)
        followup_id = new_id("fol")
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "followup:manage", clinic_id=clinic_id)
            patient = connection.execute("SELECT state FROM patients WHERE id=? AND clinic_id=?", (patient_id, clinic_id)).fetchone()
            if patient is None:
                raise NotFound("患者不存在")
            if patient["state"] != "active":
                raise Conflict("非在诊患者不能新增随访")
            existing = connection.execute("SELECT * FROM followups WHERE idempotency_key=?", (key,)).fetchone()
            if existing:
                if existing["patient_id"] != patient_id or existing["due_at"] != due or existing["reason"] != reason:
                    raise Conflict("随访幂等编号已用于其他内容")
                return self._followup_result(existing, replayed=True)
            if plan_id and connection.execute("SELECT 1 FROM plans WHERE id=? AND patient_id=? AND clinic_id=?", (plan_id, patient_id, clinic_id)).fetchone() is None:
                raise NotFound("诊疗计划不存在")
            if assigned_to and connection.execute("SELECT 1 FROM staff WHERE id=? AND clinic_id=? AND active=1", (assigned_to, clinic_id)).fetchone() is None:
                raise ValidationError("随访责任人不存在或已停用")
            connection.execute("INSERT INTO followups(id,patient_id,plan_id,due_at,channel,reason,state,assigned_to,idempotency_key,created_at) "
                               "VALUES(?,?,?,?,?,?,'pending',?,?,?)",
                               (followup_id, patient_id, plan_id, due, channel, reason, assigned_to, key, now))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=patient_id,
                               aggregate_type="followup", aggregate_id=followup_id, action="followup.scheduled",
                               occurred_at=now, payload={"due_at": due, "channel": channel, "reason": reason})
            row = connection.execute("SELECT * FROM followups WHERE id=?", (followup_id,)).fetchone()
        return self._followup_result(row, replayed=False)

    @staticmethod
    def _followup_result(row, *, replayed: bool) -> dict[str, Any]:
        return {"id": row["id"], "patient_id": row["patient_id"], "due_at": row["due_at"],
                "channel": row["channel"], "reason": row["reason"], "state": row["state"],
                "assigned_to": row["assigned_to"], "version": row["version"], "replayed": replayed}

    def claim_followups(self, clinic_id: str, actor_id: str, *, limit: int = 20, lease_minutes: int = 5) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100 or not 1 <= lease_minutes <= 60:
            raise ValidationError("领取数量或租约时长超出范围")
        now = self.now()
        until = timestamp(parsed_timestamp(now) + timedelta(minutes=lease_minutes))
        claim_token = new_id("claim")
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "followup:manage", clinic_id=clinic_id)
            rows = connection.execute(
                "SELECT f.* FROM followups f JOIN patients p ON p.id=f.patient_id WHERE p.clinic_id=? "
                "AND f.due_at<=? AND (f.state='pending' OR (f.state='claimed' AND f.claim_until<=?)) "
                "ORDER BY f.due_at,f.id LIMIT ?", (clinic_id, now, now, limit)).fetchall()
            claimed = []
            for row in rows:
                changed = connection.execute(
                    "UPDATE followups SET state='claimed',assigned_to=?,claim_token=?,claim_until=?,version=version+1 "
                    "WHERE id=? AND version=? AND (state='pending' OR claim_until<=?)",
                    (actor_id, claim_token, until, row["id"], row["version"], now)).rowcount
                if changed:
                    audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=row["patient_id"],
                                       aggregate_type="followup", aggregate_id=row["id"], action="followup.claimed",
                                       occurred_at=now, payload={"claim_until": until, "previous_version": row["version"]})
                    claimed.append({"id": row["id"], "patient_id": row["patient_id"], "due_at": row["due_at"],
                                    "reason": row["reason"], "claim_token": claim_token, "claim_until": until,
                                    "version": row["version"] + 1})
        return claimed

    def complete_followup(self, clinic_id: str, actor_id: str, followup_id: str, claim_token: str,
                          outcome: str, expected_version: int) -> dict[str, Any]:
        outcome = text(outcome, "随访结果", maximum=2000)
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "followup:manage", clinic_id=clinic_id)
            row = connection.execute("SELECT f.* FROM followups f JOIN patients p ON p.id=f.patient_id WHERE f.id=? AND p.clinic_id=?",
                                     (followup_id, clinic_id)).fetchone()
            if row is None:
                raise NotFound("随访任务不存在")
            require_match(row["version"], expected_version, "随访任务")
            if row["state"] != "claimed" or row["assigned_to"] != actor_id or row["claim_token"] != claim_token:
                raise Conflict("随访任务租约已失效或不属于当前人员")
            if row["claim_until"] <= now:
                raise Conflict("随访任务租约已过期")
            connection.execute("UPDATE followups SET state='done',outcome=?,claim_token=NULL,claim_until=NULL,version=version+1 WHERE id=?",
                               (outcome, followup_id))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=row["patient_id"],
                               aggregate_type="followup", aggregate_id=followup_id, action="followup.completed",
                               occurred_at=now, payload={"outcome": outcome, "version": expected_version + 1})
        return {"id": followup_id, "state": "done", "outcome": outcome, "version": expected_version + 1}

    def record_observation(self, clinic_id: str, actor_id: str, patient_id: str, kind: str, value: Any,
                           observed_at: str, *, plan_id: str | None = None, correction_of: str | None = None,
                           provenance: str = "clinician") -> dict[str, Any]:
        kind = choice(kind, "观察类型", {"weight_kg", "waist_cm", "symptom_score", "satisfaction", "blood_pressure"})
        provenance = choice(provenance, "数据来源", {"patient", "clinician", "import"})
        observed = timestamp(observed_at, "观察时间")
        bounds = {"weight_kg": ("1", "600", "kg"), "waist_cm": ("10", "300", "cm"),
                  "symptom_score": ("0", "10", "score"), "satisfaction": ("0", "10", "score"),
                  "blood_pressure": ("20", "300", "mmHg")}
        low, high, unit = bounds[kind]
        number = decimal_value(value, kind, minimum=low, maximum=high)
        observation_id = new_id("obs")
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:write", clinic_id=clinic_id)
            patient = connection.execute("SELECT state FROM patients WHERE id=? AND clinic_id=?", (patient_id, clinic_id)).fetchone()
            if patient is None:
                raise NotFound("患者不存在")
            if patient["state"] != "active":
                raise Conflict("非在诊患者不能添加观察值")
            if plan_id and connection.execute("SELECT 1 FROM plans WHERE id=? AND patient_id=? AND clinic_id=?", (plan_id, patient_id, clinic_id)).fetchone() is None:
                raise NotFound("诊疗计划不存在")
            if correction_of:
                original = connection.execute("SELECT * FROM observations WHERE id=? AND patient_id=?", (correction_of, patient_id)).fetchone()
                if original is None or original["correction_of"] is not None:
                    raise Conflict("只能更正已有原始观察值，不能重复更正")
                prior = connection.execute("SELECT 1 FROM observations WHERE correction_of=?", (correction_of,)).fetchone()
                if prior:
                    raise Conflict("该观察值已有更正记录；如仍需修订，请引用最新记录并说明依据")
            connection.execute(
                "INSERT INTO observations(id,patient_id,plan_id,kind,value_num,unit,observed_at,recorded_by,provenance,correction_of,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)", (observation_id, patient_id, plan_id, kind, number, unit, observed, actor_id, provenance, correction_of, now))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=patient_id,
                               aggregate_type="observation", aggregate_id=observation_id, action="observation.recorded",
                               occurred_at=now, payload={"kind": kind, "value": number, "unit": unit, "correction_of": correction_of})
        return {"id": observation_id, "patient_id": patient_id, "kind": kind, "value": number, "unit": unit,
                "observed_at": observed, "provenance": provenance, "correction_of": correction_of}

    def observation_series(self, clinic_id: str, actor_id: str, patient_id: str, kind: str) -> list[dict[str, Any]]:
        kind = choice(kind, "观察类型", {"weight_kg", "waist_cm", "symptom_score", "satisfaction", "blood_pressure"})
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            if connection.execute("SELECT 1 FROM patients WHERE id=? AND clinic_id=?", (patient_id, clinic_id)).fetchone() is None:
                raise NotFound("患者不存在")
            rows = connection.execute("SELECT * FROM observations WHERE patient_id=? AND kind=? ORDER BY observed_at,id", (patient_id, kind)).fetchall()
            return [{"id": row["id"], "value": row["value_num"], "unit": row["unit"], "observed_at": row["observed_at"],
                     "provenance": row["provenance"], "correction_of": row["correction_of"]} for row in rows]

    def report_incident(self, clinic_id: str, actor_id: str, patient_id: str, category: str,
                        severity: str, onset_at: str, summary: str, key: str, *, plan_id: str | None = None,
                        encounter_id: str | None = None) -> dict[str, Any]:
        category = text(category, "事件类别", maximum=100)
        severity = choice(severity, "严重程度", {"low", "moderate", "high", "urgent"})
        onset = timestamp(onset_at, "发生时间")
        summary = text(summary, "事件描述", maximum=3000)
        key = require_idempotency_key(key)
        incident_id = new_id("inc")
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "incident:report", clinic_id=clinic_id)
            if connection.execute("SELECT 1 FROM patients WHERE id=? AND clinic_id=? AND state='active'", (patient_id, clinic_id)).fetchone() is None:
                raise NotFound("在诊患者不存在")
            existing = connection.execute("SELECT * FROM incidents WHERE idempotency_key=?", (key,)).fetchone()
            if existing:
                if existing["patient_id"] != patient_id or existing["category"] != category or existing["summary"] != summary:
                    raise Conflict("不良事件幂等编号已用于其他内容")
                return self._incident_result(existing, replayed=True)
            if plan_id and connection.execute("SELECT 1 FROM plans WHERE id=? AND patient_id=? AND clinic_id=?", (plan_id, patient_id, clinic_id)).fetchone() is None:
                raise NotFound("诊疗计划不存在")
            if encounter_id and connection.execute("SELECT 1 FROM encounters WHERE id=? AND patient_id=? AND clinic_id=?", (encounter_id, patient_id, clinic_id)).fetchone() is None:
                raise NotFound("就诊记录不存在")
            connection.execute(
                "INSERT INTO incidents(id,patient_id,plan_id,encounter_id,severity,state,category,onset_at,reported_at,reported_by,summary,idempotency_key) "
                "VALUES(?,?,?,?,?,'reported',?,?,?,?,?,?)",
                (incident_id, patient_id, plan_id, encounter_id, severity, category, onset, now, actor_id, summary, key))
            connection.execute("INSERT INTO incident_events(id,incident_id,event_type,actor_id,note,created_at,sequence) VALUES(?,?,'reported',?,?,?,1)",
                               (new_id("iev"), incident_id, actor_id, summary, now))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=patient_id,
                               aggregate_type="incident", aggregate_id=incident_id, action="incident.reported",
                               occurred_at=now, payload={"severity": severity, "category": category})
            row = connection.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return self._incident_result(row, replayed=False)

    @staticmethod
    def _incident_result(row, *, replayed: bool) -> dict[str, Any]:
        return {"id": row["id"], "patient_id": row["patient_id"], "severity": row["severity"],
                "state": row["state"], "category": row["category"], "reported_at": row["reported_at"],
                "version": row["version"], "replayed": replayed}

    def transition_incident(self, clinic_id: str, actor_id: str, incident_id: str, action: str,
                            note: str, expected_version: int, *, assign_to: str | None = None) -> dict[str, Any]:
        states = {"triage": ("reported", "triaged"), "monitor": (("reported", "triaged"), "monitoring"),
                  "resolve": (("triaged", "monitoring"), "resolved"), "reopen": (("resolved", "closed"), "triaged"),
                  "close": ("resolved", "closed")}
        if action not in states:
            raise ValidationError("事件处置操作无效")
        note = text(note, "处置说明", maximum=2000)
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "incident:manage", clinic_id=clinic_id)
            row = connection.execute("SELECT i.* FROM incidents i JOIN patients p ON p.id=i.patient_id WHERE i.id=? AND p.clinic_id=?",
                                     (incident_id, clinic_id)).fetchone()
            if row is None:
                raise NotFound("不良事件不存在")
            require_match(row["version"], expected_version, "不良事件")
            before, after = states[action]
            if row["state"] not in ((before,) if isinstance(before, str) else before):
                raise Conflict("不良事件当前状态不允许此操作", details={"state": row["state"], "action": action})
            if assign_to:
                target = connection.execute("SELECT active,role FROM staff WHERE id=? AND clinic_id=?", (assign_to, clinic_id)).fetchone()
                if target is None or not target["active"] or target["role"] not in {"clinician", "nurse", "owner"}:
                    raise ValidationError("事件责任人必须是有效的临床岗位")
            version = row["version"] + 1
            connection.execute("UPDATE incidents SET state=?,assigned_to=COALESCE(?,assigned_to),version=? WHERE id=?",
                               (after, assign_to, version, incident_id))
            sequence = connection.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM incident_events WHERE incident_id=?", (incident_id,)).fetchone()[0]
            connection.execute("INSERT INTO incident_events(id,incident_id,event_type,actor_id,note,created_at,sequence) VALUES(?,?,?,?,?,?,?)",
                               (new_id("iev"), incident_id, action, actor_id, note, now, sequence))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=row["patient_id"],
                               aggregate_type="incident", aggregate_id=incident_id, action=f"incident.{action}",
                               occurred_at=now, payload={"from": row["state"], "to": after, "note": note, "assigned_to": assign_to})
        return {"id": incident_id, "state": after, "version": version, "assigned_to": assign_to or row["assigned_to"]}

    def incident_history(self, clinic_id: str, actor_id: str, incident_id: str) -> dict[str, Any]:
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "incident:manage", clinic_id=clinic_id)
            incident = connection.execute("SELECT i.* FROM incidents i JOIN patients p ON p.id=i.patient_id WHERE i.id=? AND p.clinic_id=?",
                                          (incident_id, clinic_id)).fetchone()
            if incident is None:
                raise NotFound("不良事件不存在")
            events = connection.execute("SELECT * FROM incident_events WHERE incident_id=? ORDER BY sequence", (incident_id,)).fetchall()
            return {"incident": self._incident_result(incident, replayed=False),
                    "events": [{"sequence": row["sequence"], "type": row["event_type"], "actor_id": row["actor_id"],
                                "note": row["note"], "created_at": row["created_at"]} for row in events]}

    def audit_history(self, clinic_id: str, actor_id: str, *, patient_id: str | None = None,
                      after: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        if after < 0:
            raise ValidationError("审计游标不得为负数")
        with self.db.transaction(write=False) as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            if patient_id:
                authorize(principal, "audit:patient", clinic_id=clinic_id)
                if connection.execute("SELECT 1 FROM patients WHERE id=? AND clinic_id=?", (patient_id, clinic_id)).fetchone() is None:
                    raise NotFound("患者不存在")
            else:
                authorize(principal, "audit:read", clinic_id=clinic_id)
            return audit.list_events(connection, clinic_id, patient_id=patient_id, after=after, limit=limit)

    def verify_audit(self, clinic_id: str, actor_id: str) -> dict[str, Any]:
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "audit:read", clinic_id=clinic_id)
            return audit.verify_chain(connection, clinic_id)

    def run_diagnostics(self, clinic_id: str, actor_id: str) -> dict[str, Any]:
        from .diagnostics import clinic_diagnostics

        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "audit:read", clinic_id=clinic_id)
            return clinic_diagnostics(connection, clinic_id, self.now())

    def clinic_summary(self, clinic_id: str, actor_id: str) -> dict[str, Any]:
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            counts = {}
            for table, condition in (("patients", "state='active'"), ("plans", "state IN ('proposed','active','paused')"),
                                     ("appointments", "state IN ('held','booked','arrived','in_service')"),
                                     ("followups", "state IN ('pending','claimed')"),
                                     ("incidents", "state NOT IN ('closed','resolved')")):
                counts[table] = connection.execute(f"SELECT count(*) FROM {table} WHERE clinic_id=? AND {condition}", (clinic_id,)).fetchone()[0] if table != "followups" and table != "incidents" else 0
            counts["followups"] = connection.execute("SELECT count(*) FROM followups f JOIN patients p ON p.id=f.patient_id WHERE p.clinic_id=? AND f.state IN ('pending','claimed')", (clinic_id,)).fetchone()[0]
            counts["incidents"] = connection.execute("SELECT count(*) FROM incidents i JOIN patients p ON p.id=i.patient_id WHERE p.clinic_id=? AND i.state NOT IN ('closed','resolved')", (clinic_id,)).fetchone()[0]
            return {"clinic_id": clinic_id, "as_of": self.now(), "counts": counts}

    def patient_timeline(self, clinic_id: str, actor_id: str, patient_id: str, *, limit: int = 100) -> dict[str, Any]:
        limit = max(1, min(limit, 300))
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            patient = connection.execute("SELECT id,state FROM patients WHERE id=? AND clinic_id=?", (patient_id, clinic_id)).fetchone()
            if patient is None:
                raise NotFound("患者不存在")
            events = audit.list_events(connection, clinic_id, patient_id=patient_id, limit=limit)
            return {"patient_id": patient_id, "patient_state": patient["state"], "events": events,
                    "next_cursor": events[-1]["sequence"] if len(events) == limit else None}
