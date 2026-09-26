"""患者安全关注项记录；系统不代替医生判断诊断或治疗方案。"""

from . import audit
from .db import Database
from .errors import Conflict, NotFound, ValidationError
from .ids import new_id
from .security import authorize, principal_for
from .validation import choice, require_match, text, timestamp


class ClinicalFlagService:
    CATEGORIES = {"allergy", "prior_reaction", "contraindication", "implant", "psychological_concern", "other"}
    SEVERITIES = {"information", "caution", "stop"}

    def __init__(self, database: Database, clock):
        self.db, self.clock = database, clock

    def report(self, clinic_id: str, actor_id: str, patient_id: str, category: str,
               severity: str, detail: str, *, effective_from: str | None = None,
               effective_until: str | None = None) -> dict:
        category = choice(category, "关注项类别", self.CATEGORIES)
        severity = choice(severity, "关注程度", self.SEVERITIES)
        detail = text(detail, "事实记录", maximum=3000)
        start = timestamp(effective_from or self.clock.now())
        end = timestamp(effective_until) if effective_until else None
        if end and end <= start:
            raise ValidationError("有效截止时间必须晚于生效时间")
        now, flag_id = timestamp(self.clock.now()), new_id("flg")
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:write", clinic_id=clinic_id)
            if connection.execute("SELECT 1 FROM patients WHERE id=? AND clinic_id=? AND state='active'", (patient_id, clinic_id)).fetchone() is None:
                raise NotFound("在诊患者不存在")
            connection.execute("INSERT INTO clinical_flags(id,patient_id,category,severity,detail,state,effective_from,effective_until,reported_by,created_at) "
                               "VALUES(?,?,?,?,?,'reported',?,?,?,?)",
                               (flag_id, patient_id, category, severity, detail, start, end, actor_id, now))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=patient_id,
                               aggregate_type="clinical_flag", aggregate_id=flag_id, action="clinical_flag.reported",
                               occurred_at=now, payload={"category": category, "severity": severity})
        return {"id": flag_id, "patient_id": patient_id, "category": category, "severity": severity,
                "state": "reported", "effective_from": start, "effective_until": end, "version": 1}

    def review(self, clinic_id: str, actor_id: str, flag_id: str, expected_version: int,
               action: str, note: str) -> dict:
        action = choice(action, "复核结论", {"confirm", "resolve"})
        note = text(note, "复核记录", maximum=2000)
        now = timestamp(self.clock.now())
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            authorize(principal, "clinical:write", clinic_id=clinic_id)
            if principal.role not in {"clinician", "owner"}:
                from .errors import Forbidden
                raise Forbidden("只有医生或诊所负责人可以复核患者安全关注项")
            row = connection.execute("SELECT f.* FROM clinical_flags f JOIN patients p ON p.id=f.patient_id "
                                     "WHERE f.id=? AND p.clinic_id=?", (flag_id, clinic_id)).fetchone()
            if row is None:
                raise NotFound("安全关注项不存在")
            require_match(row["version"], expected_version, "安全关注项")
            if row["state"] == "resolved":
                raise Conflict("已关闭关注项不能再次复核")
            if action == "resolve" and row["state"] == "reported":
                raise Conflict("未经确认的记录不能直接关闭")
            target = "confirmed" if action == "confirm" else "resolved"
            version = row["version"] + 1
            connection.execute("UPDATE clinical_flags SET state=?,reviewed_by=?,reviewed_at=?,resolution_reason=?,version=? WHERE id=?",
                               (target, actor_id, now, note if action == "resolve" else None, version, flag_id))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=row["patient_id"],
                               aggregate_type="clinical_flag", aggregate_id=flag_id, action=f"clinical_flag.{action}ed",
                               occurred_at=now, payload={"from": row["state"], "to": target, "note": note,
                                                         "version": version})
        return {"id": flag_id, "state": target, "reviewed_by": actor_id, "reviewed_at": now, "version": version}

    def list_for_patient(self, clinic_id: str, actor_id: str, patient_id: str, *, include_resolved: bool = False) -> list[dict]:
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            if connection.execute("SELECT 1 FROM patients WHERE id=? AND clinic_id=?", (patient_id, clinic_id)).fetchone() is None:
                raise NotFound("患者不存在")
            if include_resolved:
                rows = connection.execute("SELECT * FROM clinical_flags WHERE patient_id=? ORDER BY effective_from,id", (patient_id,)).fetchall()
            else:
                rows = connection.execute("SELECT * FROM clinical_flags WHERE patient_id=? AND state!='resolved' ORDER BY effective_from,id", (patient_id,)).fetchall()
            return [{"id": row["id"], "category": row["category"], "severity": row["severity"],
                     "detail": row["detail"], "state": row["state"], "effective_from": row["effective_from"],
                     "effective_until": row["effective_until"], "reported_by": row["reported_by"],
                     "reviewed_by": row["reviewed_by"], "reviewed_at": row["reviewed_at"],
                     "version": row["version"]} for row in rows]

    def blocking_flags(self, connection, patient_id: str, as_of: str) -> list[dict]:
        rows = connection.execute("SELECT id,category,severity,state,effective_from,effective_until FROM clinical_flags "
                                  "WHERE patient_id=? AND severity='stop' AND state IN ('reported','confirmed') "
                                  "AND effective_from<=? AND (effective_until IS NULL OR effective_until>?) ORDER BY id",
                                  (patient_id, as_of, as_of)).fetchall()
        return [dict(row) for row in rows]
