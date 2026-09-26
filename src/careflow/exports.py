"""经授权的一次性患者资料导出。"""

from __future__ import annotations

import hashlib
from typing import Any

from . import audit
from .db import Database, decode_json, encode_json
from .errors import Conflict, NotFound, ValidationError
from .ids import new_id
from .security import authorize, principal_for
from .validation import choice, parsed_timestamp, text, timestamp

EXPORT_SECTIONS = {"profile", "consents", "assessments", "plans", "observations", "appointments", "followups", "incidents"}


class PatientExportService:
    """仅返回被请求的数据章节，不生成可长期遗留的导出文件。"""

    def __init__(self, database: Database, clock):
        self.db = database
        self.clock = clock

    def export(self, clinic_id: str, actor_id: str, patient_id: str, sections: list[str], reason: str,
               idempotency_key: str) -> dict[str, Any]:
        if not isinstance(sections, list) or not sections or len(sections) > len(EXPORT_SECTIONS):
            raise ValidationError("至少指定一个导出章节")
        selected = sorted(set(choice(item, "导出章节", EXPORT_SECTIONS) for item in sections))
        if len(selected) != len(sections):
            raise ValidationError("导出章节不能重复")
        reason = text(reason, "导出用途", maximum=600)
        if not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key.strip()) <= 160:
            raise ValidationError("导出幂等编号无效")
        key = idempotency_key.strip()
        request = {"clinic_id": clinic_id, "patient_id": patient_id, "sections": selected, "reason": reason}
        request_hash = hashlib.sha256(encode_json(request).encode("utf-8")).hexdigest()
        now = timestamp(self.clock.now())
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            authorize(principal, "data:export", clinic_id=clinic_id)
            patient = connection.execute("SELECT * FROM patients WHERE id=? AND clinic_id=?", (patient_id, clinic_id)).fetchone()
            if patient is None:
                raise NotFound("患者不存在")
            old = connection.execute("SELECT * FROM idempotency WHERE scope='patient_export' AND key=?", (key,)).fetchone()
            if old:
                if old["request_hash"] != request_hash:
                    raise Conflict("导出幂等编号已用于其他请求")
                return {**decode_json(old["response_json"]), "replayed": True}
            consent = connection.execute(
                "SELECT * FROM consents WHERE patient_id=? AND purpose='data_export' AND state='granted' ORDER BY revision DESC LIMIT 1",
                (patient_id,)).fetchone()
            if consent is None or (consent["expires_at"] and parsed_timestamp(consent["expires_at"]) <= parsed_timestamp(now)):
                raise Conflict("患者没有当前有效的数据导出授权")
            if any(item != "profile" for item in selected):
                authorize(principal, "clinical:read", clinic_id=clinic_id)
            data: dict[str, Any] = {"patient_id": patient_id, "external_ref": patient["external_ref"],
                                    "display_name": patient["display_name"], "state": patient["state"]}
            for section in selected:
                data[section] = self._section(connection, section, patient)
            body = {"format": "careflow-patient-export-v1", "clinic_id": clinic_id, "exported_at": now,
                    "consent_id": consent["id"], "sections": selected, "data": data}
            canonical = encode_json(body)
            result = {**body, "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(), "replayed": False}
            counts = {name: len(value) if isinstance(value, list) else 1 for name, value in data.items() if name in selected}
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=patient_id,
                               aggregate_type="patient_export", aggregate_id=new_id("exp"), action="patient.exported",
                               occurred_at=now, payload={"sections": selected, "reason": reason,
                                                         "record_counts": counts, "sha256": result["sha256"]})
            connection.execute("INSERT INTO idempotency(scope,key,request_hash,response_json,created_at) VALUES('patient_export',?,?,?,?)",
                               (key, request_hash, encode_json(result), now))
        return result

    @staticmethod
    def _section(connection, section: str, patient):
        patient_id = patient["id"]
        if section == "profile":
            # 通过字段白名单避免联系方式密文、合并目标等内部字段外泄。
            return {"patient_id": patient_id, "external_ref": patient["external_ref"],
                    "display_name": patient["display_name"], "birth_date": patient["birth_date"],
                    "state": patient["state"], "created_at": patient["created_at"]}
        if section == "consents":
            rows = connection.execute("SELECT purpose,revision,text_digest,state,effective_at,expires_at,created_at FROM consents WHERE patient_id=? ORDER BY purpose,revision", (patient_id,)).fetchall()
            return [dict(row) for row in rows]
        if section == "assessments":
            rows = connection.execute("SELECT id,kind,captured_at,captured_by,measurements_json,answers_json,source,status,signed_at,version FROM assessments WHERE patient_id=? ORDER BY captured_at,id", (patient_id,)).fetchall()
            return [{"id": row["id"], "kind": row["kind"], "captured_at": row["captured_at"],
                     "captured_by": row["captured_by"], "measurements": decode_json(row["measurements_json"]),
                     "answers": decode_json(row["answers_json"]), "source": row["source"],
                     "status": row["status"], "signed_at": row["signed_at"], "version": row["version"]} for row in rows]
        if section == "plans":
            rows = connection.execute("SELECT id,kind,state,created_by,clinical_owner,assessment_id,consent_id,goal_json,risk_json,start_date,target_date,created_at,updated_at,version FROM plans WHERE patient_id=? ORDER BY created_at,id", (patient_id,)).fetchall()
            return [{"id": row["id"], "kind": row["kind"], "state": row["state"], "created_by": row["created_by"],
                     "clinical_owner": row["clinical_owner"], "assessment_id": row["assessment_id"], "consent_id": row["consent_id"],
                     "goal": decode_json(row["goal_json"]), "risk": decode_json(row["risk_json"]),
                     "start_date": row["start_date"], "target_date": row["target_date"],
                     "created_at": row["created_at"], "updated_at": row["updated_at"], "version": row["version"]} for row in rows]
        if section == "observations":
            rows = connection.execute("SELECT id,plan_id,kind,value_num,value_text,unit,observed_at,recorded_by,provenance,correction_of,created_at FROM observations WHERE patient_id=? ORDER BY observed_at,id", (patient_id,)).fetchall()
            return [dict(row) for row in rows]
        if section == "appointments":
            rows = connection.execute("SELECT id,plan_id,staff_id,kind,starts_at,ends_at,state,created_at,version FROM appointments WHERE patient_id=? ORDER BY starts_at,id", (patient_id,)).fetchall()
            return [dict(row) for row in rows]
        if section == "followups":
            rows = connection.execute("SELECT id,plan_id,due_at,channel,reason,state,assigned_to,outcome,created_at,version FROM followups WHERE patient_id=? ORDER BY due_at,id", (patient_id,)).fetchall()
            return [dict(row) for row in rows]
        if section == "incidents":
            rows = connection.execute("SELECT id,plan_id,encounter_id,severity,state,category,onset_at,reported_at,reported_by,assigned_to,summary,version FROM incidents WHERE patient_id=? ORDER BY reported_at,id", (patient_id,)).fetchall()
            return [dict(row) for row in rows]
        raise ValidationError("导出章节无效")
