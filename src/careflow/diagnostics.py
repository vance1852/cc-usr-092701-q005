"""一致性巡检只报告证据，不替运营人员自动改写临床状态。"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Any

from . import audit


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    aggregate_type: str
    aggregate_id: str
    observed: dict[str, Any]
    recommended_action: str

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "severity": self.severity, "aggregate_type": self.aggregate_type,
                "aggregate_id": self.aggregate_id, "observed": self.observed,
                "recommended_action": self.recommended_action}


class ConsistencyChecker:
    """扫描主要服务状态的不变量，排序稳定并保留每项依据。"""

    def __init__(self, connection, clinic_id: str, as_of: str):
        self.connection = connection
        self.clinic_id = clinic_id
        self.as_of = as_of
        self.findings: list[Finding] = []

    def add(self, code: str, severity: str, kind: str, identifier: str,
            observed: dict[str, Any], recommendation: str) -> None:
        self.findings.append(Finding(code, severity, kind, identifier, observed, recommendation))

    def run(self) -> dict[str, Any]:
        self.check_consent_dependencies()
        self.check_expiring_consents()
        self.check_unreviewed_safety_flags()
        self.check_owner_access()
        self.check_patient_merge_targets()
        self.check_appointment_state()
        self.check_encounter_completion()
        self.check_followup_leases()
        self.check_incident_ledger()
        self.check_signed_records()
        self.check_duplicate_active_reservations()
        chain = audit.verify_chain(self.connection, self.clinic_id)
        if not chain["ok"]:
            self.add("audit.chain_mismatch", "critical", "clinic", self.clinic_id,
                     {"sequence": chain.get("sequence"), "events_checked": chain.get("events_checked")},
                     "暂停依赖该审计链的自动处理，由负责人核对备份与原始业务凭据。")
        self.findings.sort(key=lambda item: ("critical high medium low".split().index(item.severity), item.code,
                                               item.aggregate_type, item.aggregate_id))
        counts = Counter(finding.severity for finding in self.findings)
        return {"clinic_id": self.clinic_id, "as_of": self.as_of,
                "summary": {"total": len(self.findings), "critical": counts["critical"], "high": counts["high"],
                            "medium": counts["medium"], "low": counts["low"]},
                "audit_chain": chain, "findings": [finding.as_dict() for finding in self.findings]}

    def check_unreviewed_safety_flags(self) -> None:
        rows = self.connection.execute(
            "SELECT f.id,f.patient_id,f.category,f.severity,f.effective_from,f.effective_until "
            "FROM clinical_flags f JOIN patients p ON p.id=f.patient_id WHERE p.clinic_id=? "
            "AND f.state='reported' AND f.severity='stop' AND f.effective_from<=? "
            "AND (f.effective_until IS NULL OR f.effective_until>?) ORDER BY f.effective_from,f.id",
            (self.clinic_id, self.as_of, self.as_of)).fetchall()
        for row in rows:
            self.add("clinical_flag.requires_review", "critical", "clinical_flag", row["id"],
                     {"patient_id": row["patient_id"], "category": row["category"],
                      "severity": row["severity"], "effective_from": row["effective_from"]},
                     "由临床负责人尽快核实记录来源并留下复核结论。")

    def check_expiring_consents(self) -> None:
        cutoff = (datetime.fromisoformat(self.as_of.replace("Z", "+00:00")) + timedelta(days=7)).isoformat(timespec="seconds").replace("+00:00", "Z")
        rows = self.connection.execute(
            "SELECT p.id AS plan_id,p.patient_id,p.kind,c.id AS consent_id,c.purpose,c.expires_at "
            "FROM plans p JOIN consents c ON c.id=p.consent_id WHERE p.clinic_id=? "
            "AND p.state IN ('proposed','active') AND c.state='granted' AND c.expires_at>? AND c.expires_at<=? "
            "ORDER BY c.expires_at,p.id", (self.clinic_id, self.as_of, cutoff)).fetchall()
        for row in rows:
            self.add("plan.consent_expiring", "medium", "plan", row["plan_id"],
                     {"patient_id": row["patient_id"], "kind": row["kind"], "consent_id": row["consent_id"],
                      "purpose": row["purpose"], "expires_at": row["expires_at"]},
                     "在授权到期前联系患者并确认后续安排；不能将提醒视作已续签。")

    def check_owner_access(self) -> None:
        owners = self.connection.execute(
            "SELECT s.id,s.active,c.staff_id AS has_credential FROM staff s "
            "LEFT JOIN staff_credentials c ON c.staff_id=s.id WHERE s.clinic_id=? AND s.role='owner' ORDER BY s.id",
            (self.clinic_id,)).fetchall()
        active = [row for row in owners if row["active"]]
        credentialed = [row for row in active if row["has_credential"]]
        if not active or not credentialed:
            self.add("clinic.owner_access_missing", "critical", "clinic", self.clinic_id,
                     {"active_owners": len(active), "owners_with_credentials": len(credentialed)},
                     "恢复至少一位有效负责人的登录凭据后，再继续管理诊所权限。")

    def check_patient_merge_targets(self) -> None:
        rows = self.connection.execute(
            "SELECT source.id AS source_id,source.merged_into,source.state AS source_state,"
            "target.clinic_id AS target_clinic,target.state AS target_state "
            "FROM patients source LEFT JOIN patients target ON target.id=source.merged_into "
            "WHERE source.clinic_id=? AND (source.state='merged' OR source.merged_into IS NOT NULL) ORDER BY source.id",
            (self.clinic_id,)).fetchall()
        for row in rows:
            if row["source_state"] != "merged" or not row["merged_into"] or row["target_clinic"] != self.clinic_id or row["target_state"] != "active":
                self.add("patient.merge_target_invalid", "high", "patient", row["source_id"],
                         {"source_state": row["source_state"], "merged_into": row["merged_into"],
                          "target_clinic": row["target_clinic"], "target_state": row["target_state"]},
                         "核对患者身份材料和合并审批记录，再确定应保留的有效档案。")

    def check_consent_dependencies(self) -> None:
        rows = self.connection.execute(
            "SELECT p.id,p.patient_id,p.kind,p.state,p.consent_id,c.state AS consent_state,c.expires_at "
            "FROM plans p LEFT JOIN consents c ON c.id=p.consent_id WHERE p.clinic_id=? "
            "AND p.state IN ('proposed','active') AND p.kind IN ('aesthetic','weight')",
            (self.clinic_id,)).fetchall()
        for row in rows:
            invalid = row["consent_state"] != "granted" or (row["expires_at"] and row["expires_at"] <= self.as_of)
            if invalid:
                self.add("plan.consent_unavailable", "high", "plan", row["id"],
                         {"patient_id": row["patient_id"], "kind": row["kind"], "state": row["state"],
                          "consent_id": row["consent_id"], "consent_state": row["consent_state"],
                          "consent_expires_at": row["expires_at"]},
                         "确认授权撤回或到期记录，评估计划是否应暂停并保留处置理由。")

    def check_appointment_state(self) -> None:
        rows = self.connection.execute(
            "SELECT a.id,a.patient_id,a.state,a.starts_at,a.ends_at,a.hold_expires_at,a.version "
            "FROM appointments a WHERE a.clinic_id=? AND ((a.state='held' AND a.hold_expires_at<=?) "
            "OR (a.state='in_service' AND a.ends_at<?)) ORDER BY a.id",
            (self.clinic_id, self.as_of, self.as_of)).fetchall()
        for row in rows:
            if row["state"] == "held":
                self.add("appointment.expired_hold", "medium", "appointment", row["id"],
                         {"patient_id": row["patient_id"], "hold_expires_at": row["hold_expires_at"],
                          "version": row["version"]}, "由运营人员确认未成交后释放预约占位。")
            else:
                self.add("appointment.service_overrun", "medium", "appointment", row["id"],
                         {"patient_id": row["patient_id"], "ends_at": row["ends_at"], "as_of": self.as_of},
                         "核对就诊记录后完成服务或说明仍在处置中的原因。")

    def check_encounter_completion(self) -> None:
        rows = self.connection.execute(
            "SELECT a.id AS appointment_id,a.patient_id,a.state AS appointment_state,e.id AS encounter_id,e.state AS encounter_state "
            "FROM appointments a LEFT JOIN encounters e ON e.appointment_id=a.id WHERE a.clinic_id=? "
            "AND (a.state='completed' AND (e.id IS NULL OR e.state!='signed') OR a.state='in_service' AND e.state='signed')",
            (self.clinic_id,)).fetchall()
        for row in rows:
            self.add("encounter.appointment_mismatch", "high", "appointment", row["appointment_id"],
                     {"patient_id": row["patient_id"], "appointment_state": row["appointment_state"],
                      "encounter_id": row["encounter_id"], "encounter_state": row["encounter_state"]},
                     "将预约与就诊记录逐项核实，不要仅根据其中一侧状态推定履约完成。")

    def check_followup_leases(self) -> None:
        rows = self.connection.execute(
            "SELECT f.id,f.patient_id,f.assigned_to,f.claim_until,f.version FROM followups f "
            "JOIN patients p ON p.id=f.patient_id WHERE p.clinic_id=? AND f.state='claimed' AND f.claim_until<=?",
            (self.clinic_id, self.as_of)).fetchall()
        for row in rows:
            self.add("followup.expired_claim", "low", "followup", row["id"],
                     {"patient_id": row["patient_id"], "assigned_to": row["assigned_to"],
                      "claim_until": row["claim_until"], "version": row["version"]},
                     "任务仍待处理时，可在当前负责人确认后重新领取。")

    def check_incident_ledger(self) -> None:
        rows = self.connection.execute(
            "SELECT i.id,i.patient_id,i.state,i.severity,i.version,MAX(e.sequence) AS last_sequence "
            "FROM incidents i JOIN patients p ON p.id=i.patient_id LEFT JOIN incident_events e ON e.incident_id=i.id "
            "WHERE p.clinic_id=? GROUP BY i.id ORDER BY i.id", (self.clinic_id,)).fetchall()
        for row in rows:
            last = self.connection.execute(
                "SELECT event_type FROM incident_events WHERE incident_id=? ORDER BY sequence DESC LIMIT 1", (row["id"],)
            ).fetchone()
            if last is None:
                self.add("incident.event_missing", "critical", "incident", row["id"],
                         {"state": row["state"], "version": row["version"]},
                         "暂停关闭事件，先从已签署的处置资料恢复完整事件顺序。")
            elif row["version"] != row["last_sequence"]:
                self.add("incident.version_gap", "high", "incident", row["id"],
                         {"state": row["state"], "version": row["version"], "last_event_sequence": row["last_sequence"],
                          "last_event_type": last["event_type"]}, "核對事件版本與每次處置的審計記錄。")

    def check_signed_records(self) -> None:
        rows = self.connection.execute(
            "SELECT id,patient_id,kind,status,signed_at,version FROM assessments WHERE clinic_id=? "
            "AND ((status='signed' AND signed_at IS NULL) OR (status='draft' AND signed_at IS NOT NULL))",
            (self.clinic_id,)).fetchall()
        for row in rows:
            self.add("assessment.signature_mismatch", "high", "assessment", row["id"],
                     {"patient_id": row["patient_id"], "kind": row["kind"], "status": row["status"],
                      "signed_at": row["signed_at"], "version": row["version"]}, "依据原始签署材料修复记录状态，不覆盖既有版本。")
        rows = self.connection.execute(
            "SELECT id,patient_id,state,signed_by,signed_at,version FROM encounters WHERE clinic_id=? "
            "AND ((state='signed' AND (signed_at IS NULL OR signed_by IS NULL)) OR (state='open' AND signed_at IS NOT NULL))",
            (self.clinic_id,)).fetchall()
        for row in rows:
            self.add("encounter.signature_mismatch", "high", "encounter", row["id"],
                     {"patient_id": row["patient_id"], "state": row["state"], "signed_by": row["signed_by"],
                      "signed_at": row["signed_at"], "version": row["version"]}, "保留就诊原文并由临床负责人复核签署凭据。")

    def check_duplicate_active_reservations(self) -> None:
        rows = self.connection.execute(
            "SELECT a.staff_id,a.id AS first_id,b.id AS second_id,a.starts_at,a.ends_at AS first_end,b.starts_at AS second_start,b.ends_at AS second_end "
            "FROM appointments a JOIN appointments b ON a.clinic_id=b.clinic_id AND a.staff_id=b.staff_id AND a.id<b.id "
            "WHERE a.clinic_id=? AND a.staff_id IS NOT NULL "
            "AND a.state IN ('held','booked','arrived','in_service') AND b.state IN ('held','booked','arrived','in_service') "
            "AND a.starts_at<b.ends_at AND a.ends_at>b.starts_at "
            "AND (a.hold_expires_at IS NULL OR a.hold_expires_at>?) AND (b.hold_expires_at IS NULL OR b.hold_expires_at>?) "
            "ORDER BY a.staff_id,a.starts_at,a.id", (self.clinic_id, self.as_of, self.as_of)).fetchall()
        for row in rows:
            self.add("appointment.staff_overlap", "high", "staff_schedule", row["staff_id"],
                     {"appointments": [row["first_id"], row["second_id"]],
                      "intervals": [[row["starts_at"], row["first_end"]], [row["second_start"], row["second_end"]]]},
                     "联系诊所排班负责人核对是否为合法协同服务或重复占用。")


def clinic_diagnostics(connection, clinic_id: str, as_of: str) -> dict[str, Any]:
    """公共巡检入口，调用方须先完成诊所访问授权。"""
    return ConsistencyChecker(connection, clinic_id, as_of).run()


def health_summary(report: dict[str, Any]) -> dict[str, Any]:
    """供调度汇总使用的低敏字段，不返回患者描述和处理建议文本。"""
    by_code = Counter(item["code"] for item in report["findings"])
    return {"clinic_id": report["clinic_id"], "as_of": report["as_of"], "summary": report["summary"],
            "finding_counts": dict(sorted(by_code.items())), "audit_ok": report["audit_chain"]["ok"]}
