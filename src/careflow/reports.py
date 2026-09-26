"""门诊运营汇总与按患者授权的趋势查询。"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

from .errors import NotFound, ValidationError
from .security import authorize, principal_for
from .validation import calendar_date, timestamp


class ReportService:
    """报告只归纳已记录事实，不生成诊断或治疗建议。"""

    def __init__(self, database, clock):
        self.db = database
        self.clock = clock

    def _clinic(self, connection, clinic_id: str):
        row = connection.execute("SELECT timezone,state FROM clinics WHERE id=?", (clinic_id,)).fetchone()
        if row is None:
            raise NotFound("诊所不存在")
        return row

    def daily_operations(self, clinic_id: str, actor_id: str, day: str | None = None) -> dict:
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            clinic = self._clinic(connection, clinic_id)
            zone = ZoneInfo(clinic["timezone"])
            local_day = date.fromisoformat(day) if day else self.clock.now().astimezone(zone).date()
            start = datetime.combine(local_day, datetime.min.time(), zone).astimezone(UTC)
            end = datetime.combine(local_day + timedelta(days=1), datetime.min.time(), zone).astimezone(UTC)
            start_text, end_text = timestamp(start), timestamp(end)
            appointments = connection.execute(
                "SELECT state,kind,COUNT(*) AS total FROM appointments WHERE clinic_id=? AND starts_at>=? AND starts_at<? "
                "GROUP BY state,kind ORDER BY state,kind", (clinic_id, start_text, end_text)).fetchall()
            appointment_counts: dict[str, dict[str, int]] = defaultdict(dict)
            for row in appointments:
                appointment_counts[row["state"]][row["kind"]] = row["total"]
            incidents = connection.execute(
                "SELECT i.severity,i.state,COUNT(*) AS total FROM incidents i JOIN patients p ON p.id=i.patient_id "
                "WHERE p.clinic_id=? AND i.reported_at>=? AND i.reported_at<? GROUP BY i.severity,i.state ORDER BY i.severity,i.state",
                (clinic_id, start_text, end_text)).fetchall()
            incident_counts: dict[str, dict[str, int]] = defaultdict(dict)
            for row in incidents:
                incident_counts[row["severity"]][row["state"]] = row["total"]
            followups = connection.execute(
                "SELECT f.state,COUNT(*) AS total FROM followups f JOIN patients p ON p.id=f.patient_id "
                "WHERE p.clinic_id=? AND f.due_at>=? AND f.due_at<? GROUP BY f.state ORDER BY f.state",
                (clinic_id, start_text, end_text)).fetchall()
            observations = connection.execute(
                "SELECT o.kind,COUNT(*) AS total FROM observations o JOIN patients p ON p.id=o.patient_id "
                "WHERE p.clinic_id=? AND o.observed_at>=? AND o.observed_at<? GROUP BY o.kind ORDER BY o.kind",
                (clinic_id, start_text, end_text)).fetchall()
            staff = connection.execute("SELECT role,COUNT(*) AS total FROM staff WHERE clinic_id=? AND active=1 GROUP BY role ORDER BY role",
                                      (clinic_id,)).fetchall()
            return {"clinic_id": clinic_id, "local_date": local_day.isoformat(), "timezone": clinic["timezone"],
                    "window": {"starts_at": start_text, "ends_at": end_text},
                    "appointments_by_state_and_kind": dict(appointment_counts),
                    "incidents_by_severity_and_state": dict(incident_counts),
                    "followups_by_state": {row["state"]: row["total"] for row in followups},
                    "observations_by_kind": {row["kind"]: row["total"] for row in observations},
                    "active_staff_by_role": {row["role"]: row["total"] for row in staff}}

    def followup_backlog(self, clinic_id: str, actor_id: str, *, limit: int = 200) -> dict:
        if not 1 <= limit <= 1000:
            raise ValidationError("报告数量必须为 1 至 1000")
        now = timestamp(self.clock.now())
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "followup:manage", clinic_id=clinic_id)
            self._clinic(connection, clinic_id)
            rows = connection.execute(
                "SELECT f.id,f.due_at,f.state,f.channel,f.assigned_to,p.id AS patient_id,p.external_ref "
                "FROM followups f JOIN patients p ON p.id=f.patient_id WHERE p.clinic_id=? "
                "AND f.state IN ('pending','claimed','deferred') AND f.due_at<=? "
                "ORDER BY f.due_at,f.id LIMIT ?", (clinic_id, now, limit)).fetchall()
            buckets = Counter()
            entries = []
            for row in rows:
                age_hours = max(0.0, (datetime.fromisoformat(now.replace("Z", "+00:00")) -
                                      datetime.fromisoformat(row["due_at"].replace("Z", "+00:00"))).total_seconds() / 3600)
                bucket = "under_24h" if age_hours < 24 else "1_to_3_days" if age_hours < 72 else "over_3_days"
                buckets[bucket] += 1
                entries.append({"id": row["id"], "patient_id": row["patient_id"], "patient_ref": row["external_ref"],
                                "due_at": row["due_at"], "state": row["state"], "channel": row["channel"],
                                "assigned_to": row["assigned_to"], "overdue_hours": round(age_hours, 2), "bucket": bucket})
            pending_total = connection.execute(
                "SELECT COUNT(*) FROM followups f JOIN patients p ON p.id=f.patient_id WHERE p.clinic_id=? "
                "AND f.state IN ('pending','claimed','deferred') AND f.due_at<=?", (clinic_id, now)).fetchone()[0]
            return {"clinic_id": clinic_id, "as_of": now, "total_overdue": pending_total,
                    "returned": len(entries), "truncated": pending_total > len(entries),
                    "age_buckets": {key: buckets[key] for key in ("under_24h", "1_to_3_days", "over_3_days")},
                    "items": entries}

    def appointment_outcomes(self, clinic_id: str, actor_id: str, start_date: str, end_date: str) -> dict:
        first = date.fromisoformat(calendar_date(start_date, "起始日期"))
        last = date.fromisoformat(calendar_date(end_date, "结束日期"))
        if last < first:
            raise ValidationError("结束日期不能早于起始日期")
        if (last - first).days > 370:
            raise ValidationError("单次报告跨度不得超过 371 天")
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            clinic = self._clinic(connection, clinic_id)
            zone = ZoneInfo(clinic["timezone"])
            lower = datetime.combine(first, datetime.min.time(), zone).astimezone(UTC)
            upper = datetime.combine(last + timedelta(days=1), datetime.min.time(), zone).astimezone(UTC)
            rows = connection.execute(
                "SELECT kind,state,COUNT(*) AS total FROM appointments WHERE clinic_id=? AND starts_at>=? AND starts_at<? "
                "GROUP BY kind,state ORDER BY kind,state", (clinic_id, timestamp(lower), timestamp(upper))).fetchall()
            by_kind: dict[str, dict[str, int]] = defaultdict(dict)
            totals = Counter()
            for row in rows:
                by_kind[row["kind"]][row["state"]] = row["total"]
                totals[row["state"]] += row["total"]
            denominator = sum(totals.values())
            attended = sum(totals[state] for state in ("arrived", "in_service", "completed"))
            return {"clinic_id": clinic_id, "start_date": first.isoformat(), "end_date": last.isoformat(),
                    "timezone": clinic["timezone"], "total": denominator,
                    "attendance_rate": round(attended / denominator, 4) if denominator else None,
                    "by_kind": dict(by_kind), "by_state": dict(totals)}

    def incident_summary(self, clinic_id: str, actor_id: str, start_date: str, end_date: str) -> dict:
        first = date.fromisoformat(calendar_date(start_date, "起始日期"))
        last = date.fromisoformat(calendar_date(end_date, "结束日期"))
        if last < first or (last - first).days > 370:
            raise ValidationError("报告日期范围无效")
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "incident:manage", clinic_id=clinic_id)
            clinic = self._clinic(connection, clinic_id)
            zone = ZoneInfo(clinic["timezone"])
            low = timestamp(datetime.combine(first, datetime.min.time(), zone).astimezone(UTC))
            high = timestamp(datetime.combine(last + timedelta(days=1), datetime.min.time(), zone).astimezone(UTC))
            rows = connection.execute(
                "SELECT i.category,i.severity,i.state,COUNT(*) AS total FROM incidents i JOIN patients p ON p.id=i.patient_id "
                "WHERE p.clinic_id=? AND i.reported_at>=? AND i.reported_at<? GROUP BY i.category,i.severity,i.state "
                "ORDER BY i.category,i.severity,i.state", (clinic_id, low, high)).fetchall()
            details = [{"category": row["category"], "severity": row["severity"],
                        "state": row["state"], "count": row["total"]} for row in rows]
            return {"clinic_id": clinic_id, "start_date": first.isoformat(), "end_date": last.isoformat(),
                    "timezone": clinic["timezone"], "reported": sum(row["count"] for row in details), "groups": details}

    def weight_series(self, clinic_id: str, actor_id: str, patient_id: str, *, start: str | None = None,
                      end: str | None = None) -> dict:
        start_at = timestamp(start, "起始时间") if start else None
        end_at = timestamp(end, "结束时间") if end else None
        if start_at and end_at and end_at < start_at:
            raise ValidationError("时间范围反转")
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            patient = connection.execute("SELECT id,external_ref,state FROM patients WHERE id=? AND clinic_id=?", (patient_id, clinic_id)).fetchone()
            if patient is None:
                raise NotFound("患者不存在")
            clauses = ["patient_id=?", "kind='weight_kg'"]
            params = [patient_id]
            if start_at:
                clauses.append("observed_at>=?")
                params.append(start_at)
            if end_at:
                clauses.append("observed_at<=?")
                params.append(end_at)
            rows = connection.execute("SELECT * FROM observations WHERE " + " AND ".join(clauses) + " ORDER BY observed_at,id", params).fetchall()
            corrected_ids = {row["correction_of"] for row in rows if row["correction_of"]}
            effective = [row for row in rows if row["correction_of"] is not None or row["id"] not in corrected_ids]
            effective.sort(key=lambda row: (row["observed_at"], row["id"]))
            values = []
            for row in effective:
                values.append({"id": row["id"], "observed_at": row["observed_at"], "weight_kg": row["value_num"],
                               "recorded_by": row["recorded_by"], "provenance": row["provenance"],
                               "corrects": row["correction_of"]})
            delta = round(values[-1]["weight_kg"] - values[0]["weight_kg"], 2) if len(values) >= 2 else None
            return {"patient_id": patient_id, "patient_ref": patient["external_ref"], "patient_state": patient["state"],
                    "observations": values, "count": len(values), "first_to_last_delta_kg": delta,
                    "interpretation": "仅展示已记录测量，不构成诊断或治疗建议。"}

    def plan_history(self, clinic_id: str, actor_id: str, patient_id: str) -> dict:
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            if connection.execute("SELECT 1 FROM patients WHERE id=? AND clinic_id=?", (patient_id, clinic_id)).fetchone() is None:
                raise NotFound("患者不存在")
            rows = connection.execute("SELECT id,kind,state,start_date,target_date,updated_at,version FROM plans "
                                      "WHERE patient_id=? AND clinic_id=? ORDER BY start_date,id", (patient_id, clinic_id)).fetchall()
            return {"patient_id": patient_id, "plans": [dict(row) for row in rows]}
