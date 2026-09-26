"""诊疗计划节点、延期审批和已完成工作的不可变记录。"""

from __future__ import annotations

from . import audit
from .db import Database
from .errors import Conflict, NotFound, ValidationError
from .ids import new_id, require_idempotency_key
from .security import authorize, principal_for
from .validation import choice, request_digest, text, timestamp

MILESTONE_KINDS = {"review", "measurement", "followup", "preparation", "recovery_check", "other"}


class MilestoneService:
    def __init__(self, database: Database, clock):
        self.db = database
        self.clock = clock

    def create(self, clinic_id: str, actor_id: str, plan_id: str, kind: str, title: str,
               due_at: str, idempotency_key: str, *, assigned_to: str | None = None) -> dict:
        kind = choice(kind, "节点类型", MILESTONE_KINDS)
        title = text(title, "节点名称", maximum=160)
        due = timestamp(due_at, "节点时间")
        key = require_idempotency_key(idempotency_key)
        request = {"plan_id": plan_id, "kind": kind, "title": title, "due_at": due, "assigned_to": assigned_to}
        digest = request_digest(request)
        now = timestamp(self.clock.now())
        milestone_id = new_id("msl")
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "followup:manage", clinic_id=clinic_id)
            previous = connection.execute("SELECT * FROM idempotency WHERE scope='milestone' AND key=?", (key,)).fetchone()
            if previous:
                if previous["request_hash"] != digest:
                    raise Conflict("节点幂等编号已用于其他内容")
                return {**__import__("json").loads(previous["response_json"]), "replayed": True}
            plan = connection.execute("SELECT * FROM plans WHERE id=? AND clinic_id=?", (plan_id, clinic_id)).fetchone()
            if plan is None:
                raise NotFound("诊疗计划不存在")
            if plan["state"] not in {"draft", "proposed", "active", "paused"}:
                raise Conflict("当前计划状态不能增加节点")
            if assigned_to:
                member = connection.execute("SELECT active,role FROM staff WHERE id=? AND clinic_id=?", (assigned_to, clinic_id)).fetchone()
                if member is None or not member["active"]:
                    raise ValidationError("责任人不存在或已停用")
                if member["role"] not in {"clinician", "nurse", "owner", "coordinator"}:
                    raise ValidationError("责任人岗位不能处理计划节点")
            connection.execute("INSERT INTO plan_milestones(id,plan_id,kind,title,due_at,state,assigned_to,idempotency_key,created_by,created_at,updated_at) "
                               "VALUES(?,?,?,?,?,'pending',?,?,?,?,?)",
                               (milestone_id, plan_id, kind, title, due, assigned_to, key, actor_id, now, now))
            self._event(connection, milestone_id, "created", actor_id, "建立计划节点", None, due, now)
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=plan["patient_id"],
                               aggregate_type="plan_milestone", aggregate_id=milestone_id, action="milestone.created",
                               occurred_at=now, payload={"plan_id": plan_id, "kind": kind, "due_at": due})
            result = {"id": milestone_id, "plan_id": plan_id, "kind": kind, "title": title,
                      "due_at": due, "state": "pending", "assigned_to": assigned_to, "version": 1}
            connection.execute("INSERT INTO idempotency(scope,key,request_hash,response_json,created_at) VALUES('milestone',?,?,?,?)",
                               (key, digest, __import__("json").dumps(result, ensure_ascii=False), now))
        return {**result, "replayed": False}

    def _event(self, connection, milestone_id: str, action: str, actor_id: str, reason: str,
               prior_due: str | None, next_due: str | None, now: str) -> None:
        sequence = connection.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM milestone_events WHERE milestone_id=?", (milestone_id,)).fetchone()[0]
        connection.execute("INSERT INTO milestone_events(id,milestone_id,sequence,action,actor_id,reason,prior_due_at,next_due_at,occurred_at) "
                           "VALUES(?,?,?,?,?,?,?,?,?)",
                           (new_id("mse"), milestone_id, sequence, action, actor_id, reason, prior_due, next_due, now))

    def transition(self, clinic_id: str, actor_id: str, milestone_id: str, expected_version: int,
                   action: str, *, reason: str, new_due_at: str | None = None) -> dict:
        action = choice(action, "节点处置", {"complete", "defer", "waive", "cancel"})
        reason = text(reason, "处置原因", maximum=1000)
        due = timestamp(new_due_at, "新节点时间") if new_due_at else None
        if action == "defer" and not due:
            raise ValidationError("延期必须明确新的到期时间")
        if action != "defer" and due:
            raise ValidationError("只有延期操作可以设置新到期时间")
        now = timestamp(self.clock.now())
        targets = {"complete": "completed", "defer": "pending", "waive": "waived", "cancel": "cancelled"}
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            authorize(principal, "followup:manage", clinic_id=clinic_id)
            row = connection.execute("SELECT m.*,p.patient_id,p.clinic_id AS plan_clinic FROM plan_milestones m "
                                     "JOIN plans p ON p.id=m.plan_id WHERE m.id=? AND p.clinic_id=?",
                                     (milestone_id, clinic_id)).fetchone()
            if row is None:
                raise NotFound("计划节点不存在")
            if row["version"] != expected_version:
                raise Conflict("计划节点已被更新", details={"expected_version": expected_version, "actual_version": row["version"]})
            if row["state"] not in {"pending", "deferred"}:
                raise Conflict("已结束节点不能重复处置")
            if row["assigned_to"] and row["assigned_to"] != actor_id and principal.role not in {"owner", "clinician"}:
                raise Conflict("当前节点分配给其他责任人")
            if action == "defer" and due <= now:
                raise ValidationError("延期后的时间必须晚于当前时间")
            target = targets[action]
            version = row["version"] + 1
            connection.execute("UPDATE plan_milestones SET due_at=COALESCE(?,due_at),state=?,updated_at=?,version=? WHERE id=?",
                               (due, target, now, version, milestone_id))
            self._event(connection, milestone_id, action, actor_id, reason, row["due_at"], due or row["due_at"], now)
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=row["patient_id"],
                               aggregate_type="plan_milestone", aggregate_id=milestone_id, action=f"milestone.{action}",
                               occurred_at=now, payload={"from": row["state"], "to": target, "reason": reason,
                                                         "due_at": due or row["due_at"], "version": version})
        return {"id": milestone_id, "state": target, "due_at": due or row["due_at"], "version": version}

    def list_for_plan(self, clinic_id: str, actor_id: str, plan_id: str) -> list[dict]:
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            if connection.execute("SELECT 1 FROM plans WHERE id=? AND clinic_id=?", (plan_id, clinic_id)).fetchone() is None:
                raise NotFound("诊疗计划不存在")
            rows = connection.execute("SELECT * FROM plan_milestones WHERE plan_id=? ORDER BY due_at,id", (plan_id,)).fetchall()
            return [{"id": row["id"], "kind": row["kind"], "title": row["title"], "due_at": row["due_at"],
                     "state": row["state"], "assigned_to": row["assigned_to"], "version": row["version"]} for row in rows]

    def history(self, clinic_id: str, actor_id: str, milestone_id: str) -> list[dict]:
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            if connection.execute("SELECT 1 FROM plan_milestones m JOIN plans p ON p.id=m.plan_id WHERE m.id=? AND p.clinic_id=?",
                                  (milestone_id, clinic_id)).fetchone() is None:
                raise NotFound("计划节点不存在")
            rows = connection.execute("SELECT * FROM milestone_events WHERE milestone_id=? ORDER BY sequence", (milestone_id,)).fetchall()
            return [{"sequence": row["sequence"], "action": row["action"], "actor_id": row["actor_id"],
                     "reason": row["reason"], "prior_due_at": row["prior_due_at"],
                     "next_due_at": row["next_due_at"], "occurred_at": row["occurred_at"]} for row in rows]

    def overdue(self, clinic_id: str, actor_id: str, *, limit: int = 200) -> dict:
        if not 1 <= limit <= 1000:
            raise ValidationError("查询数量须为 1 至 1000")
        now = timestamp(self.clock.now())
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "followup:manage", clinic_id=clinic_id)
            rows = connection.execute("SELECT m.id,m.plan_id,m.kind,m.title,m.due_at,m.state,m.assigned_to,p.patient_id "
                                      "FROM plan_milestones m JOIN plans p ON p.id=m.plan_id WHERE p.clinic_id=? "
                                      "AND m.state IN ('pending','deferred') AND m.due_at<=? ORDER BY m.due_at,m.id LIMIT ?",
                                      (clinic_id, now, limit)).fetchall()
            return {"clinic_id": clinic_id, "as_of": now, "items": [dict(row) for row in rows], "returned": len(rows)}
