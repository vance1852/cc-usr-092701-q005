"""诊所耗材批次、预约预留、退回与患者使用追溯。"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo

from . import audit
from .db import Database, decode_json, encode_json
from .errors import Conflict, NotFound, ValidationError
from .ids import new_id, require_idempotency_key
from .security import authorize, principal_for
from .validation import calendar_date, choice, decimal_value, request_digest, text

PRODUCT_CATEGORIES = {"consumable", "implant", "topical", "injectable", "device_accessory", "other"}


class SupplyService:
    """库存按批次分账，预约占用和实际患者使用分别记账。"""

    def __init__(self, database: Database, clock):
        self.db = database
        self.clock = clock

    def now(self) -> str:
        return self.clock.now().astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")

    def local_date(self, connection, clinic_id: str) -> str:
        row = connection.execute("SELECT timezone FROM clinics WHERE id=?", (clinic_id,)).fetchone()
        if row is None:
            raise NotFound("诊所不存在")
        return self.clock.now().astimezone(ZoneInfo(row["timezone"])).date().isoformat()

    def register_product(self, clinic_id: str, actor_id: str, name: str, category: str,
                         stock_unit: str, *, requires_lot: bool = True,
                         requires_clinician: bool = False) -> dict[str, Any]:
        name = text(name, "耗材名称", maximum=160)
        category = choice(category, "耗材类别", PRODUCT_CATEGORIES)
        stock_unit = text(stock_unit, "计量单位", maximum=24)
        if not isinstance(requires_lot, bool) or not isinstance(requires_clinician, bool):
            raise ValidationError("追溯设置必须为布尔值")
        product_id = new_id("prd")
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "staff:manage", clinic_id=clinic_id)
            connection.execute("INSERT INTO products(id,clinic_id,name,category,stock_unit,requires_lot,requires_clinician,created_at) VALUES(?,?,?,?,?,?,?,?)",
                               (product_id, clinic_id, name, category, stock_unit, int(requires_lot), int(requires_clinician), now))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                               aggregate_type="product", aggregate_id=product_id, action="product.registered",
                               occurred_at=now, payload={"category": category, "unit": stock_unit})
        return {"id": product_id, "name": name, "category": category, "stock_unit": stock_unit,
                "requires_lot": requires_lot, "requires_clinician": requires_clinician, "active": True}

    def receive_lot(self, clinic_id: str, actor_id: str, product_id: str, supplier_ref: str,
                    lot_number: str, quantity: float, idempotency_key: str, *, expires_on: str | None = None,
                    received_at: str | None = None) -> dict[str, Any]:
        supplier_ref = text(supplier_ref, "供应商编号", maximum=120)
        lot_number = text(lot_number, "生产批号", maximum=120)
        quantity = decimal_value(quantity, "入库数量", minimum="0.0001", maximum="10000000")
        key = require_idempotency_key(idempotency_key)
        expiry = calendar_date(expires_on, "失效日期") if expires_on else None
        now = self.now()
        lot_id = new_id("lot")
        request_hash = request_digest({"clinic_id": clinic_id, "product_id": product_id, "supplier_ref": supplier_ref,
                                       "lot_number": lot_number, "quantity": quantity, "expires_on": expiry})
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "staff:manage", clinic_id=clinic_id)
            old = connection.execute("SELECT response_json,request_hash FROM idempotency WHERE scope='stock_receive' AND key=?", (key,)).fetchone()
            if old:
                if old["request_hash"] != request_hash:
                    raise Conflict("入库幂等编号已用于其他内容")
                return {**decode_json(old["response_json"]), "replayed": True}
            product = connection.execute("SELECT * FROM products WHERE id=? AND clinic_id=?", (product_id, clinic_id)).fetchone()
            if product is None or not product["active"]:
                raise NotFound("耗材不存在或已停用")
            actual_receipt = received_at or now
            connection.execute("INSERT INTO product_lots(id,product_id,supplier_ref,lot_number,expires_on,received_at,received_by,state) VALUES(?,?,?,?,?,?,?,'available')",
                               (lot_id, product_id, supplier_ref, lot_number, expiry, actual_receipt, actor_id))
            self._movement(connection, lot_id, "received", quantity, None, None, actor_id,
                           "初次入库", f"{key}:receive", now)
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                               aggregate_type="product_lot", aggregate_id=lot_id, action="stock.received",
                               occurred_at=now, payload={"product_id": product_id, "quantity": quantity,
                                                         "unit": product["stock_unit"], "expires_on": expiry})
            result = {"id": lot_id, "product_id": product_id, "supplier_ref": supplier_ref,
                      "lot_number": lot_number, "quantity_received": quantity, "expires_on": expiry, "state": "available"}
            connection.execute("INSERT INTO idempotency(scope,key,request_hash,response_json,created_at) VALUES(?,?,?,?,?)",
                               ("stock_receive", key, request_hash, encode_json(result), now))
        return {**result, "replayed": False}

    def _movement(self, connection, lot_id: str, event_type: str, delta: float,
                  appointment_id: str | None, patient_id: str | None, actor_id: str | None,
                  reason: str, key: str, now: str) -> None:
        sequence = connection.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM stock_movements WHERE lot_id=?", (lot_id,)).fetchone()[0]
        connection.execute("INSERT INTO stock_movements(id,lot_id,event_type,quantity_delta,appointment_id,patient_id,actor_id,reason,idempotency_key,created_at,sequence) "
                           "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                           (new_id("mov"), lot_id, event_type, delta, appointment_id, patient_id, actor_id,
                            reason, key, now, sequence))

    def lot_balances(self, clinic_id: str, product_id: str | None = None) -> list[dict[str, Any]]:
        with self.db.transaction(write=False) as connection:
            params: tuple[Any, ...] = (clinic_id,)
            condition = "p.clinic_id=?"
            if product_id:
                condition += " AND p.id=?"
                params += (product_id,)
            rows = connection.execute(
                "SELECT p.id AS product_id,p.name,p.stock_unit,p.requires_clinician,l.id AS lot_id,l.supplier_ref,l.lot_number,l.expires_on,l.state "
                ",COALESCE(SUM(m.quantity_delta),0) AS available_quantity "
                "FROM products p JOIN product_lots l ON l.product_id=p.id LEFT JOIN stock_movements m ON m.lot_id=l.id "
                f"WHERE {condition} GROUP BY p.id,l.id ORDER BY p.name,CASE WHEN l.expires_on IS NULL THEN 1 ELSE 0 END,l.expires_on,l.received_at,l.id",
                params).fetchall()
            return [{"product_id": row["product_id"], "product_name": row["name"], "stock_unit": row["stock_unit"],
                     "requires_clinician": bool(row["requires_clinician"]), "lot_id": row["lot_id"],
                     "supplier_ref": row["supplier_ref"], "lot_number": row["lot_number"],
                     "expires_on": row["expires_on"], "state": row["state"],
                     "available_quantity": max(0.0, row["available_quantity"])} for row in rows]

    def reserve(self, clinic_id: str, actor_id: str, appointment_id: str, product_id: str,
                quantity: float, idempotency_key: str) -> dict[str, Any]:
        quantity = decimal_value(quantity, "预留数量", minimum="0.0001", maximum="100000")
        key = require_idempotency_key(idempotency_key)
        now = self.now()
        request_hash = request_digest({"clinic_id": clinic_id, "appointment_id": appointment_id,
                                       "product_id": product_id, "quantity": quantity})
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            authorize(principal, "appointment:write", clinic_id=clinic_id)
            previous = connection.execute("SELECT * FROM stock_reservation_batches WHERE idempotency_key=?", (key,)).fetchone()
            if previous:
                if previous["request_hash"] != request_hash:
                    raise Conflict("耗材预留幂等编号已用于不同请求")
                return {**decode_json(previous["result_json"]), "replayed": True}
            appointment = connection.execute("SELECT * FROM appointments WHERE id=? AND clinic_id=?", (appointment_id, clinic_id)).fetchone()
            if appointment is None:
                raise NotFound("预约不存在")
            if appointment["state"] not in {"held", "booked", "arrived"}:
                raise Conflict("当前预约状态不能预留耗材")
            product = connection.execute("SELECT * FROM products WHERE id=? AND clinic_id=? AND active=1", (product_id, clinic_id)).fetchone()
            if product is None:
                raise NotFound("耗材不存在")
            if product["requires_clinician"] and principal.role not in {"clinician", "owner"}:
                raise Conflict("此类耗材须由临床岗位预留")
            local_today = self.local_date(connection, clinic_id)
            lots = connection.execute(
                "SELECT l.*,COALESCE(SUM(m.quantity_delta),0) AS available FROM product_lots l "
                "LEFT JOIN stock_movements m ON m.lot_id=l.id WHERE l.product_id=? AND l.state='available' "
                "AND (l.expires_on IS NULL OR l.expires_on>=?) GROUP BY l.id "
                "ORDER BY CASE WHEN l.expires_on IS NULL THEN 1 ELSE 0 END,l.expires_on,l.received_at,l.id",
                (product_id, local_today)).fetchall()
            remaining = quantity
            plan = []
            for lot in lots:
                available = max(0.0, float(lot["available"]))
                if available <= 0:
                    continue
                take = min(available, remaining)
                plan.append((lot, take))
                remaining = round(remaining - take, 8)
                if remaining <= 0:
                    break
            if remaining > 0:
                raise Conflict("可用耗材不足", details={"requested": quantity, "available": round(quantity - remaining, 8),
                                                       "unit": product["stock_unit"]})
            reservations = []
            for lot, take in plan:
                reservation_id = new_id("res")
                self._movement(connection, lot["id"], "reserved", -take, appointment_id,
                               appointment["patient_id"], actor_id, "预约备货", f"{key}:{lot['id']}:reserve", now)
                connection.execute(
                    "INSERT INTO stock_reservations(id,lot_id,appointment_id,patient_id,quantity,state,idempotency_key,reserved_by,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,'reserved',?,?,?,?)",
                    (reservation_id, lot["id"], appointment_id, appointment["patient_id"], take,
                     f"{key}:{lot['id']}", actor_id, now, now))
                reservations.append({"id": reservation_id, "lot_id": lot["id"], "lot_number": lot["lot_number"],
                                     "expires_on": lot["expires_on"], "quantity": take})
            result = {"appointment_id": appointment_id, "product_id": product_id,
                      "quantity": quantity, "unit": product["stock_unit"], "reservations": reservations}
            connection.execute("INSERT INTO stock_reservation_batches(idempotency_key,request_hash,result_json,created_at,created_by) VALUES(?,?,?,?,?)",
                               (key, request_hash, encode_json(result), now, actor_id))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=appointment["patient_id"],
                               aggregate_type="appointment", aggregate_id=appointment_id, action="stock.reserved",
                               occurred_at=now, payload={"product_id": product_id, "quantity": quantity,
                                                         "reservations": reservations, "idempotency_key": key})
        return {**result, "replayed": False}

    def release_reservation(self, clinic_id: str, actor_id: str, reservation_id: str,
                            reason: str, expected_version: int) -> dict[str, Any]:
        reason = text(reason, "释放原因", maximum=600)
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "appointment:write", clinic_id=clinic_id)
            row = connection.execute(
                "SELECT r.* FROM stock_reservations r JOIN appointments a ON a.id=r.appointment_id "
                "WHERE r.id=? AND a.clinic_id=?", (reservation_id, clinic_id)).fetchone()
            if row is None:
                raise NotFound("耗材预留不存在")
            if row["version"] != expected_version:
                from .errors import Conflict
                raise Conflict("耗材预留已被更新", details={"expected_version": expected_version, "actual_version": row["version"]})
            if row["state"] != "reserved":
                raise Conflict("只有未使用的预留可以释放")
            self._movement(connection, row["lot_id"], "released", row["quantity"], row["appointment_id"],
                           row["patient_id"], actor_id, reason, f"reservation:{reservation_id}:release", now)
            connection.execute("UPDATE stock_reservations SET state='released',updated_at=?,version=version+1 WHERE id=?",
                               (now, reservation_id))
            clinic_id_for_patient = connection.execute("SELECT clinic_id FROM patients WHERE id=?", (row["patient_id"],)).fetchone()[0]
            audit.append_event(connection, clinic_id=clinic_id_for_patient, actor_id=actor_id, patient_id=row["patient_id"],
                               aggregate_type="stock_reservation", aggregate_id=reservation_id, action="stock.released",
                               occurred_at=now, payload={"quantity": row["quantity"], "reason": reason})
        return {"id": reservation_id, "state": "released", "quantity": row["quantity"], "version": expected_version + 1}

    def consume_reservation(self, clinic_id: str, actor_id: str, reservation_id: str,
                            *, expected_version: int, witnessed_by: str | None = None) -> dict[str, Any]:
        now = self.now()
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            authorize(principal, "clinical:write", clinic_id=clinic_id)
            row = connection.execute(
                "SELECT r.*,a.state AS appointment_state,p.requires_clinician,l.state AS lot_state,l.expires_on "
                "FROM stock_reservations r JOIN appointments a ON a.id=r.appointment_id "
                "JOIN products p ON p.id=(SELECT product_id FROM product_lots WHERE id=r.lot_id) "
                "JOIN product_lots l ON l.id=r.lot_id WHERE r.id=? AND a.clinic_id=?",
                (reservation_id, clinic_id)).fetchone()
            if row is None:
                raise NotFound("耗材预留不存在")
            if row["version"] != expected_version:
                raise Conflict("耗材预留已被更新", details={"expected_version": expected_version, "actual_version": row["version"]})
            if row["state"] == "consumed":
                movement = connection.execute("SELECT id FROM stock_movements WHERE idempotency_key=?", (f"reservation:{reservation_id}:consume",)).fetchone()
                return {"id": reservation_id, "state": "consumed", "movement_id": movement[0] if movement else None,
                        "quantity": row["quantity"], "replayed": True}
            if row["state"] != "reserved" or row["appointment_state"] not in {"arrived", "in_service"}:
                raise Conflict("只有已到诊且仍有效的耗材预留可以核销")
            if row["lot_state"] != "available" or (row["expires_on"] and row["expires_on"] < self.local_date(connection, clinic_id)):
                raise Conflict("耗材批次已隔离、召回或过期")
            if row["requires_clinician"] and principal.role not in {"clinician", "owner"}:
                raise Conflict("此类耗材只能由临床岗位核销")
            if witnessed_by and witnessed_by != actor_id:
                witness = connection.execute("SELECT active,role FROM staff WHERE id=? AND clinic_id=?", (witnessed_by, clinic_id)).fetchone()
                if witness is None or not witness["active"] or witness["role"] not in {"clinician", "nurse", "owner"}:
                    raise ValidationError("见证人必须是有效临床岗位")
            movement_id = new_id("mov")
            self._movement(connection, row["lot_id"], "consumed", 0, row["appointment_id"],
                           row["patient_id"], actor_id, f"患者使用；见证人={witnessed_by or '无'}",
                           f"reservation:{reservation_id}:consume", now)
            connection.execute("UPDATE stock_reservations SET state='consumed',updated_at=?,version=version+1 WHERE id=?",
                               (now, reservation_id))
            move = connection.execute("SELECT id FROM stock_movements WHERE idempotency_key=?", (f"reservation:{reservation_id}:consume",)).fetchone()
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=row["patient_id"],
                               aggregate_type="stock_reservation", aggregate_id=reservation_id, action="stock.consumed",
                               occurred_at=now, payload={"lot_id": row["lot_id"], "quantity": row["quantity"],
                                                         "witnessed_by": witnessed_by})
        return {"id": reservation_id, "state": "consumed", "movement_id": move[0],
                "quantity": row["quantity"], "replayed": False}

    def change_lot_state(self, clinic_id: str, actor_id: str, lot_id: str,
                         action: str, reason: str) -> dict[str, Any]:
        action = choice(action, "批次处置", {"quarantine", "recall", "release_quarantine"})
        reason = text(reason, "批次处置原因", maximum=1000)
        now = self.now()
        states = {"quarantine": {"available", "quarantined"}, "recall": {"available", "quarantined", "recalled"},
                  "release_quarantine": {"quarantined"}}
        targets = {"quarantine": "quarantined", "recall": "recalled", "release_quarantine": "available"}
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            authorize(principal, "incident:manage", clinic_id=clinic_id)
            lot = connection.execute("SELECT l.*,p.clinic_id FROM product_lots l JOIN products p ON p.id=l.product_id WHERE l.id=? AND p.clinic_id=?",
                                     (lot_id, clinic_id)).fetchone()
            if lot is None:
                raise NotFound("耗材批次不存在")
            if lot["state"] not in states[action]:
                raise Conflict("批次当前状态不允许此处置", details={"state": lot["state"], "action": action})
            target = targets[action]
            if target == lot["state"]:
                return {"lot_id": lot_id, "state": target, "changed": False, "affected_reservations": []}
            affected = connection.execute("SELECT id,appointment_id,patient_id,quantity FROM stock_reservations WHERE lot_id=? AND state='reserved' ORDER BY id",
                                          (lot_id,)).fetchall() if target in {"quarantined", "recalled"} else []
            connection.execute("UPDATE product_lots SET state=?,version=version+1 WHERE id=?", (target, lot_id))
            alert_id = new_id("alt")
            previous_alert = connection.execute("SELECT id FROM lot_alerts WHERE lot_id=? ORDER BY created_at DESC LIMIT 1", (lot_id,)).fetchone()
            connection.execute("INSERT INTO lot_alerts(id,lot_id,alert_type,reason,actor_id,created_at,supersedes) VALUES(?,?,?,?,?,?,?)",
                               (alert_id, lot_id, action, reason, actor_id, now, previous_alert[0] if previous_alert else None))
            self._movement(connection, lot_id, "recalled" if action == "recall" else "quarantined" if action == "quarantine" else "adjusted",
                           0, None, None, actor_id, reason, f"lot-alert:{alert_id}", now)
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                               aggregate_type="product_lot", aggregate_id=lot_id, action=f"stock.{action}",
                               occurred_at=now, payload={"from": lot["state"], "to": target, "reason": reason,
                                                         "affected_reservations": [row["id"] for row in affected]})
        return {"lot_id": lot_id, "state": target, "changed": True,
                "affected_reservations": [{"id": row["id"], "appointment_id": row["appointment_id"],
                                           "patient_id": row["patient_id"], "quantity": row["quantity"]} for row in affected]}

    def lot_history(self, clinic_id: str, actor_id: str, lot_id: str) -> dict[str, Any]:
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "audit:read", clinic_id=clinic_id)
            lot = connection.execute("SELECT l.*,p.name,p.stock_unit FROM product_lots l JOIN products p ON p.id=l.product_id WHERE l.id=? AND p.clinic_id=?",
                                     (lot_id, clinic_id)).fetchone()
            if lot is None:
                raise NotFound("耗材批次不存在")
            movements = connection.execute("SELECT * FROM stock_movements WHERE lot_id=? ORDER BY sequence", (lot_id,)).fetchall()
            balance = sum(float(row["quantity_delta"]) for row in movements)
            return {"lot_id": lot_id, "product_id": lot["product_id"], "product_name": lot["name"],
                    "lot_number": lot["lot_number"], "supplier_ref": lot["supplier_ref"], "expires_on": lot["expires_on"],
                    "state": lot["state"], "unit": lot["stock_unit"], "current_quantity": max(0.0, balance),
                    "movements": [{"sequence": row["sequence"], "event_type": row["event_type"],
                                   "quantity_delta": row["quantity_delta"], "appointment_id": row["appointment_id"],
                                   "patient_id": row["patient_id"], "actor_id": row["actor_id"],
                                   "reason": row["reason"], "created_at": row["created_at"]} for row in movements]}
