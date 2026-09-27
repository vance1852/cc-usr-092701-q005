"""门诊外设备测量的批量导入、行级核对与追加式更正。

每个文件批次保留来源、格式版本、原始行号与内容摘要；可识别的行写入观察记录，
无法识别或单位不符的行进入待核对清单，单行问题不会使整批失败。
相同批次重传返回原处理结果；同一批次键提交修订内容时生成新修订并逐行说明变化。
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from . import audit
from .db import decode_json, encode_json
from .errors import Conflict, NotFound, ValidationError
from .ids import new_id, require_idempotency_key
from .security import authorize, principal_for
from .validation import parsed_timestamp, text, timestamp

MAX_CONTENT_CHARS = 200_000
MAX_ROWS = 5_000
MAX_EXCERPT = 300
FUTURE_TOLERANCE = timedelta(minutes=10)

# 每种观察类型接受的单位别名与规范化目标；未列出的单位一律进入待核对清单。
KIND_UNITS: dict[str, dict[str, Any]] = {
    "weight_kg": {"unit": "kg", "aliases": {"kg", "kgs", "kilogram", "kilograms", "公斤", "千克"},
                  "minimum": Decimal("1"), "maximum": Decimal("600")},
    "waist_cm": {"unit": "cm", "aliases": {"cm", "centimeter", "centimeters", "厘米"},
                 "minimum": Decimal("10"), "maximum": Decimal("300")},
}
FORMAT_VERSIONS = {"scale_csv_v1", "weight_json_v1"}
CSV_HEADER = ["patient_ref", "measured_at", "kind", "value", "unit"]

ISSUE_MESSAGES = {
    "malformed_row": "行列数或字段结构不符合格式版本要求",
    "unknown_kind": "测量项目无法识别",
    "unknown_patient": "患者编号在诊所内不存在或不在诊",
    "unit_mismatch": "测量单位与项目要求不符",
    "invalid_value": "测量值不是有效数字或超出允许范围",
    "invalid_time": "测量时间无法解析或晚于当前时间",
    "duplicate_in_file": "同一文件内出现完全相同的重复行",
    "identity_changed": "修订行变更了患者或测量项目，不能直接更正原记录",
    "already_corrected": "原导入记录已被后续更正覆盖，请先核对最新有效值",
}


def _excerpt(raw: str) -> str:
    return raw if len(raw) <= MAX_EXCERPT else raw[: MAX_EXCERPT - 1] + "…"


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def parse_content(format_version: str, content: str) -> list[dict[str, Any]]:
    """按格式版本把文件内容拆成行；结构性错误整体拒绝，行内问题留给逐行核对。"""
    format_version = text(format_version, "格式版本", maximum=40)
    if format_version not in FORMAT_VERSIONS:
        raise ValidationError("格式版本不受支持", details={"allowed": sorted(FORMAT_VERSIONS)})
    if not isinstance(content, str) or not content.strip():
        raise ValidationError("导入内容不能为空")
    if len(content) > MAX_CONTENT_CHARS:
        raise ValidationError("导入内容超出大小限制")
    if format_version == "scale_csv_v1":
        return _parse_csv(content)
    return _parse_json(content)


def _parse_csv(content: str) -> list[dict[str, Any]]:
    lines = content.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        raise ValidationError("导入内容不能为空")
    try:
        header = next(csv.reader(io.StringIO(lines[0])))
    except csv.Error as exc:
        raise ValidationError("表头行无法解析") from exc
    if [cell.strip().lower() for cell in header] != CSV_HEADER:
        raise ValidationError("表头与格式版本 scale_csv_v1 不符", details={"expected": CSV_HEADER})
    rows = []
    for offset, raw in enumerate(lines[1:], start=2):
        if not raw.strip():
            continue
        try:
            cells = next(csv.reader(io.StringIO(raw)))
        except csv.Error:
            cells = None
        rows.append({"row_number": offset, "raw": raw, "cells": cells})
    return rows


def _parse_json(content: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValidationError("导入内容不是有效 JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("rows"), list):
        raise ValidationError("weight_json_v1 内容必须为包含 rows 数组的对象")
    rows = []
    for index, item in enumerate(payload["rows"], start=1):
        if isinstance(item, dict):
            cells = {key: item.get(key) for key in CSV_HEADER}
            raw = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        else:
            cells = None
            raw = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        rows.append({"row_number": index, "raw": raw, "cells": cells})
    return rows


def _normalize_kind(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    key = value.strip().lower()
    aliases = {"weight": "weight_kg", "weight_kg": "weight_kg", "体重": "weight_kg",
               "waist": "waist_cm", "waist_cm": "waist_cm", "腰围": "waist_cm"}
    return aliases.get(key)


def _decimal_in_range(value: Any, minimum: Decimal, maximum: Decimal) -> Decimal | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = Decimal(str(value).strip() if isinstance(value, str) else str(value))
    except (InvalidOperation, ValueError):
        return None
    if not number.is_finite() or number < minimum or number > maximum:
        return None
    return number


class MeasurementImportService:
    """批量测量导入的领域服务；每批的所有写入在单个事务内完成。"""

    def __init__(self, database, clock):
        self.db = database
        self.clock = clock

    def now(self) -> str:
        return timestamp(self.clock.now())

    # ------------------------------------------------------------------ 导入

    def import_batch(self, clinic_id: str, actor_id: str, batch_key: str, source: str,
                     format_version: str, content: str) -> dict[str, Any]:
        batch_key = require_idempotency_key(batch_key)
        source = text(source, "来源说明", maximum=200)
        rows = parse_content(format_version, content)
        if not rows:
            raise ValidationError("导入文件不包含任何数据行")
        if len(rows) > MAX_ROWS:
            raise ValidationError("单批导入行数超出限制", details={"maximum": MAX_ROWS})
        for row in rows:
            row["hash"] = _hash(row["raw"])
        content_hash = _hash("\n".join(row["hash"] for row in rows))
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:write", clinic_id=clinic_id)
            latest = connection.execute(
                "SELECT * FROM measurement_batches WHERE clinic_id=? AND batch_key=? ORDER BY revision DESC LIMIT 1",
                (clinic_id, batch_key)).fetchone()
            if latest and latest["content_hash"] == content_hash:
                # 相同批次重传：直接返回原处理结果，不产生任何新记录。
                result = dict(decode_json(latest["result_json"]))
                result["replayed"] = True
                return result
            revision = (latest["revision"] + 1) if latest else 1
            prior_rows = {}
            if latest:
                for row in connection.execute(
                        "SELECT * FROM measurement_batch_rows WHERE batch_id=?", (latest["id"],)).fetchall():
                    prior_rows[row["row_number"]] = dict(row)
            batch_id = new_id("imb")
            context = _ImportContext(self, connection, clinic_id, actor_id, now, batch_id, prior_rows)
            outcome = context.process(rows)
            result = {"batch_id": batch_id, "batch_key": batch_key, "revision": revision,
                      "source": source, "format_version": format_version, "content_hash": content_hash,
                      "row_count": len(rows), "imported": outcome["imported"], "duplicates": outcome["duplicates"],
                      "review_items": outcome["review_items"], "changes": outcome["changes"],
                      "counts": outcome["counts"], "processed_at": now, "replayed": False}
            connection.execute(
                "INSERT INTO measurement_batches(id,clinic_id,batch_key,revision,source,format_version,content_hash,"
                "row_count,imported_count,review_count,duplicate_count,correction_count,result_json,uploaded_by,created_at,supersedes) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (batch_id, clinic_id, batch_key, revision, source, format_version, content_hash, len(rows),
                 outcome["counts"]["imported"], outcome["counts"]["review"], outcome["counts"]["duplicate"],
                 outcome["counts"]["correction"], encode_json(result), actor_id, now,
                 latest["id"] if latest else None))
            stored_ids: dict[int, str] = {}
            for stored in outcome["stored_rows"]:
                stored_ids[stored["row_number"]] = stored["id"]
                connection.execute(
                    "INSERT INTO measurement_batch_rows(id,batch_id,row_number,row_hash,raw_excerpt,status,issue_code,"
                    "patient_id,observation_id,detail) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (stored["id"], batch_id, stored["row_number"], stored["row_hash"], stored["raw_excerpt"],
                     stored["status"], stored["issue_code"], stored["patient_id"], stored["observation_id"],
                     stored["detail"]))
            for item in outcome["review_rows"]:
                connection.execute(
                    "INSERT INTO measurement_review_items(id,clinic_id,batch_id,row_id,row_number,issue_code,raw_excerpt,"
                    "detail,status,created_at) VALUES(?,?,?,?,?,?,?,?,'pending',?)",
                    (item["id"], clinic_id, batch_id, item["row_stored_id"], item["row_number"], item["issue_code"],
                     item["raw_excerpt"], item["detail"], now))
            for item_id, row_number in outcome["relinked_reviews"]:
                # 内容未变的问题行：原待核对条目保持待处理，仅指向新批次中的行记录。
                connection.execute(
                    "UPDATE measurement_review_items SET batch_id=?,row_id=? WHERE id=? AND status='pending'",
                    (batch_id, stored_ids[row_number], item_id))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                               aggregate_type="measurement_batch", aggregate_id=batch_id,
                               action="measurement_batch.revised" if revision > 1 else "measurement_batch.imported",
                               occurred_at=now,
                               payload={"batch_key": batch_key, "revision": revision, "source": source,
                                        "format_version": format_version, "content_hash": content_hash,
                                        "row_count": len(rows), "counts": outcome["counts"],
                                        "observation_ids": [item["observation_id"] for item in outcome["imported"]],
                                        "supersedes": latest["id"] if latest else None})
        return result

    # -------------------------------------------------------------- 查询与核对

    def get_batch(self, clinic_id: str, actor_id: str, batch_id: str) -> dict[str, Any]:
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            batch = connection.execute(
                "SELECT * FROM measurement_batches WHERE id=? AND clinic_id=?", (batch_id, clinic_id)).fetchone()
            if batch is None:
                raise NotFound("导入批次不存在")
            rows = connection.execute(
                "SELECT * FROM measurement_batch_rows WHERE batch_id=? ORDER BY row_number", (batch_id,)).fetchall()
            return {"batch": {"id": batch["id"], "batch_key": batch["batch_key"], "revision": batch["revision"],
                              "source": batch["source"], "format_version": batch["format_version"],
                              "content_hash": batch["content_hash"], "row_count": batch["row_count"],
                              "imported_count": batch["imported_count"], "review_count": batch["review_count"],
                              "duplicate_count": batch["duplicate_count"], "correction_count": batch["correction_count"],
                              "uploaded_by": batch["uploaded_by"], "created_at": batch["created_at"],
                              "supersedes": batch["supersedes"]},
                    "rows": [{"row_number": row["row_number"], "row_hash": row["row_hash"],
                              "raw_excerpt": row["raw_excerpt"], "status": row["status"],
                              "issue_code": row["issue_code"], "patient_id": row["patient_id"],
                              "observation_id": row["observation_id"], "detail": row["detail"]} for row in rows]}

    def list_review_items(self, clinic_id: str, actor_id: str, *, status: str = "pending",
                          limit: int = 200) -> list[dict[str, Any]]:
        if status not in {"pending", "resolved", "dismissed", "all"}:
            raise ValidationError("核对清单状态取值无效")
        if not 1 <= limit <= 1000:
            raise ValidationError("查询数量必须为 1 至 1000")
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            if status == "all":
                rows = connection.execute(
                    "SELECT * FROM measurement_review_items WHERE clinic_id=? ORDER BY created_at,id LIMIT ?",
                    (clinic_id, limit)).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM measurement_review_items WHERE clinic_id=? AND status=? ORDER BY created_at,id LIMIT ?",
                    (clinic_id, status, limit)).fetchall()
            return [self._review_item(row) for row in rows]

    def resolve_review_item(self, clinic_id: str, actor_id: str, item_id: str, action: str,
                            note: str) -> dict[str, Any]:
        if action not in {"resolve", "dismiss"}:
            raise ValidationError("核对处置操作无效")
        note = text(note, "处置说明", maximum=600)
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:write", clinic_id=clinic_id)
            row = connection.execute(
                "SELECT * FROM measurement_review_items WHERE id=? AND clinic_id=?", (item_id, clinic_id)).fetchone()
            if row is None:
                raise NotFound("待核对条目不存在")
            if row["status"] != "pending":
                raise Conflict("该条目已完成核对", details={"status": row["status"]})
            new_status = "resolved" if action == "resolve" else "dismissed"
            connection.execute(
                "UPDATE measurement_review_items SET status=?,resolution_note=?,resolved_by=?,resolved_at=? WHERE id=?",
                (new_status, note, actor_id, now, item_id))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                               aggregate_type="measurement_review_item", aggregate_id=item_id,
                               action=f"measurement_review.{new_status}", occurred_at=now,
                               payload={"batch_id": row["batch_id"], "row_number": row["row_number"],
                                        "issue_code": row["issue_code"], "note": note})
            updated = connection.execute("SELECT * FROM measurement_review_items WHERE id=?", (item_id,)).fetchone()
        return self._review_item(updated)

    @staticmethod
    def _review_item(row) -> dict[str, Any]:
        return {"id": row["id"], "batch_id": row["batch_id"], "row_number": row["row_number"],
                "issue_code": row["issue_code"], "issue": ISSUE_MESSAGES.get(row["issue_code"], row["issue_code"]),
                "raw_excerpt": row["raw_excerpt"], "detail": row["detail"], "status": row["status"],
                "resolution_note": row["resolution_note"], "resolved_by": row["resolved_by"],
                "resolved_at": row["resolved_at"], "created_at": row["created_at"]}

    # -------------------------------------------------------------- 追加式更正

    def correct_observation(self, clinic_id: str, actor_id: str, observation_id: str,
                            value: Any, reason: str) -> dict[str, Any]:
        """导入值发现错误时追加更正记录，原始行与旧值保持不变。"""
        reason = text(reason, "更正原因", maximum=600)
        now = self.now()
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:write", clinic_id=clinic_id)
            original = connection.execute(
                "SELECT o.* FROM observations o JOIN patients p ON p.id=o.patient_id "
                "WHERE o.id=? AND p.clinic_id=?", (observation_id, clinic_id)).fetchone()
            if original is None:
                raise NotFound("观察记录不存在")
            if original["correction_of"] is not None:
                raise Conflict("请针对原始记录追加更正，不能更正另一条更正记录")
            if connection.execute("SELECT 1 FROM observations WHERE correction_of=?", (observation_id,)).fetchone():
                raise Conflict("该观察值已有更正记录；如需再次修订请引用最新记录")
            spec = KIND_UNITS.get(original["kind"])
            if spec is None:
                raise Conflict("该观察类型不支持导入更正")
            number = _decimal_in_range(value, spec["minimum"], spec["maximum"])
            if number is None:
                raise ValidationError("更正值不是有效数字或超出允许范围")
            correction_id = new_id("obs")
            connection.execute(
                "INSERT INTO observations(id,patient_id,plan_id,kind,value_num,unit,observed_at,recorded_by,provenance,"
                "correction_of,import_batch_id,import_row_number,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (correction_id, original["patient_id"], original["plan_id"], original["kind"], float(number),
                 original["unit"], original["observed_at"], actor_id, original["provenance"], observation_id,
                 original["import_batch_id"], original["import_row_number"], now))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id,
                               patient_id=original["patient_id"], aggregate_type="observation",
                               aggregate_id=correction_id, action="observation.corrected", occurred_at=now,
                               payload={"kind": original["kind"], "value": float(number), "unit": original["unit"],
                                        "correction_of": observation_id, "reason": reason,
                                        "import_batch_id": original["import_batch_id"],
                                        "import_row_number": original["import_row_number"]})
        return {"id": correction_id, "patient_id": original["patient_id"], "kind": original["kind"],
                "value": float(number), "unit": original["unit"], "observed_at": original["observed_at"],
                "provenance": original["provenance"], "correction_of": observation_id,
                "import_batch_id": original["import_batch_id"], "import_row_number": original["import_row_number"]}


class _ImportContext:
    """单批导入的行级处理；全部行处理完后由调用方在同一事务内落库。"""

    def __init__(self, service: MeasurementImportService, connection, clinic_id: str,
                 actor_id: str, now: str, batch_id: str, prior_rows: dict[int, dict[str, Any]]):
        self.service = service
        self.connection = connection
        self.clinic_id = clinic_id
        self.actor_id = actor_id
        self.now = now
        self.batch_id = batch_id
        self.prior_rows = prior_rows
        self.patients: dict[str, dict[str, Any] | None] = {}
        self.imported_keys: set[tuple] | None = None
        self.seen_hashes: set[str] = set()
        self.outcome: dict[str, Any] = {"imported": [], "duplicates": [], "review_items": [], "changes": [],
                                        "stored_rows": [], "review_rows": [], "relinked_reviews": [],
                                        "counts": {"imported": 0, "duplicate": 0, "review": 0, "correction": 0}}
        self.stored_by_number: dict[int, str] = {}

    # ------------------------------------------------------------ 行级处理

    def process(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        for row in rows:
            self._process_row(row)
        if self.prior_rows:
            current_numbers = {row["row_number"] for row in rows}
            for number in sorted(set(self.prior_rows) - current_numbers):
                prior = self.prior_rows[number]
                self.outcome["changes"].append(
                    {"row_number": number, "type": "omitted", "prior_status": prior["status"],
                     "observation_id": prior["observation_id"],
                     "note": "该行未出现在本次修订中；已写入的观察记录与待核对条目保持不变"})
        self.outcome["changes"].sort(key=lambda change: change["row_number"])
        return self.outcome

    def _process_row(self, row: dict[str, Any]) -> None:
        if row["hash"] in self.seen_hashes:
            self._store(row, "duplicate", "duplicate_in_file", None, None, ISSUE_MESSAGES["duplicate_in_file"])
            self.outcome["duplicates"].append({"row_number": row["row_number"], "reason": "duplicate_in_file"})
            self.outcome["counts"]["duplicate"] += 1
            if row["row_number"] in self.prior_rows:
                self._change(row["row_number"], "duplicate_in_file")
            return
        self.seen_hashes.add(row["hash"])
        prior = self.prior_rows.get(row["row_number"])
        if prior and prior["row_hash"] == row["hash"]:
            self._carry_forward(row, prior)
            return
        parsed, issue, detail = self._validate(row)
        if issue:
            self._to_review(row, issue, detail, parsed)
            return
        assert parsed is not None
        self._import_valid_row(row, parsed, prior)

    def _carry_forward(self, row: dict[str, Any], prior: dict[str, Any]) -> None:
        """修订中内容未变的行沿用原处理结果，不重复写入。"""
        number, status = row["row_number"], prior["status"]
        self._store(row, status, prior["issue_code"], prior["patient_id"], prior["observation_id"], prior["detail"])
        if status in {"imported", "correction"}:
            self.outcome["imported"].append({"row_number": number, "observation_id": prior["observation_id"],
                                             "patient_id": prior["patient_id"], "carried_forward": True})
            self.outcome["counts"]["correction" if status == "correction" else "imported"] += 1
        elif status == "duplicate":
            self.outcome["duplicates"].append({"row_number": number, "reason": "duplicate_of_prior_import"})
            self.outcome["counts"]["duplicate"] += 1
        else:
            pending = self.connection.execute(
                "SELECT id FROM measurement_review_items WHERE row_id=? AND status='pending'",
                (prior["id"],)).fetchone()
            stored_id = self.stored_by_number[number]
            if pending:
                self.outcome["review_items"].append({"row_number": number, "issue_code": prior["issue_code"],
                                                     "review_item_id": pending["id"], "carried_forward": True})
                self.outcome["counts"]["review"] += 1
                self.outcome["relinked_reviews"].append((pending["id"], number))
            else:
                issue = prior["issue_code"] or "malformed_row"
                item_id = new_id("imq")
                self.outcome["review_rows"].append(
                    {"id": item_id, "row_stored_id": stored_id, "row_number": number, "issue_code": issue,
                     "raw_excerpt": _excerpt(row["raw"]), "detail": prior["detail"]})
                self.outcome["review_items"].append({"row_number": number, "issue_code": issue,
                                                     "review_item_id": item_id})
                self.outcome["counts"]["review"] += 1
        self._change(number, "unchanged")

    def _import_valid_row(self, row: dict[str, Any], parsed: dict[str, Any], prior: dict[str, Any] | None) -> None:
        number = row["row_number"]
        patient = parsed["patient"]
        key = (patient["id"], parsed["kind"], parsed["observed_at"], float(parsed["value"]))
        if prior and prior["status"] in {"imported", "correction"} and prior["observation_id"]:
            previous = self.connection.execute(
                "SELECT * FROM observations WHERE id=?", (prior["observation_id"],)).fetchone()
            root_id = previous["correction_of"] if previous and previous["correction_of"] else prior["observation_id"]
            root = self.connection.execute("SELECT * FROM observations WHERE id=?", (root_id,)).fetchone()
            if root is None or root["patient_id"] != patient["id"] or root["kind"] != parsed["kind"]:
                self._to_review(row, "identity_changed", ISSUE_MESSAGES["identity_changed"], parsed)
                return
            if self.connection.execute("SELECT 1 FROM observations WHERE correction_of=?", (root["id"],)).fetchone():
                self._to_review(row, "already_corrected", ISSUE_MESSAGES["already_corrected"], parsed)
                return
            if key in self._imported_keys():
                self._mark_duplicate(row, patient["id"], "now_duplicate")
                return
            observation_id = self._insert_observation(patient["id"], parsed, row, correction_of=root["id"])
            self._store(row, "correction", None, patient["id"], observation_id,
                        f"修订原导入值 {root['value_num']} {root['unit']}")
            self.outcome["imported"].append({"row_number": number, "observation_id": observation_id,
                                             "patient_id": patient["id"], "correction_of": root["id"]})
            self.outcome["counts"]["correction"] += 1
            self._change(number, "corrected", observation_id=observation_id)
            return
        if key in self._imported_keys():
            self._mark_duplicate(row, patient["id"], "now_duplicate" if prior else None)
            return
        observation_id = self._insert_observation(patient["id"], parsed, row, correction_of=None)
        self._store(row, "imported", None, patient["id"], observation_id, None)
        self.outcome["imported"].append({"row_number": number, "observation_id": observation_id,
                                         "patient_id": patient["id"]})
        self.outcome["counts"]["imported"] += 1
        if prior:
            self._change(number, "now_imported", observation_id=observation_id)
            if prior["status"] == "review":
                self._auto_resolve_prior_review(prior, f"修订后第 {number} 行已成功导入")

    def _mark_duplicate(self, row: dict[str, Any], patient_id: str, change_type: str | None) -> None:
        self._store(row, "duplicate", None, patient_id, None, "与既有导入记录内容相同")
        self.outcome["duplicates"].append({"row_number": row["row_number"], "reason": "duplicate_of_prior_import"})
        self.outcome["counts"]["duplicate"] += 1
        if change_type:
            self._change(row["row_number"], change_type)

    # ------------------------------------------------------------ 校验与落库

    def _validate(self, row: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None, str | None]:
        cells = row["cells"]
        if cells is None:
            return None, "malformed_row", ISSUE_MESSAGES["malformed_row"]
        if isinstance(cells, list):
            if len(cells) != len(CSV_HEADER):
                return None, "malformed_row", f"列数为 {len(cells)}，应为 {len(CSV_HEADER)}"
            cells = dict(zip(CSV_HEADER, cells))
        kind = _normalize_kind(cells.get("kind"))
        if kind is None:
            return None, "unknown_kind", f"测量项目 {cells.get('kind')!r} 无法识别"
        spec = KIND_UNITS[kind]
        unit = cells.get("unit")
        if not isinstance(unit, str) or unit.strip().lower() not in spec["aliases"]:
            return None, "unit_mismatch", f"单位 {unit!r} 与 {kind} 要求的 {spec['unit']} 不符"
        value = _decimal_in_range(cells.get("value"), spec["minimum"], spec["maximum"])
        if value is None:
            return None, "invalid_value", f"测量值 {cells.get('value')!r} 无效或超出 {spec['minimum']}~{spec['maximum']}"
        try:
            observed_at = timestamp(cells.get("measured_at"), "测量时间")
        except ValidationError:
            return None, "invalid_time", f"测量时间 {cells.get('measured_at')!r} 无法解析"
        if parsed_timestamp(observed_at) > parsed_timestamp(self.now) + FUTURE_TOLERANCE:
            return None, "invalid_time", "测量时间晚于当前时间，疑似设备本地时间未校准"
        ref = cells.get("patient_ref")
        ref_text = ref.strip() if isinstance(ref, str) else ""
        if not ref_text:
            return None, "unknown_patient", "患者编号为空"
        patient = self._patient_for(ref_text)
        if patient is None:
            return None, "unknown_patient", f"患者编号 {ref_text!r} 在诊所内不存在或不在诊"
        return {"patient": patient, "kind": kind, "unit": spec["unit"], "value": value,
                "observed_at": observed_at}, None, None

    def _patient_for(self, external_ref: str) -> dict[str, Any] | None:
        if external_ref not in self.patients:
            row = self.connection.execute(
                "SELECT id,state FROM patients WHERE clinic_id=? AND external_ref=?",
                (self.clinic_id, external_ref)).fetchone()
            self.patients[external_ref] = dict(row) if row and row["state"] == "active" else None
        return self.patients[external_ref]

    def _imported_keys(self) -> set[tuple]:
        if self.imported_keys is None:
            rows = self.connection.execute(
                "SELECT o.patient_id,o.kind,o.observed_at,o.value_num FROM observations o "
                "JOIN patients p ON p.id=o.patient_id WHERE p.clinic_id=? AND o.provenance='import'",
                (self.clinic_id,)).fetchall()
            self.imported_keys = {(row["patient_id"], row["kind"], row["observed_at"], float(row["value_num"]))
                                  for row in rows}
        return self.imported_keys

    def _insert_observation(self, patient_id: str, parsed: dict[str, Any], row: dict[str, Any], *,
                            correction_of: str | None) -> str:
        observation_id = new_id("obs")
        self.connection.execute(
            "INSERT INTO observations(id,patient_id,plan_id,kind,value_num,unit,observed_at,recorded_by,provenance,"
            "correction_of,import_batch_id,import_row_number,created_at) VALUES(?,?,NULL,?,?,?,?,?,'import',?,?,?,?)",
            (observation_id, patient_id, parsed["kind"], float(parsed["value"]), parsed["unit"],
             parsed["observed_at"], self.actor_id, correction_of, self.batch_id, row["row_number"], self.now))
        self._imported_keys().add((patient_id, parsed["kind"], parsed["observed_at"], float(parsed["value"])))
        return observation_id

    def _to_review(self, row: dict[str, Any], issue: str, detail: str | None,
                   parsed: dict[str, Any] | None) -> None:
        number = row["row_number"]
        patient_id = parsed["patient"]["id"] if parsed else None
        prior = self.prior_rows.get(number)
        if prior and prior["status"] == "review":
            pending = self.connection.execute(
                "SELECT id,issue_code FROM measurement_review_items WHERE row_id=? AND status='pending'",
                (prior["id"],)).fetchone()
            if pending and pending["issue_code"] == issue:
                # 同一问题仍未解决：沿用原待核对条目，不重复开立。
                stored = self._store(row, "review", issue, patient_id, None, detail)
                self.outcome["review_items"].append({"row_number": number, "issue_code": issue,
                                                     "review_item_id": pending["id"], "carried_forward": True})
                self.outcome["counts"]["review"] += 1
                self.outcome["relinked_reviews"].append((pending["id"], number))
                self._change(number, "still_unresolved", issue_code=issue)
                return
            if pending:
                self._auto_resolve_prior_review(prior, f"修订后第 {number} 行问题类型变化，已生成新核对条目")
        stored = self._store(row, "review", issue, patient_id, None, detail)
        item_id = new_id("imq")
        self.outcome["review_rows"].append({"id": item_id, "row_stored_id": stored, "row_number": number,
                                            "issue_code": issue, "raw_excerpt": _excerpt(row["raw"]),
                                            "detail": detail})
        self.outcome["review_items"].append({"row_number": number, "issue_code": issue, "review_item_id": item_id})
        self.outcome["counts"]["review"] += 1
        if prior:
            change_type = "still_unresolved" if prior["status"] == "review" else "now_unresolved"
            self._change(number, change_type, issue_code=issue,
                         prior_observation_id=prior["observation_id"] if prior["status"] in {"imported", "correction"} else None)

    def _auto_resolve_prior_review(self, prior: dict[str, Any], note: str) -> None:
        self.connection.execute(
            "UPDATE measurement_review_items SET status='resolved',resolution_note=?,resolved_by=?,resolved_at=? "
            "WHERE row_id=? AND status='pending'", (note, self.actor_id, self.now, prior["id"]))

    def _store(self, row: dict[str, Any], status: str, issue_code: str | None,
               patient_id: str | None, observation_id: str | None, detail: str | None) -> str:
        stored_id = new_id("imr")
        self.outcome["stored_rows"].append(
            {"id": stored_id, "row_number": row["row_number"], "row_hash": row["hash"],
             "raw_excerpt": _excerpt(row["raw"]), "status": status, "issue_code": issue_code,
             "patient_id": patient_id, "observation_id": observation_id, "detail": detail})
        self.stored_by_number[row["row_number"]] = stored_id
        return stored_id

    def _change(self, row_number: int, change_type: str, **extra: Any) -> None:
        self.outcome["changes"].append({"row_number": row_number, "type": change_type, **extra})
