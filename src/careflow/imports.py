"""合作秤测量文件的批次导入：批次可追溯、行级隔离、更正只追加不改写。"""

from __future__ import annotations

import csv
import hashlib
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from . import audit
from .db import Database
from .errors import Conflict, NotFound, ValidationError
from .ids import new_id, require_id
from .security import authorize, principal_for
from .validation import parsed_timestamp, text, timestamp

REQUIRED_COLUMNS = ("patient_ref", "measured_at", "value", "unit")
MAX_CONTENT_CHARS = 900_000
MAX_ROWS = 5000
RAW_LINE_LIMIT = 500
DIFF_PREVIEW_LIMIT = 200
FUTURE_TOLERANCE = timedelta(minutes=15)
WEIGHT_MIN = Decimal("1")
WEIGHT_MAX = Decimal("600")
VALUE_EPSILON = 1e-9


class MeasurementImportService:
    """每个文件批次保留来源、格式版本、原始行号及内容摘要。

    行级问题（无法识别的患者编号、设备本地时间异常、单位不符、数值越界）
    进入待核对清单，不让整批失败，也不把错误数字写成正式记录。
    """

    FORMAT_VERSIONS = {"scale-csv-v1"}

    def __init__(self, database: Database, clock):
        self.db = database
        self.clock = clock

    def submit(self, clinic_id: str, actor_id: str, source: str, format_version: str,
               content: str, *, supersedes_batch_id: str | None = None) -> dict[str, Any]:
        source = text(source, "数据来源", maximum=120)
        if format_version not in self.FORMAT_VERSIONS:
            raise ValidationError("不支持的格式版本", details={"supported": sorted(self.FORMAT_VERSIONS)})
        content = self._normalize_content(content)
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if supersedes_batch_id is not None:
            supersedes_batch_id = require_id(supersedes_batch_id, "被更正批次编号")
        now = timestamp(self.clock.now())
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:write", clinic_id=clinic_id)
            existing = connection.execute(
                "SELECT * FROM measurement_import_batches WHERE clinic_id=? AND content_sha256=?",
                (clinic_id, digest)).fetchone()
            if existing:
                if (existing["source"] != source or existing["format_version"] != format_version
                        or existing["supersedes_batch_id"] != supersedes_batch_id):
                    raise Conflict("相同内容的文件已按其他来源、格式或更正关系导入；请核对后重新提交")
                # 相同批次重传返回原处理结果，不重复写入观察记录。
                return self._batch_result(connection, existing, replayed=True)
            if supersedes_batch_id:
                superseded = connection.execute(
                    "SELECT * FROM measurement_import_batches WHERE id=? AND clinic_id=?",
                    (supersedes_batch_id, clinic_id)).fetchone()
                if superseded is None:
                    raise NotFound("被更正的导入批次不存在")
                if superseded["source"] != source or superseded["format_version"] != format_version:
                    raise ValidationError("更正批次必须与被更正批次保持相同来源和格式版本")
                successor = connection.execute(
                    "SELECT id FROM measurement_import_batches WHERE supersedes_batch_id=?",
                    (supersedes_batch_id,)).fetchone()
                if successor:
                    raise Conflict("该批次已有后续更正批次；请基于最新批次提交更正",
                                   details={"successor_batch_id": successor["id"]})
            records = self._parse(content)
            if len(records) > MAX_ROWS:
                raise ValidationError(f"单批数据行数不能超过 {MAX_ROWS}")
            previous_rows = {}
            if supersedes_batch_id:
                for row in connection.execute(
                        "SELECT * FROM measurement_import_rows WHERE batch_id=?",
                        (supersedes_batch_id,)).fetchall():
                    previous_rows[row["row_number"]] = row
            batch_id = new_id("imp")
            connection.execute(
                "INSERT INTO measurement_import_batches(id,clinic_id,source,format_version,content_sha256,"
                "supersedes_batch_id,row_count,imported_count,duplicate_count,quarantined_count,imported_by,created_at) "
                "VALUES(?,?,?,?,?,?,0,0,0,0,?,?)",
                (batch_id, clinic_id, source, format_version, digest, supersedes_batch_id, actor_id, now))
            patients: dict[str, Any] = {}
            counts = {"imported": 0, "duplicate": 0, "quarantined": 0}
            for record in records:
                result = self._process_row(connection, clinic_id, actor_id, batch_id, record,
                                           patients, previous_rows, now)
                counts[result["status"]] += 1
                connection.execute(
                    "INSERT INTO measurement_import_rows(id,batch_id,row_number,status,issue,detail,patient_ref,"
                    "measured_at,value_num,unit,raw_line,row_digest,observation_id,correction_of) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (new_id("imr"), batch_id, result["row_number"], result["status"], result["issue"],
                     result["detail"], result["patient_ref"], result["measured_at"], result["value"],
                     result["unit"], result["raw_line"], result["row_digest"],
                     result["observation_id"], result["correction_of"]))
            connection.execute(
                "UPDATE measurement_import_batches SET row_count=?,imported_count=?,duplicate_count=?,"
                "quarantined_count=? WHERE id=?",
                (len(records), counts["imported"], counts["duplicate"], counts["quarantined"], batch_id))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                               aggregate_type="measurement_import", aggregate_id=batch_id,
                               action="measurement_import.completed", occurred_at=now,
                               payload={"source": source, "format_version": format_version,
                                        "content_sha256": digest, "row_count": len(records),
                                        "imported": counts["imported"], "duplicates": counts["duplicate"],
                                        "quarantined": counts["quarantined"],
                                        "supersedes_batch_id": supersedes_batch_id})
            batch = connection.execute("SELECT * FROM measurement_import_batches WHERE id=?", (batch_id,)).fetchone()
            return self._batch_result(connection, batch, replayed=False)

    def get_batch(self, clinic_id: str, actor_id: str, batch_id: str) -> dict[str, Any]:
        batch_id = require_id(batch_id, "批次编号")
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            batch = connection.execute(
                "SELECT * FROM measurement_import_batches WHERE id=? AND clinic_id=?",
                (batch_id, clinic_id)).fetchone()
            if batch is None:
                raise NotFound("导入批次不存在")
            result = self._batch_result(connection, batch, replayed=False)
            rows = connection.execute(
                "SELECT * FROM measurement_import_rows WHERE batch_id=? ORDER BY row_number", (batch_id,)).fetchall()
            result["rows"] = [self._row_result(row) for row in rows]
            return result

    def review_queue(self, clinic_id: str, actor_id: str, *, limit: int = 200) -> dict[str, Any]:
        """待核对清单：无法识别或单位不符等未能写入正式记录的行。"""
        if not 1 <= limit <= 500:
            raise ValidationError("核对清单数量必须为 1 至 500")
        now = timestamp(self.clock.now())
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "clinical:read", clinic_id=clinic_id)
            rows = connection.execute(
                "SELECT r.*,b.source,b.format_version,b.created_at AS batch_created_at,"
                "(SELECT n.id FROM measurement_import_batches n WHERE n.supersedes_batch_id=b.id) AS superseded_by "
                "FROM measurement_import_rows r JOIN measurement_import_batches b ON b.id=r.batch_id "
                "WHERE b.clinic_id=? AND r.status='quarantined' "
                "ORDER BY b.created_at DESC,r.batch_id,r.row_number LIMIT ?", (clinic_id, limit)).fetchall()
            total = connection.execute(
                "SELECT COUNT(*) FROM measurement_import_rows r JOIN measurement_import_batches b ON b.id=r.batch_id "
                "WHERE b.clinic_id=? AND r.status='quarantined'", (clinic_id,)).fetchone()[0]
            items = []
            for row in rows:
                item = self._row_result(row)
                item.update({"batch_id": row["batch_id"], "source": row["source"],
                             "format_version": row["format_version"], "batch_created_at": row["batch_created_at"],
                             "superseded_by": row["superseded_by"]})
                items.append(item)
            return {"clinic_id": clinic_id, "as_of": now, "total_quarantined": total,
                    "returned": len(items), "items": items}

    @staticmethod
    def _normalize_content(content: Any) -> str:
        if not isinstance(content, str):
            raise ValidationError("文件内容必须是文本")
        # 统一 BOM 与换行符，使同一文件的不同保存形式得到相同内容摘要。
        normalized = content.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
        if not normalized.strip():
            raise ValidationError("文件内容不能为空")
        if len(normalized) > MAX_CONTENT_CHARS:
            raise ValidationError("文件内容超出大小限制")
        if "\x00" in normalized:
            raise ValidationError("文件内容包含无效字符")
        return normalized

    @staticmethod
    def _parse(content: str) -> list[tuple[int, str, dict[str, str] | None]]:
        """返回 (原始行号, 原始行内容, 字段字典)；列数不符的行字段为 None。"""
        lines = content.split("\n")
        reader = csv.reader(lines)
        header: list[str] | None = None
        consumed = 0
        records: list[tuple[int, str, dict[str, str] | None]] = []
        for record in reader:
            line_number = reader.line_num
            raw_line = "\n".join(lines[consumed:line_number])
            consumed = line_number
            cells = [cell.strip() for cell in record]
            if header is None:
                if not any(cells):
                    continue
                header = cells
                if sorted(header) != sorted(REQUIRED_COLUMNS):
                    raise ValidationError("表头与格式版本 scale-csv-v1 要求的列不符",
                                          details={"required": list(REQUIRED_COLUMNS)})
                continue
            if not any(cells):
                continue
            if len(cells) != len(header):
                records.append((line_number, raw_line, None))
                continue
            records.append((line_number, raw_line, dict(zip(header, cells))))
        if header is None:
            raise ValidationError("文件缺少表头")
        return records

    def _process_row(self, connection, clinic_id: str, actor_id: str, batch_id: str,
                     record: tuple[int, str, dict[str, str] | None], patients: dict[str, Any],
                     previous_rows: dict[int, Any], now: str) -> dict[str, Any]:
        line_number, raw_line, fields = record
        result: dict[str, Any] = {
            "row_number": line_number, "status": "quarantined", "issue": None, "detail": None,
            "patient_ref": None, "measured_at": None, "value": None, "unit": None,
            "raw_line": raw_line[:RAW_LINE_LIMIT],
            "row_digest": hashlib.sha256(raw_line.encode("utf-8")).hexdigest(),
            "observation_id": None, "correction_of": None}

        def quarantine(issue: str, detail: str) -> dict[str, Any]:
            result["issue"] = issue
            result["detail"] = detail
            return result

        if fields is None:
            return quarantine("unparseable_row", "列数与表头不符")
        patient_ref = fields["patient_ref"]
        measured_raw = fields["measured_at"]
        value_raw = fields["value"]
        unit_raw = fields["unit"]
        result["patient_ref"] = patient_ref or None
        result["unit"] = unit_raw or None
        if not patient_ref or not measured_raw or not value_raw or not unit_raw:
            return quarantine("unparseable_row", "必填字段存在空白")
        try:
            measured_at = timestamp(measured_raw, "测量时间")
        except ValidationError:
            return quarantine("bad_timestamp", "测量时间不是带时区的 ISO 8601 格式")
        result["measured_at"] = measured_at
        if parsed_timestamp(measured_at) > parsed_timestamp(now) + FUTURE_TOLERANCE:
            return quarantine("future_timestamp", "测量时间晚于接收时间，疑似设备时钟错误")
        try:
            number = Decimal(value_raw)
        except InvalidOperation:
            number = None
        if number is None or not number.is_finite():
            return quarantine("bad_value", "测量值不是有效数字")
        result["value"] = float(number)
        if number < WEIGHT_MIN or number > WEIGHT_MAX:
            return quarantine("value_out_of_range", "测量值超出 1 至 600 kg 的合理范围")
        if unit_raw.lower() != "kg":
            return quarantine("unit_mismatch", f"仅接受 kg 单位，收到 '{unit_raw}'")
        patient = self._patient(patients, connection, clinic_id, patient_ref)
        if patient is None:
            return quarantine("unknown_patient", "患者编号在诊所内不存在")
        if patient["state"] != "active":
            return quarantine("patient_inactive", "患者已合并或关闭，不能写入新测量")
        value = result["value"]
        previous = previous_rows.get(line_number)
        if previous is not None and previous["status"] == "imported" and previous["observation_id"]:
            original = connection.execute("SELECT * FROM observations WHERE id=?",
                                          (previous["observation_id"],)).fetchone()
            if original is not None:
                if original["patient_id"] != patient["id"]:
                    return quarantine("patient_changed", "更正行与被更正批次同号行的患者不一致，需人工核对")
                if original["observed_at"] == measured_at and abs(original["value_num"] - value) < VALUE_EPSILON:
                    result["status"] = "duplicate"
                    result["observation_id"] = original["id"]
                    return result
                already = connection.execute("SELECT 1 FROM observations WHERE correction_of=?",
                                             (original["id"],)).fetchone()
                if original["correction_of"] is not None or already:
                    return quarantine("already_corrected", "原记录已存在更正，需人工核对后处理")
                # 导入值发现错误时追加更正，不改写旧值。
                result["correction_of"] = original["id"]
                result["observation_id"] = self._record(connection, clinic_id, actor_id, patient["id"],
                                                        value, measured_at, now, batch_id, line_number,
                                                        correction_of=original["id"])
                result["status"] = "imported"
                return result
        existing = connection.execute(
            "SELECT * FROM observations WHERE patient_id=? AND kind='weight_kg' AND observed_at=?",
            (patient["id"], measured_at)).fetchone()
        if existing is not None:
            if abs(existing["value_num"] - value) < VALUE_EPSILON:
                result["status"] = "duplicate"
                result["observation_id"] = existing["id"]
            else:
                result["issue"] = "conflicting_value"
                result["detail"] = "同一患者同一观察时间已存在不同数值的正式记录"
            return result
        result["observation_id"] = self._record(connection, clinic_id, actor_id, patient["id"],
                                                value, measured_at, now, batch_id, line_number,
                                                correction_of=None)
        result["status"] = "imported"
        return result

    def _record(self, connection, clinic_id: str, actor_id: str, patient_id: str, value: float,
                measured_at: str, now: str, batch_id: str, line_number: int,
                *, correction_of: str | None) -> str:
        observation_id = new_id("obs")
        connection.execute(
            "INSERT INTO observations(id,patient_id,plan_id,kind,value_num,unit,observed_at,recorded_by,"
            "provenance,correction_of,created_at) VALUES(?,?,NULL,'weight_kg',?,'kg',?,?,'import',?,?)",
            (observation_id, patient_id, value, measured_at, actor_id, correction_of, now))
        audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=patient_id,
                           aggregate_type="observation", aggregate_id=observation_id,
                           action="observation.recorded", occurred_at=now,
                           payload={"kind": "weight_kg", "value": value, "unit": "kg",
                                    "correction_of": correction_of,
                                    "import_batch_id": batch_id, "import_row_number": line_number})
        return observation_id

    @staticmethod
    def _patient(cache: dict[str, Any], connection, clinic_id: str, external_ref: str):
        if external_ref not in cache:
            cache[external_ref] = connection.execute(
                "SELECT id,state,external_ref FROM patients WHERE clinic_id=? AND external_ref=?",
                (clinic_id, external_ref)).fetchone()
        return cache[external_ref]

    def _batch_result(self, connection, batch, *, replayed: bool) -> dict[str, Any]:
        result = {"batch_id": batch["id"], "source": batch["source"],
                  "format_version": batch["format_version"], "content_sha256": batch["content_sha256"],
                  "supersedes_batch_id": batch["supersedes_batch_id"], "row_count": batch["row_count"],
                  "imported": batch["imported_count"], "duplicates": batch["duplicate_count"],
                  "quarantined": batch["quarantined_count"], "imported_by": batch["imported_by"],
                  "created_at": batch["created_at"], "replayed": replayed, "changes": None}
        if batch["supersedes_batch_id"]:
            result["changes"] = self._diff(connection, batch["supersedes_batch_id"], batch["id"])
        return result

    def _diff(self, connection, old_batch_id: str, new_batch_id: str) -> dict[str, Any]:
        """更正提交必须明确哪些行改变：按原始行号对照前后两批的规范化内容。"""
        old_rows = {row["row_number"]: row for row in connection.execute(
            "SELECT * FROM measurement_import_rows WHERE batch_id=?", (old_batch_id,)).fetchall()}
        new_rows = {row["row_number"]: row for row in connection.execute(
            "SELECT * FROM measurement_import_rows WHERE batch_id=?", (new_batch_id,)).fetchall()}
        added = sorted(set(new_rows) - set(old_rows))
        removed = sorted(set(old_rows) - set(new_rows))
        changed = []
        unchanged = 0
        for number in sorted(set(old_rows) & set(new_rows)):
            before, after = old_rows[number], new_rows[number]
            if self._comparable(before) == self._comparable(after):
                unchanged += 1
            else:
                changed.append({"row_number": number, "before": self._row_summary(before),
                                "after": self._row_summary(after)})
        truncated = (len(added) > DIFF_PREVIEW_LIMIT or len(removed) > DIFF_PREVIEW_LIMIT
                     or len(changed) > DIFF_PREVIEW_LIMIT)
        return {"basis_batch_id": old_batch_id, "added_count": len(added), "removed_count": len(removed),
                "changed_count": len(changed), "unchanged_count": unchanged,
                "added_rows": added[:DIFF_PREVIEW_LIMIT], "removed_rows": removed[:DIFF_PREVIEW_LIMIT],
                "changed_rows": changed[:DIFF_PREVIEW_LIMIT], "truncated": truncated}

    @staticmethod
    def _comparable(row) -> tuple:
        fields = (row["patient_ref"], row["measured_at"], row["value_num"], row["unit"])
        if any(field is not None for field in fields):
            return ("parsed",) + fields
        return ("raw", row["raw_line"])

    @staticmethod
    def _row_summary(row) -> dict[str, Any]:
        return {"row_number": row["row_number"], "status": row["status"], "issue": row["issue"],
                "patient_ref": row["patient_ref"], "measured_at": row["measured_at"],
                "value": row["value_num"], "unit": row["unit"]}

    @staticmethod
    def _row_result(row) -> dict[str, Any]:
        return {"row_number": row["row_number"], "status": row["status"], "issue": row["issue"],
                "detail": row["detail"], "patient_ref": row["patient_ref"], "measured_at": row["measured_at"],
                "value": row["value_num"], "unit": row["unit"], "observation_id": row["observation_id"],
                "correction_of": row["correction_of"], "row_digest": row["row_digest"],
                "raw_line": row["raw_line"]}
