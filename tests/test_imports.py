from __future__ import annotations

import json
import tempfile
import threading
import unittest
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from careflow.api import create_handler
from careflow.clock import FrozenClock
from careflow.db import Database
from careflow.errors import Conflict, Forbidden, ValidationError
from careflow.service import Careflow

HEADER = "patient_ref,measured_at,kind,value,unit"


class ImportCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp.name) / "clinic.sqlite3")
        self.clock = FrozenClock(datetime(2026, 9, 27, 12, 0, tzinfo=UTC))
        self.app = Careflow(self.db, self.clock)
        initial = self.app.initialize_clinic("澄序门诊", "Asia/Shanghai", "诊所负责人", "LongPassphrase!2026")
        self.clinic = initial["clinic_id"]
        self.owner = initial["owner_id"]
        self.clinician = self.app.create_staff(self.clinic, "临床医生", "clinician", actor_id=self.owner)["id"]
        self.nurse = self.app.create_staff(self.clinic, "护理人员", "nurse", actor_id=self.owner)["id"]
        self.coordinator = self.app.create_staff(self.clinic, "运营协调员", "coordinator", actor_id=self.owner)["id"]
        self.patient = self.app.create_patient(self.clinic, self.coordinator, "case-017", "林女士")

    def tearDown(self):
        self.temp.cleanup()

    def import_csv(self, lines, key="scale-week-39", actor=None, source="合作秤-A 门诊外测量"):
        content = "\n".join([HEADER, *lines])
        return self.app.imports.import_batch(
            self.clinic, actor or self.nurse, key, source, "scale_csv_v1", content)

    def test_valid_rows_become_observations_and_problem_rows_go_to_review(self):
        result = self.import_csv([
            "case-017,2026-09-20T08:00:00+08:00,weight,73.2,kg",
            "case-017,2026-09-22T08:00:00+08:00,weight,72.8,公斤",
            "case-017,2026-09-24T08:00:00+08:00,weight,160,lb",
            "case-999,2026-09-24T08:00:00+08:00,weight,70,kg",
            "case-017,2026-09-25T08:00:00+08:00,bmi,22.1,score",
            "bad,row",
            "case-017,2026-09-26T08:00:00+08:00,waist,82,cm",
            "case-017,2030-01-01T00:00:00+08:00,weight,71,kg",
        ])
        # 整批成功，三行写入正式记录，五行进入待核对，没有错误数字落库。
        self.assertEqual(result["counts"]["imported"], 3)
        self.assertEqual(result["counts"]["review"], 5)
        self.assertEqual(result["revision"], 1)
        issues = {item["issue_code"] for item in result["review_items"]}
        self.assertEqual(issues, {"unit_mismatch", "unknown_patient", "unknown_kind",
                                  "malformed_row", "invalid_time"})
        weights = self.app.observation_series(self.clinic, self.nurse, self.patient["id"], "weight_kg")
        self.assertEqual([row["value"] for row in weights], [73.2, 72.8])
        self.assertTrue(all(row["provenance"] == "import" for row in weights))
        # 待核对清单持久化且可按状态查询。
        pending = self.app.imports.list_review_items(self.clinic, self.nurse)
        self.assertEqual(len(pending), 5)
        self.assertTrue(all(item["status"] == "pending" for item in pending))
        unit_issue = next(item for item in pending if item["issue_code"] == "unit_mismatch")
        self.assertIn("160", unit_issue["raw_excerpt"])
        self.assertEqual(unit_issue["detail"], "单位 'lb' 与 weight_kg 要求的 kg 不符")
        # 导入与核对事件进入审计哈希链，链保持完整。
        self.assertTrue(self.app.verify_audit(self.clinic, self.owner)["ok"])

    def test_batch_preserves_source_format_version_line_numbers_and_excerpts(self):
        result = self.import_csv(["case-017,2026-09-20T08:00:00+08:00,weight,73.2,kg"])
        detail = self.app.imports.get_batch(self.clinic, self.nurse, result["batch_id"])
        batch = detail["batch"]
        self.assertEqual(batch["source"], "合作秤-A 门诊外测量")
        self.assertEqual(batch["format_version"], "scale_csv_v1")
        self.assertEqual(batch["row_count"], 1)
        self.assertEqual(batch["imported_count"], 1)
        self.assertIsInstance(batch["content_hash"], str)
        row = detail["rows"][0]
        self.assertEqual(row["row_number"], 2)  # 含表头，原始行号从 2 开始
        self.assertEqual(row["status"], "imported")
        self.assertIn("73.2", row["raw_excerpt"])
        # 观察记录可沿批次与行号找回文件对应行。
        obs_id = result["imported"][0]["observation_id"]
        series = self.app.observation_series(self.clinic, self.nurse, self.patient["id"], "weight_kg")
        origin = next(row["origin"] for row in series if row["id"] == obs_id)
        self.assertEqual(origin["batch_id"], result["batch_id"])
        self.assertEqual(origin["row_number"], 2)

    def test_same_batch_reupload_returns_original_result_without_duplicates(self):
        first = self.import_csv(["case-017,2026-09-20T08:00:00+08:00,weight,73.2,kg"])
        replay = self.import_csv(["case-017,2026-09-20T08:00:00+08:00,weight,73.2,kg"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["batch_id"], first["batch_id"])
        self.assertEqual(replay["imported"], first["imported"])
        weights = self.app.observation_series(self.clinic, self.nurse, self.patient["id"], "weight_kg")
        self.assertEqual(len(weights), 1)

    def test_duplicate_lines_in_file_and_cross_batch_are_not_recorded_twice(self):
        result = self.import_csv([
            "case-017,2026-09-20T08:00:00+08:00,weight,73.2,kg",
            "case-017,2026-09-20T08:00:00+08:00,weight,73.20,kg",  # 文件内重复
        ])
        self.assertEqual(result["counts"]["imported"], 1)
        self.assertEqual(result["counts"]["duplicate"], 1)
        again = self.app.imports.import_batch(
            self.clinic, self.nurse, "scale-week-40", "合作秤-A", "scale_csv_v1",
            "\n".join([HEADER, "case-017,2026-09-20T08:00:00+08:00,weight,73.2,kg"]))
        self.assertEqual(again["counts"]["duplicate"], 1)
        self.assertEqual(again["counts"]["imported"], 0)
        weights = self.app.observation_series(self.clinic, self.nurse, self.patient["id"], "weight_kg")
        self.assertEqual(len(weights), 1)

    def test_revision_appends_correction_and_reports_changed_rows(self):
        first = self.import_csv([
            "case-017,2026-09-20T08:00:00+08:00,weight,73.2,kg",
            "case-017,2026-09-22T08:00:00+08:00,weight,72.8,kg",
        ])
        original_id = first["imported"][1]["observation_id"]  # 第 3 行（72.8）将被修订
        # 修正第二行数值：同批次键、不同内容 → 新修订；第一行不变，第二行追加更正。
        revised = self.import_csv([
            "case-017,2026-09-20T08:00:00+08:00,weight,73.2,kg",
            "case-017,2026-09-22T08:00:00+08:00,weight,72.1,kg",
        ])
        self.assertEqual(revised["revision"], 2)
        self.assertEqual(revised["counts"]["correction"], 1)
        change_types = {c["row_number"]: c["type"] for c in revised["changes"]}
        self.assertEqual(change_types, {2: "unchanged", 3: "corrected"})
        correction_id = revised["imported"][1]["observation_id"]
        self.assertNotEqual(correction_id, original_id)
        # 旧值保持不变，新值是追加的更正记录。
        weights = self.app.observation_series(self.clinic, self.nurse, self.patient["id"], "weight_kg")
        by_id = {row["id"]: row for row in weights}
        self.assertEqual(by_id[original_id]["value"], 72.8)
        self.assertEqual(by_id[correction_id]["value"], 72.1)
        self.assertEqual(by_id[correction_id]["correction_of"], original_id)
        # 趋势只展示更正后的有效值。
        series = self.app.reports.weight_series(self.clinic, self.nurse, self.patient["id"])
        self.assertEqual([row["weight_kg"] for row in series["observations"]], [73.2, 72.1])

    def test_revision_fixed_problem_row_imports_and_closes_prior_review_item(self):
        first = self.import_csv(["case-017,2026-09-24T08:00:00+08:00,weight,160,lb"])
        review_id = first["review_items"][0]["review_item_id"]
        revised = self.import_csv(["case-017,2026-09-24T08:00:00+08:00,weight,72.5,kg"])
        self.assertEqual(revised["counts"]["imported"], 1)
        change = revised["changes"][0]
        self.assertEqual(change["type"], "now_imported")
        items = self.app.imports.list_review_items(self.clinic, self.nurse, status="all")
        prior = next(item for item in items if item["id"] == review_id)
        self.assertEqual(prior["status"], "resolved")

    def test_revision_with_identity_change_goes_to_review_without_touching_record(self):
        first = self.import_csv(["case-017,2026-09-20T08:00:00+08:00,weight,73.2,kg"])
        original_id = first["imported"][0]["observation_id"]
        other = self.app.create_patient(self.clinic, self.coordinator, "case-018", "秦女士")
        revised = self.import_csv(["case-018,2026-09-20T08:00:00+08:00,weight,73.2,kg"])
        self.assertEqual(revised["counts"]["review"], 1)
        self.assertEqual(revised["review_items"][0]["issue_code"], "identity_changed")
        # 原观察记录不被改写、不产生更正。
        weights = self.app.observation_series(self.clinic, self.nurse, self.patient["id"], "weight_kg")
        self.assertEqual([(row["id"], row["value"]) for row in weights], [(original_id, 73.2)])
        self.assertEqual(
            self.app.observation_series(self.clinic, self.nurse, other["id"], "weight_kg"), [])

    def test_unchanged_problem_row_keeps_single_review_item_across_revisions(self):
        self.import_csv(["case-017,2026-09-24T08:00:00+08:00,weight,160,lb"])
        # 修订文件新增一行，问题行内容保持不变。
        revised = self.import_csv([
            "case-017,2026-09-24T08:00:00+08:00,weight,160,lb",
            "case-017,2026-09-25T08:00:00+08:00,weight,72.4,kg",
        ])
        self.assertEqual(revised["revision"], 2)
        pending = self.app.imports.list_review_items(self.clinic, self.nurse)
        self.assertEqual(len(pending), 1)
        change_types = {c["row_number"]: c["type"] for c in revised["changes"]}
        self.assertEqual(change_types[2], "unchanged")  # 内容未变，沿用原处理结果
        self.assertTrue(revised["review_items"][0]["carried_forward"])
        # 待核对条目已指向最新批次的行。
        detail = self.app.imports.get_batch(self.clinic, self.nurse, revised["batch_id"])
        self.assertEqual(pending[0]["batch_id"], revised["batch_id"])
        self.assertEqual(detail["rows"][0]["status"], "review")

    def test_manual_correction_is_append_only(self):
        first = self.import_csv(["case-017,2026-09-20T08:00:00+08:00,weight,73.2,kg"])
        original_id = first["imported"][0]["observation_id"]
        correction = self.app.imports.correct_observation(
            self.clinic, self.clinician, original_id, 71.9, "设备复核后确认读数偏高")
        self.assertEqual(correction["correction_of"], original_id)
        self.assertEqual(correction["import_batch_id"], first["batch_id"])
        self.assertEqual(correction["import_row_number"], 2)
        with self.assertRaises(Conflict):
            self.app.imports.correct_observation(self.clinic, self.clinician, original_id, 71.0, "再次修订")
        weights = self.app.observation_series(self.clinic, self.nurse, self.patient["id"], "weight_kg")
        by_id = {row["id"]: row for row in weights}
        self.assertEqual(by_id[original_id]["value"], 73.2)  # 旧值仍在
        self.assertEqual(by_id[correction["id"]]["correction_of"], original_id)

    def test_review_item_can_be_resolved_with_note(self):
        result = self.import_csv(["case-017,2026-09-24T08:00:00+08:00,weight,160,lb"])
        item_id = result["review_items"][0]["review_item_id"]
        resolved = self.app.imports.resolve_review_item(
            self.clinic, self.nurse, item_id, "dismiss", "单位为磅的手工记录，已在纸质表中核对并作废")
        self.assertEqual(resolved["status"], "dismissed")
        with self.assertRaises(Conflict):
            self.app.imports.resolve_review_item(self.clinic, self.nurse, item_id, "dismiss", "重复处置")

    def test_trend_distinguishes_patient_clinician_and_device_sources(self):
        self.import_csv(["case-017,2026-09-20T08:00:00+08:00,weight,73.2,kg"])
        self.app.record_observation(self.clinic, self.clinician, self.patient["id"], "weight_kg", 72.5,
                                    "2026-09-22T08:00:00+08:00", provenance="clinician")
        self.app.record_observation(self.clinic, self.nurse, self.patient["id"], "weight_kg", 72.0,
                                    "2026-09-24T08:00:00+08:00", provenance="patient")
        series = self.app.reports.weight_series(self.clinic, self.clinician, self.patient["id"])
        provenance = [row["provenance"] for row in series["observations"]]
        self.assertEqual(provenance, ["import", "clinician", "patient"])
        self.assertEqual(series["count_by_source"], {"patient": 1, "clinician": 1, "device_import": 1})
        device_row = series["observations"][0]
        self.assertIsNotNone(device_row["origin"])
        self.assertIsNone(series["observations"][1]["origin"])

    def test_import_requires_clinical_write_permission(self):
        with self.assertRaises(Forbidden):
            self.import_csv(["case-017,2026-09-20T08:00:00+08:00,weight,73.2,kg"], actor=self.coordinator)

    def test_bad_header_and_unsupported_format_reject_whole_submission(self):
        with self.assertRaises(ValidationError):
            self.app.imports.import_batch(
                self.clinic, self.nurse, "bad-1", "合作秤-A", "scale_csv_v1",
                "patient,time,weight\ncase-017,2026-09-20T08:00:00+08:00,73.2")
        with self.assertRaises(ValidationError):
            self.app.imports.import_batch(
                self.clinic, self.nurse, "bad-2", "合作秤-A", "xls_v9",
                "\n".join([HEADER, "case-017,2026-09-20T08:00:00+08:00,weight,73.2,kg"]))

    def test_json_format_version_imports_with_same_row_level_rules(self):
        payload = {"rows": [
            {"patient_ref": "case-017", "measured_at": "2026-09-20T08:00:00+08:00", "kind": "体重",
             "value": "73.2", "unit": "kg"},
            {"patient_ref": "case-017", "measured_at": "2026-09-21T08:00:00+08:00", "kind": "weight",
             "value": "72.9", "unit": "lbs"},
        ]}
        result = self.app.imports.import_batch(
            self.clinic, self.nurse, "json-1", "合作秤-B", "weight_json_v1", json.dumps(payload))
        self.assertEqual(result["counts"]["imported"], 1)
        self.assertEqual(result["review_items"][0]["issue_code"], "unit_mismatch")
        self.assertEqual(result["review_items"][0]["row_number"], 2)  # JSON 行号从 1 开始

    def test_http_import_batch_review_list_and_weight_series_traceability(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(self.app))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            login = Request(base + "/auth/token", data=json.dumps(
                {"staff_id": self.owner, "password": "LongPassphrase!2026"}).encode(), method="POST",
                headers={"X-Clinic-ID": self.clinic, "Content-Type": "application/json"})
            with urlopen(login, timeout=3) as response:
                token = json.loads(response.read())["access_token"]
            headers = {"X-Clinic-ID": self.clinic, "Authorization": f"Bearer {token}",
                       "Content-Type": "application/json"}
            content = "\n".join([HEADER, "case-017,2026-09-20T08:00:00+08:00,weight,73.2,kg",
                                 "case-017,2026-09-22T08:00:00+08:00,weight,160,lb"])
            request = Request(base + "/imports/measurements", data=json.dumps(
                {"batch_key": "http-batch-1", "source": "合作秤-A", "format_version": "scale_csv_v1",
                 "content": content}).encode(), method="POST", headers=headers)
            with urlopen(request, timeout=3) as response:
                result = json.loads(response.read())
                self.assertEqual(response.status, 201)
            self.assertEqual(result["counts"]["imported"], 1)
            self.assertEqual(result["counts"]["review"], 1)
            with urlopen(Request(base + "/imports/review-items", headers=headers), timeout=3) as response:
                review = json.loads(response.read())
            self.assertEqual(len(review["items"]), 1)
            with urlopen(Request(
                    base + f"/patients/{self.patient['id']}/weight-series", headers=headers), timeout=3) as response:
                series = json.loads(response.read())
            self.assertEqual(series["count_by_source"]["device_import"], 1)
            self.assertEqual(series["observations"][0]["origin"]["batch_id"], result["batch_id"])
            self.assertEqual(series["observations"][0]["origin"]["row_number"], 2)
            with urlopen(Request(base + f"/imports/measurements/{result['batch_id']}", headers=headers),
                         timeout=3) as response:
                detail = json.loads(response.read())
            self.assertEqual(detail["rows"][0]["raw_excerpt"],
                             "case-017,2026-09-20T08:00:00+08:00,weight,73.2,kg")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
