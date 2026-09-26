"""仅使用标准库的 JSON HTTP 入口。"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from .db import Database
from .errors import CareflowError, ValidationError
from .service import Careflow

MAX_BODY_BYTES = 1_000_000


def create_handler(app: Careflow):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Careflow/1"
        protocol_version = "HTTP/1.1"

        def log_message(self, format, *args):
            # 不记录 URL、查询参数、患者编号或请求内容。
            return

        def send_json(self, status: int, data: object) -> None:
            body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def body(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ValidationError("Content-Length 无效") from exc
            if length < 0 or length > MAX_BODY_BYTES:
                raise ValidationError("请求内容超出大小限制")
            if length == 0:
                return {}
            if self.headers.get_content_type() != "application/json":
                raise ValidationError("请求必须使用 application/json")
            raw = self.rfile.read(length)
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValidationError("请求内容不是有效 JSON") from exc
            if not isinstance(value, dict):
                raise ValidationError("请求 JSON 顶层必须为对象")
            return value

        def clinic(self) -> str:
            value = self.headers.get("X-Clinic-ID", "")
            if not value:
                raise ValidationError("缺少 X-Clinic-ID")
            return value

        def actor(self, clinic_id: str) -> tuple[str, str]:
            header = self.headers.get("Authorization", "")
            prefix, separator, token = header.partition(" ")
            if not separator or prefix.lower() != "bearer" or not token:
                from .errors import Unauthorized
                raise Unauthorized("需要 Bearer 访问凭据")
            return app.staff_for_token(clinic_id, token), token

        def dispatch(self):
            try:
                result, status = self.route()
                self.send_json(status, result)
            except CareflowError as exc:
                self.send_json(exc.status, {"error": {"code": exc.code, "message": exc.message, "details": exc.details}})
            except BrokenPipeError:
                return
            except Exception:
                # 未知异常不向外暴露 SQL、路径、患者资料或内部栈。
                self.send_json(500, {"error": {"code": "internal_error", "message": "服务暂时无法处理请求"}})

        def do_GET(self):
            self.dispatch()

        def do_POST(self):
            self.dispatch()

        def do_PATCH(self):
            self.dispatch()

        def route(self):
            path = urlsplit(self.path)
            segments = [unquote(part) for part in path.path.strip("/").split("/") if part]
            if self.command == "GET" and segments == ["health"]:
                return {"service": "careflow", **app.db.health()}, 200
            if self.command == "POST" and segments == ["auth", "token"]:
                data = self.body()
                return app.login(self.clinic(), data.get("staff_id", ""), data.get("password", "")), 201
            clinic_id = self.clinic()
            actor_id, token = self.actor(clinic_id)
            if self.command == "POST" and segments == ["auth", "logout"]:
                return app.logout(clinic_id, actor_id, token), 200
            if self.command == "GET" and segments == ["clinic", "summary"]:
                return app.clinic_summary(clinic_id, actor_id), 200
            if self.command == "GET" and segments == ["reports", "daily"]:
                params = parse_qs(path.query)
                return app.reports.daily_operations(clinic_id, actor_id, params.get("date", [None])[0]), 200
            if self.command == "GET" and segments == ["reports", "appointments"]:
                params = parse_qs(path.query)
                return app.reports.appointment_outcomes(clinic_id, actor_id,
                                                        params.get("start", [""])[0], params.get("end", [""])[0]), 200
            if self.command == "GET" and segments == ["reports", "incidents"]:
                params = parse_qs(path.query)
                return app.reports.incident_summary(clinic_id, actor_id,
                                                    params.get("start", [""])[0], params.get("end", [""])[0]), 200
            if self.command == "POST" and segments == ["patients"]:
                data = self.body()
                return app.create_patient(clinic_id, actor_id, data.get("external_ref", ""), data.get("name", ""),
                                          birth_date=data.get("birth_date"), phone_ciphertext=data.get("phone_ciphertext")), 201
            if len(segments) == 2 and segments[0] == "patients" and self.command == "GET":
                return app.get_patient(clinic_id, actor_id, segments[1]), 200
            if len(segments) == 3 and segments[0] == "patients" and segments[2] == "merge" and self.command == "POST":
                data = self.body()
                return app.merge_patients(clinic_id, actor_id, segments[1], data.get("target_id", ""),
                                          expected_source=data.get("expected_source", 0),
                                          expected_target=data.get("expected_target", 0),
                                          reason=data.get("reason", "")), 200
            if len(segments) == 3 and segments[0] == "patients" and segments[2] == "consents" and self.command == "POST":
                data = self.body()
                return app.grant_consent(clinic_id, actor_id, segments[1], data.get("purpose", ""),
                                         data.get("revision", 0), data.get("text_digest", ""),
                                         expires_at=data.get("expires_at")), 201
            if len(segments) == 4 and segments[0] == "consents" and segments[2] == "withdraw" and self.command == "POST":
                return app.withdraw_consent(clinic_id, actor_id, segments[1], self.body().get("reason", "")), 200
            if len(segments) == 3 and segments[0] == "patients" and segments[2] == "assessments" and self.command == "POST":
                data = self.body()
                return app.create_assessment(clinic_id, actor_id, segments[1], data.get("kind", ""),
                                             data.get("measurements", {}), data.get("answers", {}),
                                             source=data.get("source", "clinician")), 201
            if len(segments) == 3 and segments[0] == "assessments" and segments[2] == "sign" and self.command == "POST":
                data = self.body()
                return app.sign_assessment(clinic_id, actor_id, segments[1], expected_version=data.get("expected_version", 0)), 200
            if len(segments) == 3 and segments[0] == "patients" and segments[2] == "plans" and self.command == "POST":
                data = self.body()
                return app.create_plan(clinic_id, actor_id, segments[1], data.get("kind", ""),
                                       data.get("clinical_owner", actor_id), data.get("goal", {}), data.get("risk", {}),
                                       data.get("start_date", ""), target_date=data.get("target_date"),
                                       assessment_id=data.get("assessment_id"), consent_id=data.get("consent_id")), 201
            if len(segments) == 3 and segments[0] == "plans" and segments[2] in {"propose", "activate", "pause", "resume", "complete", "cancel"} and self.command == "POST":
                data = self.body()
                return app.transition_plan(clinic_id, actor_id, segments[1], data.get("expected_version", 0),
                                           segments[2], reason=data.get("reason")), 200
            if len(segments) == 3 and segments[0] == "plans" and segments[2] == "milestones" and self.command == "POST":
                data = self.body()
                return app.milestones.create(clinic_id, actor_id, segments[1], data.get("kind", ""),
                                             data.get("title", ""), data.get("due_at", ""),
                                             self.headers.get("Idempotency-Key", ""),
                                             assigned_to=data.get("assigned_to")), 201
            if len(segments) == 2 and segments[0] == "plans" and self.command == "GET":
                return {"items": app.milestones.list_for_plan(clinic_id, actor_id, segments[1])}, 200
            if len(segments) == 3 and segments[0] == "milestones" and segments[2] in {"complete", "defer", "waive", "cancel"} and self.command == "POST":
                data = self.body()
                return app.milestones.transition(clinic_id, actor_id, segments[1], data.get("expected_version", 0),
                                                 segments[2], reason=data.get("reason", ""),
                                                 new_due_at=data.get("new_due_at")), 200
            if len(segments) == 3 and segments[0] == "milestones" and segments[2] == "history" and self.command == "GET":
                return {"events": app.milestones.history(clinic_id, actor_id, segments[1])}, 200
            if self.command == "GET" and segments == ["reports", "overdue-milestones"]:
                params = parse_qs(path.query)
                return app.milestones.overdue(clinic_id, actor_id, limit=int(params.get("limit", [200])[0])), 200
            if self.command == "POST" and segments == ["appointments"]:
                data = self.body()
                key = self.headers.get("Idempotency-Key", "")
                return app.create_appointment(clinic_id, actor_id, data.get("patient_id", ""), data.get("kind", ""),
                                              data.get("starts_at", ""), data.get("ends_at", ""), key,
                                              staff_id=data.get("staff_id"), plan_id=data.get("plan_id")), 201
            if len(segments) == 3 and segments[0] == "appointments" and self.command == "POST":
                data = self.body()
                return app.transition_appointment(clinic_id, actor_id, segments[1], data.get("expected_version", 0),
                                                  segments[2], reason=data.get("reason")), 200
            if self.command == "POST" and segments == ["followups"]:
                data = self.body()
                return app.schedule_followup(clinic_id, actor_id, data.get("patient_id", ""), data.get("due_at", ""),
                                            data.get("reason", ""), self.headers.get("Idempotency-Key", ""),
                                            plan_id=data.get("plan_id"), channel=data.get("channel", "phone"),
                                            assigned_to=data.get("assigned_to")), 201
            if self.command == "POST" and segments == ["followups", "claim"]:
                data = self.body()
                return {"items": app.claim_followups(clinic_id, actor_id, limit=data.get("limit", 20),
                                                       lease_minutes=data.get("lease_minutes", 5))}, 200
            if len(segments) == 3 and segments[0] == "followups" and segments[2] == "complete" and self.command == "POST":
                data = self.body()
                return app.complete_followup(clinic_id, actor_id, segments[1], data.get("claim_token", ""),
                                             data.get("outcome", ""), data.get("expected_version", 0)), 200
            if len(segments) == 3 and segments[0] == "patients" and segments[2] == "incidents" and self.command == "POST":
                data = self.body()
                return app.report_incident(clinic_id, actor_id, segments[1], data.get("category", ""),
                                           data.get("severity", ""), data.get("onset_at", ""),
                                           data.get("summary", ""), self.headers.get("Idempotency-Key", ""),
                                           plan_id=data.get("plan_id"), encounter_id=data.get("encounter_id")), 201
            if self.command == "POST" and len(segments) == 3 and segments[0] == "patients" and segments[2] == "clinical-flags":
                data = self.body()
                return app.clinical_flags.report(clinic_id, actor_id, segments[1], data.get("category", ""),
                                                 data.get("severity", ""), data.get("detail", ""),
                                                 effective_from=data.get("effective_from"),
                                                 effective_until=data.get("effective_until")), 201
            if self.command == "GET" and len(segments) == 3 and segments[0] == "patients" and segments[2] == "clinical-flags":
                params = parse_qs(path.query)
                return {"items": app.clinical_flags.list_for_patient(clinic_id, actor_id, segments[1],
                                                                       include_resolved=params.get("include_resolved", ["false"])[0].lower() == "true")}, 200
            if self.command == "POST" and len(segments) == 3 and segments[0] == "clinical-flags" and segments[2] in {"confirm", "resolve"}:
                data = self.body()
                return app.clinical_flags.review(clinic_id, actor_id, segments[1], data.get("expected_version", 0),
                                                 segments[2], data.get("note", "")), 200
            if len(segments) == 3 and segments[0] == "incidents" and self.command == "POST":
                data = self.body()
                return app.transition_incident(clinic_id, actor_id, segments[1], segments[2], data.get("note", ""),
                                               data.get("expected_version", 0), assign_to=data.get("assign_to")), 200
            if len(segments) == 3 and segments[0] == "patients" and segments[2] == "timeline" and self.command == "GET":
                params = parse_qs(path.query)
                return app.patient_timeline(clinic_id, actor_id, segments[1], limit=int(params.get("limit", [100])[0])), 200
            if len(segments) == 3 and segments[0] == "patients" and segments[2] == "weight-series" and self.command == "GET":
                params = parse_qs(path.query)
                return app.reports.weight_series(clinic_id, actor_id, segments[1],
                                                 start=params.get("start", [None])[0], end=params.get("end", [None])[0]), 200
            if len(segments) == 3 and segments[0] == "patients" and segments[2] == "plan-history" and self.command == "GET":
                return app.reports.plan_history(clinic_id, actor_id, segments[1]), 200
            if len(segments) == 3 and segments[0] == "patients" and segments[2] == "export" and self.command == "POST":
                data = self.body()
                return app.exports.export(clinic_id, actor_id, segments[1], data.get("sections", []),
                                          data.get("reason", ""), self.headers.get("Idempotency-Key", "")), 200
            if self.command == "GET" and segments == ["audit", "verify"]:
                return app.verify_audit(clinic_id, actor_id), 200
            if self.command == "GET" and segments == ["audit", "diagnostics"]:
                return app.run_diagnostics(clinic_id, actor_id), 200
            if self.command == "POST" and segments == ["products"]:
                data = self.body()
                return app.supplies.register_product(clinic_id, actor_id, data.get("name", ""),
                                                      data.get("category", ""), data.get("stock_unit", ""),
                                                      requires_lot=data.get("requires_lot", True),
                                                      requires_clinician=data.get("requires_clinician", False)), 201
            if self.command == "POST" and len(segments) == 3 and segments[0] == "products" and segments[2] == "lots":
                data = self.body()
                return app.supplies.receive_lot(clinic_id, actor_id, segments[1], data.get("supplier_ref", ""),
                                                data.get("lot_number", ""), data.get("quantity", 0),
                                                self.headers.get("Idempotency-Key", ""), expires_on=data.get("expires_on")), 201
            if self.command == "GET" and segments == ["stock", "lots"]:
                params = parse_qs(path.query)
                return {"items": app.supplies.lot_balances(clinic_id, params.get("product_id", [None])[0])}, 200
            if self.command == "POST" and segments == ["stock", "reserve"]:
                data = self.body()
                return app.supplies.reserve(clinic_id, actor_id, data.get("appointment_id", ""),
                                            data.get("product_id", ""), data.get("quantity", 0),
                                            self.headers.get("Idempotency-Key", "")), 201
            if self.command == "POST" and len(segments) == 3 and segments[0] == "stock" and segments[2] in {"consume", "release"}:
                data = self.body()
                if segments[2] == "consume":
                    return app.supplies.consume_reservation(clinic_id, actor_id, segments[1],
                                                            expected_version=data.get("expected_version", 0),
                                                            witnessed_by=data.get("witnessed_by")), 200
                return app.supplies.release_reservation(clinic_id, actor_id, segments[1], data.get("reason", ""),
                                                        data.get("expected_version", 0)), 200
            if self.command == "POST" and len(segments) == 3 and segments[0] == "stock" and segments[2] in {"quarantine", "recall", "release-quarantine"}:
                data = self.body()
                action = segments[2].replace("-", "_")
                return app.supplies.change_lot_state(clinic_id, actor_id, segments[1], action,
                                                     data.get("reason", "")), 200
            if self.command == "GET" and len(segments) == 3 and segments[0] == "stock" and segments[2] == "history":
                return app.supplies.lot_history(clinic_id, actor_id, segments[1]), 200
            if self.command == "GET" and len(segments) == 3 and segments[0] == "appointments" and segments[2] == "encounter":
                return app.encounter_for_appointment(clinic_id, actor_id, segments[1]), 200
            if self.command == "POST" and len(segments) == 3 and segments[0] == "encounters" and segments[2] == "notes":
                data = self.body()
                return app.add_encounter_note(clinic_id, actor_id, segments[1], data.get("section", ""),
                                              data.get("body", ""), expected_version=data.get("expected_version", 0),
                                              amendment_reason=data.get("amendment_reason")), 201
            if self.command == "POST" and len(segments) == 3 and segments[0] == "encounters" and segments[2] == "sign":
                data = self.body()
                return app.sign_encounter(clinic_id, actor_id, segments[1], data.get("expected_version", 0)), 200
            if self.command == "GET" and len(segments) == 2 and segments[0] == "encounters":
                return app.encounter_notes(clinic_id, actor_id, segments[1]), 200
            if self.command == "POST" and len(segments) == 3 and segments[0] == "encounters" and segments[2] == "void":
                data = self.body()
                return app.void_encounter(clinic_id, actor_id, segments[1], data.get("expected_version", 0),
                                          data.get("reason", "")), 200
            return {"error": {"code": "not_found", "message": "接口不存在"}}, 404

    return Handler


def serve(database: str, host: str = "127.0.0.1", port: int = 8080) -> None:
    app = Careflow(Database(database))
    server = ThreadingHTTPServer((host, port), create_handler(app))
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="启动澄序诊所运营服务")
    parser.add_argument("--database", default="careflow.sqlite3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("端口范围无效")
    serve(args.database, args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
