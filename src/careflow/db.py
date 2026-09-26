"""SQLite 会话、事务及领域表结构。"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .errors import StorageFailure

SCHEMA_VERSION = 1

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS clinics (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    timezone TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active','paused')),
    created_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS staff (
    id TEXT PRIMARY KEY,
    clinic_id TEXT NOT NULL REFERENCES clinics(id),
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('owner','clinician','nurse','coordinator','auditor')),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    created_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS staff_clinic_role ON staff(clinic_id, role, active);
CREATE TABLE IF NOT EXISTS staff_credentials (
    staff_id TEXT PRIMARY KEY REFERENCES staff(id),
    salt BLOB NOT NULL,
    password_hash BLOB NOT NULL,
    changed_at TEXT NOT NULL,
    credential_version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS access_sessions (
    token_hash BLOB PRIMARY KEY,
    staff_id TEXT NOT NULL REFERENCES staff(id),
    clinic_id TEXT NOT NULL REFERENCES clinics(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS sessions_staff_expiry ON access_sessions(staff_id,expires_at,revoked_at);
CREATE TABLE IF NOT EXISTS patients (
    id TEXT PRIMARY KEY,
    clinic_id TEXT NOT NULL REFERENCES clinics(id),
    external_ref TEXT NOT NULL,
    display_name TEXT NOT NULL,
    birth_date TEXT,
    phone_ciphertext TEXT,
    state TEXT NOT NULL CHECK(state IN ('active','merged','closed')),
    merged_into TEXT REFERENCES patients(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(clinic_id, external_ref)
);
CREATE INDEX IF NOT EXISTS patients_clinic_state ON patients(clinic_id,state,created_at);
CREATE TABLE IF NOT EXISTS consents (
    id TEXT PRIMARY KEY,
    patient_id TEXT NOT NULL REFERENCES patients(id),
    purpose TEXT NOT NULL,
    revision INTEGER NOT NULL,
    text_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('granted','withdrawn','expired')),
    effective_at TEXT NOT NULL,
    expires_at TEXT,
    recorded_by TEXT NOT NULL REFERENCES staff(id),
    supersedes TEXT REFERENCES consents(id),
    created_at TEXT NOT NULL,
    UNIQUE(patient_id,purpose,revision)
);
CREATE INDEX IF NOT EXISTS consents_patient_purpose ON consents(patient_id,purpose,revision DESC);
CREATE TABLE IF NOT EXISTS assessments (
    id TEXT PRIMARY KEY,
    patient_id TEXT NOT NULL REFERENCES patients(id),
    clinic_id TEXT NOT NULL REFERENCES clinics(id),
    kind TEXT NOT NULL CHECK(kind IN ('aesthetic','weight','wellbeing','screening')),
    captured_at TEXT NOT NULL,
    captured_by TEXT NOT NULL REFERENCES staff(id),
    measurements_json TEXT NOT NULL,
    answers_json TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('patient','clinician','device_import')),
    status TEXT NOT NULL CHECK(status IN ('draft','signed','superseded')),
    signed_at TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    supersedes TEXT REFERENCES assessments(id),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS assessments_patient_time ON assessments(patient_id,captured_at DESC);
CREATE TABLE IF NOT EXISTS plans (
    id TEXT PRIMARY KEY,
    patient_id TEXT NOT NULL REFERENCES patients(id),
    clinic_id TEXT NOT NULL REFERENCES clinics(id),
    kind TEXT NOT NULL CHECK(kind IN ('aesthetic','weight','wellbeing')),
    state TEXT NOT NULL CHECK(state IN ('draft','proposed','active','paused','completed','cancelled')),
    created_by TEXT NOT NULL REFERENCES staff(id),
    clinical_owner TEXT NOT NULL REFERENCES staff(id),
    assessment_id TEXT REFERENCES assessments(id),
    consent_id TEXT REFERENCES consents(id),
    goal_json TEXT NOT NULL,
    risk_json TEXT NOT NULL,
    start_date TEXT NOT NULL,
    target_date TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS plans_patient_state ON plans(patient_id,state,updated_at DESC);
CREATE TABLE IF NOT EXISTS plan_milestones (
    id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES plans(id),
    kind TEXT NOT NULL CHECK(kind IN ('review','measurement','followup','preparation','recovery_check','other')),
    title TEXT NOT NULL,
    due_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','completed','deferred','waived','cancelled')),
    assigned_to TEXT REFERENCES staff(id),
    idempotency_key TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL REFERENCES staff(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS milestones_due ON plan_milestones(state,due_at,plan_id);
CREATE TABLE IF NOT EXISTS milestone_events (
    id TEXT PRIMARY KEY,
    milestone_id TEXT NOT NULL REFERENCES plan_milestones(id),
    sequence INTEGER NOT NULL,
    action TEXT NOT NULL,
    actor_id TEXT NOT NULL REFERENCES staff(id),
    reason TEXT NOT NULL,
    prior_due_at TEXT,
    next_due_at TEXT,
    occurred_at TEXT NOT NULL,
    UNIQUE(milestone_id,sequence)
);
CREATE TABLE IF NOT EXISTS plan_revisions (
    plan_id TEXT NOT NULL REFERENCES plans(id),
    revision INTEGER NOT NULL,
    snapshot_json TEXT NOT NULL,
    changed_by TEXT NOT NULL REFERENCES staff(id),
    change_reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(plan_id,revision)
);
CREATE TABLE IF NOT EXISTS appointments (
    id TEXT PRIMARY KEY,
    clinic_id TEXT NOT NULL REFERENCES clinics(id),
    patient_id TEXT NOT NULL REFERENCES patients(id),
    plan_id TEXT REFERENCES plans(id),
    staff_id TEXT REFERENCES staff(id),
    kind TEXT NOT NULL,
    starts_at TEXT NOT NULL,
    ends_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('held','booked','arrived','in_service','completed','cancelled','no_show')),
    hold_expires_at TEXT,
    idempotency_key TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES staff(id),
    created_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(clinic_id,idempotency_key)
);
CREATE INDEX IF NOT EXISTS appointments_schedule ON appointments(clinic_id,starts_at,ends_at,state);
CREATE INDEX IF NOT EXISTS appointments_patient ON appointments(patient_id,starts_at DESC);
CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    clinic_id TEXT NOT NULL REFERENCES clinics(id),
    name TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN ('consumable','implant','topical','injectable','device_accessory','other')),
    stock_unit TEXT NOT NULL,
    requires_lot INTEGER NOT NULL CHECK(requires_lot IN (0,1)),
    requires_clinician INTEGER NOT NULL CHECK(requires_clinician IN (0,1)),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    created_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(clinic_id,name)
);
CREATE TABLE IF NOT EXISTS product_lots (
    id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES products(id),
    supplier_ref TEXT NOT NULL,
    lot_number TEXT NOT NULL,
    expires_on TEXT,
    received_at TEXT NOT NULL,
    received_by TEXT NOT NULL REFERENCES staff(id),
    state TEXT NOT NULL CHECK(state IN ('available','quarantined','recalled','expired','depleted')),
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(product_id,supplier_ref,lot_number)
);
CREATE TABLE IF NOT EXISTS stock_movements (
    id TEXT PRIMARY KEY,
    lot_id TEXT NOT NULL REFERENCES product_lots(id),
    event_type TEXT NOT NULL CHECK(event_type IN ('received','reserved','released','consumed','adjusted','quarantined','recalled')),
    quantity_delta REAL NOT NULL,
    appointment_id TEXT REFERENCES appointments(id),
    patient_id TEXT REFERENCES patients(id),
    actor_id TEXT REFERENCES staff(id),
    reason TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    UNIQUE(lot_id,idempotency_key),
    UNIQUE(lot_id,sequence)
);
CREATE TABLE IF NOT EXISTS stock_reservations (
    id TEXT PRIMARY KEY,
    lot_id TEXT NOT NULL REFERENCES product_lots(id),
    appointment_id TEXT NOT NULL REFERENCES appointments(id),
    patient_id TEXT NOT NULL REFERENCES patients(id),
    quantity REAL NOT NULL CHECK(quantity>0),
    state TEXT NOT NULL CHECK(state IN ('reserved','released','consumed')),
    idempotency_key TEXT NOT NULL UNIQUE,
    reserved_by TEXT NOT NULL REFERENCES staff(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS stock_lot_state ON stock_reservations(lot_id,state);
CREATE INDEX IF NOT EXISTS stock_appointment ON stock_reservations(appointment_id,state);
CREATE TABLE IF NOT EXISTS stock_reservation_batches (
    idempotency_key TEXT PRIMARY KEY,
    request_hash TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES staff(id)
);
CREATE TABLE IF NOT EXISTS lot_alerts (
    id TEXT PRIMARY KEY,
    lot_id TEXT NOT NULL REFERENCES product_lots(id),
    alert_type TEXT NOT NULL CHECK(alert_type IN ('quarantine','recall','release_quarantine')),
    reason TEXT NOT NULL,
    actor_id TEXT NOT NULL REFERENCES staff(id),
    created_at TEXT NOT NULL,
    supersedes TEXT REFERENCES lot_alerts(id),
    UNIQUE(lot_id,id)
);
CREATE INDEX IF NOT EXISTS lot_alerts_recent ON lot_alerts(lot_id,created_at DESC);
CREATE TABLE IF NOT EXISTS encounters (
    id TEXT PRIMARY KEY,
    appointment_id TEXT NOT NULL UNIQUE REFERENCES appointments(id),
    patient_id TEXT NOT NULL REFERENCES patients(id),
    clinic_id TEXT NOT NULL REFERENCES clinics(id),
    state TEXT NOT NULL CHECK(state IN ('open','signed','amended','void')),
    opened_by TEXT NOT NULL REFERENCES staff(id),
    opened_at TEXT NOT NULL,
    signed_by TEXT REFERENCES staff(id),
    signed_at TEXT,
    version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS encounter_notes (
    id TEXT PRIMARY KEY,
    encounter_id TEXT NOT NULL REFERENCES encounters(id),
    section TEXT NOT NULL,
    body TEXT NOT NULL,
    author_id TEXT NOT NULL REFERENCES staff(id),
    revision INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    supersedes TEXT REFERENCES encounter_notes(id),
    UNIQUE(encounter_id,section,revision)
);
CREATE TABLE IF NOT EXISTS followups (
    id TEXT PRIMARY KEY,
    patient_id TEXT NOT NULL REFERENCES patients(id),
    plan_id TEXT REFERENCES plans(id),
    encounter_id TEXT REFERENCES encounters(id),
    due_at TEXT NOT NULL,
    channel TEXT NOT NULL CHECK(channel IN ('phone','message','in_person')),
    reason TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','claimed','done','deferred','cancelled')),
    assigned_to TEXT REFERENCES staff(id),
    claim_token TEXT,
    claim_until TEXT,
    outcome TEXT,
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS followups_due ON followups(state,due_at);
CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    patient_id TEXT NOT NULL REFERENCES patients(id),
    plan_id TEXT REFERENCES plans(id),
    kind TEXT NOT NULL CHECK(kind IN ('weight_kg','waist_cm','symptom_score','satisfaction','blood_pressure')),
    value_num REAL,
    value_text TEXT,
    unit TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    recorded_by TEXT NOT NULL REFERENCES staff(id),
    provenance TEXT NOT NULL CHECK(provenance IN ('patient','clinician','import')),
    correction_of TEXT REFERENCES observations(id),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS observations_patient_kind_time ON observations(patient_id,kind,observed_at);
CREATE TABLE IF NOT EXISTS clinical_flags (
    id TEXT PRIMARY KEY,
    patient_id TEXT NOT NULL REFERENCES patients(id),
    category TEXT NOT NULL CHECK(category IN ('allergy','prior_reaction','contraindication','implant','psychological_concern','other')),
    severity TEXT NOT NULL CHECK(severity IN ('information','caution','stop')),
    detail TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('reported','confirmed','resolved')),
    effective_from TEXT NOT NULL,
    effective_until TEXT,
    reported_by TEXT NOT NULL REFERENCES staff(id),
    reviewed_by TEXT REFERENCES staff(id),
    reviewed_at TEXT,
    resolution_reason TEXT,
    created_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS clinical_flags_patient_state ON clinical_flags(patient_id,state,severity,effective_from);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    patient_id TEXT NOT NULL REFERENCES patients(id),
    plan_id TEXT REFERENCES plans(id),
    encounter_id TEXT REFERENCES encounters(id),
    severity TEXT NOT NULL CHECK(severity IN ('low','moderate','high','urgent')),
    state TEXT NOT NULL CHECK(state IN ('reported','triaged','monitoring','resolved','closed')),
    category TEXT NOT NULL,
    onset_at TEXT NOT NULL,
    reported_at TEXT NOT NULL,
    reported_by TEXT NOT NULL REFERENCES staff(id),
    assigned_to TEXT REFERENCES staff(id),
    summary TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS incidents_patient ON incidents(patient_id,reported_at DESC);
CREATE TABLE IF NOT EXISTS incident_events (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL REFERENCES staff(id),
    note TEXT NOT NULL,
    created_at TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    UNIQUE(incident_id,sequence)
);
CREATE TABLE IF NOT EXISTS idempotency (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(scope,key)
);
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    clinic_id TEXT NOT NULL REFERENCES clinics(id),
    actor_id TEXT REFERENCES staff(id),
    patient_id TEXT REFERENCES patients(id),
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    action TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_digest TEXT NOT NULL,
    digest TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_patient_sequence ON audit_events(patient_id,sequence);
CREATE INDEX IF NOT EXISTS audit_aggregate ON audit_events(aggregate_type,aggregate_id,sequence);
"""


class Database:
    """每次事务使用独立连接，进程内写锁配合 SQLite 事务保证原子更新。"""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._write_lock = threading.RLock()
        self._memory_uri = self.path == ":memory:"
        if self._memory_uri:
            self.path = f"file:careflow-{id(self)}?mode=memory&cache=shared"
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, uri=self._memory_uri, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def initialize(self) -> None:
        if not self._memory_uri:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        try:
            with self.session() as connection:
                connection.executescript(SCHEMA)
                connection.execute(
                    "INSERT INTO schema_meta(key,value) VALUES('schema_version',?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (str(SCHEMA_VERSION),),
                )
        except sqlite3.Error as exc:
            raise StorageFailure("数据库初始化失败", details={"reason": type(exc).__name__}) from exc

    @contextmanager
    def transaction(self, *, write: bool = True) -> Iterator[sqlite3.Connection]:
        lock = self._write_lock if write else _NullLock()
        with lock:
            connection = self.connect()
            try:
                connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    @contextmanager
    def session(self) -> Iterator[sqlite3.Connection]:
        """创建生命周期明确的只读或初始化连接。"""
        connection = self.connect()
        try:
            yield connection
        finally:
            connection.close()

    def health(self) -> dict[str, object]:
        try:
            with self.session() as connection:
                row = connection.execute("PRAGMA quick_check").fetchone()
                version = connection.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
                return {"ok": bool(row and row[0] == "ok"), "schema_version": int(version[0]) if version else None}
        except sqlite3.Error:
            return {"ok": False, "schema_version": None}


class _NullLock:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def encode_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def decode_json(value: str) -> object:
    return json.loads(value)
