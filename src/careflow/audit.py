"""以哈希链记录业务事件，供诊所内审与异常追溯。"""

from __future__ import annotations

import hashlib
from typing import Any

from .db import encode_json
from .ids import new_id

GENESIS = "0" * 64


def append_event(
    connection,
    *,
    clinic_id: str,
    actor_id: str | None,
    patient_id: str | None,
    aggregate_type: str,
    aggregate_id: str,
    action: str,
    occurred_at: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    previous = connection.execute(
        "SELECT digest FROM audit_events WHERE clinic_id=? ORDER BY sequence DESC LIMIT 1", (clinic_id,)
    ).fetchone()
    previous_digest = previous[0] if previous else GENESIS
    body = {
        "clinic_id": clinic_id,
        "actor_id": actor_id,
        "patient_id": patient_id,
        "aggregate_type": aggregate_type,
        "aggregate_id": aggregate_id,
        "action": action,
        "occurred_at": occurred_at,
        "payload": payload,
        "previous_digest": previous_digest,
    }
    digest = hashlib.sha256(encode_json(body).encode("utf-8")).hexdigest()
    event_id = new_id("evt")
    connection.execute(
        "INSERT INTO audit_events(id,clinic_id,actor_id,patient_id,aggregate_type,aggregate_id,action,occurred_at,payload_json,previous_digest,digest) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (event_id, clinic_id, actor_id, patient_id, aggregate_type, aggregate_id, action, occurred_at,
         encode_json(payload), previous_digest, digest),
    )
    return {**body, "id": event_id, "digest": digest}


def verify_chain(connection, clinic_id: str) -> dict[str, Any]:
    rows = connection.execute(
        "SELECT * FROM audit_events WHERE clinic_id=? ORDER BY sequence", (clinic_id,)
    ).fetchall()
    previous = GENESIS
    for row in rows:
        payload = {
            "clinic_id": row["clinic_id"],
            "actor_id": row["actor_id"],
            "patient_id": row["patient_id"],
            "aggregate_type": row["aggregate_type"],
            "aggregate_id": row["aggregate_id"],
            "action": row["action"],
            "occurred_at": row["occurred_at"],
            "payload": __import__("json").loads(row["payload_json"]),
            "previous_digest": previous,
        }
        expected = hashlib.sha256(encode_json(payload).encode("utf-8")).hexdigest()
        if row["previous_digest"] != previous or row["digest"] != expected:
            return {"ok": False, "sequence": row["sequence"], "events_checked": row["sequence"] - 1}
        previous = row["digest"]
    return {"ok": True, "events_checked": len(rows), "head": previous}


def list_events(connection, clinic_id: str, *, patient_id: str | None = None, after: int = 0, limit: int = 100):
    limit = max(1, min(limit, 500))
    if patient_id:
        rows = connection.execute(
            "SELECT * FROM audit_events WHERE clinic_id=? AND patient_id=? AND sequence>? ORDER BY sequence LIMIT ?",
            (clinic_id, patient_id, after, limit),
        ).fetchall()
    else:
        rows = connection.execute(
            "SELECT * FROM audit_events WHERE clinic_id=? AND sequence>? ORDER BY sequence LIMIT ?",
            (clinic_id, after, limit),
        ).fetchall()
    return [
        {"sequence": row["sequence"], "id": row["id"], "actor_id": row["actor_id"], "patient_id": row["patient_id"],
         "aggregate_type": row["aggregate_type"], "aggregate_id": row["aggregate_id"], "action": row["action"],
         "occurred_at": row["occurred_at"], "payload": __import__("json").loads(row["payload_json"]), "digest": row["digest"]}
        for row in rows
    ]
