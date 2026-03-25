from flask import Blueprint, request
from app import db
from app.utils import (ok, err, meta, require_bearer,
                        validate_access_record, serialise_access_record_summary,
                        VALID_STATES, VALID_BASES, REVOKE_REASONS)
from app.routes.admin import _serialise_record
from app.webhooks import deliver_event

bp = Blueprint("data_users", __name__)


def _audit(token_payload, event_type, detail):
    try:
        db.write_audit(token_payload.get("sub", "unknown"), event_type, detail)
    except Exception:
        pass


@bp.route("/v1/records", methods=["GET"])
@require_bearer("data_user", "admin")
def list_own_records(token_payload):
    """List all access records belonging to the authenticated Data User."""
    state = request.args.get("state")
    basis = request.args.get("legal-basis")
    limit = min(int(request.args.get("limit", 200)), 500)

    if state and state not in VALID_STATES:
        return err(f"state must be one of {sorted(VALID_STATES)}", 400, "VAL002")
    if basis and basis not in VALID_BASES:
        return err("legal-basis invalid", 400, "VAL003")

    docs = db.list_records_for_duid(token_payload["duid"], state, basis, limit)
    return ok({
        "response": meta("/v1/records"),
        "records":  [_serialise_record(d) for d in docs],
        "total":    len(docs),
    })


@bp.route("/v1/access-records", methods=["POST"])
@require_bearer("data_user")
def create_access_record(token_payload):
    body   = request.get_json(silent=True) or {}
    reid_token = body.pop("reidentification-token", None)

    # Cross-DUID: if a reidentification-token is supplied, validate it and
    # resolve the ir internally. identity-record-ref is not required in this case.
    if reid_token:
        ir, error = db.validate_reidentification_token(reid_token, token_payload["duid"])
        if error == "NOT_FOUND":
            return err("reidentification-token not found", 404, "NOT001")
        if error == "FORBIDDEN":
            return err("reidentification-token was not initiated by this Data User", 403, "AUTH003")
        if error == "NOT_CONFIRMED":
            return err("reidentification-token has not been confirmed by the customer yet", 422, "VAL002")
        if error == "ALREADY_USED":
            return err("reidentification-token has already been used", 409, "CON001")
        if error == "EXPIRED":
            return err("reidentification-token has expired (valid for 1 hour)", 422, "VAL002")
        if error:
            return err(f"reidentification-token invalid: {error}", 400, "VAL001")
        # Inject the resolved ir into the payload
        body.setdefault("record-metadata", {})["identity-record-ref"] = ir

    errors = validate_access_record(body)
    if errors:
        return err("; ".join(errors), 400, "VAL001")

    doc    = db.create_access_record(token_payload["duid"], body)
    ak     = doc["ak"]
    expiry = body.get("access-event", {}).get("expiry")
    _audit(token_payload, "record.created", {"ak": ak, "mpxn": doc.get("mpxn"),
                                              "cross_duid": bool(reid_token)})

    resp = ok({
        "response":     meta(f"/v1/access-records/{ak}"),
        "access-token": {"key": ak, "expiry": expiry},
    }, 201)
    resp[0].headers["Location"] = f"/v1/access-records/{ak}"
    return resp


@bp.route("/v1/access-records/<ak>", methods=["PUT"])
@require_bearer("data_user")
def replace_access_record(ak, token_payload):
    body   = request.get_json(silent=True) or {}
    errors = validate_access_record(body)
    if errors:
        return err("; ".join(errors), 400, "VAL001")

    doc, error_code = db.replace_access_record(ak, token_payload["duid"], body)
    if error_code == "NOT_FOUND":
        return err("Access record not found or access denied", 404, "NOT001")
    if error_code == "CONFLICT":
        return err("Record is not ACTIVE and cannot be replaced", 409, "CON001")

    expiry = body.get("access-event", {}).get("expiry")
    _audit(token_payload, "record.updated", {"ak": ak, "mpxn": doc.get("mpxn")})
    return ok({
        "response":     meta(f"/v1/access-records/{ak}"),
        "access-token": {"key": ak, "expiry": expiry},
    })


@bp.route("/v1/access-records/<ak>", methods=["DELETE"])
@require_bearer("data_user")
def revoke_access(ak, token_payload):
    reason = request.args.get("reason")
    if reason and reason not in REVOKE_REASONS:
        return err(f"reason must be one of {sorted(REVOKE_REASONS)}", 400, "VAL001")

    doc = db.revoke_access_record(ak, token_payload["duid"])
    if doc is None:
        return err("Access record not found, already revoked, or access denied",
                   404, "NOT001")

    revoked_at = doc["revoked_at"]
    _audit(token_payload, "record.revoked",
           {"ak": ak, "mpxn": doc.get("mpxn"), "reason": reason})

    # Build spec-compliant webhook payload envelope
    p             = doc.get("payload", {})
    ctrl_ref      = p.get("access-event", {}).get("controller-reference")
    deliver_event(token_payload["duid"], "consent.withdrawal", {
        "ak":                   ak,
        "mpxn":                 doc.get("mpxn"),
        "revoked-at":           revoked_at,
        "controller-reference": ctrl_ref,
    })

    return ok({
        "response":   meta(f"/v1/access-records/{ak}"),
        "ak":         ak,
        "revoked-at": revoked_at,
    })


@bp.route("/v1/meter-points/<mpxn>/access-records", methods=["GET"])
@require_bearer("data_user")
def list_access_records(mpxn, token_payload):
    state = request.args.get("state")
    basis = request.args.get("legal-basis")

    if state and state not in (VALID_STATES | {"DISCOVERED"}):
        return err(f"state must be one of {sorted(VALID_STATES)}", 400, "VAL002")
    if basis and basis not in VALID_BASES:
        return err("legal-basis invalid", 400, "VAL003")

    docs = db.list_records_for_mpxn(mpxn, token_payload["duid"], state, basis)
    return ok({
        "response":       meta(f"/v1/meter-points/{mpxn}/access-records"),
        "mpxn":           mpxn,
        "access-records": [serialise_access_record_summary(d) for d in docs],
    })
