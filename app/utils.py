import re
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import request, jsonify
from app.auth import decode_token

# ── constants ─────────────────────────────────────────────────────────────────

MPXN_RE  = re.compile(r"^(?:[0-9A-HJ-NPR-Z]{2}[0-9]{8,10}|[0-9]{6,13})$")
AK_RE    = re.compile(r"^ak_[0-9a-f]{24}$")
IR_RE    = re.compile(r"^ir_[0-9a-f]{24}$")
URI_RE   = re.compile(r"^https?://")
DATE_RE  = re.compile(r"^\d{4}-\d{2}-\d{2}$")

CONSENT_BASES = {"uk-consent", "uk-explicit-consent"}
VALID_BASES   = {
    "uk-consent", "uk-explicit-consent",
    "uk-legitimate-interests", "uk-public-task",
    "uk-legal-obligation", "uk-contract",
}
VALID_STATES     = {"ACTIVE", "EXPIRED", "REVOKED"}
VALID_DATA_TYPES = {
    "HH-CONSUMPTION", "HH-EXPORT", "MTH-CONSUMPTION", "MTH-EXPORT",
    "ANNUAL-CONSUMPTION", "ANNUAL-EXPORT", "TARIFF-IMPORT", "TARIFF-EXPORT",
}
VALID_ARRANGEMENT_TYPES = {"sole", "joint", "group"}
VALID_CONTROLLER_ROLES  = {"sole", "lead", "joint", "member"}
REVOKE_REASONS = {
    "customer-request", "contract-ended", "lia-lapsed",
    "statutory-authority-lapsed", "data-no-longer-required", "other",
}

# ── response helpers ──────────────────────────────────────────────────────────

def _tid() -> str:
    return f"tid_{secrets.token_hex(12)}"

def meta(resource: str) -> dict:
    return {
        "resource":       resource,
        "timestamp":      datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "transaction-id": _tid(),
    }

def ok(body: dict, status: int = 200):
    return jsonify(body), status

def err(message: str, status: int, code: str = "ERR000") -> tuple:
    return jsonify({
        "response": meta(""),
        "errors":   [{"error-code": code, "message": message}],
    }), status

# ── auth decorator ────────────────────────────────────────────────────────────

def require_bearer(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return err("Missing or invalid Authorization header", 401, "AUTH001")
            token = auth[7:]
            payload = decode_token(token)
            if payload is None:
                return err("Token invalid or expired", 401, "AUTH002")
            if roles and payload.get("role") not in roles:
                return err("Insufficient permissions for this role", 403, "AUTH003")
            return fn(*args, token_payload=payload, **kwargs)
        return wrapper
    return decorator

# ── validators ────────────────────────────────────────────────────────────────

def validate_identity_record(body: dict) -> list[str]:
    errors = []
    pii = body.get("pii-principal", {})
    if not pii:
        errors.append("pii-principal required")
    else:
        if not pii.get("mpxn"):
            errors.append("pii-principal.mpxn required")
        elif not MPXN_RE.match(str(pii["mpxn"])):
            errors.append("pii-principal.mpxn invalid format")
        if not pii.get("move-in-date"):
            errors.append("pii-principal.move-in-date required")
        elif not DATE_RE.match(str(pii["move-in-date"])):
            errors.append("pii-principal.move-in-date must be YYYY-MM-DD")
    if not body.get("expressed-by"):
        errors.append("expressed-by required")
    elif body["expressed-by"] not in ("data-subject", "authorised-representative"):
        errors.append("expressed-by must be data-subject or authorised-representative")
    return errors

def validate_access_record(body: dict) -> list[str]:
    errors = []

    # top-level required
    for key in ("record-metadata", "processing", "access-event"):
        if key not in body:
            errors.append(f"'{key}' is required")
    if errors:
        return errors

    rm   = body.get("record-metadata", {})
    proc = body.get("processing", {})
    ae   = body.get("access-event", {})
    notice = body.get("notice")  # may be None for non-consent

    # record-metadata
    if not rm.get("schema-version"):
        errors.append("record-metadata.schema-version required")

    ir_ref = rm.get("identity-record-ref", "")
    if not ir_ref:
        errors.append("record-metadata.identity-record-ref required")
    elif not IR_RE.match(str(ir_ref)):
        errors.append("record-metadata.identity-record-ref must match ir_<24hex>")

    arr = rm.get("controller-arrangement", {})
    if not arr:
        errors.append("record-metadata.controller-arrangement required")
    else:
        arr_type = arr.get("arrangement-type")
        if not arr_type:
            errors.append("controller-arrangement.arrangement-type required")
        elif arr_type not in VALID_ARRANGEMENT_TYPES:
            errors.append(f"controller-arrangement.arrangement-type must be one of {sorted(VALID_ARRANGEMENT_TYPES)}")

        controllers = arr.get("controllers", [])
        if not controllers:
            errors.append("controller-arrangement.controllers must contain at least one entry")
        else:
            lead_roles = [c.get("role") for c in controllers
                          if c.get("role") in ("sole", "lead")]
            if not lead_roles:
                errors.append("controller-arrangement must have exactly one sole or lead controller")
            for c in controllers:
                if not c.get("name"):
                    errors.append("each controller must have a name")
                if not c.get("contact-url"):
                    errors.append("each controller must have a contact-url")
                elif not URI_RE.match(c["contact-url"]):
                    errors.append(f"controller contact-url must be a valid URI")
                if c.get("role") not in VALID_CONTROLLER_ROLES:
                    errors.append(f"controller role must be one of {sorted(VALID_CONTROLLER_ROLES)}")

        if arr_type == "joint" and not arr.get("art26-reference"):
            errors.append("controller-arrangement.art26-reference required for joint arrangements")

    # processing
    legal_basis = proc.get("legal-basis")
    if not legal_basis:
        errors.append("processing.legal-basis required")
    elif legal_basis not in VALID_BASES:
        errors.append(f"processing.legal-basis must be one of {sorted(VALID_BASES)}")
    if not proc.get("purpose"):
        errors.append("processing.purpose required")
    if not proc.get("data-types"):
        errors.append("processing.data-types required (non-empty array)")
    else:
        bad = [t for t in proc["data-types"] if t not in VALID_DATA_TYPES]
        if bad:
            errors.append(f"processing.data-types contains unknown types: {bad}")

    # access-event
    if not ae.get("state"):
        errors.append("access-event.state required")
    elif ae["state"] not in VALID_STATES:
        errors.append(f"access-event.state must be one of {sorted(VALID_STATES)}")
    if not ae.get("registered-at"):
        errors.append("access-event.registered-at required")
    if "expiry" not in ae:
        errors.append("access-event.expiry required (use null for no expiry)")
    # consent key only required for consent-based legal bases
    # for non-consent bases it must be absent or null (validated below)

    # notice / consent cross-validation
    if legal_basis in CONSENT_BASES:
        if notice is None:
            errors.append("notice must be provided for consent-based records")
        else:
            has_shared = notice.get("shared-notice") is not None
            has_notices = bool(notice.get("notices"))
            if not has_shared and not has_notices:
                errors.append("notice must have either shared-notice or notices array")
            if has_shared:
                sn = notice["shared-notice"]
                if not sn.get("terms-url"):
                    errors.append("notice.shared-notice.terms-url required")
                if not sn.get("notice-version"):
                    errors.append("notice.shared-notice.notice-version required")
        consent = ae.get("consent")
        if consent is None:
            errors.append("access-event.consent must be provided for consent-based records")
        else:
            if not consent.get("consent-type"):
                errors.append("access-event.consent.consent-type required")
            elif consent["consent-type"] not in ("expressed-consent", "explicit-consent"):
                errors.append("access-event.consent.consent-type invalid")
    else:
        if notice is not None:
            errors.append("notice must be null for non-consent legal bases")
        if ae.get("consent") is not None:
            errors.append("access-event.consent must be null for non-consent legal bases")

    return errors

def serialise_access_record_summary(d: dict) -> dict:
    """Serialise a DB doc to AccessRecordSummary shape."""
    if d.get("type") == "discovered_record":
        return {
            "ak":                  d["ak"],
            "lead-controller-name": None,
            "arrangement-type":    None,
            "controller-count":    None,
            "record-metadata":     None,
            "legal-basis":         None,
            "purpose":             None,
            "data-types":          d.get("data_types_observed", []),
            "state":               "DISCOVERED",
            "expiry":              None,
            "discovered-access": {
                "mpxn":                   d.get("mpxn"),
                "organisation-name":      d.get("organisation_name"),
                "organisation-reference": d.get("organisation_reference"),
                "first-seen":             d.get("first_seen"),
                "last-seen":              d.get("last_seen"),
                "data-types-observed":    d.get("data_types_observed", []),
                "source-reference":       d.get("source_reference"),
                "superseded-by":          d.get("superseded_by"),
            },
        }

    p   = d.get("payload", {})
    arr = p.get("record-metadata", {}).get("controller-arrangement", {})
    controllers = arr.get("controllers", [])

    lead_name = next(
        (c.get("name", "") for c in controllers if c.get("role") in ("sole", "lead")),
        None,
    )

    return {
        "ak":                  d["ak"],
        "lead-controller-name": lead_name,
        "arrangement-type":    arr.get("arrangement-type"),
        "controller-count":    len(controllers),
        "record-metadata":     p.get("record-metadata"),
        "legal-basis":         p.get("processing", {}).get("legal-basis"),
        "purpose":             p.get("processing", {}).get("purpose"),
        "data-types":          p.get("processing", {}).get("data-types", []),
        "state":               d.get("state"),
        "expiry":              p.get("access-event", {}).get("expiry"),
        "discovered-access":   None,
    }

def serialise_identity_record(doc: dict) -> dict:
    return {
        "ir":          doc["ir"],
        "created-at":  doc.get("created_at"),
        "pii-principal": doc.get("pii_principal"),
        "expressed-by":  doc.get("expressed_by"),
        "principal-verification": doc.get("principal_verification"),
        "has-email":   doc.get("has_email", False),
        "credentials": [
            {
                "credential-id":  c.get("credential-id"),
                "registered-at":  c.get("registered-at"),
                "transports":     c.get("transports", []),
            }
            for c in doc.get("credentials", [])
        ],
        "anonymised-at": doc.get("anonymised_at"),
    }
