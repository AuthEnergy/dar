"""
CouchDB data layer for the Data Access Register.

Databases:
  dar_identity  : identity records  (type: identity_record)
  dar_records   : access records    (type: access_record | discovered_record)
  dar_accounts  : API accounts      (type: account)
  dar_webhooks  : webhook subs      (type: webhook)
  dar_sessions  : portal sessions   (type: portal_session) + CoT events (type: cot_event)
  dar_audit     : audit events      (type: audit_event)
"""
import hashlib
import hmac
import secrets
import requests
from datetime import datetime, timezone
from app.config import Config


# ── helpers ───────────────────────────────────────────────────────────────────

def _auth():
    return (Config.COUCHDB_USER, Config.COUCHDB_PASSWORD)

def _db(name: str) -> str:
    return f"{Config.COUCHDB_URL}/{name}"

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _gen(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(12)}"

def _get(db: str, doc_id: str) -> dict | None:
    r = requests.get(f"{_db(db)}/{doc_id}", auth=_auth())
    return r.json() if r.status_code == 200 else None

def _put(db: str, doc: dict) -> dict:
    r = requests.put(f"{_db(db)}/{doc['_id']}", json=doc, auth=_auth())
    r.raise_for_status()
    return doc

def _find(db: str, selector: dict, limit: int = 200) -> list:
    r = requests.post(
        f"{_db(db)}/_find",
        json={"selector": selector, "limit": limit},
        auth=_auth(),
    )
    if r.status_code != 200:
        return []
    return r.json().get("docs", [])


# ── init ──────────────────────────────────────────────────────────────────────

def init_db():
    import time

    # Wait for CouchDB to be ready — retry up to 30s
    for attempt in range(30):
        try:
            r = requests.get(f"{Config.COUCHDB_URL}/_up", auth=_auth(), timeout=3)
            if r.status_code == 200:
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)
    else:
        raise RuntimeError("CouchDB did not become ready in time")

    # Create application databases — 201 = created, 412 = already exists, both fine
    for db_name in ["dar_identity", "dar_records", "dar_accounts",
                    "dar_webhooks", "dar_sessions", "dar_audit"]:
        r = requests.put(f"{Config.COUCHDB_URL}/{db_name}", auth=_auth())
        if r.status_code not in (201, 412):
            raise RuntimeError(f"DB init failed for {db_name}: {r.text}")

    # Create indexes — non-fatal if they already exist
    indexes = [
        ("dar_identity", ["duid"]),
        ("dar_identity", ["duid", "mpxn"]),
        ("dar_identity", ["email_hash"]),
        ("dar_records",  ["mpxn"]),
        ("dar_records",  ["duid"]),
        ("dar_records",  ["duid", "mpxn"]),
        ("dar_records",  ["type"]),
        ("dar_accounts", ["duid"]),
        ("dar_accounts", ["role"]),
        ("dar_webhooks", ["duid"]),
        ("dar_sessions", ["token"]),
        ("dar_sessions", ["mpxn"]),
        ("dar_audit",    ["timestamp"]),
        ("dar_audit",    ["account_id"]),
        ("dar_audit",    ["event_type"]),
        ("dar_audit",    ["ak"]),
    ]
    for db_name, fields in indexes:
        try:
            requests.post(
                f"{_db(db_name)}/_index",
                json={"index": {"fields": fields}},
                auth=_auth(),
                timeout=5,
            )
        except Exception:
            pass  # Non-fatal — queries fall back to full scans


# ── accounts ──────────────────────────────────────────────────────────────────

def get_account(account_id: str) -> dict | None:
    return _get("dar_accounts", account_id)

def verify_account(account_id: str, secret_key: str) -> bool:
    acc = get_account(account_id)
    if not acc:
        return False
    return hmac.compare_digest(
        acc.get("secret_hash", ""),
        hashlib.sha256(secret_key.encode()).hexdigest(),
    )

def create_account(account_id: str, secret_key: str, duid: str,
                   display_name: str, role: str,
                   contact_url: str = "", data_types: list = None) -> dict:
    doc = {
        "_id":                  account_id,
        "type":                 "account",
        "duid":                 duid,
        "display_name":         display_name,
        "role":                 role,
        "contact_url":          contact_url,
        "data_types_supported": data_types or [],
        "status":               "active",
        "secret_hash":          hashlib.sha256(secret_key.encode()).hexdigest(),
        "registered_at":        _now(),
        "callback_urls":        [],
    }
    return _put("dar_accounts", doc)

def get_data_user_profile(duid: str) -> dict | None:
    docs = _find("dar_accounts", {"duid": duid, "role": "data_user"})
    return docs[0] if docs else None

def get_account_by_duid(duid: str) -> dict | None:
    docs = _find("dar_accounts", {"duid": duid})
    return docs[0] if docs else None


# ── identity records ──────────────────────────────────────────────────────────

def create_identity_record(duid: str, body: dict) -> tuple[dict, str | None]:
    """
    Create an IdentityRecord. Returns (doc, passkey_redirect_url).
    passkey_redirect_url is non-None when initiate-passkey-registration is True.
    """
    ir  = _gen("ir")
    now = _now()
    pii = body.get("pii-principal", {})
    mpxn = pii.get("mpxn", "")

    email      = body.get("email")
    email_hash = hashlib.sha256(email.lower().encode()).hexdigest() if email else None

    init_passkey = body.get("initiate-passkey-registration", False)
    passkey_redirect = None
    pending_passkey_token = None

    if init_passkey:
        token_ref            = _gen("mlr")
        pending_passkey_token = token_ref
        passkey_redirect = {
            "redirect-url": f"{Config.PORTAL_BASE_URL}/passkey/register?session={_gen('pks')}",
            "token-ref":    token_ref,
            "expires-at":   _now(),
            "return-url":   body.get("passkey-return-url"),
        }

    doc = {
        "_id":               ir,
        "type":              "identity_record",
        "ir":                ir,
        "duid":              duid,
        "mpxn":              mpxn,
        "created_at":        now,
        "pii_principal":     pii,
        "expressed_by":      body.get("expressed-by"),
        "principal_verification": body.get("principal-verification"),
        "email_hash":        email_hash,
        "has_email":         email_hash is not None,
        "credentials":       [],
        "anonymised_at":     None,
        "pending_reidentify_tokens": (
            {pending_passkey_token: {"method": "passkey-register", "status": "pending"}}
            if pending_passkey_token else {}
        ),
    }
    _put("dar_identity", doc)
    return doc, passkey_redirect

def get_identity_record(ir: str, duid: str) -> dict | None:
    doc = _get("dar_identity", ir)
    if not doc or doc.get("duid") != duid:
        return None
    return doc

def lookup_identity_records(duid: str, mpxn: str = None,
                             email: str = None) -> list:
    selector: dict = {"type": "identity_record", "duid": duid}
    if mpxn:
        selector["mpxn"] = mpxn
    if email:
        selector["email_hash"] = hashlib.sha256(
            email.lower().encode()).hexdigest()
    return _find("dar_identity", selector)

def check_identity_record_exists(mpxn: str) -> bool:
    """Check if ANY identity record exists for this MPxN across all Data Users.
    Returns True/False only — no ir key or PII exposed."""
    docs = _find("dar_identity", {"type": "identity_record", "mpxn": mpxn}, 1)
    return len([d for d in docs if not d.get("anonymised_at")]) > 0

def initiate_reidentify_by_mpxn(mpxn: str, initiating_duid: str, method: str,
                                  redirect_url: str = None,
                                  passkey_return_url: str = None,
                                  display_name: str = None) -> tuple[dict | None, str]:
    """Initiate re-identification for a customer by MPxN, without exposing the ir.
    Used by Data User B to re-use an existing Identity Record from another Data User.
    The ir is resolved internally — never returned to the caller.
    display_name is the initiating Data User's name shown to the customer."""
    # Find the identity record for this MPxN (any Data User)
    docs = _find("dar_identity", {"type": "identity_record", "mpxn": mpxn})
    active = [d for d in docs if not d.get("anonymised_at")]
    if not active:
        return None, "NOT_FOUND"

    # Use the most recently created record
    doc = sorted(active, key=lambda d: d.get("created_at", ""), reverse=True)[0]
    ir  = doc["ir"]

    import secrets as _secrets
    token_ref = _gen("mlr")
    now = _now()

    if method == "magic-link":
        if not doc.get("has_email"):
            return None, "NO_EMAIL"
        tokens = doc.get("pending_reidentify_tokens", {})
        tokens[token_ref] = {
            "method":           "magic-link",
            "status":           "pending",
            "created_at":       now,
            "redirect_url":     redirect_url,
            "initiating_duid":  initiating_duid,
            "cross_duid":       True,
            "display_name":     display_name,
        }
        doc["pending_reidentify_tokens"] = tokens
        _put("dar_identity", doc)
        return {
            "method":      "magic-link",
            "magic-link": {
                "dispatched-to": "c*****r@example.com",
                "expires-at":    now,
                "token-ref":     token_ref,
                "redirect-url":  redirect_url,
            },
            "passkey": None,
        }, ""

    elif method in ("passkey-assert", "passkey-register"):
        if method == "passkey-assert" and not doc.get("credentials"):
            return None, "NO_CREDENTIALS"
        tokens = doc.get("pending_reidentify_tokens", {})
        tokens[token_ref] = {
            "method":           method,
            "status":           "pending",
            "created_at":       now,
            "return_url":       passkey_return_url,
            "initiating_duid":  initiating_duid,
            "cross_duid":       True,
            "display_name":     display_name,
        }
        doc["pending_reidentify_tokens"] = tokens
        _put("dar_identity", doc)
        return {
            "method":      method,
            "magic-link":  None,
            "passkey": {
                "redirect-url": f"{Config.PORTAL_BASE_URL}/passkey/assert?session={_gen('pks')}",
                "token-ref":    token_ref,
                "expires-at":   now,
                "return-url":   passkey_return_url,
            },
        }, ""

    return None, "INVALID_METHOD"

def validate_reidentification_token(token_ref: str, initiating_duid: str) -> tuple[str | None, str]:
    """Validate a cross-DUID reidentification token.
    Returns (ir, error). ir is None on error.
    Token must be confirmed, cross_duid, initiated by this duid, and single-use."""
    from datetime import timezone
    import dateutil.parser

    # Find the identity record containing this token
    # We store tokens on the identity record — scan for it
    all_irs = _find("dar_identity", {"type": "identity_record"}, 500)
    for doc in all_irs:
        tokens = doc.get("pending_reidentify_tokens", {})
        if token_ref not in tokens:
            continue
        token = tokens[token_ref]

        if token.get("initiating_duid") != initiating_duid:
            return None, "FORBIDDEN"
        if not token.get("cross_duid"):
            return None, "NOT_CROSS_DUID"
        if token.get("status") != "confirmed":
            return None, "NOT_CONFIRMED"
        if token.get("consumed"):
            return None, "ALREADY_USED"

        # Check not expired — tokens valid for 1 hour
        try:
            age = (datetime.now(timezone.utc) -
                   dateutil.parser.isoparse(token["created_at"])).total_seconds()
            if age > 3600:
                return None, "EXPIRED"
        except Exception:
            pass

        # Mark as consumed
        token["consumed"] = True
        tokens[token_ref] = token
        doc["pending_reidentify_tokens"] = tokens
        _put("dar_identity", doc)
        return doc["ir"], ""

    return None, "NOT_FOUND"

def anonymise_identity_record(ir: str, duid: str) -> tuple[dict | None, str]:
    """
    Returns (doc, error). error is '' on success, 'NOT_FOUND' or 'CONFLICT'.
    Pre-condition: all linked access records must be REVOKED or EXPIRED.
    """
    doc = _get("dar_identity", ir)
    if not doc or doc.get("duid") != duid:
        return None, "NOT_FOUND"

    # Check no ACTIVE records link to this ir
    active = _find("dar_records", {"type": "access_record",
                                    "identity_record_ref": ir,
                                    "state": "ACTIVE"})
    if active:
        return None, "CONFLICT"

    now = _now()
    doc["pii_principal"]          = None
    doc["expressed_by"]           = None
    doc["principal_verification"] = None
    doc["email_hash"]             = None
    doc["has_email"]              = False
    doc["credentials"]            = []
    doc["anonymised_at"]          = now
    _put("dar_identity", doc)
    return doc, ""

def remove_passkey_credential(ir: str, duid: str,
                               credential_id: str) -> bool:
    doc = _get("dar_identity", ir)
    if not doc or doc.get("duid") != duid:
        return False
    before = len(doc.get("credentials", []))
    doc["credentials"] = [c for c in doc.get("credentials", [])
                          if c.get("credential-id") != credential_id]
    if len(doc["credentials"]) == before:
        return False  # credential_id not found
    _put("dar_identity", doc)
    return True

def initiate_reidentify(ir: str, duid: str, method: str,
                        redirect_url: str = None,
                        passkey_return_url: str = None) -> tuple[dict | None, str]:
    """
    Returns (result_dict, error). result_dict contains magic-link or passkey data.
    """
    doc = _get("dar_identity", ir)
    if not doc or doc.get("duid") != duid:
        return None, "NOT_FOUND"
    if doc.get("anonymised_at"):
        return None, "ANONYMISED"

    token_ref = _gen("mlr")
    now = _now()

    if method == "magic-link":
        if not doc.get("has_email"):
            return None, "NO_EMAIL"
        # Store pending token
        tokens = doc.get("pending_reidentify_tokens", {})
        tokens[token_ref] = {"method": "magic-link", "status": "pending",
                             "created_at": now, "redirect_url": redirect_url}
        doc["pending_reidentify_tokens"] = tokens
        _put("dar_identity", doc)
        return {
            "method": "magic-link",
            "magic-link": {
                "dispatched-to": "c*****r@example.com",  # masked
                "expires-at":    now,
                "token-ref":     token_ref,
                "redirect-url":  redirect_url,
            },
            "passkey": None,
        }, ""

    elif method in ("passkey-assert", "passkey-register"):
        if method == "passkey-assert" and not doc.get("credentials"):
            return None, "NO_CREDENTIALS"
        tokens = doc.get("pending_reidentify_tokens", {})
        tokens[token_ref] = {"method": method, "status": "pending",
                             "created_at": now, "return_url": passkey_return_url}
        doc["pending_reidentify_tokens"] = tokens
        _put("dar_identity", doc)
        return {
            "method": method,
            "magic-link": None,
            "passkey": {
                "redirect-url": f"{Config.PORTAL_BASE_URL}/passkey/assert?session={_gen('pks')}",
                "token-ref":    token_ref,
                "expires-at":   now,
                "return-url":   passkey_return_url,
            },
        }, ""

    return None, "INVALID_METHOD"

def poll_reidentify(ir: str, duid: str, token_ref: str) -> tuple[dict | None, str]:
    doc = _get("dar_identity", ir)
    if not doc or doc.get("duid") != duid:
        return None, "NOT_FOUND"
    tokens = doc.get("pending_reidentify_tokens", {})
    token = tokens.get(token_ref)
    if not token:
        return None, "NOT_FOUND"
    return {
        "method":       token["method"],
        "status":       token["status"],
        "confirmed-at": token.get("confirmed_at"),
    }, ""


# ── access records ────────────────────────────────────────────────────────────

def _lead_controller_name(payload: dict) -> str:
    arr = payload.get("record-metadata", {}).get(
        "controller-arrangement", {})
    for c in arr.get("controllers", []):
        if c.get("role") in ("sole", "lead"):
            return c.get("name", "")
    return ""

def _extract_mpxn(ir_ref: str, duid: str = None) -> str:
    """Resolve mpxn from identity record. duid=None allows cross-DUID lookup."""
    selector = {"ir": ir_ref}
    if duid:
        selector["duid"] = duid
    ir_doc = _find("dar_identity", selector)
    if ir_doc:
        return ir_doc[0].get("mpxn", "")
    return ""

def create_access_record(duid: str, payload: dict) -> dict:
    ak  = _gen("ak")
    now = _now()
    ir_ref = payload.get("record-metadata", {}).get("identity-record-ref", "")
    mpxn   = _extract_mpxn(ir_ref, duid)

    payload.setdefault("record-metadata", {})
    payload["record-metadata"]["record-identifier"] = ak
    payload["record-metadata"]["created-at"]        = now

    # Link to any DISCOVERED record for this mpxn
    superseded_by = None
    if mpxn:
        discovered = _find("dar_records", {"type": "discovered_record", "mpxn": mpxn})
        if discovered:
            disc = discovered[0]
            disc["superseded_by"] = ak
            _put("dar_records", disc)
            superseded_by = disc["ak"]

    doc = {
        "_id":                  ak,
        "type":                 "access_record",
        "ak":                   ak,
        "duid":                 duid,
        "mpxn":                 mpxn,
        "identity_record_ref":  ir_ref,
        "state":                payload.get("access-event", {}).get("state", "ACTIVE"),
        "created_at":           now,
        "updated_at":           now,
        "payload":              payload,
        "supersedes":           superseded_by,
    }
    return _put("dar_records", doc)

def replace_access_record(ak: str, duid: str,
                           payload: dict) -> tuple[dict | None, str]:
    doc = _get("dar_records", ak)
    if not doc or doc.get("duid") != duid:
        return None, "NOT_FOUND"
    if doc.get("state") != "ACTIVE":
        return None, "CONFLICT"

    now = _now()
    payload.setdefault("record-metadata", {})
    payload["record-metadata"]["record-identifier"] = ak
    payload["record-metadata"]["created-at"]        = doc.get("created_at", now)

    doc["payload"]    = payload
    doc["state"]      = payload.get("access-event", {}).get("state", doc["state"])
    doc["updated_at"] = now
    return _put("dar_records", doc), ""

def revoke_access_record(ak: str, duid: str) -> dict | None:
    doc = _get("dar_records", ak)
    if not doc or doc.get("duid") != duid:
        return None
    if doc.get("state") == "REVOKED":
        return None
    now = _now()
    doc["state"]      = "REVOKED"
    doc["revoked_at"] = now
    doc["updated_at"] = now
    doc.get("payload", {}).get("access-event", {}).update({
        "state": "REVOKED", "revoked-at": now,
    })
    return _put("dar_records", doc)

def get_access_record(ak: str) -> dict | None:
    return _get("dar_records", ak)

def verify_access_record(ak: str) -> dict | None:
    return get_access_record(ak)

def list_records_for_mpxn(mpxn: str, duid: str = None,
                           state_filter: str = None,
                           basis_filter: str = None) -> list:
    # No duid filter — the customer portal shows ALL Data Users' records for this MPxN
    selector = {"type": "access_record", "mpxn": mpxn}
    docs = _find("dar_records", selector)
    if not basis_filter:
        discovered = _find("dar_records", {"type": "discovered_record", "mpxn": mpxn})
        docs = docs + discovered
    if state_filter:
        docs = [d for d in docs if d.get("state") == state_filter]
    if basis_filter:
        docs = [d for d in docs
                if d.get("payload", {}).get("processing", {}).get("legal-basis") == basis_filter]
    return docs

def list_records_for_duid(duid: str, state_filter: str = None,
                           basis_filter: str = None, limit: int = 200) -> list:
    """Returns all access records registered by a specific Data User (for dashboard)."""
    selector = {"type": "access_record", "duid": duid}
    docs = _find("dar_records", selector, limit)
    if state_filter:
        docs = [d for d in docs if d.get("state") == state_filter]
    if basis_filter:
        docs = [d for d in docs
                if d.get("payload", {}).get("processing", {}).get("legal-basis") == basis_filter]
    return docs


# ── discovered records (DCC) ──────────────────────────────────────────────────

def submit_discovered_record(body: dict) -> tuple[dict, bool]:
    mpxn    = body["mpxn"]
    org_ref = body["organisation-reference"]
    src_ref = body["source-reference"]

    existing = _find("dar_records", {
        "type":                   "discovered_record",
        "mpxn":                   mpxn,
        "organisation_reference": org_ref,
        "source_reference":       src_ref,
    })
    if existing:
        doc = existing[0]
        doc["last_seen"]           = body.get("last-seen", _now())
        doc["data_types_observed"] = body.get("data-types-observed",
                                              doc.get("data_types_observed", []))
        _put("dar_records", doc)
        return doc, False

    ak  = _gen("ak")
    now = _now()
    doc = {
        "_id":                    ak,
        "type":                   "discovered_record",
        "ak":                     ak,
        "mpxn":                   mpxn,
        "state":                  "DISCOVERED",
        "organisation_name":      body.get("organisation-name"),
        "organisation_reference": org_ref,
        "source_reference":       src_ref,
        "first_seen":             body.get("first-seen", now),
        "last_seen":              body.get("last-seen", now),
        "data_types_observed":    body.get("data-types-observed", []),
        "created_at":             now,
        "superseded_by":          None,
    }
    return _put("dar_records", doc), True


# ── CoT events (DCC) ─────────────────────────────────────────────────────────

def submit_cot_event(body: dict) -> tuple[dict, bool]:
    mpxn     = body["mpxn"]
    eff_date = body["effective-date"]
    src_ref  = body["source-reference"]

    existing = _find("dar_sessions", {
        "type":             "cot_event",
        "mpxn":             mpxn,
        "effective_date":   eff_date,
        "source_reference": src_ref,
    })
    if existing:
        return existing[0], False

    eid = _gen("cot")
    now = _now()
    doc = {
        "_id":              eid,
        "type":             "cot_event",
        "event_id":         eid,
        "mpxn":             mpxn,
        "effective_date":   eff_date,
        "source_reference": src_ref,
        "submitted_at":     now,
    }
    _put("dar_sessions", doc)
    return doc, True

def get_active_records_for_mpxn(mpxn: str) -> list:
    return _find("dar_records", {"type": "access_record",
                                  "mpxn": mpxn, "state": "ACTIVE"})


# ── webhooks ──────────────────────────────────────────────────────────────────

def list_webhooks(duid: str) -> list:
    return _find("dar_webhooks", {"type": "webhook", "duid": duid})

def create_webhook(duid: str, callback_url: str, alert_email: str,
                   notify_days_before: int, event_types: list,
                   signing_secret: str) -> dict:
    wid = _gen("wid")
    now = _now()
    doc = {
        "_id":                wid,
        "type":               "webhook",
        "wid":                wid,
        "duid":               duid,
        "callback_url":       callback_url,
        "alert_email":        alert_email,
        "notify_days_before": notify_days_before,
        "event_types":        event_types,
        "signing_secret":     signing_secret,
        "active":             True,
        "created_at":         now,
        "updated_at":         now,
    }
    return _put("dar_webhooks", doc)

def get_webhook_by_callback_url(duid: str, callback_url: str) -> dict | None:
    docs = _find("dar_webhooks", {"type": "webhook", "duid": duid,
                                   "callback_url": callback_url})
    return docs[0] if docs else None

def delete_webhook(wid: str, duid: str) -> bool:
    doc = _get("dar_webhooks", wid)
    if not doc or doc.get("duid") != duid:
        return False
    doc["_deleted"] = True
    requests.put(f"{_db('dar_webhooks')}/{wid}", json=doc, auth=_auth())
    return True

def update_webhook(wid: str, duid: str, updates: dict) -> tuple[dict | None, str]:
    doc = _get("dar_webhooks", wid)
    if not doc or doc.get("duid") != duid:
        return None, "NOT_FOUND"
    field_map = {
        "callback-url":       "callback_url",
        "alert-email":        "alert_email",
        "notify-days-before": "notify_days_before",
        "event-types":        "event_types",
    }
    for api_key, db_key in field_map.items():
        if api_key in updates:
            doc[db_key] = updates[api_key]
    new_secret = None
    if updates.get("rotate-secret"):
        new_secret = secrets.token_hex(32)
        doc["signing_secret"] = new_secret
    doc["updated_at"] = _now()
    return _put("dar_webhooks", doc), (new_secret or "")

def get_webhooks_for_event(duid: str, event_type: str) -> list:
    hooks = _find("dar_webhooks", {"type": "webhook", "duid": duid, "active": True})
    return [h for h in hooks if event_type in h.get("event_types", [])]

def get_all_webhooks_for_event(event_type: str, mpxn: str = None) -> list:
    hooks = _find("dar_webhooks", {"type": "webhook", "active": True})
    result = []
    for h in hooks:
        if event_type not in h.get("event_types", []):
            continue
        if mpxn:
            recs = _find("dar_records", {"type": "access_record",
                                          "duid": h["duid"],
                                          "mpxn": mpxn, "state": "ACTIVE"})
            if not recs:
                continue
        result.append(h)
    return result


# ── portal sessions ───────────────────────────────────────────────────────────

def create_portal_session(duid: str, mpxn: str,
                           return_url: str, purpose: str) -> dict:
    token = secrets.token_urlsafe(32)
    now   = _now()
    doc = {
        "_id":        token,
        "type":       "portal_session",
        "token":      token,
        "duid":       duid,
        "mpxn":       mpxn,
        "return_url": return_url,
        "purpose":    purpose,
        "used":       False,
        "created_at": now,
    }
    return _put("dar_sessions", doc)

def redeem_portal_session(token: str) -> dict | None:
    import dateutil.parser
    doc = _get("dar_sessions", token)
    if not doc or doc.get("type") != "portal_session":
        return None
    if doc.get("used"):
        return None
    try:
        age = (datetime.now(timezone.utc) -
               dateutil.parser.isoparse(doc["created_at"])).total_seconds()
        if age > 60:
            return None
    except Exception:
        return None
    doc["used"] = True
    _put("dar_sessions", doc)
    return doc


# ── audit log ─────────────────────────────────────────────────────────────────

def write_audit(account_id: str, event_type: str, detail: dict) -> dict:
    eid = _gen("aud")
    now = _now()
    doc = {
        "_id":        eid,
        "type":       "audit_event",
        "event_id":   eid,
        "account_id": account_id,
        "event_type": event_type,
        "ak":         detail.get("ak"),
        "mpxn":       detail.get("mpxn"),
        "detail":     detail,
        "timestamp":  now,
    }
    return _put("dar_audit", doc)

def list_audit_events(limit: int = 100, account_id: str = None,
                      event_type: str = None, ak: str = None) -> list:
    selector: dict = {"type": "audit_event"}
    if account_id:
        selector["account_id"] = account_id
    if event_type:
        selector["event_type"] = event_type
    if ak:
        selector["ak"] = ak
    r = requests.post(
        f"{_db('dar_audit')}/_find",
        json={"selector": selector,
              "sort": [{"timestamp": "desc"}],
              "limit": limit},
        auth=_auth(),
    )
    if r.status_code != 200:
        return []
    return r.json().get("docs", [])


# ── admin ─────────────────────────────────────────────────────────────────────

def list_all_accounts() -> list:
    return _find("dar_accounts", {"type": "account"})

def suspend_account(account_id: str) -> dict | None:
    doc = _get("dar_accounts", account_id)
    if not doc:
        return None
    doc["status"] = "suspended"
    doc["updated_at"] = _now()
    return _put("dar_accounts", doc)

def reactivate_account(account_id: str) -> dict | None:
    doc = _get("dar_accounts", account_id)
    if not doc:
        return None
    doc["status"] = "active"
    doc["updated_at"] = _now()
    return _put("dar_accounts", doc)

def list_all_records(limit: int = 200, state: str = None,
                     legal_basis: str = None) -> list:
    selector: dict = {"type": "access_record"}
    if state:
        selector["state"] = state
    r = requests.post(
        f"{_db('dar_records')}/_find",
        json={"selector": selector, "limit": limit},
        auth=_auth(),
    )
    if r.status_code != 200:
        return []
    docs = r.json().get("docs", [])
    if legal_basis:
        docs = [d for d in docs
                if d.get("payload", {}).get("processing", {})
                     .get("legal-basis") == legal_basis]
    return docs

def search_records(query: str, limit: int = 50) -> list:
    if query.startswith("ak_"):
        doc = _get("dar_records", query)
        return [doc] if doc else []
    return _find("dar_records", {"type": "access_record", "mpxn": query}, limit)

def list_all_webhooks(limit: int = 200) -> list:
    return _find("dar_webhooks", {"type": "webhook"}, limit)

def get_account_stats() -> dict:
    accounts = list_all_accounts()
    records  = _find("dar_records", {"type": "access_record"}, 1000)
    webhooks = _find("dar_webhooks", {"type": "webhook"}, 1000)
    return {
        "total_accounts":  len(accounts),
        "active_accounts": sum(1 for a in accounts if a.get("status") == "active"),
        "total_records":   len(records),
        "active_records":  sum(1 for r in records if r.get("state") == "ACTIVE"),
        "revoked_records": sum(1 for r in records if r.get("state") == "REVOKED"),
        "total_webhooks":  len(webhooks),
        "active_webhooks": sum(1 for w in webhooks if w.get("active")),
    }
