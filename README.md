# Data Access Register (DAR)

A demo-ready alpha implementation of the **Central Data Access Register** — a lightweight, open register of lawful customer energy data access across all UK GDPR legal bases, aligned to ISO/IEC TS 27560:2023.

> **This is a design proposal under active development and not yet a production ready service.**  
> To discuss the design, contact [contact@auth.energy](mailto:contact@auth.energy).

**Docs:** [docs.auth.energy/data-access-register](https://docs.auth.energy/data-access-register)

---

## What Is It?

The DAR is a practical, lightweight alternative to the full [Consumer Consent Solution](https://retailenergycode.co.uk/our-programmes/consumer-consent-solution/) being designed by the [Retail Energy Code](https://retailenergycode.co.uk/). It records all lawful access to customer energy meter data — not just consent — and is designed for UK energy industry use under the Smart Energy Code.

Key properties:

- Records access under **any lawful basis** — consent, legitimate interests, public task, legal obligation, or contract
- **ISO/IEC TS 27560:2023** compliant record structure
- **SEC compliant** — Data Users are registered as SEC Other Users
- Supports any approved **Identity Verification Scheme**
- Supports **automatic discovery** of access via DCC transaction logs
- Notifies Data Users of **Change of Tenancy** events via webhook
- Supports a **Central Customer Portal** and in-app consent display
- Historic and expired access records can be submitted at any time

---

## Party Model

| Party | UK GDPR Role | Description |
|---|---|---|
| **Data User** | Processor | Registers and manages access records. Authenticated via bearer token. SEC Other User. |
| **Controller** | Data Controller | B2B customer of the Data User. Bears GDPR accountability for the legal basis claimed. |
| **Customer** | Data Subject | The energy customer. Identified by MPxN. |
| **Data Provider** | Data Source | Verifies access records before releasing meter data. |
| **DCC** | — | Submits discovered access records and Change of Tenancy events. |
| **Portal Operator** | — | Authorised third-party transparency portal (e.g. Citizens Advice). Queries any MPxN on behalf of a confirmed customer. |

---

## Implementation

### Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 |
| Framework | Flask 3 |
| Database | CouchDB 3.3 |
| Server | Apache 2.4 + mod_wsgi |
| Auth | HS256 JWT (stdlib only) |

### Quick Start (Docker)

```bash
cd docker
docker compose up
```

API available at `http://localhost:5001`.

### Seed Demo Data

Populates the register with sample accounts and access records matching the customer portal mockup:

```bash
docker compose -f docker/docker-compose.yml exec api python seed_demo.py
```

### Running Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

---

## API Endpoints

### Authentication
| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/auth/token` | Exchange Basic Auth for JWT bearer token (7200s) |

### Identity Records
| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/identity-records` | Create an Identity Record — MPxN, address, verification evidence, optional email |
| `GET` | `/v1/identity-records?mpxn=&email=` | Look up records for a returning customer |
| `GET` | `/v1/identity-records/{ir}` | Retrieve a specific Identity Record |
| `DELETE` | `/v1/identity-records/{ir}` | Anonymise — GDPR Art. 17 erasure, retains `ir` key for audit |
| `DELETE` | `/v1/identity-records/{ir}/credentials/{credentialId}` | Remove a passkey credential |
| `POST` | `/v1/identity-records/{ir}/re-identify` | Initiate re-identification (magic link, passkey assert, passkey register) |
| `GET` | `/v1/identity-records/{ir}/re-identify/{tokenRef}` | Poll or confirm re-identification status |

### Re-identification
| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/identity-records/exists?mpxn=` | Check existence and available re-identification methods (cross-DUID) |
| `POST` | `/v1/identity-records/reidentify` | Initiate cross-DUID re-identification by MPxN — `ir` never exposed |
| `GET` | `/v1/identity-records/reidentify/{tokenRef}` | Poll cross-DUID re-identification status by token-ref |

### Data Users
| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/access-records` | Register a new access record → 201 + Location |
| `PUT` | `/v1/access-records/{ak}` | Full replacement of an ACTIVE record → 200 |
| `DELETE` | `/v1/access-records/{ak}[?reason=]` | Revoke — transitions to REVOKED, retained for audit |
| `GET` | `/v1/meter-points/{mpxn}/access-records` | List all records for a meter point — `data_user` scoped to own MPxNs, `portal` requires reidentification token |
| `GET` | `/v1/records` | List own access records |

### Data Providers
| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/access-records/{ak}` | Verify access record — **unauthenticated**, returns no PII |
| `GET` | `/v1/data-users/{duid}` | Look up a Data User's status and profile |

### Self-Service
| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/self` | Own account profile |
| `POST` | `/v1/self/rotate-secret` | Rotate secret key — returned once |

### Customer Portal
| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/customer-sessions` | Issue a 60-second portal redirect token |

### DCC (restricted)
| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/discovered-access` | Submit a discovered (unregistered) access record |
| `POST` | `/v1/cot-events` | Submit a Change of Tenancy event — fires `tenancy.change` webhooks |

### Webhooks
| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/webhooks` | List subscriptions |
| `POST` | `/v1/webhooks` | Register a subscription |
| `DELETE` | `/v1/webhooks/{wid}` | Delete a subscription |
| `PATCH` | `/v1/webhooks/{wid}` | Update a subscription |

Webhook event types: `consent.withdrawal`, `consent.expiring`, `tenancy.change`

### Admin (restricted)
| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/admin/stats` | Register statistics |
| `GET` | `/v1/admin/accounts` | List all accounts |
| `POST` | `/v1/admin/accounts` | Create an account |
| `POST` | `/v1/admin/accounts/{id}/suspend` | Suspend an account |
| `POST` | `/v1/admin/accounts/{id}/reactivate` | Reactivate an account |
| `GET` | `/v1/admin/records` | Search all access records |
| `GET` | `/v1/admin/webhooks` | List all webhook subscriptions |
| `GET` | `/v1/admin/audit` | Audit log |

---

## User Interfaces

All UIs are served by the API and require no separate deployment.

| URL | Audience | Description |
|---|---|---|
| `/admin` | Ops team | Account management, record search, audit log |
| `/dashboard` | Data Users | Own records, webhooks, account settings |
| `/portal` | Customers | View and withdraw access registrations |

Third-party portal operators (e.g. Citizens Advice) can build their own branded transparency portal using the `portal` role and the re-identification endpoints. See [Portal Operators guide](docs.auth.energy/data-access-register/portal-operators).

---

## Legal Bases Supported

| Value | Plain name | UK GDPR Article |
|---|---|---|
| `uk-consent` | Consent | Art. 6(1)(a) |
| `uk-explicit-consent` | Explicit Consent | Art. 9(2)(a) |
| `uk-legitimate-interests` | Legitimate Interests | Art. 6(1)(f) |
| `uk-public-task` | Public Task | Art. 6(1)(e) |
| `uk-legal-obligation` | Legal Obligation | Art. 6(1)(c) |
| `uk-contract` | Contract | Art. 6(1)(b) |

---

## Access Record Lifecycle

```
[ACTIVE] ──revoke──▶ [REVOKED]
[ACTIVE] ──expiry──▶ [EXPIRED]
```

Records are never hard-deleted. All state transitions are recorded with timestamps.

---

## Account Management

Provision an account via the admin UI at `/admin`, or using the CLI script:

```bash
python setup_account.py \
  --account-id bright_energy \
  --secret-key s3cr3t \
  --duid duid_brightenergyabc123 \
  --display-name "Bright Energy Ltd" \
  --role data_user \
  --contact-url https://bright-energy.com/contact
```

Roles: `data_user` · `data_provider` · `dcc` · `admin` · `portal`

---

## Contributing

This is an open design proposal. Feedback and contributions are welcome — open an issue or contact [contact@auth.energy](mailto:contact@auth.energy).

---

## License

See [LICENSE](LICENSE.md).

---

*[Auth Energy](https://auth.energy) · [docs.auth.energy/data-access-register](https://docs.auth.energy/data-access-register)*
