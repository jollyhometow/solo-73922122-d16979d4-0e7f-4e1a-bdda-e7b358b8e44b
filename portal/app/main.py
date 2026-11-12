"""Enterprise portal API.

Endpoints
---------
POST /login               exchange an authorization code at the IdP, then
                          (serialized) create a local session unless the
                          identity JWT is covered by a logout cutoff.
POST /backchannel-logout  receive a logout JWT from the IdP, persist the
                          target's max logout iat, revoke covered sessions.
GET  /me                  resolve the random session credential.
POST /reports/download    fetch a support-supplied http URL under the fixed
                          egress policy and return the full body as an
                          attachment (SSRF-hardened, see app/fetcher.py).
GET  /debug/state         demo aid: current cutoffs / counters.
GET  /healthz             liveness.

Concurrency model
-----------------
Two replicas of this process share one SQLite file.  Each login/logout
critical section is a single BEGIN IMMEDIATE transaction, so SQLite
serializes them across processes; session validation reads see a consistent
snapshot.  The (potentially slow) IdP token exchange happens BEFORE the
transaction starts, so no database write lock is ever held while waiting
for the identity source.

All endpoints are synchronous ``def`` functions: Starlette runs them in a
thread pool, so a /login blocked on a late IdP response never stalls
logout processing in the same process.
"""

from __future__ import annotations

import secrets
import sqlite3
import time

import httpx
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import RedirectResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from . import config, security
from .db import Database
from .fetcher import EgressPolicyError, UpstreamFetchError, download

db = Database(config.DB_PATH)

app = FastAPI(
    title="Enterprise Portal",
    version="1.1.0",
    description=(
        "Portal with back-channel logout and an SSRF-hardened report download. "
        "Demo flow: get a code from the IdP (`POST {idp}/authorize`), exchange "
        "it via `POST /login` below, call `GET /me` with the returned "
        "`session_id` (Authorize button), then `POST /reports/download` with a "
        "support-supplied http URL to receive the report body as an attachment. "
        "Log the user out at the IdP (`POST {idp}/logout`) and watch `GET /me` "
        "turn 401."
    ),
)

bearer = HTTPBearer(auto_error=False, description="Random session credential from POST /login")


class LoginRequest(BaseModel):
    code: str = Field(
        ..., description="Authorization code issued by the IdP (POST /authorize)",
        json_schema_extra={"examples": ["paste-code-from-idp-authorize-here"]},
    )


class LogoutRequest(BaseModel):
    logout_token: str = Field(
        ..., description="RS256 logout JWT (purpose=logout, jti, iat, exp, sid and/or sub)"
    )


class ReportDownloadRequest(BaseModel):
    url: str = Field(
        ...,
        max_length=2048,
        description=(
            "Support-supplied report URL. Only plain http:// URLs with no "
            "userinfo are accepted; every address (initial and each redirect) "
            "must resolve to an IPv4 inside the fixed egress CIDRs/ports."
        ),
        json_schema_extra={"examples": ["http://vendor.reports.local/reports/diagnostic.txt"]},
    )


def require_session(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> sqlite3.Row:
    """Shared session gate used by every authenticated endpoint."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=401, detail="missing session credential")
    row = db.read_one(
        "SELECT sub, sid, id_token_iat, created_at FROM sessions WHERE session_id = ?",
        (credentials.credentials,),
    )
    if row is None:
        raise HTTPException(status_code=401, detail="session unknown or revoked")
    return row


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}


@app.post("/login", summary="Exchange an authorization code and create a session")
def login(body: LoginRequest):
    # Step 1 — exchange the code at the attached identity source.  This may
    # take a while (late login response).  NO database lock is held here.
    try:
        resp = httpx.post(
            config.TOKEN_URL, json={"code": body.code},
            timeout=config.TOKEN_EXCHANGE_TIMEOUT,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"identity provider unreachable: {exc}") from exc
    if resp.status_code != 200:
        raise HTTPException(status_code=401, detail="authorization code rejected by identity provider")
    id_token = resp.json().get("id_token", "")

    # Step 2 — verify signature, purpose, validity window (fixed key/iss/aud).
    claims = security.verify_identity_token(id_token)
    sub, sid, iat = claims["sub"], claims["sid"], int(claims["iat"])

    # Step 3 — serialized critical section: re-check the logout cutoffs and
    # create the session atomically.  A logout processed while we waited in
    # step 1 is now visible and wins.
    with db.write_txn() as conn:
        rows = conn.execute(
            "SELECT max_logout_iat FROM logout_cutoffs "
            "WHERE (target_type = 'sid' AND target_value = ?) "
            "   OR (target_type = 'sub' AND target_value = ?)",
            (sid, sub),
        ).fetchall()
        cutoff = max((row["max_logout_iat"] for row in rows), default=None)
        if cutoff is not None and iat <= cutoff:
            # Identity JWT not later than the logout cutoff: in-flight login
            # must not create a session.
            raise HTTPException(
                status_code=409,
                detail=(
                    f"login superseded by logout (token iat {iat} <= "
                    f"logout cutoff {cutoff}); no session created"
                ),
            )
        session_id = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO sessions (session_id, sub, sid, id_token_iat, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (session_id, sub, sid, iat, int(time.time())),
        )
    return {"session_id": session_id, "token_type": "Bearer", "sub": sub, "sid": sid, "id_token_iat": iat}


@app.post("/backchannel-logout", summary="Receive a logout JWT from the identity source")
def backchannel_logout(body: LogoutRequest):
    # Verify signature, purpose, validity window (fixed key/iss/aud).
    claims = security.verify_logout_token(body.logout_token)
    jti = claims["jti"]
    logout_iat = int(claims["iat"])
    targets = [(kind, claims[kind]) for kind in ("sid", "sub") if claims.get(kind)]

    # Serialized critical section (across both portal processes).
    with db.write_txn() as conn:
        already = conn.execute(
            "SELECT 1 FROM processed_logout_jtis WHERE jti = ?", (jti,)
        ).fetchone()
        if already:
            # Duplicate notification: pure no-op, cannot widen revocation.
            return {"status": "duplicate", "jti": jti, "revoked_sessions": 0}

        conditions, params = [], []
        cutoffs = {}
        for kind, value in targets:
            row = conn.execute(
                "SELECT max_logout_iat FROM logout_cutoffs "
                "WHERE target_type = ? AND target_value = ?",
                (kind, value),
            ).fetchone()
            effective = row["max_logout_iat"] if row else None
            if effective is None or logout_iat > effective:
                # Only ever raise the cutoff — out-of-order notifications
                # must not lower it.
                effective = logout_iat
                conn.execute(
                    "INSERT INTO logout_cutoffs "
                    "(target_type, target_value, max_logout_iat, source_jti, updated_at) "
                    "VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(target_type, target_value) DO UPDATE SET "
                    "max_logout_iat = excluded.max_logout_iat, "
                    "source_jti = excluded.source_jti, "
                    "updated_at = excluded.updated_at",
                    (kind, value, effective, jti, int(time.time())),
                )
            cutoffs[f"{kind}={value}"] = effective
            conditions.append(f"({kind} = ? AND id_token_iat <= ?)")
            params.extend([value, effective])

        revoked = conn.execute(
            f"DELETE FROM sessions WHERE {' OR '.join(conditions)}", params
        ).rowcount
        conn.execute(
            "INSERT INTO processed_logout_jtis (jti, processed_at) VALUES (?, ?)",
            (jti, int(time.time())),
        )
    return {
        "status": "ok",
        "jti": jti,
        "logout_iat": logout_iat,
        "cutoffs": cutoffs,
        "revoked_sessions": revoked,
    }


@app.get("/me", summary="Resolve the current session")
def me(row: sqlite3.Row = Depends(require_session)):
    return {
        "sub": row["sub"],
        "sid": row["sid"],
        "id_token_iat": row["id_token_iat"],
        "created_at": row["created_at"],
    }


@app.post(
    "/reports/download",
    summary="Download a support report URL under the fixed egress policy",
    responses={
        200: {"content": {"application/octet-stream": {}}, "description": "Full report body, as attachment"},
        400: {"description": "URL violates the egress policy (scheme/userinfo/CIDR/port/redirect limit)"},
        502: {"description": "Policy passed but the upstream fetch failed"},
        504: {"description": "The 5 s overall time budget was exhausted"},
    },
)
def download_report(body: ReportDownloadRequest, row: sqlite3.Row = Depends(require_session)):
    # Session gate first (require_session); nothing is fetched anonymously.
    # The fetcher enforces: http-only + no userinfo, configured-DNS A lookups,
    # every address inside the startup-fixed CIDRs/ports (initial + every
    # redirect), address-pinned connections with the original Host header and
    # no re-resolution, <=3 redirects, 5 s total, <=1 MiB body, no cookies and
    # no portal credentials forwarded.  Failures never return a partial body.
    try:
        data, content_type, filename = download(body.url)
    except EgressPolicyError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except UpstreamFetchError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    # Only carry the media type; drop any upstream Content-Disposition and
    # always force an attachment so the body is downloaded, not rendered.
    media_type = content_type.split(";", 1)[0].strip() or "application/octet-stream"
    safe_filename = filename.replace('"', "")
    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'},
    )


@app.get("/debug/state", summary="Demo aid: persisted logout cutoffs and counters")
def debug_state():
    cutoffs = db.read_all(
        "SELECT target_type, target_value, max_logout_iat, source_jti, updated_at "
        "FROM logout_cutoffs ORDER BY target_type, target_value"
    )
    sessions = db.read_all(
        "SELECT sub, sid, id_token_iat, created_at FROM sessions ORDER BY created_at"
    )
    jtis = db.read_one("SELECT COUNT(*) AS n FROM processed_logout_jtis")
    return {
        "logout_cutoffs": [dict(r) for r in cutoffs],
        "active_sessions": [dict(r) for r in sessions],
        "processed_logout_jtis": jtis["n"],
    }


@app.get("/debug/egress-policy", summary="Demo aid: the fixed report-download egress policy")
def debug_egress_policy():
    # Read-only view of what the fetcher will accept; it cannot be changed here.
    return {
        "allowed_cidrs": [str(network) for network in config.EGRESS_ALLOWED_CIDRS],
        "allowed_ports": sorted(config.EGRESS_ALLOWED_PORTS),
        "dns_servers": list(config.EGRESS_DNS_SERVERS),
        "dns_port": config.EGRESS_DNS_PORT,
        "max_redirects": config.EGRESS_MAX_REDIRECTS,
        "total_timeout_seconds": config.EGRESS_TOTAL_TIMEOUT,
        "max_body_bytes": config.EGRESS_MAX_BODY_BYTES,
        "schemes": ["http"],
        "ip_versions": [4],
        "userinfo_allowed": False,
        "cookies_shared_across_requests": False,
        "portal_identity_forwarded": False,
    }
