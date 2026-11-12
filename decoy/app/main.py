"""Internal decoy service (offline demo).

Stands in for a sensitive intranet endpoint that must NEVER be reachable
through the portal's download primitive.  Every request that arrives here,
by any method or path, is recorded in memory and exposed via
``GET /requests``.  The demo asserts that the list stays empty even when
the supplied URL redirects into this network or DNS answers switch to this
address (rebinding).
"""

from __future__ import annotations

import threading
import time

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

app = FastAPI(
    title="Internal Decoy Service",
    version="1.0.0",
    description=(
        "Pretend sensitive intranet host outside the portal egress CIDR. "
        "Any request arriving here proves the SSRF defense failed."
    ),
)

_lock = threading.Lock()
_hits: list[dict] = []


@app.middleware("http")
async def record_everything(request: Request, call_next):
    # The demo's own administrative checks (/requests, /healthz) must not
    # count as attacks: they come directly from the test harness, not the
    # portal. Everything else, on any path, is recorded as a hit.
    if request.url.path not in ("/requests", "/healthz"):
        body = await request.body()
        hit = {
            "ts": round(time.time(), 3),
            "method": request.method,
            "path": request.url.path,
            "query": str(request.url.query),
            "host_header": request.headers.get("host"),
            "headers": dict(request.headers),
            "body_bytes": len(body),
        }
        with _lock:
            _hits.append(hit)
    return await call_next(request)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/requests", summary="All requests the decoy has received (must stay empty in the demo)")
def requests_received():
    with _lock:
        return {"count": len(_hits), "hits": list(_hits)}


@app.post("/requests/clear", summary="Reset the recorded request list")
def clear_requests():
    with _lock:
        _hits.clear()
    return {"status": "cleared"}


@app.api_route(
    "/{rest:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    include_in_schema=False,
)
def catch_all(rest: str):
    # Sensitive-looking payload so an accidental leak is obvious in logs.
    return PlainTextResponse("INTERNAL ONLY - this response must never leave via the portal\n")
