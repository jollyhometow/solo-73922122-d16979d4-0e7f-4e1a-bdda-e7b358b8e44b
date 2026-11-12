"""Vendor report service (offline demo).

Serves the "supplier" diagnostic reports and a handful of deterministic
paths used to exercise the portal's SSRF defenses.  The vendor lives inside
the portal's allowed egress CIDR; its ``/redirect/internal`` path redirects
to an address outside that CIDR, which the portal must refuse on the
redirect hop without contacting the internal target.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse, Response

REDIRECT_BASE = os.getenv("VENDOR_INTERNAL_REDIRECT_BASE", "http://intranet.internal:8080")
MAX_BODY_BYTES = int(os.getenv("VENDOR_DEMO_BODY_BYTES", str(2 * 1024 * 1024)))  # 2 MiB

app = FastAPI(
    title="Vendor Report Service",
    version="1.0.0",
    description="Supplier-side reports for the SSRF demo. All responses are generated locally.",
)

REPORT_BODY = (
    "DIAGNOSTIC REPORT (vendor-generated, offline demo)\n"
    "==================================================\n"
    "ticket:        SRV-2026-1112\n"
    "device:        gateway-fw-01\n"
    "firmware:      4.2.7\n"
    "result:        no anomalies detected\n"
    "this file was fetched through the portal's /reports/download API.\n"
)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def root():
    return {"service": "vendor-reports", "paths": sorted(route.path for route in app.routes)}


@app.get("/reports/diagnostic.txt", response_class=PlainTextResponse, summary="A normal diagnostic report")
def diagnostic():
    return PlainTextResponse(REPORT_BODY, media_type="text/plain; charset=utf-8")


@app.get("/redirect/internal", summary="302 redirect to an internal address outside the egress CIDR")
def redirect_internal():
    # The redirect target resolves (via the demo DNS) to the decoy network.
    # The portal must re-validate this hop and refuse before any connection.
    return RedirectResponse(url=f"{REDIRECT_BASE}/secret", status_code=302)


@app.get("/redirect/loop", summary="Redirect chain longer than the 3-hop limit")
def redirect_loop(request: Request):
    return RedirectResponse(url="/redirect/loop", status_code=302)


@app.get("/redirect/ok", summary="One allowed redirect back to a normal report")
def redirect_ok():
    return RedirectResponse(url="/reports/diagnostic.txt", status_code=302)


@app.get("/too-large", summary="A 2 MiB body that exceeds the portal's 1 MiB cap")
def too_large():
    # Slightly over the limit; the portal must abort and return an error
    # rather than a truncated attachment.
    return Response(content=b"x" * MAX_BODY_BYTES, media_type="application/octet-stream")


@app.get("/slow", summary="Deliberately slow response (exceeds the 5 s total budget)")
def slow():
    import time

    time.sleep(8)
    return PlainTextResponse("this must never be returned\n")


@app.api_route("/echo", methods=["GET", "POST"], summary="Echo request headers (proves no portal identity is forwarded)")
def echo(request: Request):
    headers = {key: value for key, value in request.headers.items()}
    return {
        "note": "the portal must not send Authorization or Cookie here",
        "headers": headers,
        "has_authorization": "authorization" in {k.lower() for k in headers},
        "has_cookie": "cookie" in {k.lower() for k in headers},
    }
