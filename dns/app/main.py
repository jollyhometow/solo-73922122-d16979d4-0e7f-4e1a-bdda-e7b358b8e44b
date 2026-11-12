"""Local authoritative DNS for the offline SSRF demo.

The demo must run with no public network, so this tiny service replaces a
real DNS deployment.  It answers A queries from a fixed, file-backed zone
table (records.json) and, for ``rebind_a`` names, rotates the answer per
client to emulate DNS rebinding:

  * 1st A query from a client -> the approved vendor address;
  * every later A query       -> the internal decoy address.

A portal that re-resolved the name when connecting would therefore reach
the decoy.  The hardened fetcher resolves exactly once per hop, validates
every returned address and pins the approved address for the actual TCP
connection, so the decoy never sees a request.

The same process also exposes a small HTTP API (query log / reset) so the
demo script can prove how many DNS queries each fetch triggered.
"""

from __future__ import annotations

import json
import os
import socketserver
import threading
import time

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import uvicorn
from fastapi import FastAPI

RECORDS_PATH = os.getenv("DNS_RECORDS_PATH", "/srv/records.json")
DNS_BIND_HOST = os.getenv("DNS_BIND_HOST", "0.0.0.0")
DNS_BIND_PORT = int(os.getenv("DNS_BIND_PORT", "53"))
HTTP_PORT = int(os.getenv("DNS_HTTP_PORT", "8080"))

with open(RECORDS_PATH, encoding="utf-8") as handle:
    ZONES: dict[str, dict] = json.load(handle)["zones"]

_state_lock = threading.Lock()
_query_log: list[dict] = []
# (client_ip, qname) -> number of A queries already answered by that client
_rebind_counters: dict[tuple[str, str], int] = {}

app = FastAPI(title="Local Demo DNS", version="1.0.0")


def _answer_for(client_ip: str, qname: str) -> tuple[list[str], str]:
    """Return (ipv4 addresses, rcode) for an A query."""
    zone = ZONES.get(qname)
    if zone is None:
        return [], dns.rcode.to_text(dns.rcode.NXDOMAIN)
    if "a" in zone:
        return list(zone["a"]), "NOERROR"
    if "rebind_a" in zone:
        key = (client_ip, qname)
        with _state_lock:
            index = _rebind_counters.get(key, 0)
            _rebind_counters[key] = index + 1
        answers = zone["rebind_a"]
        return [answers[min(index, len(answers) - 1)]], "NOERROR"
    return [], dns.rcode.to_text(dns.rcode.NXDOMAIN)


def _handle_query(wire: bytes, client_ip: str) -> bytes:
    query = dns.message.from_wire(wire)
    reply = dns.message.make_response(query)
    if not query.question:
        reply.set_rcode(dns.rcode.FORMERR)
        return reply.to_wire()

    question = query.question[0]
    qname = question.name.to_text(omit_final_dot=True).lower()
    qtype = dns.rdatatype.to_text(question.rdtype)

    entry = {
        "ts": round(time.time(), 3),
        "client": client_ip,
        "qname": qname,
        "qtype": qtype,
    }

    if qtype != "A" or question.rdclass != dns.rdataclass.IN:
        # The portal only ever asks for IN A; reply NXDOMAIN for anything
        # else (e.g. AAAA) rather than inventing out-of-scope records.
        entry["rcode"] = "NXDOMAIN"
        entry["answers"] = []
        reply.set_rcode(dns.rcode.NXDOMAIN)
    else:
        addresses, rcode = _answer_for(client_ip, qname)
        entry["rcode"] = rcode
        entry["answers"] = addresses
        if addresses:
            rrset = dns.rrset.from_text(question.name, 300, "IN", "A", *addresses)
            reply.answer.append(rrset)
            reply.flags |= dns.flags.AA
        else:
            reply.set_rcode(dns.rcode.NXDOMAIN)

    with _state_lock:
        _query_log.append(entry)
    return reply.to_wire()


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, socket_ = self.request
        response = _handle_query(data, self.client_address[0])
        socket_.sendto(response, self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        # DNS over TCP: 2-byte big-endian length prefix, then the message.
        prefix = self._recv_exact(2)
        if prefix is None:
            return
        length = int.from_bytes(prefix, "big")
        wire = self._recv_exact(length)
        if wire is None:
            return
        response = _handle_query(wire, self.client_address[0])
        self.request.sendall(len(response).to_bytes(2, "big") + response)

    def _recv_exact(self, size: int) -> bytes | None:
        chunks = []
        remaining = size
        while remaining:
            chunk = self.request.recv(remaining)
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)


class _ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/records", summary="Configured demo zone data")
def records():
    return ZONES


@app.get("/queries", summary="Every DNS query this server has answered")
def queries():
    with _state_lock:
        return {
            "queries": list(_query_log),
            "rebind_counters": {
                f"{client} {name}": count for (client, name), count in _rebind_counters.items()
            },
        }


@app.post("/queries/clear", summary="Reset the query log and rebind rotation state")
def clear_queries():
    with _state_lock:
        _query_log.clear()
        _rebind_counters.clear()
    return {"status": "cleared"}


def _serve_dns() -> None:
    udp_server = _ThreadingUDPServer((DNS_BIND_HOST, DNS_BIND_PORT), UDPHandler)
    tcp_server = _ThreadingTCPServer((DNS_BIND_HOST, DNS_BIND_PORT), TCPHandler)
    threading.Thread(target=udp_server.serve_forever, daemon=True).start()
    threading.Thread(target=tcp_server.serve_forever, daemon=True).start()


if __name__ == "__main__":
    _serve_dns()
    uvicorn.run(app, host="0.0.0.0", port=HTTP_PORT)
