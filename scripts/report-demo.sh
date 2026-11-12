#!/usr/bin/env bash
# End-to-end demo of the SSRF-hardened report download against the running
# stack (docker compose up). Fully offline: DNS, vendor and the internal
# decoy are all local services. Requires: curl, jq, python3 (+dnspython).
#
#   PORTAL_URL=http://localhost:8001 IDP_URL=http://localhost:9000 \
#   DNS_ADMIN_URL=http://localhost:1054 DNS_QUERY_HOST=127.0.0.1 DNS_QUERY_PORT=1053 \
#   DECOY_URL=http://localhost:8090 ./scripts/report-demo.sh
set -euo pipefail

PORTAL_URL="${PORTAL_URL:-http://localhost:8001}"
IDP_URL="${IDP_URL:-http://localhost:9000}"
DNS_ADMIN_URL="${DNS_ADMIN_URL:-http://localhost:1054}"
# DNS server used for a direct verification query (host/port reachable from
# wherever this script runs). Compose publishes UDP/53 on host port 1053.
DNS_QUERY_HOST="${DNS_QUERY_HOST:-127.0.0.1}"
DNS_QUERY_PORT="${DNS_QUERY_PORT:-1053}"
DECOY_URL="${DECOY_URL:-http://localhost:8090}"
# Vendor host/port. In Compose the vendor listens on 8080, which is also an
# allowed egress port, so its intranet redirect is blocked purely by CIDR.
VENDOR_HOST="${VENDOR_HOST:-vendor.reports.local}"
VENDOR_PORT="${VENDOR_PORT:-8080}"
VENDOR_BASE="http://${VENDOR_HOST}:${VENDOR_PORT}"

step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
json_post() { curl -sS -X POST "$1" -H 'content-type: application/json' -d "$2"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }
# POST {"url": ...} with an authenticated session.
fetch() { curl -sS -w '\n%{http_code}' -X POST "$PORTAL_URL/reports/download" \
  -H "Authorization: Bearer $SESSION" -H 'content-type: application/json' \
  -d "{\"url\":\"$1\"}"; }

step "0. fixed egress policy as visible from the portal"
curl -sS "$PORTAL_URL/debug/egress-policy" | jq .

step "1. establish a portal session (existing session auth)"
CODE=$(json_post "$IDP_URL/authorize" '{"sub":"carol","delay_seconds":0}' | jq -r .code)
SESSION=$(json_post "$PORTAL_URL/login" "{\"code\":\"$CODE\"}" | jq -r .session_id)
[ -n "$SESSION" ] && [ "$SESSION" != "null" ] || fail "no session returned"
echo "session acquired"

step "2. download WITHOUT a session -> 401"
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$PORTAL_URL/reports/download" \
  -H 'content-type: application/json' -d "{\"url\":\"$VENDOR_BASE/reports/diagnostic.txt\"}")
echo "status=$code (expect 401)"
[ "$code" = "401" ] || fail "unauthenticated download was not rejected"

# Reset the decoy's hit list and the DNS query/rebind state for clean assertions.
curl -sS -X POST "$DECOY_URL/requests/clear" >/dev/null
curl -sS -X POST "$DNS_ADMIN_URL/queries/clear" >/dev/null

step "3. NORMAL download: vendor report comes back as a full attachment"
BODY_FILE=$(mktemp)
HTTP=$(curl -sS -D - -o "$BODY_FILE" -w '%{http_code}' -X POST "$PORTAL_URL/reports/download" \
  -H "Authorization: Bearer $SESSION" -H 'content-type: application/json' \
  -d "{\"url\":\"$VENDOR_BASE/reports/diagnostic.txt\"}")
echo "$HTTP" | grep -iE '^HTTP/|content-disposition|content-type'
echo "--- attachment body ---"; cat "$BODY_FILE"; echo "-----------------------"
echo "$HTTP" | head -1 | grep -q ' 200' || fail "normal download did not return 200"
grep -qi 'content-disposition: attachment' <<<"$HTTP" || fail "response is not an attachment"
grep -q 'DIAGNOSTIC REPORT' "$BODY_FILE" || fail "report body mismatch"

step "4. REDIRECT INTO THE INTRANET: 400 and the decoy receives nothing"
# The redirect target resolves to an address outside the egress CIDR on the
# SAME allowed port, so the CIDR check - not the port check - refuses the hop.
RESP=$(fetch "$VENDOR_BASE/redirect/internal")
echo "status=$(echo "$RESP" | tail -1) (expect 400)"
echo "$RESP" | head -n -1 | jq -r .detail
[ "$(echo "$RESP" | tail -1)" = "400" ] || fail "intranet redirect was not refused"
echo "$RESP" | head -n -1 | jq -e '.detail | test("outside the allowed egress CIDRs")' >/dev/null \
  || fail "redirect was refused for the wrong reason (CIDR check expected)"

step "5. DNS REBIND: 1st answer approved, later answers point at the decoy"
echo "DNS answers configured for rebind.reports.local:"
curl -sS "$DNS_ADMIN_URL/records" | jq '."rebind.reports.local"'
# What makes this a real rebinding test: the name is queried exactly ONCE.
# The portal validates that answer, pins the approved address and opens the
# TCP connection to it with the original Host header - it never re-resolves,
# so the answer changing to the decoy on the next query cannot steer the
# connection. A 200 with ZERO decoy hits is the proof.
RESP=$(fetch "http://rebind.reports.local:8080/reports/diagnostic.txt")
echo "portal status: $(echo "$RESP" | tail -1) (expect 200 - pinned to the first, approved answer)"
[ "$(echo "$RESP" | tail -1)" = "200" ] || fail "rebind fetch did not succeed on the approved address"
echo "$RESP" | head -n -1 | grep -q 'DIAGNOSTIC REPORT' || fail "rebind fetch body mismatch"
echo "DNS query log for the rebind name (exactly ONE query, answer stays approved):"
curl -sS "$DNS_ADMIN_URL/queries" | jq '.queries[] | select(.qname=="rebind.reports.local")'
n_queries=$(curl -sS "$DNS_ADMIN_URL/queries" | jq '[.queries[] | select(.qname=="rebind.reports.local")] | length')
[ "$n_queries" = "1" ] || fail "expected exactly one DNS query, got $n_queries (re-resolution occurred!)"
echo "Two DIRECT lookups now show the rotation (1st approved, then the decoy forever):"
python3 - "$DNS_QUERY_HOST" "$DNS_QUERY_PORT" <<'PY'
import sys
import dns.resolver

host, port = sys.argv[1], int(sys.argv[2])
resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = [host]
resolver.port = port
for i in (1, 2, 3):
    answer = resolver.resolve("rebind.reports.local", "A")
    print(f"  direct lookup #{i}: {sorted(r.address for r in answer)}")
PY

step "6. MULTIPLE A RECORDS, one of them internal: 400 (every address is checked)"
RESP=$(fetch "http://multi.reports.local:8080/reports/diagnostic.txt")
echo "status: $(echo "$RESP" | tail -1) (expect 400)"
echo "$RESP" | head -n -1 | jq -r .detail
[ "$(echo "$RESP" | tail -1)" = "400" ] || fail "mixed-address answer was not refused"

step "7. policy rejects bad scheme, userinfo and disallowed ports before any fetch"
for payload in \
  "{\"url\":\"https://$VENDOR_HOST:8080/reports/diagnostic.txt\"}" \
  "{\"url\":\"http://carol:hunter2@$VENDOR_HOST:8080/reports/diagnostic.txt\"}" \
  "{\"url\":\"http://$VENDOR_HOST:22/reports/diagnostic.txt\"}" \
  '{"url":"http://intranet.internal:8080/secret"}' \
  '{"url":"http://172.31.20.66:8080/secret"}'; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$PORTAL_URL/reports/download" \
    -H "Authorization: Bearer $SESSION" -H 'content-type: application/json' -d "$payload")
  echo "  $payload -> $code (expect 400)"
  [ "$code" = "400" ] || fail "policy violation was not refused: $payload"
done

step "8. limits: >3 redirects, 5 s total timeout, 1 MiB body cap (no partial reports)"
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$PORTAL_URL/reports/download" \
  -H "Authorization: Bearer $SESSION" -H 'content-type: application/json' \
  -d "{\"url\":\"$VENDOR_BASE/redirect/loop\"}")
echo "  redirect loop -> $code (expect 400)"
[ "$code" = "400" ] || fail "redirect limit not enforced"

start=$(date +%s)
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$PORTAL_URL/reports/download" \
  -H "Authorization: Bearer $SESSION" -H 'content-type: application/json' \
  -d "{\"url\":\"$VENDOR_BASE/slow\"}")
elapsed=$(( $(date +%s) - start ))
echo "  slow upstream -> $code after ${elapsed}s (expect 504 within ~5s)"
[ "$code" = "504" ] || fail "total timeout not enforced"
[ "$elapsed" -le 7 ] || fail "total budget exceeded"

code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$PORTAL_URL/reports/download" \
  -H "Authorization: Bearer $SESSION" -H 'content-type: application/json' \
  -d "{\"url\":\"$VENDOR_BASE/too-large\"}")
echo "  2 MiB body -> $code (expect 502, no truncated attachment)"
[ "$code" = "502" ] || fail "body size cap not enforced"

step "9. no portal identity / cookies are forwarded; one allowed redirect works"
curl -sS -X POST "$PORTAL_URL/reports/download" \
  -H "Authorization: Bearer $SESSION" -H 'content-type: application/json' \
  -d "{\"url\":\"$VENDOR_BASE/echo\"}" | jq '{has_authorization, has_cookie, host: .headers.host, user_agent: .headers."user-agent"}'
curl -sS -X POST "$PORTAL_URL/reports/download" \
  -H "Authorization: Bearer $SESSION" -H 'content-type: application/json' \
  -d "{\"url\":\"$VENDOR_BASE/redirect/ok\"}" | head -3

step "10. ASSERTIONS: zero requests reached the decoy; inspect DNS traffic"
DECOY_HITS=$(curl -sS "$DECOY_URL/requests" | jq .count)
echo "decoy request count: $DECOY_HITS (expect 0)"
[ "$DECOY_HITS" = "0" ] || { curl -sS "$DECOY_URL/requests" | jq .; fail "the decoy was contacted!"; }
echo "DNS queries observed by the local resolver:"
curl -sS "$DNS_ADMIN_URL/queries" | jq .

rm -f "$BODY_FILE"
printf '\n\033[32mALL CHECKS PASSED\033[0m\n'
