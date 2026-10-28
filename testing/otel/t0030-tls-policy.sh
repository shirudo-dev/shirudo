#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0030 -- outbound TLS policy: every libcurl client shirudo opens requires
# TLS 1.3 and a hybrid ML-KEM key exchange, nothing classical. Drives the
# OTLP log exporter (`shirudo status --otel`) against local servers: a
# TLS 1.2-only HTTPS server, which must be refused before any request
# reaches it; an `openssl s_server` limited to X25519, which must also be
# refused; and an `openssl s_server` with handshake tracing, which must
# see X25519MLKEM768 offered and select it. The s_server cases need an
# OpenSSL >= 3.5 (skipped otherwise); the first runs everywhere.

cd "$(dirname "$0")/.."
. ./test-lib.sh

S=${SHIRUDO:-../shirudo}

command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ -x "$S" ] || test_skip_all "shirudo not built"

WORK=$(mktemp -d)
# s_server has usually exited on its own by now; under set -e a failed
# kill must not abort the loop before the TLS 1.2 server is reached.
cleanup() {
	for p in "$WORK"/*.pid; do
		[ -e "$p" ] || continue
		kill "$(cat "$p")" 2>/dev/null || :
	done
	rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-subj /CN=localhost -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' \
	-days 2 -keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1 ||
	test_skip_all "openssl could not mint a test certificate"

cat >"$WORK/tls12-server.py" <<'PY'
import http.server, ssl, sys
port, cert, key, seen = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        open(seen, "w").write("request\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain(cert, key)
srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PY

free_port() {
	python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

wait_for_port() {
	i=0
	while ! python3 -c 'import socket, sys
s = socket.socket()
s.settimeout(0.2)
sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)' "$1" 2>/dev/null; do
		i=$((i + 1))
		[ "$i" -lt 100 ] || return 1
		sleep .05
	done
}

# The exporter is the TLS client under test; the test certificate is its
# trust anchor so the policy, not certificate verification, decides.
export_status() {
	OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="https://127.0.0.1:$1/v1/logs" \
	OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE="$WORK/cert.pem" \
	OTEL_EXPORTER_OTLP_LOGS_TIMEOUT=3000 \
		timeout 60 "$S" status --otel >/dev/null 2>"$WORK/client.err"
}

port12=$(free_port)
python3 "$WORK/tls12-server.py" "$port12" "$WORK/cert.pem" "$WORK/key.pem" \
	"$WORK/seen" >"$WORK/tls12.log" 2>&1 &
echo $! >"$WORK/tls12.pid"
wait_for_port "$port12" || test_skip_all "TLS 1.2 test server did not start"

test_expect_success 'a TLS 1.2-only collector is refused before any request is sent' '
	! export_status "$port12" &&
	grep -q "OTEL export failed" "$WORK/client.err" &&
	! test -e "$WORK/seen"
'

if openssl list -tls1_3 -tls-groups 2>/dev/null | grep -qi 'X25519MLKEM768'; then
	portx=$(free_port)
	openssl s_server -accept "$portx" -cert "$WORK/cert.pem" -key "$WORK/key.pem" \
		-tls1_3 -groups X25519 -naccept 1 -www -trace >"$WORK/trace-x25519.log" 2>&1 &
	echo $! >"$WORK/s_server_x.pid"
	i=0
	while ! grep -q '^ACCEPT' "$WORK/trace-x25519.log" 2>/dev/null; do
		i=$((i + 1))
		[ "$i" -lt 100 ] || test_skip_all "openssl s_server did not start"
		sleep .05
	done

	test_expect_success 'a TLS 1.3 server offering only classical X25519 is refused' '
		! export_status "$portx" &&
		grep -q "OTEL export failed" "$WORK/client.err" &&
		! grep -q "ServerHello, Length" "$WORK/trace-x25519.log"
	'

	port13=$(free_port)
	openssl s_server -accept "$port13" -cert "$WORK/cert.pem" -key "$WORK/key.pem" \
		-tls1_3 -naccept 1 -www -trace >"$WORK/trace.log" 2>&1 &
	echo $! >"$WORK/s_server.pid"
	# s_server serves exactly one connection, so poll its own ACCEPT line
	# rather than connecting to it.
	i=0
	while ! grep -q '^ACCEPT' "$WORK/trace.log" 2>/dev/null; do
		i=$((i + 1))
		[ "$i" -lt 100 ] || test_skip_all "openssl s_server did not start"
		sleep .05
	done
	export_status "$port13" || :

	test_expect_success 'the client offers X25519MLKEM768 as its first key share' '
		awk "/ClientHello, Length/{c=1} /ServerHello, Length/{c=0} c" "$WORK/trace.log" |
			grep "NamedGroup:" | head -1 | grep -q "X25519MLKEM768"
	'

	test_expect_success 'the server selects X25519MLKEM768 for the key exchange' '
		awk "/ServerHello, Length/{s=1} s" "$WORK/trace.log" |
			grep -q "NamedGroup: X25519MLKEM768"
	'

	test_expect_success 'the handshake is TLS 1.3' '
		awk "/ServerHello, Length/{s=1} s" "$WORK/trace.log" |
			grep -q "supported_versions"
	'
else
	printf '# openssl lacks X25519MLKEM768 (needs OpenSSL >= 3.5); hybrid key exchange case not run\n'
fi

test_done
