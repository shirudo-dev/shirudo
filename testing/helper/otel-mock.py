#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
"""OTLP/HTTP sink for the exporter tests.

usage: otel-mock.py <success|retry|partial> <port-file> <body-file>
                    <meta-file> [<cert.pem> <key.pem>]

Listens on an ephemeral loopback port (written to <port-file> once
bound), serves until the exchange the mode describes is complete, then
exits 0 so a test can `wait` for it:

  success  the first request is accepted with 200 {}
  retry    the first two requests fail with 503, the third succeeds
  partial  the first request gets 200 with a partialSuccess body, which
           the exporter must treat as a non-retryable failure

The last request body (gzip-decoded when announced) is written as JSON
to <body-file>; <meta-file> records the attempt count, the request path
and, when sent, the Authorization and Content-Encoding headers. With a
certificate and key the sink speaks HTTPS.
"""

import gzip
import http.server
import json
import pathlib
import ssl
import sys
import time


mode, port_file, body_file, meta_file = sys.argv[1:5]
tls = sys.argv[5:7]
attempts = 0
meta = {}
request_times = []


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def reply(self, status, body, headers=None):
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        global attempts, meta
        attempts += 1
        request_times.append(time.monotonic())
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.headers.get("Content-Encoding", "").lower() == "gzip":
            raw = gzip.decompress(raw)
        meta = {"attempts": attempts, "path": self.path,
                "raw_bytes": len(raw)}
        if len(request_times) > 1:
            meta["interval_ms"] = round(
                (request_times[-1] - request_times[-2]) * 1000)
        if self.headers.get("Authorization"):
            meta["authorization"] = self.headers["Authorization"]
        if self.headers.get("Content-Type"):
            meta["content_type"] = self.headers["Content-Type"]
        if self.headers.get("Content-Encoding"):
            meta["content_encoding"] = self.headers["Content-Encoding"]
        try:
            document = json.loads(raw)
        except ValueError:
            document = {"invalid": raw.decode(errors="replace")}
        pathlib.Path(body_file).write_text(json.dumps(document, indent=1))
        pathlib.Path(meta_file).write_text(json.dumps(meta))

        if mode == "retry" and attempts < 3:
            self.reply(503, {"message": "try again"})
            return
        if mode.startswith("retry-") and mode not in {
                "retry-after", "retry-exhaust-503"}:
            status = int(mode.split("-")[1])
            if attempts == 1:
                self.reply(status, {"message": "try again"})
                return
        if mode == "retry-after" and attempts == 1:
            self.reply(503, {"message": "try again"}, {"Retry-After": "1"})
            return
        if mode == "retry-exhaust-503":
            self.reply(503, {"message": "try again"})
            self.server.done = attempts >= 3
            return
        if mode.startswith("fatal-"):
            self.reply(int(mode.split("-")[1]), {"message": "not retryable"})
            self.server.done = True
            return
        if mode == "disconnect":
            self.close_connection = True
            self.server.done = True
            return
        if mode == "timeout":
            time.sleep(0.3)
            self.reply(200, {})
            self.server.done = True
            return
        if mode == "partial-zero":
            self.reply(200, {"partialSuccess": {"rejectedLogRecords": "0"}})
        elif mode == "malformed":
            self.reply(200, b"not-json")
        elif mode == "partial":
            self.reply(200, {"partialSuccess": {"rejectedLogRecords": 1,
                                                 "errorMessage": "rejected by mock"}})
        else:
            self.reply(200, {})
        self.server.done = True


server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
server.done = False
if tls:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tls[0], tls[1])
    server.socket = context.wrap_socket(server.socket, server_side=True)
pathlib.Path(port_file).write_text(f"{server.server_address[1]}\n")
server.timeout = 0.25
while not server.done:
    server.handle_request()
    if mode == "no-request" and attempts == 0:
        server.done = True
if mode == "no-request":
    pathlib.Path(meta_file).write_text(json.dumps({"attempts": attempts}))
server.server_close()
