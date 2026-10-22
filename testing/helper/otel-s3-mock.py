#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
"""Combined S3 PUT and OTLP log sink used by t0014."""

import gzip
import hashlib
import hmac
import http.server
import json
import pathlib
import sys
import time


mode, port_file, snapshot_file, log_file, meta_file = sys.argv[1:6]
requests = []
put_attempts = 0


def sigv4_valid(handler):
    """Verify the libcurl AWS4 signature used by all test requests."""
    authorization = handler.headers.get("Authorization", "")
    try:
        algorithm, fields_text = authorization.split(" ", 1)
        fields = dict(field.split("=", 1)
                      for field in fields_text.split(", "))
        access, scope = fields["Credential"].split("/", 1)
        date, region, service, terminal = scope.split("/")
        signed = fields["SignedHeaders"].split(";")
        canonical_headers = "".join(
            f"{name}:{' '.join(handler.headers[name].strip().split())}\n"
            for name in signed
        )
        path, _, query = handler.path.partition("?")
        canonical_request = "\n".join([
            handler.command,
            path,
            query,
            canonical_headers,
            ";".join(signed),
            handler.headers["x-amz-content-sha256"],
        ])
        request_hash = hashlib.sha256(canonical_request.encode()).hexdigest()
        string_to_sign = "\n".join([
            algorithm,
            handler.headers["x-amz-date"],
            scope,
            request_hash,
        ])
        key = hmac.new(b"AWS4secret", date.encode(), hashlib.sha256).digest()
        key = hmac.new(key, region.encode(), hashlib.sha256).digest()
        key = hmac.new(key, service.encode(), hashlib.sha256).digest()
        key = hmac.new(key, terminal.encode(), hashlib.sha256).digest()
        signature = hmac.new(key, string_to_sign.encode(),
                             hashlib.sha256).hexdigest()
        return (algorithm == "AWS4-HMAC-SHA256" and access == "test" and
                bool(region) and service == "s3" and
                terminal == "aws4_request" and
                hmac.compare_digest(signature, fields["Signature"]))
    except (KeyError, ValueError):
        return False


def save_meta():
    pathlib.Path(meta_file).write_text(json.dumps({
        "requests": requests,
        "put_attempts": put_attempts,
    }))


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def read_body(self):
        return self.rfile.read(int(self.headers.get("Content-Length", "0")))

    def reply(self, status, body=b"{}"):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        global put_attempts
        put_attempts += 1
        body = self.read_body()
        pathlib.Path(snapshot_file).write_bytes(body)
        requests.append({
            "method": "PUT",
            "path": self.path,
            "authorization": self.headers.get("Authorization", ""),
            "content_type": self.headers.get("Content-Type", ""),
            "content_encoding": self.headers.get("Content-Encoding", ""),
            "content_sha256": self.headers.get("x-amz-content-sha256", ""),
            "checksum_sha256": self.headers.get("x-amz-checksum-sha256", ""),
            "if_none_match": self.headers.get("If-None-Match", ""),
            "cache_control": self.headers.get("Cache-Control", ""),
            "security_token": self.headers.get("x-amz-security-token", ""),
            "tenant_id": self.headers.get("X-Tenant-ID", ""),
            "sigv4_valid": sigv4_valid(self),
            "region": self.headers["Authorization"].split(
                "Credential=", 1)[1].split("/", 3)[2]
            if "Credential=" in self.headers.get("Authorization", "") else "",
        })
        save_meta()
        if mode == "s3-fail":
            self.reply(403)
            self.server.done = True
        elif mode == "s3-retry" and put_attempts == 1:
            self.reply(503)
        elif mode.startswith("s3-retry-") and put_attempts == 1:
            self.reply(int(mode.rsplit("-", 1)[1]))
        elif mode == "s3-exhaust":
            self.reply(503)
            self.server.done = put_attempts >= 2
        elif mode == "exists":
            self.reply(412)
        else:
            self.reply(200)

    def do_POST(self):
        body = self.read_body()
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        pathlib.Path(log_file).write_bytes(body)
        requests.append({
            "method": "POST",
            "path": self.path,
            "content_encoding": self.headers.get("Content-Encoding", ""),
            "tenant_id": self.headers.get("X-Tenant-ID", ""),
        })
        save_meta()
        if mode in {"otel-fail", "otel-retry"} and len(
                [request for request in requests if request["method"] == "POST"]
        ) == 1:
            self.reply(503)
            self.server.done = mode == "otel-fail"
        else:
            self.reply(200)
            self.server.done = True

    def log_message(self, *args):
        pass


server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
server.timeout = 5
server.done = False
pathlib.Path(port_file).write_text(str(server.server_port))
deadline = time.monotonic() + 20
while not server.done and time.monotonic() < deadline:
    server.handle_request()
if not server.done:
    raise SystemExit("mock timed out waiting for request sequence")
