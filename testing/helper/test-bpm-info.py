#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import gzip
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest


SHIRUDO = str(Path(sys.argv.pop(1)).resolve())
README = b"# Example package\n\nPackage documentation without a final newline."


def package_bytes(entries):
    body = io.BytesIO()
    with tarfile.open(fileobj=body, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in entries:
            header = tarfile.TarInfo(name)
            header.size = len(content)
            archive.addfile(header, io.BytesIO(content))
    return body.getvalue()


def package(readme=README):
    entries = [("example-1.0/Beefile", b'[package]\nname = "example"\n')]
    if readme is not None:
        entries.append(("example-1.0/README.md", readme))
    return package_bytes(entries)


def staged_downloads():
    return [name for name in os.listdir("/tmp")
            if name.startswith("shirudo-bpm-")]


def open_files(pid):
    """None when the process is not dumpable and the runner is not root."""
    try:
        fds = os.listdir(f"/proc/{pid}/fd")
    except PermissionError:
        return None
    links = []
    for fd in fds:
        try:
            links.append(os.readlink(f"/proc/{pid}/fd/{fd}"))
        except OSError:
            pass
    return links


class BpmTestCase(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="shirudo-bpm-info-test-")
        self.root = Path(self.work.name)
        self.addCleanup(self.work.cleanup)

    def env(self):
        env = {**os.environ, "BPM_OCI_SCHEME": "http",
               "REGISTRY_AUTH_FILE": str(self.root / "absent-auth.json"),
               "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}
        env.pop("BPM_OCI_CA_FILE", None)
        env.pop("BPM_OCI_USERNAME", None)
        env.pop("BPM_OCI_PASSWORD", None)
        return env

    def run_bpm(self, *args):
        return subprocess.run([SHIRUDO, "bpm", *args], cwd=self.root,
                              capture_output=True, env=self.env())


class InfoTests(BpmTestCase):

    def run_info(self, *args):
        return self.run_bpm("info", *args)

    def local(self, body):
        path = self.root / "package.bee"
        path.write_bytes(body)
        return self.run_info(str(path))

    def test_local_readme_is_exact(self):
        result = self.local(package())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, README)
        self.assertEqual(list(self.root.iterdir()), [self.root / "package.bee"])

    def test_readme_controls_show_as_question_marks(self):
        readme = (b"# T\x1b]0;x\x07itle\r\nline\rover\n"
                  b"\xc2\x9b2J caf\xc3\xa9 \xff\n")
        result = self.local(package(readme))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout,
                         b"# T?]0;x?itle\r\nline?over\n??2J caf\xc3\xa9 ?\n")

    def test_member_name_controls_show_as_question_marks(self):
        path = self.root / "package.bee"
        path.write_bytes(package_bytes([
            ("example-1.0/Beefile", b'[package]\nname = "example"\n'),
            ("example-1.0/upatches/a\x1b[2Jb.upatch", b"x"),
        ]))
        result = self.run_info("upatches", str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"upatches/a?[2Jb.upatch\n")

    def test_empty_readme(self):
        result = self.local(package(b""))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_missing_readme(self):
        result = self.local(package(None))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"README.md", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_missing_beefile(self):
        result = self.local(package_bytes([("example-1.0/README.md", README)]))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Beefile", result.stderr)

    def test_readme_belongs_to_beefile_directory(self):
        result = self.local(package_bytes([
            ("other-1.0/README.md", b"wrong README"),
            ("example-1.0/Beefile", b'[package]\nname = "example"\n'),
            ("example-1.0/README.md", README),
        ]))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, README)

    def test_unrelated_readme_is_not_used(self):
        result = self.local(package_bytes([
            ("example-1.0/Beefile", b'[package]\nname = "example"\n'),
            ("other-1.0/README.md", README),
        ]))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_non_regular_readme_is_rejected(self):
        body = io.BytesIO()
        with tarfile.open(fileobj=body, mode="w:gz") as archive:
            header = tarfile.TarInfo("example-1.0/Beefile")
            archive.addfile(header, io.BytesIO())
            header = tarfile.TarInfo("example-1.0/README.md")
            header.type = tarfile.SYMTYPE
            header.linkname = "/etc/passwd"
            archive.addfile(header)
        result = self.local(body.getvalue())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def headers(self, mutate):
        body = io.BytesIO()
        beefile = b'[package]\nname = "example"\n'
        with tarfile.open(fileobj=body, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, content in (("example-1.0/Beefile", beefile),
                                  ("example-1.0/README.md", README)):
                header = tarfile.TarInfo(name)
                header.size = len(content)
                archive.addfile(header, io.BytesIO(content))
        tar = bytearray(body.getvalue())
        # The README's header follows the Beefile's header and one data block.
        mutate(tar, 1024)
        return gzip.compress(bytes(tar))

    @staticmethod
    def checksum(tar, at):
        tar[at + 148:at + 156] = b" " * 8
        tar[at + 148:at + 156] = b"%06o\0 " % sum(tar[at:at + 512])

    def test_a_recomputed_checksum_is_accepted(self):
        result = self.local(self.headers(lambda tar, at: self.checksum(tar, at)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, README)

    def test_a_header_whose_checksum_fails_is_refused(self):
        def flip(tar, at):
            tar[at + 3] ^= 1
        result = self.local(self.headers(flip))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_a_size_field_with_a_stray_byte_is_refused(self):
        def stray(tar, at):
            tar[at + 124:at + 136] = b"%010o" % len(README) + b"x\0"
            self.checksum(tar, at)
        result = self.local(self.headers(stray))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_invalid_and_truncated_archives(self):
        for body in (b"not a package", package()[:30]):
            with self.subTest(body=body):
                result = self.local(body)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")

    def test_oversized_readme(self):
        result = self.local(package(b"x" * (4 * 1024 * 1024 + 1)))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_usage_and_help(self):
        self.assertEqual(self.run_info().returncode, 2)
        self.assertEqual(self.run_info("one", "two").returncode, 2)
        result = self.run_info("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"package-file|package-reference", result.stderr)

    def test_invalid_oci_reference(self):
        result = self.run_info("oci://registry.example/package")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_oci_readme_and_integrity(self):
        blob = package()
        digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        for expected_digest, size, success in (
            (digest, len(blob), True),
            ("sha256:" + "0" * 64, len(blob), False),
            (digest, len(blob) + 1, False),
        ):
            with self.subTest(digest=expected_digest, size=size):
                manifest = json.dumps({
                    "schemaVersion": 2,
                    "layers": [{
                        "mediaType": "application/vnd.shirudo.bpm.package.v1+gzip",
                        "digest": expected_digest, "size": size,
                    }],
                }).encode()
                requests = []

                class Handler(http.server.BaseHTTPRequestHandler):
                    def log_message(self, *_args):
                        pass

                    def do_GET(self):
                        requests.append(self.path)
                        if self.path == "/v2/test/example/manifests/1.0":
                            payload = manifest
                        elif self.path == "/v2/test/example/blobs/" + expected_digest:
                            payload = blob
                        else:
                            self.send_error(404)
                            return
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(payload)))
                        self.end_headers()
                        self.wfile.write(payload)

                server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    reference = f"oci://127.0.0.1:{server.server_port}/test/example:1.0"
                    result = self.run_info(reference)
                    self.assertEqual(list(self.root.iterdir()), [])
                    if success:
                        pulled = self.run_bpm("pull", reference)
                        self.assertEqual(pulled.returncode, 0, pulled.stderr)
                        path = self.root / "example-1.0.bee"
                        self.assertEqual(path.read_bytes(), blob)
                        path.unlink()
                finally:
                    server.shutdown()
                    thread.join()
                    server.server_close()
                self.assertEqual(result.returncode == 0, success, result.stderr)
                self.assertEqual(result.stdout, README if success else b"")
                self.assertEqual(len(requests), 4 if success else 2)
                self.assertEqual(list(self.root.iterdir()), [])


class Registry:
    """Serves one package blob; with hold set, stops halfway until released."""

    def __init__(self, blob, hold=False):
        self.digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        self.halfway = threading.Event()
        self.release = threading.Event()
        manifest = json.dumps({
            "schemaVersion": 2,
            "layers": [{
                "mediaType": "application/vnd.shirudo.bpm.package.v1+gzip",
                "digest": self.digest, "size": len(blob),
            }],
        }).encode()
        registry = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                if self.path == "/v2/test/example/manifests/1.0":
                    payload = manifest
                elif self.path == "/v2/test/example/blobs/" + registry.digest:
                    payload = blob
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if payload is blob and hold:
                    self.wfile.write(payload[:len(payload) // 2])
                    self.wfile.flush()
                    registry.halfway.set()
                    registry.release.wait(30)
                    payload = payload[len(payload) // 2:]
                self.wfile.write(payload)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.reference = f"oci://127.0.0.1:{self.server.server_port}/test/example:1.0"

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()


class MemoryTests(BpmTestCase):
    """A download bpm reads is kept in memory, never in a file of /tmp."""

    def test_oci_download_stays_in_memory(self):
        blob = package(readme=README + b"x" * 300000)
        registry = Registry(blob, hold=True)
        self.addCleanup(registry.close)
        before = set(staged_downloads())
        proc = subprocess.Popen([SHIRUDO, "bpm", "info", registry.reference],
                                cwd=self.root, env=self.env(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertTrue(registry.halfway.wait(30))
        staged = set(staged_downloads()) - before
        links = open_files(proc.pid)
        registry.release.set()
        out, err = proc.communicate(timeout=60)
        self.assertEqual(proc.returncode, 0, err)
        self.assertTrue(out.startswith(README), out[:80])
        self.assertFalse(staged, staged)
        if links is None:
            return
        self.assertTrue(any(link.startswith("/memfd:shirudo-bpm-package")
                            for link in links), links)
        self.assertFalse([link for link in links if link.startswith("/tmp/")],
                         links)

    def test_key_fingerprint_of_file_package_and_download(self):
        key, cert = self.root / "key.pem", self.root / "cert.der"
        made = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec",
             "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
             "-keyout", str(key), "-outform", "DER", "-out", str(cert),
             "-days", "1", "-subj", "/CN=bpm-info"],
            capture_output=True)
        if made.returncode:
            self.skipTest("openssl cannot make a certificate")
        bee = self.root / "example.bee"
        bee.write_bytes(package_bytes([
            ("example-1.0/Beefile", b'[package]\nname = "example"\n'),
            ("example-1.0/cert.der", cert.read_bytes())]))
        registry = Registry(bee.read_bytes())
        self.addCleanup(registry.close)
        prints = [self.run_bpm("key", "fingerprint", source)
                  for source in (str(cert), str(bee), registry.reference)]
        for result in prints:
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(prints[0].stdout.strip()), 64)
        self.assertEqual({result.stdout for result in prints},
                         {prints[0].stdout})


if __name__ == "__main__":
    unittest.main()
