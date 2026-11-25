#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

"""Exercise BPM keys, isolating writes in a private mount namespace."""

import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading


def main():
    binary = str(Path(sys.argv[1]).resolve())
    isolated = sys.argv[2:] == ["--isolated-keys"]
    with tempfile.TemporaryDirectory(prefix="shirudo-bpm-key-test-") as tmp:
        root = Path(tmp)
        var_lib = root / "var-lib"
        etc = root / "etc"
        keys = var_lib / "shirudo/keys"
        registry = etc / "shirudo/bpm"
        prefix = []
        if isolated:
            var_lib.mkdir()
            etc.mkdir()
            prefix = ["unshare", "--mount", "--propagation", "private", "sh", "-ec",
                      'mount --bind "$1" /var/lib && mount --bind "$2" /etc && '
                      'shift 2 && exec "$@"', "test-bpm-key", str(var_lib), str(etc)]
        env = dict(os.environ, BPM_OCI_SCHEME="http", NO_PROXY="127.0.0.1",
                   no_proxy="127.0.0.1",
                   REGISTRY_AUTH_FILE=str(root / "absent-auth.json"))
        for name in ("BPM_OCI_CA_FILE", "BPM_OCI_USERNAME", "BPM_OCI_PASSWORD"):
            env.pop(name, None)

        def bpm(*args):
            return subprocess.run([*prefix, binary, "bpm", *args], cwd=root,
                                  env=env, capture_output=True, text=True)

        def run(*args, ok=True):
            result = bpm("key", *args)
            assert (result.returncode == 0) == ok, (args, result)
            return result.stdout.strip()

        def openssl(*args, body=None):
            return subprocess.run(["openssl", *args], cwd=root, input=body,
                                  capture_output=True, check=True).stdout

        def certificate(name, newkey="ML-DSA-87"):
            pem = root / f"{name}.pem"
            der = root / f"{name}.der"
            openssl("req", "-x509", "-newkey", newkey, "-nodes",
                    "-keyout", f"{name}.key", "-out", str(pem),
                    "-days", "1", "-subj", f"/CN={name}")
            openssl("x509", "-in", str(pem), "-outform", "DER", "-out", str(der))
            pub = openssl("x509", "-in", str(pem), "-pubkey", "-noout")
            spki = openssl("pkey", "-pubin", "-outform", "DER", body=pub)
            return pem, der, hashlib.sha256(spki).hexdigest()

        def package(name, cert, member="demo/cert.der", kind=tarfile.REGTYPE):
            path = root / name
            with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
                entry = tarfile.TarInfo(member)
                entry.type = kind
                entry.size = len(cert)
                archive.addfile(entry, io.BytesIO(cert))
            return path

        pem, der, fingerprint = certificate("first")
        _, other, other_fp = certificate("second")
        _, classical, classical_fp = certificate("classical", "rsa:2048")
        bee = package("package.bee", der.read_bytes())
        assert run("--list-cmds").splitlines() == ["add", "fingerprint", "list"]
        for command in ("add", "fingerprint", "list"):
            run(command, "--help")
        for args in (("add",), ("fingerprint",), ("list", "extra"),
                     ("fingerprint", str(bee), "extra"), ("invalid",)):
            run(*args, ok=False)
        assert run("fingerprint", str(der)) == fingerprint
        assert run("fingerprint", str(pem)) == fingerprint
        assert run("fingerprint", str(bee)) == fingerprint
        assert run("fingerprint", str(classical)) == classical_fp
        assert hashlib.sha256(der.read_bytes()).hexdigest() != fingerprint
        (root / "invalid.der").write_text("not a certificate")
        run("fingerprint", str(root / "invalid.der"), ok=False)
        run("fingerprint", str(root / "missing.bee"), ok=False)
        for name, member, kind in (
                ("missing.bee", "demo/other", tarfile.REGTYPE),
                ("nested.bee", "demo/nested/cert.der", tarfile.REGTYPE),
                ("traversal.bee", "../cert.der", tarfile.REGTYPE),
                ("symlink.bee", "demo/cert.der", tarfile.SYMTYPE)):
            bad = package(name, der.read_bytes(), member, kind)
            run("fingerprint", str(bad), ok=False)
        print("certificate and package fingerprints, help, and invalid inputs: passed")

        if isolated:
            assert json.loads(run("list", "--json"))["fingerprints"] == []
            refused = bpm("key", "add", str(classical))
            assert refused.returncode and "accepts only ML-DSA-87" in refused.stderr, refused
            assert not keys.exists()
            register = ("config", "register", "add", "src", "oci://registry.example", "--cert")
            refused = bpm(*register, str(classical))
            assert refused.returncode == 2 and "accepts only ML-DSA-87" in refused.stderr, refused
            assert not registry.exists()
            added = bpm(*register, str(pem))
            assert added.returncode == 0, added
            assert (registry / "keys/src.der").read_bytes() == der.read_bytes()
            assert (registry / "registries.d/src.conf").is_file()
            assert run("add", str(pem)) == fingerprint
            assert os.readlink(keys / "cert.der") == f"/var/lib/shirudo/keys/{fingerprint}.der"
            assert (keys / f"{fingerprint}.der").read_bytes() == der.read_bytes()
            assert run("add", str(bee)) == fingerprint
            assert (keys / f"{fingerprint}.der").read_bytes() == der.read_bytes()
            run("add", str(other), ok=False)
            assert not (keys / f"{other_fp}.der").exists()
            shutil.copyfile(other, keys / f"{other_fp}.der")
            (keys / ("0" * 64 + ".der")).write_bytes(der.read_bytes())
            (keys / ("1" * 64 + ".der")).write_text("invalid")
            (keys / ("2" * 64 + ".der")).symlink_to(der)
            (keys / ("3" * 64 + ".der")).mkdir()
            assert json.loads(run("list", "--json"))["fingerprints"] == sorted([fingerprint, other_fp])
            (keys / f"{other_fp}.der").unlink()
            (keys / f"{other_fp.upper()}.DER").write_bytes(other.read_bytes())
            assert json.loads(run("list", "--json"))["fingerprints"] == sorted([fingerprint, other_fp])
            print("isolated key installation, repeat add, replacement refusal, sorted listing: passed")

        payload = bee.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        media = "application/vnd.shirudo.bpm.package.v1+gzip"

        class Registry(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if "/manifests/" in self.path:
                    tag = self.path.rsplit("/", 1)[1]
                    layer = dict(mediaType=media, digest=f"sha256:{digest}",
                                 size=len(payload), annotations={
                                     "org.opencontainers.image.title": "download.bee"})
                    if tag == "bad-digest":
                        layer["digest"] = "sha256:" + "0" * 64
                    elif tag == "bad-size":
                        layer["size"] += 1
                    elif tag == "missing-layer":
                        layer["mediaType"] = "application/octet-stream"
                    elif tag == "escape-title":
                        layer["annotations"]["org.opencontainers.image.title"] = \
                            "\x1b[2Jdownload.bee"
                    body = json.dumps(dict(schemaVersion=2, layers=[layer])).encode()
                    content_type = "application/vnd.oci.image.manifest.v1+json"
                elif "/blobs/" in self.path:
                    body, content_type = payload, media
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Registry)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            reference = f"oci://127.0.0.1:{server.server_port}/demo/package:"
            assert run("fingerprint", reference + "valid") == fingerprint
            if isolated:
                assert run("add", reference + "valid") == fingerprint
                assert (keys / f"{fingerprint}.der").read_bytes() == der.read_bytes()
            for tag in ("bad-digest", "bad-size", "missing-layer"):
                run("fingerprint", reference + tag, ok=False)
                if isolated:
                    run("add", reference + tag, ok=False)
                    assert (keys / f"{fingerprint}.der").read_bytes() == der.read_bytes()
            def pull(tag):
                return subprocess.run([binary, "bpm", "pull", reference + tag],
                                      cwd=root, env=env, capture_output=True,
                                      text=True)

            assert not (root / "download.bee").exists()
            result = pull("valid")
            assert result.returncode == 0, result
            assert (root / "download.bee").read_bytes() == payload
            # The registry names the file, so a pull never replaces one, nor
            # removes it when the download then fails its digest.
            for tag in ("valid", "bad-digest"):
                result = pull(tag)
                assert result.returncode != 0, result
                assert "exists" in result.stderr, result
                assert (root / "download.bee").read_bytes() == payload
            result = pull("escape-title")
            assert result.returncode == 0, result
            assert (root / "package-escape-title.bee").read_bytes() == payload
            assert not any("\x1b" in p.name for p in root.iterdir())
            print("OCI keys, descriptor rejection, private downloads, and pull: passed")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    main()
