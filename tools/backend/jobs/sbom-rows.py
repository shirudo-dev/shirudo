#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# jobs/sbom-rows.py -- the parts of jobs/sbom-scan and jobs/sbom-put that
# shell does not reach: reading image.json and the SBOMs, and the
# matcher's JSON.
#
#   sbom-rows.py files
#   sbom-rows.py images <store directory> <work directory>
#   sbom-rows.py rows <work directory> <scanned_at>
#   sbom-rows.py put <directory> <image_id> <image_version> <image_root or ->
#                    <built_at> <sbom>
#   sbom-rows.py stored <image.json> <sbom_sha256>
#
# files prints the names of the objects an image directory may hold that
# the job reads, one per line.
#
# images finds every <image_id>/<image_version>/<image_root or ->/image.json
# under the store and decides the state of each image. It copies every
# SBOM it accepts into the work directory, where the matcher reads it,
# and writes there images.json, what the next step needs, and
# images.tsv: per image its number, state, SBOM copy ("-" for none) and
# directory in the store, separated by tabs.
#
# rows reads those, the matcher's version.json and its output for each
# image, trivy-<number>.json, and writes sbom_images.jsonl and
# sbom_vulns.jsonl in ClickHouse's JSONEachRow format, with scanned_at,
# seconds since the epoch, on every row, and summary, one line per image
# loaded.
#
# put checks an image's key and build time and its CycloneDX SBOM as
# images would, and writes into the directory, which must be empty, the
# image.json and sbom.cdx.json that make the image's directory in the
# store. It prints the image's path in the store, the SHA-256 of the
# SBOM and the number of its components, separated by tabs.
#
# stored says whether the image.json of an image already in the store
# names that SHA-256 and format: status 0 when it does, 1 when it names
# another SBOM or cannot be read.
#
# Exit status: 0; 3 when an object or a matcher's output was left out and
# named on standard error, the rest written; 1 when nothing could be done
# or put refused the image; 2 for wrong usage.

import calendar
import hashlib
import json
import os
import re
import sys

PROG = "sbom-scan"
SEGMENT = re.compile(r"[A-Za-z0-9_~+-][A-Za-z0-9._~+-]{0,254}")
HEX64 = re.compile(r"[0-9a-f]{64}")
BUILT_AT = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")
DEFAULT_FORMAT = "cyclonedx-json"
UINT32_MAX = 2**32 - 1
LEFT_OUT = 3


class Refused(Exception):
    pass


def unique_keys(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise Refused("a key is given twice in one object")
        seen[key] = value
    return seen


def not_a_number(name):
    raise Refused("%s is not a JSON number" % name)


def parse_json(data, what):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("%s is not UTF-8" % what)
    decoder = json.JSONDecoder(object_pairs_hook=unique_keys,
                               parse_constant=not_a_number)
    try:
        return decoder.decode(text)
    except (ValueError, RecursionError):
        raise Refused("%s is not a JSON value" % what)


def printable(text):
    return "".join(c if c.isprintable() else "?" for c in text)


def text_of(obj, key, where, required=False):
    """A string member; absent or null is empty unless it is required."""
    value = obj.get(key)
    if value is None:
        value = ""
    if type(value) is not str:
        raise Refused("%s of %s is not a string" % (key, where))
    if required and not value:
        raise Refused("%s has no %s" % (where, key))
    return value


def read_cyclonedx(data):
    """The components of a CycloneDX JSON SBOM, nested ones included."""
    bom = parse_json(data, "sbom.cdx.json")
    if type(bom) is not dict or bom.get("bomFormat") != "CycloneDX":
        raise Refused('bomFormat of sbom.cdx.json is not "CycloneDX"')
    components = []
    pending = [bom.get("components", [])]
    while pending:
        level = pending.pop()
        if type(level) is not list:
            raise Refused("components of sbom.cdx.json is not an array")
        for component in level:
            if type(component) is not dict:
                raise Refused("a component of sbom.cdx.json is not an object")
            where = "a component of sbom.cdx.json"
            components.append({
                "type": text_of(component, "type", where),
                "name": text_of(component, "name", where, required=True),
                "version": text_of(component, "version", where),
                "purl": text_of(component, "purl", where),
            })
            pending.append(component.get("components", []))
    return components


# Each SBOM format the job reads: the name of its file in the image's
# directory and the reader that turns the file into component rows. A
# second format is one more line and one more reader; the matcher has to
# read the file too.
FORMATS = {
    "cyclonedx-json": ("sbom.cdx.json", read_cyclonedx),
}


def epoch(built_at):
    match = BUILT_AT.fullmatch(built_at)
    if not match:
        raise Refused('built_at of image.json is not "YYYY-MM-DDThh:mm:ssZ"')
    year, month, day, hour, minute, second = map(int, match.groups())
    if not (1 <= month <= 12 and 1 <= day <= 31 and hour <= 23
            and minute <= 59 and second <= 59):
        raise Refused("built_at of image.json is not a time")
    try:
        calendar.weekday(year, month, day)
    except ValueError:
        raise Refused("built_at of image.json is not a time")
    seconds = calendar.timegm((year, month, day, hour, minute, second))
    if not 0 <= seconds <= UINT32_MAX:
        raise Refused("built_at of image.json is out of range")
    return seconds


def read_image_json(path, image_id, image_version, image_root):
    """The format, SBOM hash and build time image.json names."""
    with open(path, "rb") as f:
        meta = parse_json(f.read(), "image.json")
    if type(meta) is not dict:
        raise Refused("image.json is not an object")
    for key, expected in (("image_id", image_id),
                          ("image_version", image_version),
                          ("image_root", image_root)):
        if key not in meta:
            raise Refused("image.json has no %s" % key)
        if meta[key] != expected:
            raise Refused("%s of image.json is not the one of its path" % key)
    sbom_format = meta.get("sbom_format", DEFAULT_FORMAT)
    if type(sbom_format) is not str or not sbom_format:
        raise Refused("sbom_format of image.json is not a string")
    sbom_sha256 = meta.get("sbom_sha256")
    if type(sbom_sha256) is not str or not HEX64.fullmatch(sbom_sha256):
        raise Refused("sbom_sha256 of image.json is not 64 lowercase hex digits")
    built_at = meta.get("built_at")
    if type(built_at) is not str:
        raise Refused("built_at of image.json is not a string")
    return sbom_format, sbom_sha256, epoch(built_at)


def image(store, work, n, directory):
    """The row of one image, its state, and the SBOM copy when it is ok."""
    image_id, image_version, root = directory.split("/")
    image_root = "" if root == "-" else root
    row = {
        "image_id": image_id,
        "image_version": image_version,
        "image_root": image_root,
        "sbom_format": DEFAULT_FORMAT,
        "sbom_sha256": "",
        "state": "parse_error",
        "built_at": 0,
    }
    where = os.path.join(store, image_id, image_version, root)
    try:
        sbom_format, sbom_sha256, built_at = read_image_json(
            os.path.join(where, "image.json"), image_id, image_version,
            image_root)
    except Refused as reason:
        return row, "-", str(reason), 0
    row["sbom_format"] = sbom_format
    row["built_at"] = built_at

    if sbom_format not in FORMATS:
        row["state"] = "unsupported_format"
        return row, "-", 'sbom_format "%s" has no reader' % sbom_format, 0
    name, reader = FORMATS[sbom_format]
    if not os.path.isfile(os.path.join(where, name)):
        row["state"] = "missing"
        return row, "-", "no %s" % name, 0
    with open(os.path.join(where, name), "rb") as f:
        data = f.read()
    if hashlib.sha256(data).hexdigest() != sbom_sha256:
        row["state"] = "hash_mismatch"
        return row, "-", "the SHA-256 of %s is not sbom_sha256" % name, 0
    try:
        components = reader(data)
    except Refused as reason:
        return row, "-", str(reason), 0

    # The matcher reads the bytes that were hashed, not the store again.
    copy = os.path.join(work, "%d.%s" % (n, name))
    with open(copy, "wb") as f:
        f.write(data)
    row["state"] = "ok"
    row["sbom_sha256"] = sbom_sha256
    return row, copy, "", len(components)


def image_directories(store):
    """The image directories under the store; other image.json are named."""
    found = []
    left_out = False
    for top, dirs, files in os.walk(store):
        dirs.sort()
        if "image.json" not in files:
            continue
        path = os.path.relpath(os.path.join(top, "image.json"), store)
        parts = path.split(os.sep)
        if (len(parts) == 4 and SEGMENT.fullmatch(parts[0])
                and SEGMENT.fullmatch(parts[1])
                and (parts[2] == "-" or HEX64.fullmatch(parts[2]))):
            found.append("/".join(parts[:3]))
            continue
        print("%s: %s is not <image_id>/<image_version>/<image_root or ->"
              "/image.json, left out" % (PROG, printable(path)),
              file=sys.stderr)
        left_out = True
    return sorted(found), left_out


def images_main(store, work):
    if not os.path.isdir(store):
        print("%s: no store directory %s" % (PROG, printable(store)),
              file=sys.stderr)
        return 1
    directories, left_out = image_directories(store)
    images = []
    with open(os.path.join(work, "images.tsv"), "w", encoding="utf-8") as tsv:
        for n, directory in enumerate(directories, 1):
            try:
                row, copy, reason, components = image(store, work, n,
                                                      directory)
            except OSError as error:
                print("%s: %s: cannot read %s, left out" % (
                    PROG, directory, printable(error.filename or "a file")),
                    file=sys.stderr)
                left_out = True
                continue
            images.append({"n": n, "directory": directory, "row": row,
                           "reason": reason, "components": components})
            tsv.write("%d\t%s\t%s\t%s\n" % (n, row["state"], copy, directory))
    with open(os.path.join(work, "images.json"), "w", encoding="ascii") as f:
        json.dump(images, f)
    return LEFT_OUT if left_out else 0


def kernel_package(name):
    """A package of the kernel: the node may run another one."""
    return name.startswith("linux-image-") or name in ("kernel", "kernel-core")


def findings(data):
    """The findings of Trivy's JSON report, and how many were of the kernel."""
    report = parse_json(data, "the report")
    if type(report) is not dict:
        raise Refused("the report is not an object")
    results = report.get("Results")
    if results is None:
        results = []
    if type(results) is not list:
        raise Refused("Results of the report is not an array")
    rows = set()
    kernel = 0
    for result in results:
        if type(result) is not dict:
            raise Refused("a result of the report is not an object")
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            continue
        if type(vulnerabilities) is not list:
            raise Refused("Vulnerabilities of a result is not an array")
        for v in vulnerabilities:
            if type(v) is not dict:
                raise Refused("a vulnerability of the report is not an object")
            where = "a vulnerability of the report"
            vuln_id = text_of(v, "VulnerabilityID", where, required=True)
            package = text_of(v, "PkgName", where, required=True)
            installed = text_of(v, "InstalledVersion", where)
            fixed = text_of(v, "FixedVersion", where)
            severity = text_of(v, "Severity", where) or "UNKNOWN"
            if kernel_package(package):
                kernel += 1
                continue
            rows.add((vuln_id, package, installed, fixed, severity))
    return sorted(rows), kernel


def db_version(work):
    """When the matcher's advisory database was built, as it says."""
    path = os.path.join(work, "version.json")
    if not os.path.exists(path):
        return ""
    with open(path, "rb") as f:
        version = parse_json(f.read(), "the matcher's version")
    if type(version) is not dict:
        raise Refused("the matcher's version is not an object")
    database = version.get("VulnerabilityDB")
    if type(database) is not dict or type(database.get("UpdatedAt")) is not str:
        return ""
    return database["UpdatedAt"]


def write_rows(path, table):
    with open(path, "w", encoding="ascii") as out:
        for row in table:
            out.write(json.dumps(row, separators=(",", ":")) + "\n")


def rows_main(work, scanned_at):
    try:
        scanned_at = int(scanned_at)
    except ValueError:
        scanned_at = -1
    if not 0 <= scanned_at <= UINT32_MAX:
        print("%s: scanned_at is not a time" % PROG, file=sys.stderr)
        return 1
    with open(os.path.join(work, "images.json"), encoding="ascii") as f:
        images = json.load(f)
    try:
        database = db_version(work)
    except Refused as reason:
        print("%s: %s, nothing loaded" % (PROG, reason), file=sys.stderr)
        return 1

    image_rows = []
    vuln_rows = []
    summary = []
    left_out = False
    # sbom_vulns is keyed by the SBOM, not the image: images built from
    # the same packages share one SBOM, whose findings a node reads once.
    loaded_by = {}
    for image in images:
        row = dict(image["row"], db_version="", scanned_at=scanned_at)
        directory = image["directory"]
        if row["state"] != "ok":
            image_rows.append(row)
            summary.append("%s: %s, %s" % (directory, row["state"],
                                           image["reason"]))
            continue
        report = os.path.join(work, "trivy-%d.json" % image["n"])
        if not os.path.exists(report):
            continue
        try:
            with open(report, "rb") as f:
                found, kernel = findings(f.read())
        except Refused as reason:
            print("%s: %s: the matcher's report is refused, not loaded: %s"
                  % (PROG, directory, reason), file=sys.stderr)
            left_out = True
            continue
        row["db_version"] = database
        image_rows.append(row)
        line = "%s: ok, components: %d, findings: %d" % (
            directory, image["components"], len(found))
        if kernel:
            line += ", of kernel packages left out: %d" % kernel
        if row["sbom_sha256"] in loaded_by:
            summary.append("%s, the SBOM of %s" % (
                line, loaded_by[row["sbom_sha256"]]))
            continue
        loaded_by[row["sbom_sha256"]] = directory
        summary.append(line)
        for vuln_id, package, installed, fixed, severity in found:
            vuln_rows.append({
                "sbom_sha256": row["sbom_sha256"],
                "vuln_id": vuln_id,
                "package": package,
                "installed": installed,
                "fixed": fixed,
                "severity": severity,
                "scanned_at": scanned_at,
            })

    write_rows(os.path.join(work, "sbom_images.jsonl"), image_rows)
    write_rows(os.path.join(work, "sbom_vulns.jsonl"), vuln_rows)
    summary.append("loaded images: %d, findings: %d" % (len(image_rows),
                                                         len(vuln_rows)))
    with open(os.path.join(work, "summary"), "w", encoding="utf-8") as f:
        for line in summary:
            f.write("%s: %s\n" % (PROG, line))
    return LEFT_OUT if left_out else 0


def put_main(directory, image_id, image_version, root, built_at, sbom):
    """Stage the image.json and SBOM of one image for the store."""
    try:
        if not SEGMENT.fullmatch(image_id):
            raise Refused("the image id is not 1 to 255 of [A-Za-z0-9._~+-]"
                          " that do not start with a dot")
        if not SEGMENT.fullmatch(image_version):
            raise Refused("the image version is not 1 to 255 of"
                          " [A-Za-z0-9._~+-] that do not start with a dot")
        if root != "-" and not HEX64.fullmatch(root):
            raise Refused("the image root is not 64 lowercase hex digits")
        try:
            epoch(built_at)
        except Refused:
            raise Refused('the build time is not a UTC "YYYY-MM-DDThh:mm:ssZ"')
        name, reader = FORMATS[DEFAULT_FORMAT]
        with open(sbom, "rb") as f:
            data = f.read()
        components = reader(data)
    except Refused as reason:
        print("%s: %s" % (PROG, reason), file=sys.stderr)
        return 1
    except OSError as error:
        print("%s: cannot read %s" % (PROG, printable(error.filename or sbom)),
              file=sys.stderr)
        return 1
    sbom_sha256 = hashlib.sha256(data).hexdigest()
    meta = {
        "image_id": image_id,
        "image_version": image_version,
        "image_root": "" if root == "-" else root,
        "sbom_format": DEFAULT_FORMAT,
        "sbom_sha256": sbom_sha256,
        "built_at": built_at,
    }
    with open(os.path.join(directory, name), "wb") as f:
        f.write(data)
    with open(os.path.join(directory, "image.json"), "w",
              encoding="ascii") as f:
        json.dump(meta, f, separators=(",", ":"))
        f.write("\n")
    print("%s/%s/%s\t%s\t%d" % (image_id, image_version, root, sbom_sha256,
                                len(components)))
    return 0


def stored_main(path, sbom_sha256):
    """Whether the stored image.json names this SBOM."""
    try:
        with open(path, "rb") as f:
            meta = parse_json(f.read(), "image.json")
    except (OSError, Refused):
        return 1
    if type(meta) is not dict:
        return 1
    same = (meta.get("sbom_sha256") == sbom_sha256
            and meta.get("sbom_format", DEFAULT_FORMAT) == DEFAULT_FORMAT)
    return 0 if same else 1


def main():
    global PROG
    args = sys.argv[1:]
    if args == ["files"]:
        print("image.json")
        for name, _ in FORMATS.values():
            print(name)
        return 0
    if len(args) == 3 and args[0] == "images":
        return images_main(args[1], args[2])
    if len(args) == 3 and args[0] == "rows":
        return rows_main(args[1], args[2])
    if len(args) == 7 and args[0] == "put":
        PROG = "sbom-put"
        return put_main(*args[1:])
    if len(args) == 3 and args[0] == "stored":
        return stored_main(args[1], args[2])
    print("usage: sbom-rows.py files | images <store> <work> | "
          "rows <work> <scanned_at> | put <directory> <image_id> "
          "<image_version> <image_root or -> <built_at> <sbom> | "
          "stored <image.json> <sbom_sha256>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
