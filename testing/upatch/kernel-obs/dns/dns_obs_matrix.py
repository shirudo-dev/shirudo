#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Validate the DNS packet-case builders and batch encoding."""

from __future__ import annotations

import argparse
import ipaddress
import struct
import sys
from dataclasses import dataclass, field
from typing import Callable


BATCH_MAGIC = 0x31534E44
BATCH_VERSION = 1
QUERY = 0
RESPONSE = 1
A = 1
AAAA = 28
IN = 1

COUNTERS = (
    "QUERY_PACKET",
    "QUERY_NO_UID",
    "QUERY_HDR_FAIL",
    "QUERY_IS_RESPONSE",
    "QUERY_QDCOUNT_BAD",
    "QUERY_SCRATCH_MISS",
    "QUERY_NAME_FAIL",
    "QUERY_EMPTY_NAME",
    "QUERY_QTYPE_READ_FAIL",
    "QUERY_QTYPE_UNSUPPORTED",
    "QUERY_STORED",
    "RESP_PACKET",
    "RESP_HDR_FAIL",
    "RESP_NOT_RESPONSE",
    "RESP_QDCOUNT_BAD",
    "RESP_NO_ANSWER",
    "RESP_REQ_MISS",
    "RESP_QNAME_SKIP_FAIL",
    "RESP_QTYPE_READ_FAIL",
    "RESP_QTYPE_MISMATCH",
    "RESP_ANSWER_SEEN",
    "RESP_ANSWER_SKIP_FAIL",
    "RESP_RR_READ_FAIL",
    "RESP_RDATA_BOUNDS_FAIL",
    "RESP_ADDR_UNSUPPORTED",
    "RESP_ADDR_PARSED",
    "RESP_TOUCH",
    "RESP_DELETE",
    "TOUCH_CALLED",
    "TOUCH_INIT_FAIL",
    "TOUCH_HIT",
    "ALLOC_ATTEMPT",
    "ALLOC_BAD_IDX",
    "ALLOC_OK",
    "ALLOC_ENTRY_MISS",
    "CAS_OK",
    "CAS_FAIL",
    "PACKET_IPV4",
    "PACKET_IPV6",
    "PACKET_NOT_UDP",
    "PACKET_PORT_SKIP",
)
COUNTER = {name: index for index, name in enumerate(COUNTERS)}

# These depend on unavailable task state, arena exhaustion, or races and are
# intentionally outside the deterministic packet-controlled coverage set.
NON_PACKET_COUNTERS = {
    "QUERY_NO_UID",
    "QUERY_SCRATCH_MISS",
    "TOUCH_INIT_FAIL",
    "ALLOC_BAD_IDX",
    "ALLOC_ENTRY_MISS",
    "CAS_FAIL",
}


@dataclass
class Case:
    name: str
    direction: int
    txid: int
    frame: bytes
    counters: dict[str, int] = field(default_factory=dict)
    request: bool | None = False
    request_name: str | None = None
    request_qtype: int | None = None


def wire_name(name: str | list[bytes]) -> bytes:
    labels = [part.encode("ascii") for part in name.split(".")] if isinstance(name, str) else name
    return b"".join(bytes((len(label),)) + label for label in labels) + b"\x00"


def dns_header(txid: int, flags: int, qdcount: int, ancount: int = 0,
               nscount: int = 0, arcount: int = 0) -> bytes:
    return struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)


def question(name: bytes, qtype: int = A, qclass: int = IN) -> bytes:
    return name + struct.pack("!HH", qtype, qclass)


def query_payload(txid: int, name: bytes, qtype: int = A, qclass: int = IN,
                  flags: int = 0x0100, qdcount: int = 1) -> bytes:
    return dns_header(txid, flags, qdcount) + question(name, qtype, qclass)


def rr(owner: bytes = b"\xc0\x0c", rtype: int = A, rclass: int = IN,
       ttl: int = 60, rdata: bytes = b"\xc0\x00\x02\x01",
       rdlen: int | None = None) -> bytes:
    if rdlen is None:
        rdlen = len(rdata)
    return owner + struct.pack("!HHIH", rtype, rclass, ttl, rdlen) + rdata


def response_payload(txid: int, name: bytes, qtype: int = A,
                     answers: list[bytes] | None = None, qclass: int = IN,
                     flags: int = 0x8180, qdcount: int = 1,
                     ancount: int | None = None) -> bytes:
    answers = [] if answers is None else answers
    if ancount is None:
        ancount = len(answers)
    return (dns_header(txid, flags, qdcount, ancount) +
            question(name, qtype, qclass) + b"".join(answers))


def udp(payload: bytes, source: int, dest: int, length: int | None = None,
        checksum: int = 0) -> bytes:
    if length is None:
        length = 8 + len(payload)
    return struct.pack("!HHHH", source, dest, length, checksum) + payload


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return (b"\x02\x00\x00\x00\x00\x02" +
            b"\x02\x00\x00\x00\x00\x01" +
            struct.pack("!H", ethertype) + payload)


def ipv4(payload: bytes, protocol: int = 17, ihl: int = 5,
         version: int = 4, fragment: int = 0,
         total_length: int | None = None, options: bytes | None = None,
         source_address: str = "192.0.2.1",
         dest_address: str = "198.51.100.53") -> bytes:
    if options is None:
        options = b"\x00" * max(0, ihl * 4 - 20)
    actual_header_len = 20 + len(options)
    if total_length is None:
        total_length = actual_header_len + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        (version << 4) | (ihl & 0x0F), 0, total_length & 0xFFFF,
        0x1234, fragment, 64, protocol, 0,
        ipaddress.IPv4Address(source_address).packed,
        ipaddress.IPv4Address(dest_address).packed,
    )
    return header + options + payload


def ipv6(payload: bytes, next_header: int = 17, version: int = 6,
         payload_length: int | None = None,
         source_address: str = "2001:db8::1",
         dest_address: str = "2001:db8::53") -> bytes:
    if payload_length is None:
        payload_length = len(payload)
    return struct.pack(
        "!IHBB16s16s", version << 28, payload_length & 0xFFFF,
        next_header, 64,
        ipaddress.IPv6Address(source_address).packed,
        ipaddress.IPv6Address(dest_address).packed,
    ) + payload


def frame4(payload: bytes, direction: int, source: int | None = None,
           dest: int | None = None, source_address: str | None = None,
           dest_address: str | None = None, **ip_kwargs: object) -> bytes:
    if source is None:
        source = 40000 if direction == QUERY else 53
    if dest is None:
        dest = 53 if direction == QUERY else 40000
    if source_address is None:
        source_address = "192.0.2.1" if direction == QUERY else "198.51.100.53"
    if dest_address is None:
        dest_address = "198.51.100.53" if direction == QUERY else "192.0.2.1"
    return ethernet(ipv4(udp(payload, source, dest),
                         source_address=source_address,
                         dest_address=dest_address, **ip_kwargs))


def frame6(payload: bytes, direction: int, source: int | None = None,
           dest: int | None = None, source_address: str | None = None,
           dest_address: str | None = None, **ip_kwargs: object) -> bytes:
    if source is None:
        source = 40000 if direction == QUERY else 53
    if dest is None:
        dest = 53 if direction == QUERY else 40000
    if source_address is None:
        source_address = "2001:db8::1" if direction == QUERY else "2001:db8::53"
    if dest_address is None:
        dest_address = "2001:db8::53" if direction == QUERY else "2001:db8::1"
    return ethernet(ipv6(udp(payload, source, dest),
                         source_address=source_address,
                         dest_address=dest_address, **ip_kwargs), 0x86DD)


def count(**values: int) -> dict[str, int]:
    return values


class Matrix:
    def __init__(self, first_txid: int = 0x1000) -> None:
        self.cases: list[Case] = []
        self.next_txid = first_txid

    def txid(self) -> int:
        value = self.next_txid
        self.next_txid += 1
        return value

    def add(self, case: Case) -> None:
        if not 0 <= case.txid <= 0xFFFF:
            raise ValueError(f"bad transaction ID in {case.name}")
        self.cases.append(case)

    def pair(self, stem: str, name: str, qtype: int, answers: list[bytes],
             *, ipv6_transport: bool = False,
             response_counters: dict[str, int] | None = None) -> int:
        txid = self.txid()
        qname = wire_name(name)
        make_frame = frame6 if ipv6_transport else frame4
        family_counter = "PACKET_IPV6" if ipv6_transport else "PACKET_IPV4"
        self.add(Case(
            f"{stem}: query", QUERY, txid,
            make_frame(query_payload(txid, qname, qtype), QUERY),
            count(**{family_counter: 1, "QUERY_PACKET": 1,
                     "QUERY_STORED": 1}),
            True, name, qtype,
        ))
        expected = {
            family_counter: 1,
            "RESP_PACKET": 1,
            "RESP_ANSWER_SEEN": len(answers),
            "RESP_ADDR_PARSED": len(answers),
            "RESP_TOUCH": len(answers),
            "RESP_DELETE": 1,
            "TOUCH_CALLED": len(answers),
        }
        if response_counters:
            expected.update(response_counters)
        self.add(Case(
            f"{stem}: response", RESPONSE, txid,
            make_frame(response_payload(txid, qname, qtype, answers), RESPONSE),
            expected, False,
        ))
        return txid


def add_transport_cases(matrix: Matrix) -> None:
    txid = matrix.txid()
    matrix.add(Case("transport: non-IP EtherType", QUERY, txid,
                    ethernet(b"not ip", 0x88B5), {}, False))

    txid = matrix.txid()
    matrix.add(Case("transport: IPv4 non-UDP", QUERY, txid,
                    ethernet(ipv4(b"tcp", protocol=6)),
                    count(PACKET_IPV4=1, PACKET_NOT_UDP=1), False))

    txid = matrix.txid()
    matrix.add(Case("transport: IPv6 non-UDP", RESPONSE, txid,
                    ethernet(ipv6(b"tcp", next_header=6), 0x86DD),
                    count(PACKET_IPV6=1, PACKET_NOT_UDP=1), False))

    txid = matrix.txid()
    payload = query_payload(txid, wire_name("port.example"))
    matrix.add(Case("transport: query wrong destination port", QUERY, txid,
                    frame4(payload, QUERY, dest=5353),
                    count(PACKET_IPV4=1, PACKET_PORT_SKIP=1), False))

    txid = matrix.txid()
    payload = response_payload(txid, wire_name("port.example"), answers=[rr()])
    matrix.add(Case("transport: response wrong source port", RESPONSE, txid,
                    frame4(payload, RESPONSE, source=5353),
                    count(PACKET_IPV4=1, PACKET_PORT_SKIP=1), False))

    txid = matrix.txid()
    payload = query_payload(txid, wire_name("ihl.example"))
    matrix.add(Case("transport: IPv4 IHL below minimum", QUERY, txid,
                    frame4(payload, QUERY, ihl=4), count(PACKET_IPV4=1), False))

    txid = matrix.txid()
    matrix.add(Case("transport: truncated IPv4 header", QUERY, txid,
                    ethernet(b"\x45" + b"\x00" * 18),
                    {}, False))

    txid = matrix.txid()
    matrix.add(Case("transport: truncated IPv6 header", RESPONSE, txid,
                    ethernet(b"\x60" + b"\x00" * 38, 0x86DD),
                    {}, False))

    txid = matrix.txid()
    payload = query_payload(txid, wire_name("options.example"))
    matrix.add(Case("transport: IPv4 maximum IHL", QUERY, txid,
                    frame4(payload, QUERY, ihl=15),
                    count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                    True, "options.example", A))
    matrix.add(Case("transport: IPv4 maximum IHL response", RESPONSE, txid,
                    frame4(response_payload(txid, wire_name("options.example"),
                                            answers=[rr(rdata=b"\xc0\x00\x02\x02")]),
                           RESPONSE, ihl=15),
                    count(PACKET_IPV4=1, RESP_PACKET=1, RESP_ANSWER_SEEN=1,
                          RESP_ADDR_PARSED=1, RESP_TOUCH=1, RESP_DELETE=1,
                          TOUCH_CALLED=1), False))


def add_query_cases(matrix: Matrix) -> None:
    for suffix, payload, expected in (
        ("empty DNS payload", b"", count(QUERY_PACKET=1, QUERY_HDR_FAIL=1)),
        ("two-byte DNS payload", b"\x12\x34", count(QUERY_PACKET=1, QUERY_HDR_FAIL=1)),
        ("four-byte DNS payload", b"\x12\x34\x01\x00", count(QUERY_PACKET=1, QUERY_HDR_FAIL=1)),
    ):
        txid = matrix.txid()
        matrix.add(Case(f"query: {suffix}", QUERY, txid,
                        frame4(payload, QUERY),
                        {"PACKET_IPV4": 1, **expected}, False))

    txid = matrix.txid()
    matrix.add(Case("query: QR bit set", QUERY, txid,
                    frame4(query_payload(txid, wire_name("qr.example"), flags=0x8100), QUERY),
                    count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_IS_RESPONSE=1), False))

    for qdcount in (0, 2):
        txid = matrix.txid()
        matrix.add(Case(f"query: qdcount {qdcount}", QUERY, txid,
                        frame4(query_payload(txid, wire_name("qd.example"),
                                             qdcount=qdcount), QUERY),
                        count(PACKET_IPV4=1, QUERY_PACKET=1,
                              QUERY_QDCOUNT_BAD=1), False))

    malformed_names = (
        ("header only", b""),
        ("reserved label prefix 01", b"\x40"),
        ("reserved label prefix 10", b"\x80"),
        ("compression in query", b"\xc0\x0c"),
        ("label length 64", b"\x40" + b"a" * 64 + b"\x00"),
        ("truncated label", b"\x05abc"),
        ("missing terminator", b"\x03abc"),
    )
    for suffix, raw_name in malformed_names:
        txid = matrix.txid()
        payload = dns_header(txid, 0x0100, 1) + raw_name
        matrix.add(Case(f"query name: {suffix}", QUERY, txid,
                        frame4(payload, QUERY),
                        count(PACKET_IPV4=1, QUERY_PACKET=1,
                              QUERY_NAME_FAIL=1), False))

    txid = matrix.txid()
    payload = dns_header(txid, 0x0100, 1) + b"\x00" + struct.pack("!HH", A, IN)
    matrix.add(Case("query name: root", QUERY, txid, frame4(payload, QUERY),
                    count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_EMPTY_NAME=1), False))

    for suffix, tail in (("missing qtype", b""), ("missing qclass", struct.pack("!H", A))):
        txid = matrix.txid()
        payload = dns_header(txid, 0x0100, 1) + wire_name("short.example") + tail
        matrix.add(Case(f"query: {suffix}", QUERY, txid,
                        frame4(payload, QUERY),
                        count(PACKET_IPV4=1, QUERY_PACKET=1,
                              QUERY_QTYPE_READ_FAIL=1), False))

    txid = matrix.txid()
    matrix.add(Case("query: unsupported TXT qtype", QUERY, txid,
                    frame4(query_payload(txid, wire_name("txt.example"), 16), QUERY),
                    count(PACKET_IPV4=1, QUERY_PACKET=1,
                          QUERY_QTYPE_UNSUPPORTED=1), False))


def add_response_state_cases(matrix: Matrix) -> None:
    qname = wire_name("state.example")

    txid = matrix.txid()
    matrix.add(Case("response: short header", RESPONSE, txid,
                    frame4(b"\x12\x34\x81\x80\x00\x01", RESPONSE),
                    count(PACKET_IPV4=1, RESP_PACKET=1, RESP_HDR_FAIL=1), False))

    txid = matrix.txid()
    matrix.add(Case("response: unsolicited", RESPONSE, txid,
                    frame4(response_payload(txid, qname, answers=[rr()]), RESPONSE),
                    count(PACKET_IPV4=1, RESP_PACKET=1, RESP_REQ_MISS=1), False))

    # Early header-state rejects retain the request; the final valid response
    # consumes it.  This makes retention visible rather than inferred.
    for suffix, kwargs, branch in (
        ("QR clear", {"flags": 0x0100}, "RESP_NOT_RESPONSE"),
        ("qdcount zero", {"qdcount": 0}, "RESP_QDCOUNT_BAD"),
        ("no answers", {"ancount": 0}, "RESP_NO_ANSWER"),
    ):
        txid = matrix.txid()
        name = f"retain-{txid:x}.example"
        raw_name = wire_name(name)
        matrix.add(Case(f"response state {suffix}: query", QUERY, txid,
                        frame4(query_payload(txid, raw_name), QUERY),
                        count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                        True, name, A))
        payload = response_payload(txid, raw_name, answers=[rr()], **kwargs)
        matrix.add(Case(f"response state: {suffix}", RESPONSE, txid,
                        frame4(payload, RESPONSE),
                        count(PACKET_IPV4=1, RESP_PACKET=1, **{branch: 1}),
                        True, name, A))
        matrix.add(Case(f"response state {suffix}: cleanup", RESPONSE, txid,
                        frame4(response_payload(txid, raw_name, answers=[rr(rdata=b"\xc0\x00\x02\x40")]), RESPONSE),
                        count(PACKET_IPV4=1, RESP_PACKET=1,
                              RESP_ANSWER_SEEN=1, RESP_ADDR_PARSED=1,
                              RESP_TOUCH=1, RESP_DELETE=1, TOUCH_CALLED=1), False))

    destructive = (
        ("malformed question name", b"\x40", "RESP_QNAME_SKIP_FAIL"),
        ("truncated question type", wire_name("state.example") + b"\x00", "RESP_QTYPE_READ_FAIL"),
    )
    for suffix, question_bytes, branch in destructive:
        txid = matrix.txid()
        matrix.add(Case(f"response {suffix}: query", QUERY, txid,
                        frame4(query_payload(txid, qname), QUERY),
                        count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                        True, "state.example", A))
        payload = dns_header(txid, 0x8180, 1, 1) + question_bytes
        matrix.add(Case(f"response: {suffix}", RESPONSE, txid,
                        frame4(payload, RESPONSE),
                        count(PACKET_IPV4=1, RESP_PACKET=1, **{branch: 1}), False))

    txid = matrix.txid()
    matrix.add(Case("response qtype mismatch: query", QUERY, txid,
                    frame4(query_payload(txid, qname, A), QUERY),
                    count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                    True, "state.example", A))
    matrix.add(Case("response: qtype mismatch", RESPONSE, txid,
                    frame4(response_payload(txid, qname, AAAA,
                                            [rr(rtype=AAAA, rdata=b"\x00" * 16)]), RESPONSE),
                    count(PACKET_IPV4=1, RESP_PACKET=1,
                          RESP_QTYPE_MISMATCH=1), False))


def add_rr_cases(matrix: Matrix) -> None:
    scenarios: list[tuple[str, bytes, dict[str, int]]] = [
        ("malformed owner", b"\x40", count(RESP_ANSWER_SEEN=1,
                                             RESP_ANSWER_SKIP_FAIL=1,
                                             RESP_DELETE=1)),
        ("truncated fixed fields", b"\xc0\x0c\x00\x01", count(RESP_ANSWER_SEEN=1,
                                                               RESP_RR_READ_FAIL=1,
                                                               RESP_DELETE=1)),
        ("RDATA logical bounds", rr(rdlen=0xFFFF, rdata=b""),
         count(RESP_ANSWER_SEEN=1, RESP_RDATA_BOUNDS_FAIL=1,
               RESP_DELETE=1)),
        ("unsupported TXT", rr(rtype=16, rdata=b"data"),
         count(RESP_ANSWER_SEEN=1, RESP_ADDR_UNSUPPORTED=1,
               RESP_DELETE=1)),
        ("A wrong RDLENGTH", rr(rtype=A, rdata=b"\xc0\x00\x02", rdlen=3),
         count(RESP_ANSWER_SEEN=1, RESP_ADDR_UNSUPPORTED=1,
               RESP_DELETE=1)),
        ("AAAA wrong RDLENGTH", rr(rtype=AAAA, rdata=b"\x00" * 15, rdlen=15),
         count(RESP_ANSWER_SEEN=1, RESP_ADDR_UNSUPPORTED=1,
               RESP_DELETE=1)),
        ("truncated A RDATA", rr(rtype=A, rdata=b"\xc0\x00", rdlen=4),
         count(RESP_ANSWER_SEEN=1, RESP_DELETE=1)),
    ]
    for suffix, answer, expected in scenarios:
        txid = matrix.txid()
        name = f"rr-{txid:x}.example"
        qname = wire_name(name)
        matrix.add(Case(f"RR {suffix}: query", QUERY, txid,
                        frame4(query_payload(txid, qname), QUERY),
                        count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                        True, name, A))
        payload = response_payload(txid, qname, answers=[answer])
        matrix.add(Case(f"RR: {suffix}", RESPONSE, txid,
                        frame4(payload, RESPONSE),
                        {"PACKET_IPV4": 1, "RESP_PACKET": 1, **expected}, False))

    # Both compressed and full owner names are supported by the answer walker.
    full_owner = wire_name("owner.example")
    matrix.pair("RR full owner", "owner.example", A,
                [rr(owner=full_owner, rdata=b"\xc0\x00\x02\x50")])
    partial_owner = b"\x03www\xc0\x0c"
    matrix.pair("RR partial compression", "partial.example", A,
                [rr(owner=partial_owner, rdata=b"\xc0\x00\x02\x51")])

    # Unsupported records are skipped while later supported records are used.
    txid = matrix.txid()
    name = "mixed.example"
    qname = wire_name(name)
    answers = [rr(rtype=16, rdata=b"txt"), rr(rdata=b"\xcb\x00\x71\x4a")]
    matrix.add(Case("RR mixed types: query", QUERY, txid,
                    frame4(query_payload(txid, qname), QUERY),
                    count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                    True, name, A))
    matrix.add(Case("RR mixed types: response", RESPONSE, txid,
                    frame4(response_payload(txid, qname, answers=answers), RESPONSE),
                    count(PACKET_IPV4=1, RESP_PACKET=1, RESP_ANSWER_SEEN=2,
                          RESP_ADDR_UNSUPPORTED=1, RESP_ADDR_PARSED=1,
                          RESP_TOUCH=1, RESP_DELETE=1, TOUCH_CALLED=1), False))

    # The loop is intentionally capped at 75 answers.
    fillers = [rr(rtype=16, rdata=b"x") for _ in range(74)]
    matrix.pair("RR supported answer at slot 75", "slot75.example", A,
                fillers + [rr(rdata=b"\xcb\x00\x71\x4b")],
                response_counters={"RESP_ADDR_UNSUPPORTED": 74,
                                   "RESP_ADDR_PARSED": 1,
                                   "RESP_TOUCH": 1,
                                   "TOUCH_CALLED": 1})

    txid = matrix.txid()
    name = "slot76.example"
    qname = wire_name(name)
    answers = [rr(rtype=16, rdata=b"x") for _ in range(75)]
    answers.append(rr(rdata=b"\xcb\x00\x71\x4c"))
    matrix.add(Case("RR answer beyond slot 75: query", QUERY, txid,
                    frame4(query_payload(txid, qname), QUERY),
                    count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                    True, name, A))
    matrix.add(Case("RR answer beyond slot 75: response", RESPONSE, txid,
                    frame4(response_payload(txid, qname, answers=answers), RESPONSE),
                    count(PACKET_IPV4=1, RESP_PACKET=1, RESP_ANSWER_SEEN=75,
                          RESP_ADDR_UNSUPPORTED=75, RESP_DELETE=1), False))

    # A valid first answer remains observable when a later answer is malformed.
    txid = matrix.txid()
    name = "partial-response.example"
    qname = wire_name(name)
    payload = response_payload(txid, qname,
                               answers=[rr(rdata=b"\xc0\x00\x02\x52")],
                               ancount=2)
    matrix.add(Case("RR partial response: query", QUERY, txid,
                    frame4(query_payload(txid, qname), QUERY),
                    count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                    True, name, A))
    matrix.add(Case("RR partial response", RESPONSE, txid,
                    frame4(payload, RESPONSE),
                    count(PACKET_IPV4=1, RESP_PACKET=1, RESP_ANSWER_SEEN=2,
                          RESP_ANSWER_SKIP_FAIL=1, RESP_ADDR_PARSED=1,
                          RESP_TOUCH=1, RESP_DELETE=1, TOUCH_CALLED=1), False))

    # Trailing records above ANCOUNT are ignored.
    txid = matrix.txid()
    name = "ancount-limit.example"
    qname = wire_name(name)
    encoded = (dns_header(txid, 0x8180, 1, 1) + question(qname) +
               rr(rdata=b"\xc0\x00\x02\x53") +
               rr(rdata=b"\xc0\x00\x02\x54"))
    matrix.add(Case("RR ANCOUNT limit: query", QUERY, txid,
                    frame4(query_payload(txid, qname), QUERY),
                    count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                    True, name, A))
    matrix.add(Case("RR ANCOUNT limit", RESPONSE, txid, frame4(encoded, RESPONSE),
                    count(PACKET_IPV4=1, RESP_PACKET=1, RESP_ANSWER_SEEN=1,
                          RESP_ADDR_PARSED=1, RESP_TOUCH=1,
                          RESP_DELETE=1, TOUCH_CALLED=1), False))


def add_flow_collision_cases(matrix: Matrix) -> None:
    def query_case(label: str, txid: int, name: str, frame: bytes,
                   family_counter: str = "PACKET_IPV4") -> None:
        matrix.add(Case(label, QUERY, txid, frame,
                        count(**{family_counter: 1, "QUERY_PACKET": 1,
                                 "QUERY_STORED": 1}),
                        True, name, A))

    def response_case(label: str, txid: int, frame: bytes,
                      family_counter: str = "PACKET_IPV4") -> None:
        matrix.add(Case(label, RESPONSE, txid, frame,
                        count(**{family_counter: 1, "RESP_PACKET": 1,
                                 "RESP_ANSWER_SEEN": 1,
                                 "RESP_ADDR_PARSED": 1,
                                 "RESP_TOUCH": 1, "RESP_DELETE": 1,
                                 "TOUCH_CALLED": 1}), False))

    # Same transaction ID, resolver, and client address; only the client UDP
    # port differs. Both requests must survive and may complete out of order.
    txid = matrix.txid()
    first_name = "flow-port-first.example"
    second_name = "flow-port-second.example"
    first_qname = wire_name(first_name)
    second_qname = wire_name(second_name)
    query_case("flow key client port: first query", txid, first_name,
               frame4(query_payload(txid, first_qname), QUERY, source=41001))
    query_case("flow key client port: second query", txid, second_name,
               frame4(query_payload(txid, second_qname), QUERY, source=41002))
    response_case("flow key client port: second response first", txid,
                  frame4(response_payload(
                      txid, second_qname,
                      answers=[rr(rdata=b"\xc6\x33\x64\xc9")]),
                      RESPONSE, dest=41002))
    response_case("flow key client port: first response second", txid,
                  frame4(response_payload(
                      txid, first_qname,
                      answers=[rr(rdata=b"\xc6\x33\x64\xc8")]),
                      RESPONSE, dest=41001))

    # Reusing an ID and port across different client/resolver address pairs
    # must likewise retain both pending requests.
    txid = matrix.txid()
    first_name = "flow-address-first.example"
    second_name = "flow-address-second.example"
    first_qname = wire_name(first_name)
    second_qname = wire_name(second_name)
    query_case("flow key addresses: first query", txid, first_name,
               frame4(query_payload(txid, first_qname), QUERY, source=42000))
    query_case("flow key addresses: second query", txid, second_name,
               frame4(query_payload(txid, second_qname), QUERY, source=42000,
                      source_address="192.0.2.2",
                      dest_address="198.51.100.54"))
    response_case("flow key addresses: second response first", txid,
                  frame4(response_payload(
                      txid, second_qname,
                      answers=[rr(rdata=b"\xc6\x33\x64\xcb")]),
                      RESPONSE, dest=42000,
                      source_address="198.51.100.54",
                      dest_address="192.0.2.2"))
    response_case("flow key addresses: first response second", txid,
                  frame4(response_payload(
                      txid, first_qname,
                      answers=[rr(rdata=b"\xc6\x33\x64\xca")]),
                      RESPONSE, dest=42000))

    # Address family is part of the key, so identical IDs and numeric ports
    # coexist across IPv4 and IPv6.
    txid = matrix.txid()
    ipv4_name = "flow-family-v4.example"
    ipv6_name = "flow-family-v6.example"
    ipv4_qname = wire_name(ipv4_name)
    ipv6_qname = wire_name(ipv6_name)
    query_case("flow key family: IPv4 query", txid, ipv4_name,
               frame4(query_payload(txid, ipv4_qname), QUERY, source=43000))
    query_case("flow key family: IPv6 query", txid, ipv6_name,
               frame6(query_payload(txid, ipv6_qname), QUERY, source=43000),
               "PACKET_IPV6")
    response_case("flow key family: IPv6 response first", txid,
                  frame6(response_payload(
                      txid, ipv6_qname,
                      answers=[rr(rdata=b"\xc6\x33\x64\xcd")]),
                      RESPONSE, dest=43000), "PACKET_IPV6")
    response_case("flow key family: IPv4 response second", txid,
                  frame4(response_payload(
                      txid, ipv4_qname,
                      answers=[rr(rdata=b"\xc6\x33\x64\xcc")]),
                      RESPONSE, dest=43000))

    # A same-ID response from a different client port must miss without
    # deleting the correct request, which is then consumed normally.
    txid = matrix.txid()
    name = "flow-wrong-tuple.example"
    qname = wire_name(name)
    query_case("flow key wrong tuple: query", txid, name,
               frame4(query_payload(txid, qname), QUERY, source=44000))
    matrix.add(Case(
        "flow key wrong tuple: response misses", RESPONSE, txid,
        frame4(response_payload(
            txid, qname, answers=[rr(rdata=b"\xc6\x33\x64\xfe")]),
            RESPONSE, dest=44001),
        count(PACKET_IPV4=1, RESP_PACKET=1, RESP_REQ_MISS=1), False))
    response_case("flow key wrong tuple: correct response retained", txid,
                  frame4(response_payload(
                      txid, qname,
                      answers=[rr(rdata=b"\xc6\x33\x64\xcf")]),
                      RESPONSE, dest=44000))


def build_deterministic_matrix() -> Matrix:
    matrix = Matrix()
    add_transport_cases(matrix)
    add_query_cases(matrix)
    add_response_state_cases(matrix)
    add_rr_cases(matrix)
    add_flow_collision_cases(matrix)

    matrix.pair("valid IPv4 A", "basic.example", A,
                [rr(rdata=b"\xc0\x00\x02\x0a")],
                response_counters={"ALLOC_ATTEMPT": 1, "ALLOC_OK": 1,
                                   "CAS_OK": 1})
    matrix.pair("valid IPv6 transport and AAAA", "v6.example", AAAA,
                [rr(rtype=AAAA,
                    rdata=ipaddress.IPv6Address("2001:db8::10").packed)],
                ipv6_transport=True)

    long_name = ".".join(["a"] * 127)
    matrix.pair("127-label maximum wire name", long_name, A,
                [rr(rdata=b"\xc0\x00\x02\x0b")])

    # Multiple answers for one address exercise lookup and seen_count updates.
    matrix.pair("duplicate address answer", "duplicate.example", A,
                [rr(rdata=b"\xc0\x00\x02\x14"),
                 rr(rdata=b"\xc0\x00\x02\x14")],
                response_counters={"ALLOC_ATTEMPT": 1, "ALLOC_OK": 1,
                                   "CAS_OK": 1, "TOUCH_HIT": 1})

    # One address stores four names and evicts the oldest on the fifth.
    for index in range(1, 6):
        matrix.pair(f"name slot {index}", f"name{index}.example", A,
                    [rr(rdata=b"\xc0\x00\x02\x15")])

    matrix.pair("one name, two addresses", "multi-address.example", A,
                [rr(rdata=b"\xc0\x00\x02\x1e"),
                 rr(rdata=b"\xc0\x00\x02\x1f")])
    return matrix


def encode_batch(cases: list[Case]) -> bytes:
    output = bytearray(struct.pack("<IHHI", BATCH_MAGIC, BATCH_VERSION, 0,
                                   len(cases)))
    for case in cases:
        if len(case.frame) > 0xFFFF:
            raise ValueError(f"frame too large in {case.name}: {len(case.frame)}")
        output.extend(struct.pack("<HBBHH", len(case.frame), case.direction,
                                  0, case.txid, 0))
        output.extend(case.frame)
    return bytes(output)


def build_known_gap_matrix() -> tuple[list[Case], list[tuple[str, Callable[[dict], bool]]]]:
    matrix = Matrix(0x7000)
    probes: list[tuple[str, Callable[[dict], bool]]] = []

    def add_query_probe(label: str, frame_builder: Callable[[int, bytes], bytes],
                        qclass: int = IN, name: str | None = None) -> None:
        txid = matrix.txid()
        text_name = name or f"gap-{txid:x}.example"
        raw_name = wire_name(text_name)
        case_index = len(matrix.cases)
        payload = query_payload(txid, raw_name, qclass=qclass)
        matrix.add(Case(label, QUERY, txid, frame_builder(txid, payload), request=None))
        probes.append((label, lambda result: bool(result["request"])))
        matrix.add(Case(label + ": cleanup", RESPONSE, txid,
                        frame4(response_payload(txid, raw_name, answers=[rr()]), RESPONSE),
                        request=None))
        assert case_index == len(matrix.cases) - 2

    add_query_probe("fragmented IPv4 query is accepted",
                    lambda _txid, payload: frame4(payload, QUERY, fragment=0x2000))
    add_query_probe("non-IN question class is accepted",
                    lambda _txid, payload: frame4(payload, QUERY), qclass=3)

    txid = matrix.txid()
    original = wire_name("original.example")
    other = wire_name("different.example")
    matrix.add(Case("response qname mismatch: query", QUERY, txid,
                    frame4(query_payload(txid, original), QUERY), request=None))
    response_index = len(matrix.cases)
    matrix.add(Case("response qname mismatch is accepted", RESPONSE, txid,
                    frame4(response_payload(txid, other, answers=[rr()]), RESPONSE),
                    request=None))
    probes.append(("response qname is not matched to query",
                   lambda result: (not result["request"] and
                                   result["counter_delta"][COUNTER["RESP_TOUCH"]] == 1)))

    txid = matrix.txid()
    raw_name = wire_name("pointer.example")
    matrix.add(Case("unchecked pointer target: query", QUERY, txid,
                    frame4(query_payload(txid, raw_name), QUERY), request=None))
    pointer_index = len(matrix.cases)
    matrix.add(Case("unchecked compression pointer target", RESPONSE, txid,
                    frame4(response_payload(txid, raw_name,
                                            answers=[rr(owner=b"\xff\xff")]), RESPONSE),
                    request=None))
    probes.append(("answer compression pointer target is not validated",
                   lambda result: result["counter_delta"][COUNTER["RESP_TOUCH"]] == 1))

    txid = matrix.txid()
    raw_name = wire_name("flags.example")
    matrix.add(Case("response flags: query", QUERY, txid,
                    frame4(query_payload(txid, raw_name), QUERY), request=None))
    flags_index = len(matrix.cases)
    matrix.add(Case("response opcode/rcode/TC flags", RESPONSE, txid,
                    frame4(response_payload(txid, raw_name, answers=[rr()],
                                            flags=0x8B83), RESPONSE), request=None))
    probes.append(("response opcode, rcode, and TC are not filtered",
                   lambda result: result["counter_delta"][COUNTER["RESP_TOUCH"]] == 1))

    txid = matrix.txid()
    raw_name = wire_name("length.example")
    dns = query_payload(txid, raw_name)
    malformed_udp = udp(dns, 40000, 53, length=8)
    length_index = len(matrix.cases)
    matrix.add(Case("UDP length shorter than DNS payload", QUERY, txid,
                    ethernet(ipv4(malformed_udp)), request=None))
    probes.append(("IPv4 and UDP declared lengths are not enforced",
                   lambda result: bool(result["request"])))
    matrix.add(Case("UDP length: cleanup", RESPONSE, txid,
                    frame4(response_payload(txid, raw_name, answers=[rr()]), RESPONSE),
                    request=None))

    txid = matrix.txid()
    raw_name = wire_name("oversize.example")
    oversize_index = len(matrix.cases)
    matrix.add(Case("packet larger than 1232-byte parsing budget", QUERY, txid,
                    frame4(query_payload(txid, raw_name) + b"x" * 1300, QUERY),
                    request=None))
    probes.append(("overall UDP packet size is not capped at 1232 bytes",
                   lambda result: bool(result["request"])))
    matrix.add(Case("oversize packet: cleanup", RESPONSE, txid,
                    frame4(response_payload(txid, raw_name, answers=[rr()]), RESPONSE),
                    request=None))

    # Keep the probe/result association explicit despite cleanup actions.
    probe_indices = [0, 2, response_index, pointer_index, flags_index,
                     length_index, oversize_index]
    return matrix.cases, [(label, (lambda pred, index: lambda results: pred(results[index]))(predicate, index))
                          for (label, predicate), index in zip(probes, probe_indices)]


def validate_matrix(cases: list[Case]) -> None:
    if not cases:
        raise AssertionError("empty DNS test matrix")
    names = [case.name for case in cases]
    if len(names) != len(set(names)):
        raise AssertionError("duplicate DNS matrix case names")
    batch = encode_batch(cases)
    if struct.unpack_from("<IHHI", batch) != (BATCH_MAGIC, BATCH_VERSION, 0, len(cases)):
        raise AssertionError("batch header self-test failed")
    offset = struct.calcsize("<IHHI")
    for expected, case in enumerate(cases):
        frame_len, direction, flags, txid, reserved = struct.unpack_from("<HBBHH", batch, offset)
        offset += struct.calcsize("<HBBHH")
        if (frame_len, direction, flags, txid, reserved) != (
                len(case.frame), case.direction, 0, case.txid, 0):
            raise AssertionError(f"batch record self-test failed at {expected}")
        if batch[offset:offset + frame_len] != case.frame:
            raise AssertionError(f"batch frame self-test failed at {expected}")
        offset += frame_len
    if offset != len(batch):
        raise AssertionError("batch has trailing bytes")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if not args.self_test:
        parser.error("select --self-test")

    matrix = build_deterministic_matrix()
    validate_matrix(matrix.cases)
    known_cases, _ = build_known_gap_matrix()
    validate_matrix(known_cases)
    print(f"PASS matrix self-test: {len(matrix.cases)} deterministic packets, "
          f"{len(known_cases)} known-gap packets")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, RuntimeError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
