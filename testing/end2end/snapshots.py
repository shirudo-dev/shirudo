# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import json


def read_documents(path):
    with open(path, encoding="utf-8") as stream:
        documents = [json.loads(line) for line in stream]
    for document in documents:
        if isinstance(document, dict):
            assert document["schema"] == 1, document
            assert document["upatch"] == "kernel-obs", document
            assert isinstance(document["records"], list), document
            for name in ("used", "overflow", "lost"):
                assert isinstance(document["interval"][name], int), document
            assert document["interval"]["overflow"] == 0, document
            assert document["interval"]["lost"] == 0, document
    return documents


def tables_from(documents):
    return {document["map"]: document["records"] for document in documents
            if isinstance(document, dict)}
