# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Sphinx extension for the backend's table reference: it reads the CREATE
# statements of tools/backend/sql/*.sql and documents each table from
# them, so that the engine, key, TTL, columns and the views around a
# table come from the schema and only the prose comes from the page.
#
#   .. clickhouse-table:: shirudo.keepalive
#      :kind: store
#      :written-by: tests insert here directly
#      :ttl: how the TTL is set, or why there is none
#      :row-size: ~200 B per record
#      :scale: nodes x 1,440 records per day x retention
#      :reference: 600k rows, about 120 MB
#      :bytes: 120e6
#
#      What the table is for, then notes as a bullet list.
#
#      :received: what the column holds
#      :TraceId, SpanId: one meaning for several columns
#
# A column the schema has and the page does not describe, a column the
# page describes and the schema does not have, and a table of the schema no
# page documents are warnings, which -W turns into errors.
#
# .. clickhouse-sizes:: puts the row size, scale and reference figures
# of every table in one table with their total, and :table:`name` links
# a table from prose.
#
# .. clickhouse-flow:: draws how a record moves between tables. The page
# places the boxes and names the arrows; each arrow must be a view of
# sql/ that writes a table of the one box from a table of the other,
# and is solid when that view runs on insert and dashed when it is
# refreshed. A box takes the colour of its tables' kind.
#
#   box  <key> <x> <y> <width> <table>... [| <label>]
#   edge <from> <r|l|t|b> <to> <r|l|t|b> [<label>]

import glob
import os
import re
from html import escape

from docutils import nodes
from docutils.parsers.rst import directives
from sphinx.util import logging
from sphinx.util.docutils import SphinxDirective, SphinxRole

logger = logging.getLogger(__name__)

KINDS = {
    "null": "Null engine: holds no rows, feeds the views on it",
    "store": "Stored",
    "ref": "Reference data",
    "derived": "Derived by a view",
    "ui": "Derived by a view, read by the UI",
}


# -- reading the schema ------------------------------------------------

def strip_comments(text):
    out, i, quote = [], 0, False
    while i < len(text):
        c = text[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 1
            elif c == "'":
                quote = False
        elif c == "'":
            quote = True
            out.append(c)
        elif text.startswith("--", i):
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        else:
            out.append(c)
        i += 1
    return "".join(out)


# Splits text at sep where it is outside quotes and brackets.
def split_top(text, sep):
    parts, depth, quote, start = [], 0, False, 0
    for i, c in enumerate(text):
        if quote:
            if c == "'" and text[i - 1] != "\\":
                quote = False
        elif c == "'":
            quote = True
        elif c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == sep and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return [p.strip() for p in parts if p.strip()]


def matching_paren(text, open_at):
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    raise ValueError("unbalanced parentheses")


COLUMN_TAIL = re.compile(r"\s+(DEFAULT|MATERIALIZED|ALIAS|EPHEMERAL|CODEC"
                         r"|COMMENT|TTL)\b")
CLAUSES = ("ENGINE", "PARTITION BY", "PRIMARY KEY", "ORDER BY", "TTL",
           "SETTINGS")
NAME = r"[A-Za-z_][\w]*\.[A-Za-z_][\w]*"


def parse_column(text):
    name, rest = text.split(None, 1)
    m = COLUMN_TAIL.search(rest)
    ctype = rest[:m.start()].strip() if m else rest.strip()
    tail = rest[m.start():].strip() if m else ""
    codec = re.search(r"CODEC\(([^)]*\)?)\)", tail)
    return {
        "name": name,
        "type": " ".join(ctype.split()),
        "default": " ".join(tail.split()) if re.match(
            r"(DEFAULT|MATERIALIZED|ALIAS)\b", tail) else "",
        "codec": codec.group(1) if codec else "",
    }


def parse_clauses(text):
    found = []
    for clause in CLAUSES:
        for m in re.finditer(r"(?<![\w.])%s\b" % clause.replace(" ", r"\s+"),
                             text):
            found.append((m.start(), m.end(), clause))
    found.sort()
    out = {}
    for n, (start, end, clause) in enumerate(found):
        stop = found[n + 1][0] if n + 1 < len(found) else len(text)
        value = text[end:stop].strip().lstrip("=").strip()
        out[clause] = " ".join(value.split())
    return out


def parse_statement(text, path):
    m = re.match(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(%s)\s*\(" %
                 NAME, text)
    if m:
        close = matching_paren(text, m.end() - 1)
        cols = [parse_column(c)
                for c in split_top(text[m.end():close], ",")
                if not re.match(r"(INDEX|PROJECTION|CONSTRAINT)\b", c)]
        return {"what": "table", "name": m.group(1), "file": path,
                "columns": cols, "clauses": parse_clauses(text[close + 1:])}
    m = re.match(r"CREATE\s+(MATERIALIZED\s+)?VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?"
                 r"(%s)\s+(.*?)\bAS\b(.*)" % NAME, text, re.S)
    if m:
        head = " ".join(m.group(3).split())
        refresh = re.search(r"REFRESH\s+(.*?)(?:\s+APPEND)?\s*(?:TO\b|$)",
                            head)
        to = re.search(r"\bTO\s+(%s)" % NAME, head)
        body = re.sub(r"'(?:[^'\\]|\\.)*'", "''", m.group(4))
        sources = []
        for ref in re.findall(r"(?<![\w.])(%s)(?![\w(])" % NAME, body):
            if ref not in sources:
                sources.append(ref)
        return {"what": "mv" if m.group(1) else "view", "name": m.group(2),
                "file": path, "to": to.group(1) if to else None,
                "refresh": refresh.group(1).lower() if refresh else None,
                "append": " APPEND " in " %s " % head, "sources": sources}
    return None


# The schema's directory, relative to the root of the checkout.
SCHEMA_DIR = os.path.join("tools", "backend", "sql")


def read_schema(root):
    schema = {}
    for path in sorted(glob.glob(os.path.join(root, SCHEMA_DIR, "*.sql"))):
        with open(path, encoding="utf-8") as stream:
            text = strip_comments(stream.read())
        rel = os.path.relpath(path, root)
        for statement in split_top(text, ";"):
            parsed = parse_statement(statement, rel)
            if parsed:
                schema[parsed["name"]] = parsed
    # A qualified name in a query is a table only if the schema has it;
    # the others are columns of a table alias.
    for spec in schema.values():
        if "sources" in spec:
            spec["sources"] = [s for s in spec["sources"] if s in schema]
    return schema


# -- the directive -----------------------------------------------------

class tableref(nodes.Inline, nodes.Element):
    """A table name, linked to its section once every page is read."""


class flow(nodes.General, nodes.Element):
    """Filled with the diagram once every page is read."""


class sizes(nodes.General, nodes.Element):
    """Filled with the size table once every page is read."""


def short(name):
    return name.split(".", 1)[1] if name.startswith("shirudo.") else name


def ref(name):
    node = tableref(target=name)
    node += nodes.literal(short(name), short(name))
    return node


def para(*parts):
    p = nodes.paragraph()
    for part in parts:
        p += part if isinstance(part, nodes.Node) else nodes.Text(part)
    return p


def table(headers, rows, widths, classes=()):
    tbl = nodes.table(classes=list(classes))
    group = nodes.tgroup(cols=len(headers))
    tbl += group
    for width in widths:
        group += nodes.colspec(colwidth=width)
    head = nodes.thead()
    group += head
    row = nodes.row()
    for h in headers:
        row += nodes.entry("", nodes.paragraph(text=h))
    head += row
    body = nodes.tbody()
    group += body
    for cells in rows:
        row = nodes.row(classes=cells.get("classes", []))
        for cell in cells["cells"]:
            entry = nodes.entry()
            entry += cell if isinstance(cell, list) else [cell]
            row += entry
        body += row
    return tbl


def joined(items):
    p = nodes.paragraph()
    for n, item in enumerate(items):
        if n:
            p += nodes.Text("; ")
        for part in item:
            p += part if isinstance(part, nodes.Node) else nodes.Text(part)
    return p


# An insert-triggered view fires on inserts into the first table its
# query reads, and only that one; the tables it joins it only queries.
def triggered_by(view):
    if view["what"] != "mv" or view["refresh"] or not view["sources"]:
        return None
    return view["sources"][0]


def interval(text):
    m = re.match(r"every (\d+) (\w+)$", text)
    if m and m.group(1) != "1":
        return "every %s %ss" % m.groups()
    return text


def schema_of(env):
    if not hasattr(env, "clickhouse_schema"):
        env.clickhouse_schema = read_schema(
            os.path.dirname(os.path.abspath(env.srcdir)))
    return env.clickhouse_schema


class ClickHouseTable(SphinxDirective):

    required_arguments = 1
    has_content = True
    option_spec = {
        "kind": lambda arg: directives.choice(arg, tuple(KINDS)),
        "written-by": directives.unchanged,
        "queried-by": directives.unchanged,
        "ttl": directives.unchanged,
        "row-size": directives.unchanged,
        "scale": directives.unchanged,
        "reference": directives.unchanged,
        "bytes": float,
    }

    def inline(self, text):
        parsed, messages = self.state.inline_text(text, self.lineno)
        return parsed + messages

    def run(self):
        name = self.arguments[0]
        schema = schema_of(self.env)
        spec = schema.get(name)
        if spec is None or spec["what"] != "table":
            logger.warning("clickhouse-table: %s is not a table of the schema", name,
                           location=self.get_location())
            return []

        content = nodes.container()
        self.state.nested_parse(self.content, self.content_offset, content)
        meanings = {}
        for fields in list(content.findall(nodes.field_list)):
            for field in fields.children:
                fname = field[0].astext()
                for col in re.split(r",\s*", fname):
                    meanings[col] = (fname, field[1].children)
            fields.parent.remove(fields)

        out = []
        kind = self.options.get("kind")
        if kind:
            out.append(nodes.paragraph(text=KINDS[kind],
                                       classes=["meta", "kind-" + kind]))
        out += content.children

        clauses = spec["clauses"]
        views = [v for v in schema.values() if v["what"] in ("mv", "view")]
        writers = [v for v in views if v["what"] == "mv" and v["to"] == name]
        fires = [v for v in views if triggered_by(v) == name]
        readers = [v for v in views if name in v["sources"][1:]
                   or (name in v["sources"] and not triggered_by(v))]

        def written(v):
            if v["refresh"]:
                how = "refresh %s, %s" % (
                    interval(v["refresh"]),
                    "append" if v["append"] else "replaces the table")
                return [nodes.literal(text=short(v["name"])), " (%s)" % how]
            return [nodes.literal(text=short(v["name"])), " on insert into ",
                    ref(v["sources"][0])]

        def view_item(v):
            if v["what"] == "view":
                return [nodes.literal(text=short(v["name"])), " (view)"]
            return [nodes.literal(text=short(v["name"])), " into ",
                    ref(v["to"])]

        facts = [("Engine", [nodes.literal(text=clauses.get("ENGINE", ""))])]
        for label, clause in (("Order by", "ORDER BY"),
                              ("Partition by", "PARTITION BY"),
                              ("Primary key", "PRIMARY KEY"),
                              ("TTL", "TTL"), ("Settings", "SETTINGS")):
            value = [nodes.literal(text=clauses[clause])] \
                if clause in clauses else []
            if clause == "TTL" and "ttl" in self.options:
                value += ([nodes.Text(". ")] if value else []) + \
                    self.inline(self.options["ttl"])
            if value:
                facts.append((label, value))
        facts.append(("Defined in", [nodes.literal(text=spec["file"])]))

        def extra(option, items):
            if option in self.options:
                items.append(self.inline(self.options[option]))
            return items

        wrote = extra("written-by", [written(v) for v in writers])
        facts.append(("Written by", joined(wrote) if wrote else "nothing"))
        facts.append(("Fires on insert",
                      joined([view_item(v) for v in fires]) if fires
                      else "nothing"))
        read = extra("queried-by", [view_item(v) for v in readers])
        facts.append(("Queried by", joined(read) if read else
                      "nothing in the schema"))
        for label, option in (("Row size", "row-size"), ("Scale", "scale"),
                              ("Reference fleet", "reference")):
            if option in self.options:
                facts.append((label, self.inline(self.options[option])))

        flist = nodes.field_list(classes=["facts"])
        for label, value in facts:
            body = nodes.field_body()
            if isinstance(value, str):
                body += nodes.paragraph(text=value)
            elif isinstance(value, nodes.paragraph):
                body += value
            else:
                body += para(*value)
            flist += nodes.field("", nodes.field_name(text=label), body)
        out.append(flist)

        rows, seen = [], set()
        for col in spec["columns"]:
            ctype = [nodes.literal(text=col["type"])]
            if col["codec"]:
                ctype.append(nodes.Text(" "))
                ctype.append(nodes.literal(text="CODEC(%s)" % col["codec"],
                                           classes=["codec"]))
            meaning = meanings.get(col["name"])
            cells = [para(nodes.literal(text=col["name"])), para(*ctype)]
            body = [n.deepcopy() for n in meaning[1]] if meaning else []
            if col["default"]:
                body.append(nodes.paragraph(
                    "", "", nodes.literal(text=col["default"]),
                    classes=["default"]))
            cells.append(body or nodes.paragraph())
            rows.append({"cells": cells})
            if meaning is None:
                logger.warning("clickhouse-table: %s.%s is not described",
                               name, col["name"],
                               location=self.get_location())
            seen.add(col["name"])
        for col in sorted(set(meanings) - seen):
            logger.warning("clickhouse-table: %s has no column %s", name, col,
                           location=self.get_location())

        cols = nodes.container(classes=["columns"])
        cols += nodes.rubric(text="Columns (%d)" % len(spec["columns"]))
        cols += table(["Column", "Type", "Meaning"], rows, [22, 26, 52],
                      classes=["columns"])
        out.append(cols)

        section = self.state.parent
        anchor = section["ids"][0] if section.get("ids") else ""
        tables = getattr(self.env, "clickhouse_tables", {})
        if name in tables and tables[name]["docname"] != self.env.docname:
            logger.warning("clickhouse-table: %s is documented twice", name,
                           location=self.get_location())
        tables[name] = {
            "docname": self.env.docname, "anchor": anchor,
            "row_size": self.options.get("row-size", ""),
            "reference": self.options.get("reference", ""),
            "bytes": self.options.get("bytes"),
            "kind": self.options.get("kind", "store"),
        }
        self.env.clickhouse_tables = tables
        return out


class ClickHouseSizes(SphinxDirective):

    def run(self):
        return [sizes()]


class ClickHouseFlow(SphinxDirective):

    has_content = True
    option_spec = {"alt": directives.unchanged_required}

    def run(self):
        schema = schema_of(self.env)
        boxes, edges = {}, []
        for line in self.content:
            words = line.split("|", 1)
            fields = words[0].split()
            if not fields:
                continue
            if fields[0] == "box" and len(fields) >= 6:
                names = [n if "." in n else "shirudo." + n for n in fields[5:]]
                for n in names:
                    if schema.get(n, {}).get("what") != "table":
                        logger.warning("clickhouse-flow: %s is not a table "
                                       "of the schema", n,
                                       location=self.get_location())
                label = words[1].strip() if len(words) > 1 else \
                    " / ".join(short(n) for n in names)
                boxes[fields[1]] = {"x": int(fields[2]), "y": int(fields[3]),
                                    "w": int(fields[4]), "tables": names,
                                    "label": label}
            elif fields[0] == "edge" and len(fields) >= 5:
                a, b = fields[1], fields[3]
                if a not in boxes or b not in boxes:
                    logger.warning("clickhouse-flow: edge %s -> %s names an "
                                   "unknown box", a, b,
                                   location=self.get_location())
                    continue
                views = edge_views(schema, boxes[a]["tables"],
                                   boxes[b]["tables"])
                if not views:
                    logger.warning("clickhouse-flow: no view of the schema writes "
                                   "%s from %s", boxes[b]["label"],
                                   boxes[a]["label"],
                                   location=self.get_location())
                edges.append({"from": a, "fs": fields[2], "to": b,
                              "ts": fields[4],
                              "label": " ".join(fields[5:]),
                              "refresh": bool(views) and
                              all(v["refresh"] for v in views)})
            else:
                logger.warning("clickhouse-flow: cannot read %r", line,
                               location=self.get_location())
        return [flow(boxes=boxes, edges=edges,
                     alt=self.options.get("alt", ""))]


# The tables a view reads, with the tables behind any view it reads.
def reads(schema, view, seen=()):
    out = set()
    for src in view["sources"]:
        spec = schema.get(src, {})
        if spec.get("what") == "view" and src not in seen:
            out |= reads(schema, spec, seen + (src,))
        else:
            out.add(src)
    return out


# The views that write a table of dst from a table of src: an insert
# view only from the table it fires on, a refreshed one from any it reads.
def edge_views(schema, src, dst):
    found = []
    for v in schema.values():
        if v["what"] != "mv" or v["to"] not in dst:
            continue
        inputs = reads(schema, v) if v["refresh"] else {triggered_by(v)}
        if inputs & set(src):
            found.append(v)
    return found


BOX_H = 30


def side(box, where):
    x, y, w = box["x"], box["y"], box["w"]
    return {"r": (x + w, y + BOX_H / 2), "l": (x, y + BOX_H / 2),
            "b": (x + w / 2, y + BOX_H), "t": (x + w / 2, y)}[where]


def flow_svg(app, docname, node):
    boxes, edges = node["boxes"], node["edges"]
    tables = getattr(app.env, "clickhouse_tables", {})
    width = max(b["x"] + b["w"] for b in boxes.values()) + 10
    height = max(b["y"] for b in boxes.values()) + BOX_H + 10
    out = ['<figure class="flow"><div class="flow-scroll">'
           '<svg viewBox="0 0 %d %d" role="img" aria-label="%s">'
           '<defs><marker id="flow-ah" viewBox="0 0 10 10" refX="9" '
           'refY="5" markerWidth="7" markerHeight="7" orient="auto-start-'
           'reverse"><path d="M0,0 L10,5 L0,10 z"/></marker></defs>'
           % (width, height, escape(node["alt"]))]
    for e in edges:
        (x1, y1) = side(boxes[e["from"]], e["fs"])
        (x2, y2) = side(boxes[e["to"]], e["ts"])
        if e["fs"] == "r" and e["ts"] == "l":
            mx = (x1 + x2) / 2
            d = "M%g,%g C%g,%g %g,%g %g,%g" % (x1, y1, mx, y1, mx, y2,
                                               x2 - 2, y2)
        else:
            d = "M%g,%g L%g,%g" % (x1, y1, x2, y2 + (-2 if y2 > y1 else 2))
        out.append('<path class="edge%s" d="%s" marker-end="url(#flow-ah)"/>'
                   % (" dash" if e["refresh"] else "", d))
        if e["label"]:
            down = e["fs"] == "b"
            out.append('<text class="lbl" x="%g" y="%g" text-anchor="%s">%s'
                       '</text>' % ((x1 + x2) / 2 + (6 if down else 0),
                                    (y1 + y2) / 2 - (0 if down else 6),
                                    "start" if down else "middle",
                                    escape(e["label"])))
    for b in boxes.values():
        kind = tables.get(b["tables"][0], {}).get("kind", "store")
        box = ('<rect class="box k-%s" x="%d" y="%d" width="%d" height="%d" '
               'rx="4"/><text x="%g" y="%g" text-anchor="middle">%s</text>'
               % (kind, b["x"], b["y"], b["w"], BOX_H, b["x"] + b["w"] / 2,
                  b["y"] + BOX_H / 2 + 4, escape(b["label"])))
        entry = tables.get(b["tables"][0])
        if entry:
            uri = app.builder.get_relative_uri(docname, entry["docname"])
            if entry["anchor"]:
                uri += "#" + entry["anchor"]
            box = '<a href="%s">%s</a>' % (escape(uri), box)
        out.append(box)
    out.append('</svg></div><figcaption><span class="key k-null"></span>Null '
               '<span class="key k-store"></span>stored '
               '<span class="key k-ref"></span>reference '
               '<span class="key k-derived"></span>derived '
               '<span class="key k-ui"></span>read by the UI · solid: on '
               'insert · dashed: refreshed</figcaption></figure>')
    return "".join(out)


class TableRole(SphinxRole):

    def run(self):
        name = self.text.strip()
        if "." not in name:
            name = "shirudo." + name
        if name not in schema_of(self.env):
            logger.warning("table: %s is not in the schema", name,
                           location=self.get_location())
        return [ref(name)], []


# -- resolving ---------------------------------------------------------

def link(app, fromdoc, name, inner):
    entry = getattr(app.env, "clickhouse_tables", {}).get(name)
    if entry is None:
        return inner
    uri = app.builder.get_relative_uri(fromdoc, entry["docname"])
    if entry["anchor"]:
        uri += "#" + entry["anchor"]
    node = nodes.reference("", "", internal=True, refuri=uri)
    node += inner
    return node


def fmt_bytes(b):
    if b >= 1e9:
        return "%.0f GB" % (b / 1e9)
    if b >= 1e6:
        return "%.0f MB" % (b / 1e6)
    return "under 1 MB" if b > 0 else "0"


def resolve(app, doctree, docname):
    for node in list(doctree.findall(tableref)):
        node.replace_self(link(app, docname, node["target"],
                               node.children[0].deepcopy()))
    for node in list(doctree.findall(flow)):
        if app.builder.format == "html":
            node.replace_self(nodes.raw("", flow_svg(app, docname, node),
                                        format="html"))
        else:
            node.replace_self(nodes.paragraph(text=node["alt"]))
    tables = getattr(app.env, "clickhouse_tables", {})
    schema = schema_of(app.env)
    for node in list(doctree.findall(sizes)):
        order = [n for n in schema if n in tables]
        total = sum(tables[n]["bytes"] or 0 for n in order)
        rows = []
        for n in order:
            t = tables[n]
            rows.append({"cells": [
                para(link(app, docname, n, nodes.literal(text=n))),
                nodes.paragraph(text=t["reference"]),
                nodes.paragraph(text=fmt_bytes(t["bytes"] or 0),
                                classes=["num"])]})
        rows.append({"classes": ["total"], "cells": [
            nodes.paragraph(text="Total, approximate"),
            nodes.paragraph(text="All tables at the reference fleet"),
            nodes.paragraph(text="about %.1f GB" % (total / 1e9),
                            classes=["num"])]})
        node.replace_self(table(["Table", "Reference fleet", "Bytes"], rows,
                                [30, 55, 15], classes=["sizes"]))


def check(app, env):
    tables = getattr(env, "clickhouse_tables", {})
    for name, spec in schema_of(env).items():
        if spec["what"] == "table" and name not in tables:
            logger.warning("clickhouse-table: %s (%s) is not documented",
                           name, spec["file"])


def purge(app, env, docname):
    tables = getattr(env, "clickhouse_tables", {})
    for name in [n for n, t in tables.items() if t["docname"] == docname]:
        del tables[name]


def merge(app, env, docnames, other):
    tables = getattr(env, "clickhouse_tables", {})
    tables.update(getattr(other, "clickhouse_tables", {}))
    env.clickhouse_tables = tables


# The pages that document a table are read again whenever the schema
# changes, which Sphinx cannot see on its own.
def reread_schema(app, env, added, changed, removed):
    old = getattr(env, "clickhouse_schema", None)
    env.clickhouse_schema = read_schema(
        os.path.dirname(os.path.abspath(env.srcdir)))
    if old == env.clickhouse_schema:
        return []
    tables = getattr(env, "clickhouse_tables", {})
    return sorted({t["docname"] for t in tables.values()})


def setup(app):
    app.add_node(tableref)
    app.add_node(flow)
    app.add_node(sizes)
    app.add_directive("clickhouse-table", ClickHouseTable)
    app.add_directive("clickhouse-sizes", ClickHouseSizes)
    app.add_directive("clickhouse-flow", ClickHouseFlow)
    app.add_role("table", TableRole())
    app.connect("env-get-outdated", reread_schema)
    app.connect("doctree-resolved", resolve)
    app.connect("env-check-consistency", check)
    app.connect("env-purge-doc", purge)
    app.connect("env-merge-info", merge)
    return {"parallel_read_safe": True, "parallel_write_safe": True}
