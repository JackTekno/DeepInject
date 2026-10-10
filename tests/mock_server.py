#!/usr/bin/env python3
"""Local mock target for DeepInject tests.

Simulates a time-based (and boolean-based) blind SQL injection inside a small
in-memory "database". It is deliberately tiny and dependency-free (stdlib only)
so the test suite can verify end-to-end extraction without touching any real
system.

Run directly for a manual smoke test:
    python tests/mock_server.py --port 8099 --dialect mysql
"""

import argparse
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# ── Fake database ────────────────────────────────────────────

DATABASES = ["information_schema", "app_db"]

TABLES = {
    "app_db": ["orders", "users"],
}

COLUMNS = {
    "app_db.users": ["id", "password", "username"],
    "app_db.orders": ["id", "total"],
}

ROWS = {
    "app_db.users": [
        {"id": "1", "username": "admin", "password": "s3cr3t"},
        {"id": "2", "username": "alice", "password": "hunter2"},
    ],
    "app_db.orders": [
        {"id": "1", "total": "42"},
    ],
}

FINGERPRINT = {
    "VERSION()": "8.0.36-mock",
    "DATABASE()": "app_db",
    "USER()": "root@localhost",
    "@@HOSTNAME": "mock-host",
    "@@datadir": "/var/lib/mysql/",
}


def _table_count(db):
    return len(TABLES.get(db, []))


def _column_count(db, tbl):
    return len(COLUMNS.get(f"{db}.{tbl}", []))


def _row_count(db, tbl):
    return len(ROWS.get(f"{db}.{tbl}", []))


# ── Tiny SQL expression evaluator (only what the tool emits) ──

def _scalar(query):
    """Evaluate a whitelisted set of SELECT expressions from the fake DB."""
    q = re.sub(r"\s+", " ", query.strip().rstrip(";"))
    low = q.lower()

    if low.startswith("select "):
        low = low[7:].strip()

    m = re.fullmatch(r"'([^']*)'", low)
    if m:
        return m.group(1)

    for expr, value in FINGERPRINT.items():
        if low == expr.lower():
            return value

    m = re.search(r"count\(schema_name\) from information_schema\.schemata", low)
    if m:
        return str(len(DATABASES))

    m = re.search(r"schema_name from information_schema\.schemata.*limit (\d+),1", low)
    if m:
        idx = int(m.group(1))
        return DATABASES[idx] if idx < len(DATABASES) else ""

    m = re.search(r"count\(table_name\) from information_schema\.tables where table_schema='([^']+)'", low)
    if m:
        return str(_table_count(m.group(1)))

    m = re.search(r"table_name from information_schema\.tables where table_schema='([^']+)'.*limit (\d+),1", low)
    if m:
        tables = TABLES.get(m.group(1), [])
        idx = int(m.group(2))
        return tables[idx] if idx < len(tables) else ""

    m = re.search(r"count\(column_name\) from information_schema\.columns where table_schema='([^']+)' and table_name='([^']+)'", low)
    if m:
        return str(_column_count(m.group(1), m.group(2)))

    m = re.search(r"column_name from information_schema\.columns where table_schema='([^']+)' and table_name='([^']+)'.*limit (\d+),1", low)
    if m:
        cols = COLUMNS.get(f"{m.group(1)}.{m.group(2)}", [])
        idx = int(m.group(3))
        return cols[idx] if idx < len(cols) else ""

    m = re.search(r"count\(\*\) from ([a-z_]+)\.([a-z_]+)", low)
    if m:
        return str(_row_count(m.group(1), m.group(2)))

    m = re.search(r"ifnull\(cast\(([a-z_]+) as char\),'~null~'\) from ([a-z_]+)\.([a-z_]+) limit (\d+),1", low)
    if m:
        col, db, tbl, idx = m.group(1), m.group(2), m.group(3), int(m.group(4))
        rows = ROWS.get(f"{db}.{tbl}", [])
        if idx < len(rows):
            return rows[idx].get(col, "~NULL~")
        return "~NULL~"

    raise ValueError(f"mock: unsupported scalar query: {query}")


def _numeric(query):
    return int(_scalar(query))


# ── Condition + payload evaluation ───────────────────────────

def _strip_outer_parens(expr):
    """Remove redundant balanced outer parentheses: '((1=1))' -> '1=1'."""
    expr = expr.strip()
    while expr.startswith("(") and expr.endswith(")"):
        depth = 0
        balanced = True
        for i, ch in enumerate(expr):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(expr) - 1:
                    balanced = False
                    break
        if not balanced:
            break
        expr = expr[1:-1].strip()
    return expr


def _matching_paren(text, open_idx):
    """Index of the ')' matching the '(' at open_idx, or -1."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _inner_call(text, func):
    """Return the argument text of func(...) from a '<func>(...)' expression."""
    idx = text.lower().find(f"{func}(")
    if idx < 0:
        return None
    open_idx = idx + len(func)
    close_idx = _matching_paren(text, open_idx)
    if close_idx < 0:
        return None
    return text[open_idx + 1:close_idx]


def _eval_condition(cond):
    """Evaluate the subset of boolean conditions DeepInject generates."""
    c = re.sub(r"\s+", " ", cond.strip())
    c = _strip_outer_parens(c)

    if ">" in c:
        left, _, right = c.rpartition(">")
        right = right.strip()
        if right.isdigit():
            try:
                return _eval_value(left) > int(right)
            except ValueError:
                pass
    try:
        return bool(_eval_value(c))
    except ValueError:
        raise ValueError(f"mock: unsupported condition: {cond}")


def _eval_value(expr):
    """Evaluate a scalar/boolean expression (only what the tool emits)."""
    e = _strip_outer_parens(re.sub(r"\s+", " ", expr.strip()))
    low = e.lower()

    m = re.fullmatch(r"(\d+)=(\d+)", e)
    if m:
        return m.group(1) == m.group(2)

    if low == "(select 1) is not null":
        return True

    if low.startswith("length("):
        inner = _inner_call(e, "length")
        if inner is not None:
            return len(str(_eval_value(inner)))

    if low.startswith("ascii("):
        inner = _inner_call(e, "ascii")
        if inner is not None:
            argument = _strip_outer_parens(inner)
            m = re.fullmatch(r"substring\((.+),\s*(\d+)\s*,\s*1\)", argument, re.IGNORECASE)
            if m:
                value = str(_eval_value(m.group(1)))
                pos = int(m.group(2))
                char = value[pos - 1] if pos - 1 < len(value) else "\x00"
                return ord(char)

    value = _scalar(e)
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        return int(value)
    return value


def _extract_sleep_seconds(payload):
    for pattern in (r"sleep\((\d+)\)", r"waitfor delay '0:0:(\d+)'", r"pg_sleep\((\d+)\)"):
        m = re.search(pattern, payload, re.IGNORECASE)
        if m:
            return int(m.group(1))
    return None


def _condition_from_payload(payload):
    """Pull the boolean condition out of any supported MySQL style payload."""
    patterns = (
        r"if\(\(\s*(.+?)\s*\)>0\s*,\s*sleep\(",
        r"if\(\(\s*(.+?)\s*\)\s*\)\s*>\s*0",
        r"case when \(\s*(.+?)\s*\)>0 then sleep\(",
        r"where \(\s*(.+?)\s*\)>0",
        r"elt\(\(\s*(.+?)\s*\)>0\s*,\s*sleep\(",
        r"sleep\(if\(\(\s*(.+?)\s*\)>0\s*,",
    )
    for pattern in patterns:
        m = re.search(pattern, payload, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def evaluate_payload(payload):
    """Return seconds the mock should sleep for this payload."""
    sleep = _extract_sleep_seconds(payload)
    if sleep is None:
        return 0.0

    cond = _condition_from_payload(payload)
    if cond is None:
        return float(sleep)
    try:
        decide = _eval_condition(cond)
    except ValueError:
        return 0.0
    return float(sleep) if decide else 0.0


# ── HTTP handler ─────────────────────────────────────────────

TRUE_PAGE = b"<html><body><h1>Welcome back, admin</h1><p>3 records found</p></body></html>"
FALSE_PAGE = b"<html><body><h1>No results found</h1></body></html>"

# TRUE / FALSE wrappers the tool can emit (the mock only needs the MySQL pair).
BOOL_TEMPLATES = [
    ("1 AND ({c})", "1 AND NOT ({c})"),
    ("1 AND (CASE WHEN ({c}) THEN 1 ELSE 0 END)=1",
     "1 AND (CASE WHEN ({c}) THEN 0 ELSE 1 END)=1"),
]


def _extract_condition(payload, template):
    """Return the {c} substring if `payload` matches `template`, else None.

    Uses balanced-parenthesis matching (conditions themselves contain nested
    parentheses such as ``(SELECT ...)``), so a naive first-``)`` search would
    truncate them.
    """
    prefix, _, suffix = template.partition("{c}")
    start = payload.find(prefix)
    if start < 0:
        return None
    start += len(prefix)

    if prefix.endswith("("):
        open_idx = start - 1
        close_idx = _matching_paren(payload, open_idx)
        if close_idx < 0:
            return None
        cond = payload[start:close_idx]
    else:
        cond = payload[start:]

    if suffix:
        end = payload.find(suffix, start + len(cond))
        if end < 0:
            return None
        cond = payload[start:end]
    return cond


def _template_prefix(template):
    """Literal text before the {c} placeholder — used as a match marker."""
    return template.partition("{c}")[0]


class Handler(BaseHTTPRequestHandler):
    dialect = "mysql"
    sleep_scale = 1.0

    def log_message(self, *args):
        pass

    def _payloads(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        payloads = [v for values in params.values() for v in values]

        length = int(self.headers.get("Content-Length") or 0)
        if length:
            body = self.rfile.read(length)
            ctype = self.headers.get("Content-Type", "")
            if "application/json" in ctype:
                try:
                    data = json.loads(body.decode("utf-8", "replace") or "{}")
                    payloads += [str(v) for v in data.values()]
                except json.JSONDecodeError:
                    pass
            else:
                text = body.decode("utf-8", "replace")
                parts = re.split(r"[\r\n]", text)
                for part in parts:
                    for chunk in part.split("&"):
                        _, _, value = chunk.partition("=")
                        if value:
                            payloads.append(value)
        for _, value in self.headers.items():
            payloads.append(value)
        return payloads

    def _handle(self, method):
        payloads = self._payloads()
        for payload in payloads:
            seconds = evaluate_payload(payload) * self.sleep_scale
            if seconds > 0:
                time.sleep(seconds)

        body = self._render(payloads)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(body)

    def _render(self, payloads):
        if self.dialect != "bool":
            return b"<html><body>DeepInject mock target.</body></html>"

        # Evaluate the real boolean condition so TRUE/FALSE pages only differ
        # for conditions the tool actually asked about.
        for payload in payloads:
            for true_tpl, false_tpl in BOOL_TEMPLATES:
                for negate, template in ((False, true_tpl), (True, false_tpl)):
                    if _template_prefix(template) not in payload:
                        continue
                    cond = _extract_condition(payload, template)
                    if cond is None:
                        continue
                    try:
                        value = _eval_condition(cond)
                    except ValueError:
                        continue
                    if negate:
                        value = not value
                    return TRUE_PAGE if value else FALSE_PAGE
        return TRUE_PAGE

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_HEAD(self):
        self._handle("HEAD")


def serve(port=0, dialect="mysql", sleep_scale=1.0):
    """Start the mock server in a daemon thread; return (server, base_url)."""
    handler = type("BoundHandler", (Handler,), {"dialect": dialect, "sleep_scale": sleep_scale})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def main():
    parser = argparse.ArgumentParser(description="DeepInject mock target")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--dialect", choices=["mysql", "bool"], default="mysql")
    parser.add_argument("--sleep-scale", type=float, default=1.0)
    args = parser.parse_args()
    server, url = serve(args.port, args.dialect, args.sleep_scale)
    print(f"[+] mock target ({args.dialect}) listening on {url}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
