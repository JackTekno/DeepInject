#!/usr/bin/env python3
"""DeepInject self-test suite.

Run from the repository root:

    python -m unittest discover -s tests -v
    python tests/test_deepinject.py          # same thing directly

Coverage:
  * pure helpers (payload factory, obfuscator, parsers, filename safety)
  * checkpoint store reuse across runs
  * response fingerprint diffing
  * end-to-end extraction against the stdlib mock SQLi server:
      - time-based enumerate/columns/dump
      - boolean-based technique (response diffing)
      - resume from checkpoint without repeating requests
      - CLI surface flags (--verify, --dump-all, --fmt json, --state-clear)
"""

import io
import json
import os
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import deepinject as di  # noqa: E402
from tests import mock_server  # noqa: E402


def make_config(url, **overrides):
    cfg = di.Config(
        url=url,
        inject_param="id",
        inject_type="get",
        sleep_sec=1,
        threshold=0.2,
        retries=1,
        timeout=5,
        threads=1,
        dbms=di.DBMS.MYSQL,
        payload_style=0,
        technique=di.TECH_TIME,
        bool_template=di._BoolTemplates.for_dbms(di.DBMS.MYSQL),
    )
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


def cli_config(url, **overrides):
    """Build a Config the way main() would, for CLI-level validation coverage."""
    fields = {
        "url": url, "inject_param": "id", "inject_type": "get",
        "multipart_fields": {}, "file_fields": [],
        "cookies": {}, "headers": di.default_headers([]),
        "sleep_sec": 1, "threshold": 0.2, "retries": 1, "timeout": 5,
        "max_len": 32, "threads": 1, "dbms": di.DBMS.MYSQL,
        "obfuscation_level": 0, "payload_style": 0, "technique": di.TECH_TIME,
        "bool_template": di._BoolTemplates.for_dbms(di.DBMS.MYSQL),
        "assume_yes": True,
    }
    fields.update(overrides)
    return di.Config(**fields)


class ServerMixin:
    dialect = "mysql"
    sleep_scale = 1.0

    @classmethod
    def setUpClass(cls):
        cls.server, cls.url = mock_server.serve(dialect=cls.dialect, sleep_scale=cls.sleep_scale)
        # Warm up the server: the first request to a freshly bound socket can be
        # slow enough to look like a delay and flake the assertions below.
        try:
            di.requests.get(cls.url, timeout=5)
        except Exception:
            pass

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()


class TestHelpers(unittest.TestCase):

    def test_fmt_duration(self):
        self.assertEqual(di.fmt_duration(9.5), "9.5s")
        self.assertEqual(di.fmt_duration(90), "1m 30s")
        self.assertEqual(di.fmt_duration(3725), "1h 2m 5s")
        self.assertEqual(di.fmt_duration(-3), "0.0s")

    def test_parse_kv_and_cookies(self):
        self.assertEqual(di.parse_kv("a=1,b=2"), {"a": "1", "b": "2"})
        self.assertEqual(di.parse_kv("flag"), {"flag": ""})
        self.assertEqual(di.parse_kv(""), {})
        self.assertEqual(di.parse_cookies("PHPSESSID=abc; role=admin"),
                         {"PHPSESSID": "abc", "role": "admin"})

    def test_default_headers_merge(self):
        headers = di.default_headers(["Referer: https://x.local", "X-Test:value"])
        self.assertIn("User-Agent", headers)
        self.assertEqual(headers["Referer"], "https://x.local")
        self.assertEqual(headers["X-Test"], "value")

    def test_sanitize_and_slug(self):
        self.assertEqual(di.sanitize_filename("app_db"), "app_db")
        self.assertEqual(di.sanitize_filename("../../etc/passwd"), "etc_passwd")
        self.assertEqual(di.sanitize_filename("..\\..\\windows\\system32"), "windows_system32")
        self.assertEqual(di.sanitize_filename("///"), "deepinject")
        self.assertEqual(di.target_slug("https://target.local/upload.php?a=1"),
                         "target.local_upload.php")

    def test_bool_template_override(self):
        self.assertIsNone(di._BoolTemplates.parse_override(""))
        with self.assertRaises(ValueError):
            di._BoolTemplates.parse_override("1 AND ({c})")
        tpl = di._BoolTemplates.parse_override("1 AND ({c})|1 AND NOT ({c})")
        self.assertEqual(tpl[0].format(c="1=1"), "1 AND (1=1)")
        self.assertEqual(tpl[1].format(c="1=1"), "1 AND NOT (1=1)")

    def test_ask_yes_no_non_interactive(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=False):
            self.assertTrue(di.ask_yes_no("continue?", default=True))
            self.assertFalse(di.ask_yes_no("continue?", default=False))
        self.assertTrue(di.ask_yes_no("continue?", assume_yes=True))


class TestPayloadFactory(unittest.TestCase):

    def test_styles_per_dbms(self):
        self.assertEqual(di.PayloadFactory.styles_for("mysql"), [0, 1, 2, 3, 4, 5, 6, 7])
        self.assertNotIn(6, di.PayloadFactory.styles_for("pgsql"))
        self.assertTrue(di.PayloadFactory.supports("sqlite", 3))
        self.assertFalse(di.PayloadFactory.supports("sqlite", 6))

    def test_payloads_are_native(self):
        cases = {
            "mysql": "SLEEP(5)",
            "mssql": "WAITFOR DELAY '0:0:5'",
            "pgsql": "PG_SLEEP(5)",
            "oracle": "DBMS_PIPE.RECEIVE_MESSAGE",
            "sqlite": "RECURSIVE",
        }
        for dbms, needle in cases.items():
            payload = di.PayloadFactory.build(dbms, 0, "1=1", 5)
            self.assertIn(needle, payload, f"{dbms} payload not native: {payload}")

    def test_style_fallback_for_unsupported_style(self):
        payload = di.PayloadFactory.build("sqlite", 6, "ASCII(1)>0", 3)
        self.assertIn("RECURSIVE", payload)

    def test_true_probe_contains_sleep(self):
        self.assertIn("SLEEP(4)", di.PayloadFactory.true_probe("mysql", 0, 4))

    def test_condition_is_embedded(self):
        payload = di.PayloadFactory.build("mysql", 0, "ASCII(SUBSTRING((SELECT 1),1,1))>64", 2)
        self.assertIn("ASCII(SUBSTRING((SELECT 1),1,1))>64", payload)


class TestObfuscator(unittest.TestCase):

    def test_level0_is_identity(self):
        payload = "1 AND SLEEP(5)"
        self.assertEqual(di.Obfuscator.apply(payload, 0), payload)

    def test_level1_removes_spaces(self):
        out = di.Obfuscator.apply("1 AND SLEEP(5)", 1)
        self.assertNotIn(" ", out)

    def test_hex_and_char_helpers(self):
        self.assertEqual(di.Obfuscator.hex_str("ab"), "0x6162")
        self.assertEqual(di.Obfuscator.char_func("ab"), "CHAR(97,98)")


class TestFingerprint(unittest.TestCase):

    def test_identical_fingerprints_have_zero_diff(self):
        a = di.ResponseFingerprint(status=200, length=100, words=10, body_md5="x")
        b = di.ResponseFingerprint(status=200, length=100, words=10, body_md5="x")
        self.assertEqual(a.diff_score(b), 0)
        self.assertTrue(a.same_as(b))

    def test_status_change_dominates(self):
        a = di.ResponseFingerprint(status=200, length=100, words=10, body_md5="x")
        b = di.ResponseFingerprint(status=500, length=100, words=10, body_md5="x")
        self.assertGreater(a.diff_score(b), 100)


class TestCheckpointStore(unittest.TestCase):

    def test_roundtrip_and_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            store = di.CheckpointStore(path)
            self.assertIsNone(store.get("len", "abc"))
            store.set(12, "len", "abc")
            self.assertEqual(store.get("len", "abc"), 12)
            self.assertTrue(os.path.exists(path))

            reopened = di.CheckpointStore(path)
            self.assertEqual(reopened.get("len", "abc"), 12)
            self.assertGreaterEqual(reopened.hits, 1)

    def test_fresh_discards_previous_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            di.CheckpointStore(path).set(1, "k")
            store = di.CheckpointStore(path, fresh=True)
            self.assertIsNone(store.get("k"))

    def test_corrupt_state_file_is_tolerated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write("{not json")
            store = di.CheckpointStore(path)
            self.assertEqual(store.data["steps"], {})


class TestStats(unittest.TestCase):

    def test_record_and_snapshot(self):
        stats = di.Stats()
        stats.record(0.5, 100, 200)
        stats.record(1.5, 200, 200, retry=True)
        stats.record(3.0, 0, None, timeout=True)
        snap = stats.snapshot()
        self.assertEqual(snap["requests"], 3)
        self.assertEqual(snap["retries"], 1)
        self.assertEqual(snap["timeouts"], 1)
        self.assertEqual(snap["status_codes"], {"200": 2})
        self.assertAlmostEqual(snap["avg_latency"], 5.0 / 3, places=3)
        self.assertTrue(any("Requests" in line for line in stats.summary_lines()))

    def test_snapshot_and_summary_do_not_deadlock(self):
        # snapshot() aggregates while holding the stats lock and calls rate()/
        # avg_latency()/median_latency(); with a plain Lock that self-deadlocks,
        # which used to hang every run at the final report.
        stats = di.Stats()
        stats.record(0.1, 10, 200)
        done = []

        def worker():
            stats.summary_lines()
            stats.snapshot()
            done.append(True)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive(), "Stats.snapshot() deadlocked")
        self.assertEqual(done, [True])


class TestTimeBasedExtraction(ServerMixin, unittest.TestCase):
    dialect = "mysql"
    sleep_scale = 0.12  # keep the suite fast while still measurable

    def setUp(self):
        self.cfg = make_config(self.url, threshold=0.07, sleep_sec=1, max_len=32)
        self.engine = di.InjectionEngine(self.cfg)
        self.extractor = di.DataExtractor(self.engine)
        self.enumerator = di.Enumerator(self.extractor)

    def test_verify_detects_vulnerability(self):
        self.assertTrue(self.engine.verify())

    def test_calibrate_returns_baseline(self):
        baseline = self.engine.calibrate(samples=2)
        self.assertGreaterEqual(baseline, 0)
        self.assertLess(baseline, self.cfg.threshold)

    def test_charset_char_extraction(self):
        got = self.extractor.extract("SELECT VERSION()", show=False)
        self.assertEqual(got, mock_server.FINGERPRINT["VERSION()"])

    def test_line_based_char_expr_matches_mysql(self):
        self.assertEqual(self.extractor.char_expr("SELECT 1", 3),
                         "ASCII(SUBSTRING((SELECT 1),3,1))")

    def test_data_extractor_char_expr_per_dbms(self):
        cases = {
            di.DBMS.MSSQL: "ASCII(SUBSTRING((SELECT 1),2,1))",
            di.DBMS.PGSQL: "ASCII(SUBSTRING((SELECT 1) FROM 2 FOR 1))",
            di.DBMS.ORACLE: "ASCII(SUBSTR((SELECT 1),2,1))",
        }
        for dbms, expected in cases.items():
            self.cfg.dbms = dbms
            self.assertEqual(self.extractor.char_expr("SELECT 1", 2), expected)

    def test_enum_databases(self):
        self.assertEqual(self.enumerator.enum_databases(), mock_server.DATABASES)

    def test_enum_tables(self):
        self.assertEqual(self.enumerator.enum_tables("app_db"), mock_server.TABLES["app_db"])

    def test_enum_columns(self):
        self.assertEqual(self.enumerator.enum_columns("app_db", "users"),
                         mock_server.COLUMNS["app_db.users"])

    def test_dump_table(self):
        rows = self.enumerator.dump_table("app_db", "users",
                                          mock_server.COLUMNS["app_db.users"], limit=5)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["username"], "admin")
        self.assertEqual(rows[0]["password"], "s3cr3t")
        self.assertEqual(rows[1]["username"], "alice")

    def test_universal_get_count_stops_at_zero(self):
        count = self.extractor.get_count(
            "SELECT COUNT(table_name) FROM information_schema.tables WHERE table_schema='app_db'")
        self.assertEqual(count, 2)
        empty = self.extractor.get_count(
            "SELECT COUNT(table_name) FROM information_schema.tables WHERE table_schema='nope'")
        self.assertEqual(empty, 0)

    def test_condition_memo_avoids_repeat_requests(self):
        cond = "ASCII(SUBSTRING((SELECT 'ab'),1,1))>64"
        first = self.engine.inject_condition_memo(cond)
        before = self.engine.stats.requests
        second = self.engine.inject_condition_memo(cond)
        self.assertEqual(first, second)
        self.assertEqual(self.engine.stats.requests, before, "memoized condition re-sent a request")

    def test_request_delay_is_applied(self):
        self.cfg.request_delay = 0.05
        start = di.time.monotonic()
        self.engine._send("1")
        self.assertGreaterEqual(di.time.monotonic() - start, 0.05)


class TestBooleanTechnique(ServerMixin, unittest.TestCase):
    dialect = "bool"

    def setUp(self):
        self.cfg = make_config(self.url, technique=di.TECH_BOOL, threshold=0.2)
        self.engine = di.InjectionEngine(self.cfg)
        self.extractor = di.DataExtractor(self.engine)
        self.enumerator = di.Enumerator(self.extractor)

    def test_calibration_finds_difference(self):
        ok, score = self.engine.calibrate_boolean(samples=1)
        self.assertTrue(ok)
        self.assertGreater(score, 0)
        self.assertGreater(self.engine.bool_tolerance, 0)

    def test_boolean_condition_true_false(self):
        self.engine.calibrate_boolean(samples=1)
        self.assertTrue(self.engine.bool_inject("1=1"))
        self.assertFalse(self.engine.bool_inject("1=2"))

    def test_boolean_enum_databases(self):
        self.engine.calibrate_boolean(samples=1)
        self.assertEqual(self.enumerator.enum_databases(), mock_server.DATABASES)

    def test_time_base_on_boolean_target_is_not_vulnerable(self):
        # The boolean mock never sleeps, so a time-based decision must stay below
        # the threshold. The asserted payload is an unconditional true_probe
        # (which embeds a real SLEEP call); the mock ignores SLEEP entirely in
        # bool mode, so a positive would mean the engine mis-attributed latency.
        cfg = make_config(self.url, technique=di.TECH_TIME, payload_style=0, threshold=0.5)
        engine = di.InjectionEngine(cfg)
        engine._send(di.PayloadFactory.true_probe("mysql", 0, 1))  # warm-up
        elapsed = engine._send(di.PayloadFactory.true_probe("mysql", 0, 0))
        self.assertLess(elapsed, cfg.threshold,
                        "boolean-only target should not look time-vulnerable")


class TestResume(ServerMixin, unittest.TestCase):
    dialect = "mysql"
    sleep_scale = 0.12

    def test_state_reuses_completed_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = os.path.join(tmp, "state.json")

            cfg = make_config(self.url, threshold=0.07, state_file=state, max_len=32)
            engine = di.InjectionEngine(cfg)
            engine.state = di.CheckpointStore(state)
            extractor = di.DataExtractor(engine)
            self.assertEqual(extractor.extract("SELECT DATABASE()", show=False), "app_db")
            first_requests = engine.stats.requests
            self.assertGreater(first_requests, 0)

            engine2 = di.InjectionEngine(cfg)
            engine2.state = di.CheckpointStore(state)
            extractor2 = di.DataExtractor(engine2)
            self.assertEqual(extractor2.extract("SELECT DATABASE()", show=False), "app_db")
            self.assertEqual(engine2.stats.requests, 0,
                             "resumed extraction should not need new requests")

    def test_cli_state_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = os.path.join(tmp, "state.json")
            di.CheckpointStore(state).set(1, "k")
            code = di.main_entry(["-u", "http://127.0.0.1:1/", "--param", "id",
                                  "--state", state, "--state-clear"])
            self.assertEqual(code, 0)
            self.assertIsNone(di.CheckpointStore(state).get("k"))


class TestCliValidation(unittest.TestCase):
    """Usage errors must exit 2, and main_entry must translate them to a code."""

    def _exit_code(self, argv):
        # main() is the CLI surface and is expected to raise SystemExit;
        # main_entry() is the embeddable surface and returns the code instead.
        with self.assertRaises(SystemExit) as ctx:
            di.main(argv)
        self.assertEqual(ctx.exception.code, 2)
        return di.main_entry(argv)

    def test_missing_param_exits_2(self):
        self.assertEqual(self._exit_code(["-u", "http://127.0.0.1:1/"]), 2)

    def test_bad_json_body_exits_2(self):
        self.assertEqual(
            self._exit_code(["-u", "http://127.0.0.1:1/", "--param", "id",
                             "--type", "json", "--json-body", "{oops"]), 2)

    def test_json_type_requires_body(self):
        self.assertEqual(
            self._exit_code(["-u", "http://127.0.0.1:1/", "--param", "id",
                             "--type", "json"]), 2)

    def test_invalid_bool_template_exits_2(self):
        self.assertEqual(
            self._exit_code(["-u", "http://127.0.0.1:1/", "--param", "id",
                             "--bool-template", "no-placeholder"]), 2)

    def test_resume_requires_state(self):
        self.assertEqual(
            self._exit_code(["-u", "http://127.0.0.1:1/", "--param", "id", "--resume"]), 2)

    def test_non_positive_timing_rejected(self):
        self.assertEqual(
            self._exit_code(["-u", "http://127.0.0.1:1/", "--param", "id", "--sleep", "0"]), 2)


class TestCliEndToEnd(ServerMixin, unittest.TestCase):
    dialect = "mysql"
    sleep_scale = 0.12

    def _run(self, extra):
        argv = ["-u", self.url, "--type", "get", "--param", "id",
                "--sleep", "1", "--threshold", "0.07", "--retries", "1",
                "--verify", "--auto-detect"] + extra
        return di.main_entry(argv)

    def test_verify_only_run(self):
        self.assertEqual(self._run([]), 0)

    def test_enum_db_writes_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.json")
            code = di.main_entry(["-u", self.url, "--type", "get", "--param", "id",
                                  "--sleep", "1", "--threshold", "0.07", "--retries", "1",
                                  "--technique", "time", "--auto-detect",
                                  "--enum-db", "-o", out, "--fmt", "json", "-y"])
            self.assertEqual(code, 0)
            with open(out, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["databases"], mock_server.DATABASES)
            self.assertEqual(data["_meta"]["technique"], "time")
            self.assertIn("stats", data)

    def test_dump_all_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "all.json")
            dump_dir = os.path.join(tmp, "tables")
            code = di.main_entry(["-u", self.url, "--type", "get", "--param", "id",
                                  "--sleep", "1", "--threshold", "0.07", "--retries", "1",
                                  "--technique", "time", "--auto-detect",
                                  "--dump-all", "--dump-limit", "3", "--db", "app_db",
                                  "--dump-dir", dump_dir,
                                  "-o", out, "--fmt", "json", "-y"])
            self.assertEqual(code, 0)
            with open(out, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["dump_all_summary"]["tables_dumped"], 2)
            self.assertGreaterEqual(data["dump_all_summary"]["rows_extracted"], 3)
            self.assertTrue(os.path.exists(os.path.join(dump_dir, "manifest.json")))
            self.assertTrue(os.path.exists(os.path.join(dump_dir, "app_db.users.json")))

    def test_dump_all_skips_system_schemas(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "all.json")
            code = di.main_entry(["-u", self.url, "--type", "get", "--param", "id",
                                  "--sleep", "1", "--threshold", "0.07", "--retries", "1",
                                  "--technique", "time", "--auto-detect",
                                  "--dump-all", "--dump-limit", "2",
                                  "-o", out, "--fmt", "json", "-y"])
            self.assertEqual(code, 0)
            with open(out, "r", encoding="utf-8") as f:
                data = json.load(f)
            dumped = data["dump_all_summary"]["dumped_databases"]
            self.assertIn("app_db", dumped)
            self.assertNotIn("information_schema", dumped)
            # No report section may reference the skipped schema either
            self.assertFalse([k for k in data if "information_schema" in k],
                             "skipped schema leaked into the report sections")

    def test_dump_all_exclude_db_empty_allows_all(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "all.json")
            code = di.main_entry(["-u", self.url, "--type", "get", "--param", "id",
                                  "--sleep", "1", "--threshold", "0.07", "--retries", "1",
                                  "--technique", "time", "--auto-detect",
                                  "--dump-all", "--dump-limit", "1", "--exclude-db", "-",
                                  "-o", out, "--fmt", "json", "-y"])
            self.assertEqual(code, 0)
            with open(out, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertIn("information_schema", data["dump_all_summary"]["databases"])

    def test_bool_report_formats(self):
        # Only the report writers are under test here, so run against a boolean
        # target; each format re-uses its own calibration but the mock is shared.
        server, url = mock_server.serve(dialect="bool")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                for fmt in ("txt", "csv", "jsonl"):
                    out = os.path.join(tmp, f"out.{fmt}")
                    code = di.main_entry(["-u", url, "--type", "get", "--param", "id",
                                          "--sleep", "1", "--threshold", "0.2", "--retries", "1",
                                          "--technique", "bool", "--enum-db",
                                          "-o", out, "--fmt", fmt, "-y"])
                    self.assertEqual(code, 0)
                    self.assertTrue(os.path.getsize(out) > 0, f"empty {fmt} report")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
