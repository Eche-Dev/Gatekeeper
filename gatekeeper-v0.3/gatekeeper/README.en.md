# Gatekeeper

> **This is the English README.** The Spanish one is the primary one:
> [README.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/README.md).
> The documentation (including the web version) is in Spanish.

![CI](https://github.com/Eche-Dev/Gatekeeper/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.13-blue)
![mypy](https://img.shields.io/badge/mypy-strict-2a6db2)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

**Gatekeeper is a security middleware for FastAPI and Starlette.** It sits in
front of your application and, on every request, it does three things:

1. **Limits the traffic** per IP (sliding window, in memory or shared in Redis).
2. **Adds the security headers** your app should serve and nobody remembers to
   add (`nosniff`, `HSTS`, `X-Frame-Options`…).
3. **Looks for attack patterns** in the path, the query string, the headers and
   the body: SQLi, XSS, path traversal, NoSQL, system commands, SSRF, SSTI,
   CRLF, Log4Shell and proto pollution.

It is **one more layer** of defence in depth, not a WAF: it does not replace
parameterized queries or input validation. And it does not promise "nobody will
attack you": it **publishes how much it detects and how much it gets wrong**,
with three measured corpora and the numbers in plain sight.

## Why it exists

Three problems that show up in almost any API and that do not need anybody to
be malicious:

- **One IP can ask for everything.** Without a request limit, a loop against
  your login is a brute-force attack and a crawler is a DDoS.
- **Security headers do not install themselves.** `X-Content-Type-Options`,
  `Strict-Transport-Security` or `X-Frame-Options` have to be added by hand in
  every service, and one forgotten microservice is enough.
- **An unvalidated field is a door.** A search, a filter or a parameter that
  ends up in a query or in a template becomes an injection if nobody reviews
  it.

Gatekeeper covers all three **in one place, in front of your app**, without
touching endpoint by endpoint.

## Installation

```bash
pip install gatekeeper-asgi             # core
pip install "gatekeeper-asgi[yaml]"     # + YAML configuration
pip install "gatekeeper-asgi[redis]"    # + rate limit shared between workers
```

It needs Python 3.10+ and Starlette 0.23+ (FastAPI already brings it).

## Usage

```python
from fastapi import FastAPI
from gatekeeper import Config, GatekeeperMiddleware

app = FastAPI()
app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=100, rate_window=60))
# or with Redis, so every worker counts the same thing:
# Config(rate_backend="redis", redis_url="redis://localhost:6379/0")
# or: Config.from_yaml("gatekeeper.yaml")   (see examples/gatekeeper.yaml)
```

One line and your app already has rate limiting, security headers and
inspection of the query and the body. The whole configuration is in the
[API reference](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/api.md).

## What happens when it fires

A request with an SQLi payload in the query:

```console
$ curl -i "http://localhost:8000/?q=1%27%20OR%20%271%27%3D%271"
HTTP/1.1 403 Forbidden
content-type: application/json
x-content-type-options: nosniff
x-frame-options: DENY
strict-transport-security: max-age=31536000; includeSubDomains

{"detail":"Forbidden"}
```

And in the log, a JSON event (never the payload **values**: only the rule, the
**name** of the field that fired — the attacker picks that name, so it is
sanitized and truncated — and the pattern):

```json
{"ts": 1793039080.65, "event": "attack_detected", "ip": "203.0.113.7",
 "method": "GET", "path": "/", "rule": "sqli", "source": "query",
 "field": "q", "pattern": "\\b(or|and)\\b\\s{0,16}...", "blocked": true}
```

The full event catalogue is in
[`corpus/events.json`](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/events.json).

## What it inspects

| | Detail |
|---|---|
| Rate limiting | Sliding window per IP. In memory (one process) or in Redis with an atomic Lua script (shared between workers), via `redis.asyncio`, without blocking the event loop |
| Headers | `nosniff`, `X-Frame-Options`, `HSTS`, `Referrer-Policy`, `Permissions-Policy`. It never overwrites your app's, and they also go on the rejections |
| Detection | Eleven families: SQLi, XSS, path traversal, sensitive files, NoSQL, system commands, SSRF, SSTI, CRLF, Log4Shell and proto pollution. The detail of each one, with its false-positive boundary, is in [docs/amenazas.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/amenazas.md) (in Spanish) |
| Surfaces | Path, query string, headers, JSON and form body, multipart names and the WebSocket handshake |
| Evasion | Repeated URL encoding (3 rounds), IIS `%uXXXX` escapes, full-width characters (NFKC), SQL comments `/**/` and versioned ones (`/*!50000…*/`), HTML entities, numeric **and named** |
| Budgets | `max_body_size` (256 KiB), `max_fields` (1000 texts) and `max_inspection_ms` (1000 ms). When they run out the request is rejected with **413**: it is never admitted uninspected |
| Your own rules | Regexes in YAML or in `Config(custom_rules=...)`, validated at startup (a regex with catastrophic backtracking is a `ValueError`) |
| Audit | JSON events on the `gatekeeper` logger. Never the values of the fields |

## What it measures (not what it promises)

Three corpora are measured, and all three are guarded in CI: if a new rule
makes them worse, the workflow fails.

The first is **ours**, written by hand and with documented provenance
([corpus/](https://github.com/Eche-Dev/Gatekeeper/tree/main/gatekeeper-v0.3/gatekeeper/corpus/)):

| Metric (own corpus) | Value |
|---|---|
| Attacks detected | 159 / 159 (**100.0%**) |
| Undocumented false negatives | 0 |
| Legitimate requests blocked without documentation | **0** / 131 |
| Documented false positives (accepted limits) | 8 |

The second one is the **held-out** corpus: written once, without looking at the
rule signatures, and measured ever since. It is the one that says whether the
rules generalize or only remember the cases they were written with:

| Metric (held-out corpus) | Value |
|---|---|
| Attacks detected | 103 / 109 (**94.5%**) |
| Undocumented false negatives | 0 (6 documented, with their reason) |
| Legitimate requests blocked without documentation | **0** / 140 |
| Documented false positives (accepted limits) | 5 |

94.5% instead of 100% is expected: the own corpus can be used to tune the
rules, the held-out one cannot. That difference is information, not a defect:
it is what separates "the rules detect this" from "the rules detect what they
were written for". The methodology is in
[corpus/HELDOUT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/HELDOUT.md)
(in Spanish).

The third one is **someone else's**: the regression tests of the
[OWASP Core Rule Set](https://github.com/coreruleset/coreruleset) (Apache-2.0,
commit `30cb436`, imported with `tools/import_crs.py`), written by other people
for a different WAF, with its own negatives:

| Metric (external CRS corpus, families 930/941/942) | Value |
|---|---|
| Imported tests | 1379 (1135 in scope, 12 excluded and declared) |
| Attacks detected | 465 / 1135 (**41.0%**) |
| CRS negatives blocked (FP) | 11 / 232 (4.7%) |

That 41.0% is not a goal: it is the **baseline** of a corpus designed for a
500+ rule WAF with far more obfuscated payloads, and the workflow watches it so
that it does not drop. Publishing the whole thing is the point: a 100% of our
own and a 41.0% of someone else's, both measured and both guarded in CI.

The details, including the payloads that slip through and why, are in
[corpus/REPORT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/REPORT.md).
These numbers measure the individual scans; they do not include
`inspect_cross_carrier=True`.

## Configuration

The essentials, the rest in the
[API reference](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/api.md):

| Option | Default | What it does |
|---|---|---|
| `rate_limit` / `rate_window` | `100` / `60` | allowed requests per IP and window (0 disables) |
| `rate_backend` | `memory` | `memory` or `redis` (shared between workers) |
| `inspect_requests` / `inspect_body` | `True` | inspection of query and body |
| `monitor_only` | `False` | log without blocking (to measure before you block) |
| `disabled_rules` | `∅` | turn specific families off (`sqli`, `xss`, `path_traversal`…) |
| `rule_packs` | `∅` (all) | enable a subset: `minimal`, `api`, `web`, `infrastructure`, `strict` |
| `exclude_fields` | `[]` | fields exempt from inspection (parameter, header or JSON pointer); globs allowed |
| `custom_rules` | `∅` | your own regexes: `{name: regex}` or `[{name, pattern}]` |
| `max_body_size` | `256 KiB` | limit of the inspected body |
| `max_fields` / `max_inspection_ms` | `1000` / `1000` | inspection budgets (when exhausted → 413) |
| `redis_timeout` | `2.0` | seconds to wait when connecting to Redis. With Redis down, every request waits this long (measured: 2.0 s per request) |
| `allow_paths` | `[]` | globs exempt from inspection (not from rate limiting) |
| `blocked_ips` / `trust_proxy` | `∅` / `False` | blocking by IP or CIDR, and use of `X-Forwarded-For` |

`Config` **fails at startup**, not in production: unknown keys (a typo like
`rate_limt`), invalid or empty regexes, duplicate names, non-existent
`disabled_rules` and unknown packs raise `ValueError`.

### Two decisions that usually come up

**If your app exposes less surface than you assume**, instead of turning rules
off one by one, enable a pack:

```python
from gatekeeper import Config

Config(rule_packs=["api"])   # SQLi, NoSQL, traversal, files, SSRF, Log4Shell, CRLF, cmdi
```

An unknown pack is a `ValueError` at startup: an app cannot end up without
protection because somebody wrote `rule_packs=["we"]`.

**If your app deliberately accepts a value that a signature blocks** (a search
engine that indexes security documentation, a `template` parameter with Jinja, a
webhook), exempt **that field**, not the whole family:

```python
Config(exclude_fields=["template", "bio", "doc_*"])
```

It works on all three transports (query parameter, header and JSON pointer),
and the detection that crosses several fields is preserved: if you exclude `a`
but the payload is split between `a` and `b`, Gatekeeper removes `a` from the
target and keeps watching `b`.

### Measure before you block

Put the middleware in front with `monitor_only=True`, let the real traffic run
and look at what fires:

```bash
gatekeeper report gatekeeper.log          # ranking of rules, paths and fields
gatekeeper report gatekeeper.log --json   # machine-readable output
```

The report groups by (rule, field) — what repeats is noise — and proposes a
ready-to-paste `exclude_fields` or `disabled_rules`. It accepts the JSON
emitted by Gatekeeper's logger or a generic access log
(`GET /path?q=… 200`).

## What it does NOT cover

- Regex detection has false positives and false negatives: it **does not
  replace** parameterized queries, input validation or a real WAF.
- The **contents** of uploaded files are not inspected (field and file names
  are).
- WebSocket **frames** are not inspected: the handshake is (path, query and
  headers), and it is rate limited too.
- Binaries that are not JSON (image, PDF, zip…) are not read.
- By default every body value is analysed on its own. With
  `inspect_cross_carrier=True` the path/query is combined with the non-excluded
  textual values; it is opt-in and its result is **not** in the numbers above.
- Mongo's `$gt`/`$lt`/`$in` operators are left out of the NoSQL signature on
  purpose (legitimate filters use them); `localhost` and `127.0.0.1` do not
  count as SSRF (development OAuth).
- With `rate_backend="memory"` and several workers, the effective limit is
  multiplied: use Redis.
- If Redis does not answer, `rate_fail_open=True` (the default) keeps admitting
  requests; set it to `False` if you prefer 503.
- `trust_proxy=False` by default; enable it only behind a trusted proxy, and
  add `trusted_proxy_cidrs` if the app is reachable another way.
- `allow_paths` exempts from inspection, not from rate limiting or IP
  blocking.

## Demo

A real session against
[`demo/app.py`](https://github.com/Eche-Dev/Gatekeeper/tree/main/gatekeeper-v0.3/gatekeeper/demo/)
(uvicorn + curl, no tricks): normal traffic passes, the payloads get 403, and
the audit log records the rule, the field and the pattern that fired — never
the content.

![Gatekeeper demo](https://github.com/Eche-Dev/Gatekeeper/raw/main/gatekeeper-v0.3/gatekeeper/docs/assets/demo.gif)

## Cost per request

`python benchmarks/latency.py` measures the cost on your machine, calling ASGI
directly and without network. In the last local run (Python 3.14.8 on Windows),
the full scenario —query inspection plus rate limiting— had a **p50 of 141 µs,
a p95 of 155 µs and a p99 of 216 µs** over a 13 µs baseline without the
middleware. With a small JSON body, p50 of 244 µs.

**The size of the body is what matters**, and it is worth being explicit:

| Body | p50 | p95 | p99 | CPU |
|---|---:|---:|---:|---:|
| empty | 141 µs | 155 µs | 216 µs | 0.6 ms |
| 100 KB | **8.3 ms** | 10.9 ms | 18.7 ms | 9.0 ms |

A 100 KB body costs **59 times more** than an empty one, and the middleware
pays it **before** the application sees the request. The default budget
(`max_body_size`, 256 KiB) is what keeps it from growing without a limit; with
big bodies, lowering it is the first lever.

These are noisy local measurements: they are not end-to-end latency and not an
SLA. The benchmark publishes p50, p95 and p99 so the tail does not hide behind
an average, and `python benchmarks/latency.py --save base.json` saves a
baseline to compare a change on the same machine. The CI compares **the PR code
and `main` on the same runner** (the machine noise cancels out; an absolute
threshold would not work).

**And if Redis goes down**, every request waits for the connection timeout
before deciding: measured, **2.0 s per request** with the default value
(fail-open admitted the request after 2.017 ms; fail-closed returned 503 after
2.018 ms). It is a wait, not a failure: the API still answers, but slowly. It
is tunable with `redis_timeout` (2.0 s by default; lower it if your Redis is on
the same network).

## Documentation

Full guide with
[MkDocs Material](https://squidfunk.github.io/mkdocs-material/) in
[`docs/`](https://github.com/Eche-Dev/Gatekeeper/tree/main/gatekeeper-v0.3/gatekeeper/docs/):
usage, detection and measurement, threat model, security, API reference and
development. Locally: `mkdocs serve`. It is published at
<https://eche-dev.github.io/Gatekeeper/> on every push to `main` (`--strict`
build in CI: a broken link fails the workflow).

New to the project? Start with the
[quick start guide](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/inicio-rapido.md):
two `curl` commands verify that a normal request gets 200 and an attack gets
403. And if you decide **where** to deploy it, the
[deployment guide](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/despliegue.md)
says which value changes in each topology (one process, several workers,
Docker, reverse proxy).

Contributing: [CONTRIBUTING.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/CONTRIBUTING.md)
· [Code of conduct](https://github.com/Eche-Dev/Gatekeeper/blob/main/CODE_OF_CONDUCT.md)
· Issue and PR templates in the repo root.

## Development

```bash
pip install -e ".[dev]"
ruff check .            # style
mypy                    # strict types (src/gatekeeper)
bandit -r src -q        # static security analysis
pytest --cov=gatekeeper   # includes fuzzing with hypothesis (tests/test_fuzz.py)
python tools/evaluate.py --check     # detection and FP rates (own + CRS)
python tools/import_crs.py --check   # provenance of the external corpus
python tools/check_docs.py           # docs coherence: version, links, minimums
python benchmarks/latency.py         # per-request cost
python -m build && twine check dist/*   # the package can be published
```

## Project

- [CHANGELOG.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/CHANGELOG.md) — what changes in each version.
- [SECURITY.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/SECURITY.md) — threat model, limits and how to report a vulnerability.
- [corpus/REPORT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/REPORT.md) — generated detection report.

MIT licensed.
