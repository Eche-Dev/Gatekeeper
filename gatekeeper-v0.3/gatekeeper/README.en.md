# Gatekeeper

> **This is the English README.** The Spanish one is
> [README.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/README.md),
> and so is the documentation (the web version is in Spanish).

![CI](https://github.com/Eche-Dev/Gatekeeper/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.13-blue)
![mypy](https://img.shields.io/badge/mypy-strict-2a6db2)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

Security middleware for FastAPI/Starlette. One extra layer in front of your app:
rate limiting, security headers, attack-pattern detection in query and body,
your own rules via YAML, and JSON audit events.

```bash
pip install gatekeeper-asgi             # core
pip install "gatekeeper-asgi[yaml]"     # + YAML configuration
pip install "gatekeeper-asgi[redis]"    # + rate limit shared between workers
```

```python
from fastapi import FastAPI
from gatekeeper import Config, GatekeeperMiddleware

app = FastAPI()
app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=100, rate_window=60))
# or with Redis, so every worker counts the same thing:
# Config(rate_backend="redis", redis_url="redis://localhost:6379/0")
# or: Config.from_yaml("gatekeeper.yaml")   (see examples/gatekeeper.yaml)
```

## What it covers

| Protection | Detail |
|---|---|
| Rate limiting | Sliding window per IP. In memory (one process) or in Redis with an atomic Lua script (shared between workers), via `redis.asyncio`, without blocking the event loop |
| Headers | nosniff, X-Frame-Options, HSTS, Referrer-Policy, Permissions-Policy (never overwrites your app's) |
| SQLi | UNION SELECT, tautologies (`' OR '1'='1`, `?a=1=1`), stacked queries (`; DROP`), time-based (`sleep()`, `WAITFOR DELAY`), error-based (`EXTRACTVALUE`, `CONVERT`), column probing (`ORDER BY 10`) |
| XSS | `<script>`, event handlers with and without a tag (`onerror=`, ` onload=`), `javascript:`, `data:text/html`, with double encoding |
| Path traversal | `../`, `..\`, `..;/`, with repeated decoding and segment boundaries (`foo../x` is not a jump) |
| Sensitive files | `/etc/passwd`, `shadow`, `subuid`; `/proc/self/environ`; `win.ini`; `.ssh/id_*`; `.aws/credentials`; `.docker/secrets`; `.git/config`; `.env` (they need a separator: `?q=.env` passes) |
| NoSQL | Mongo injection operators: `$ne`, `$nin`, `$where`, `$regex` inside JSON or brackets (`user[$ne]=x`). `$gt`/`$lt`/`$in` are left out: legitimate filters use them |
| System commands | Shell separator + binary (`; ls`, `\| cat`, `&& whoami`, `$(id)`, `` `uname` ``), Windows LOLBins (`powershell.exe`), PHP webshells (`;system('`, `shell_exec(`), reverse shell `/dev/tcp/` |
| SSRF | Cloud metadata (AWS/GCP/Azure/Alibaba) and local-read schemes (`file://`, `gopher://`, `dict://`, `jar://`); `localhost` is not blocked (development OAuth) |
| SSTI | Template arithmetic (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`) and dangerous objects (`config`, `self`, `__class__`, `__subclasses__`) |
| CRLF | Newline followed by a header: response splitting and header injection (real CRLF or a literal `\r\n`) |
| Log4Shell | `${jndi:ldap://…}` with its obfuscations (`${${::-j}ndi:`) and exfiltration lookups (`${env:AWS_SECRET…}`) |
| Proto pollution | `__proto__` anywhere, and `constructor.prototype` |
| Evasion | Repeated URL encoding (3 rounds), IIS `%uXXXX` escapes in either case, full-width characters (`＜script` via NFKC), SQL comments `/**/` and versioned ones (`/*!50000union*/`), HTML entities, numeric **and named** (`&lt;script`), tab/NL inside the scheme (`java\tscript:`) |
| Body limit | `max_body_size` (256 KiB by default) → 413 if the declared or read size exceeds it |
| Budgets | `max_fields` (1000 texts) and `max_inspection_ms` (1000 ms) → 413 when exhausted: inspection cost scales with the fields, not with the bytes |
| Generic content type | `application/octet-stream` is **sniffed**: if the body is JSON, it is inspected as JSON (the attacker controls the header) |
| Multipart | The **field and file names** are inspected (`filename=../../etc/passwd`), not the file contents. `inspect_multipart=False` turns it off |
| WebSocket | The **handshake** (path, query and headers) is inspected and is **rate limited**; the frames are not. `inspect_websockets=False` turns it off |
| Query + body crossing | Opt-in with `inspect_cross_carrier=True`; combines path/query with non-excluded textual body values, it can add false positives, try it first with `monitor_only=True` |
| Your own rules | Regexes in YAML or `Config(custom_rules=...)`, validated at startup |
| Path exclusion | `allow_paths` (globs). Paths with `..`, `\` or residual encoding are never exempt |
| Audit | JSON events on the `gatekeeper` logger; never the **values** of the fields (yes the **name** of the one that fired, sanitized and truncated) |
| Monitor mode | `monitor_only=True` logs without blocking, to measure false positives on your real traffic |

## What it measures (not what it promises)

Three corpora are measured. The first is ours, written by hand and with
documented provenance
([corpus/](https://github.com/Eche-Dev/Gatekeeper/tree/main/gatekeeper-v0.3/gatekeeper/corpus/)):

| Metric (own corpus) | Value |
|---|---|
| Attacks detected | 159 / 159 (**100.0%**) |
| Undocumented false negatives | 0 |
| Legitimate requests blocked without documentation | **0** / 131 |
| Documented false positives (accepted limits) | 8 |
| Documented false negatives (accepted limits) | 0 |

Eleven detection families: SQLi, XSS, path traversal, sensitive files, NoSQL,
system commands, SSRF, SSTI, CRLF, Log4Shell and proto pollution. The
breakdown with each family's false-positive boundary is in
[docs/amenazas.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/amenazas.md)
(in Spanish).

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
rules, the held-out one cannot. The methodology, and the failures this corpus
found in the rules, are in
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
These numbers measure individual scans; they do not include
`inspect_cross_carrier=True`.

The details, including the payloads that slip through and why, are in
[corpus/REPORT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/REPORT.md).
The workflow fails if a new rule makes those numbers worse
(`python tools/evaluate.py --check`).

## Demo

A real session against
[`demo/app.py`](https://github.com/Eche-Dev/Gatekeeper/tree/main/gatekeeper-v0.3/gatekeeper/demo/)
(uvicorn + curl, no tricks): normal traffic passes, the payloads get 403, and
the audit log records the rule, the field and the pattern that fired — never
the content.

![Gatekeeper demo](https://github.com/Eche-Dev/Gatekeeper/raw/main/gatekeeper-v0.3/gatekeeper/docs/assets/demo.gif)

The demo app includes a playground with buttons and deployment configs for
Vercel (`vercel --prod`) and Docker:
[`demo/`](https://github.com/Eche-Dev/Gatekeeper/tree/main/gatekeeper-v0.3/gatekeeper/demo/).

## Latency

`python benchmarks/latency.py` measures the per-request cost on your machine,
calling ASGI directly and without network:

| Scenario | p50 | p95 | p99 | +p50 vs base |
|---|---|---|---|---|
| no middleware (base) | 17.40 | 56.70 | 308.70 | — |
| headers only | 41.60 | 194.10 | 989.50 | +23.50 |
| query inspection, no body and no rate limit | 206.10 | 937.80 | 2057.20 | +171.20 |
| JSON body inspection, no rate limit | 346.60 | 612.90 | 1029.60 | +329.20 |
| opt-in query/body crossing (benign) | 434.80 | 715.00 | 1179.90 | +429.20 |
| opt-in query/body crossing (attack, 403) | 322.90 | 474.50 | 709.50 | +305.50 |
| rate limit only | 46.50 | 55.30 | 99.00 | +27.30 |
| full (inspection + rate limit) | 193.40 | 394.10 | 677.90 | +173.70 |
| attacker request (early 403) | 114.40 | 331.30 | 743.20 | +97.40 |

A local run on **Python 3.14.8 on Windows**, with 1000 iterations × 5 rounds,
produced those percentiles; the overhead column uses 3 repetitions. The results
depend on the environment and are not a production latency promise. The body
and crossing scenarios hand the real body to the middleware; the tests verify
that the benign case answers 200 and the attack crossing answers 403.

**The family prefilter.** Before running the regexes, it checks whether the
text contains a mandatory literal of each family and skips the ones that
cannot match. It does not apply to texts shorter than 128 characters. This
optimization must not change detections. `tests/test_prefilter.py` compares the
scan with and without the prefilter over the 2086 values of both corpora (own
payloads, CRS requests and header values) and requires the same result.

The benchmark publishes p50, p95 and p99 per request so the tail does not hide
behind an average. In this run the full scenario had a p50 of 193.40 µs, a p95
of 394.10 µs and a p99 of 677.90 µs; these are noisy local measurements, not
end-to-end latency and not an SLA.

`python benchmarks/latency.py --save base.json` and, after changing the code,
`python benchmarks/latency.py --baseline base.json` compare two versions **on
your machine** and tell you whether a scenario got worse by more than a margin
(25% by default). They are for comparing changes under similar local
conditions before opening a PR that touches the hot path.

### Comparing performance

There is no fixed latency threshold in CI: shared runners are not a stable
baseline. The benchmark is a local report; to compare changes, save a baseline
and run both versions on the same machine:

```bash
# 1. With the current code, save the baseline
python benchmarks/latency.py --save base.json

# 2. Change the code (or switch branch) and measure again
python benchmarks/latency.py --baseline base.json
```

The comparison is **on the same machine**: shared runners are worthless for
comparing anything. The script exits with a non-zero code if a scenario got
worse by more than the 25% margin (`--margen` to tune it), and tells you
which one. To filter out system noise, `--repeats` measures each scenario
several times and keeps the median.

If the change touches the hot path (the rules, the normalization or the
prefilter), compare before opening the PR: no test detects a latency
regression.

## Documentation

Full guide with
[MkDocs Material](https://squidfunk.github.io/mkdocs-material/) in
[`docs/`](https://github.com/Eche-Dev/Gatekeeper/tree/main/gatekeeper-v0.3/gatekeeper/docs/):
usage, detection and measurement, threat model, security, API reference and
development. Locally: `mkdocs serve`. It is published at
<https://eche-dev.github.io/Gatekeeper/> on every push to `main` (`--strict`
build in CI: a broken link fails the workflow).

The guide is in Spanish. New to the project? Start with the
[quick start guide](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/inicio-rapido.md):
two `curl` commands verify that a normal request gets 200 and an attack gets
403. And if you decide **where** to deploy it, the
[deployment guide](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/docs/despliegue.md)
says which value changes in each topology (one process, several workers,
Docker, reverse proxy).

Contributing: [CONTRIBUTING.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/CONTRIBUTING.md)
· [Code of conduct](https://github.com/Eche-Dev/Gatekeeper/blob/main/CODE_OF_CONDUCT.md)
· Issue and PR templates in the repo root.

## What it does NOT cover

- Regex detection has false positives and false negatives: it **does not
  replace** parameterized queries, input validation or a real WAF.
- The **contents** of uploaded files are not inspected (uploads pass intact;
  field and file names are inspected).
- WebSocket **frames** are not inspected: the handshake is (path, query and
  headers), and it is rate limited too.
- Binaries that are not JSON (image, PDF, zip…) are not read.
- By default every body value is analysed on its own. With
  `inspect_cross_carrier=True`, non-excluded textual values are combined with
  path/query; JSON keys and headers do not take part.
- `inspect_cross_carrier=True` combines path/query with the non-excluded
  textual body values when the individual scans find nothing. Keys are
  inspected individually but are not combined. It is opt-in, and its result is
  not included in the published corpus metrics.
- Mongo's `$gt`/`$lt`/`$in` operators are left out of the NoSQL signature on
  purpose (legitimate filters use them); `localhost` and `127.0.0.1` do not
  count as SSRF (development OAuth).
- With `rate_backend="memory"` and several workers, the effective limit is
  multiplied: use Redis.
- If Redis does not answer, `rate_fail_open=True` (the default) keeps
  admitting requests; set it to `False` if you prefer 503.
- `trust_proxy=False` by default; enable it only behind a trusted proxy. With
  `trust_proxy=True` the XFF is read right to left (`ips[-trusted_proxies]`);
  add `trusted_proxy_cidrs` if the app is reachable another way.
- A JSON/form body larger than `max_body_size` is rejected: raise it or use
  `inspect_body=False`.
- `allow_paths` exempts from inspection, not from rate limiting or IP
  blocking.

## Configuration

| Option | Default | Description |
|---|---|---|
| `rate_limit` / `rate_window` | `100` / `60` | allowed requests per IP and window (0 disables) |
| `rate_backend` | `memory` | `memory` or `redis` |
| `redis_url` / `redis_prefix` | `redis://localhost:6379/0` / `gatekeeper:rl:` | connection and key prefix |
| `rate_fail_open` | `True` | policy if Redis does not answer: admit or 503 |
| `inspect_requests` / `inspect_body` | `True` | inspection of query and body |
| `inspect_cross_carrier` | `False` | combine path/query + textual body values after clean individual scans |
| `monitor_only` | `False` | log without blocking |
| `disabled_rules` | `∅` | `sqli`, `xss`, `path_traversal`, `sensitive_files`, `nosql`, `cmdi`, `ssrf`, `ssti`, `crlf`, `log4shell`, `proto_pollution` or your own rules |
| `rule_packs` | `∅` (all) | opt-in packs: `minimal`, `api`, `web`, `infrastructure`, `strict` (see below) |
| `exclude_fields` | `[]` | fields (parameter, header or JSON pointer) exempt from inspection; globs allowed |
| `custom_rules` | `∅` | `{name: regex}` or a list of `{name, pattern}` |
| `max_body_size` | `256 KiB` | limit of the inspected body |
| `max_fields` | `1000` | texts inspected per request (key + value = 2); `0` = no limit |
| `max_inspection_ms` | `1000` | milliseconds of inspection per request; `0` = no limit |
| `allow_paths` | `[]` | globs exempt from inspection |
| `inspect_headers` | `user-agent, referer, cookie, x-forwarded-for` | headers inspected (`∅` disables) |
| `blocked_ips` / `trust_proxy` | `∅` / `False` | blocking by IP or CIDR, and use of `X-Forwarded-For` |
| `trusted_proxies` / `trusted_proxy_cidrs` | `1` / `∅` | proxy hops to skip in the XFF, and the networks it is trusted from |
| `security_headers` | see source | `None` = default headers |

`Config` fails at startup, not in production: unknown keys (a typo like
`rate_limt`), invalid or empty regexes, duplicate names, non-existent
`disabled_rules` and unknown packs raise `ValueError`.
Your own rules are evaluated on text that is **decoded, without `/**/` comments
and lowercased**; avoid patterns with catastrophic backtracking, your own
patterns are not bounded by Gatekeeper.

## Rule packs

The eleven families are evaluated by default. If your app exposes less surface
than you assume, you can enable a subset (the packs are **opt-in**: without
`rule_packs` nothing changes from what Gatekeeper already did).

| Pack | Families | For what |
|---|---|---|
| `strict` | all eleven | explicit default; apps that serve third-party HTML |
| `web` | `web` + `xss` | public web with HTML (the pack almost everybody wants) |
| `api` | `sqli`, `nosql`, `path_traversal`, `sensitive_files`, `ssrf`, `log4shell`, `crlf`, `cmdi` | JSON/GraphQL APIs: no `xss`, `ssti` nor `proto_pollution` because there is no template to render |
| `minimal` | `sqli`, `path_traversal` | only what does not depend on the exposed surface |
| `infrastructure` | `ssrf`, `log4shell`, `crlf`, `cmdi` | second layer behind a WAF, or backend without SQL |

```python
from gatekeeper import Config

Config(rule_packs=["api"], disabled_rules=["cmdi"])   # API without XSS nor SSTI, without cmdi
```

An unknown pack is a `ValueError` at startup: an app cannot end up without
protection because somebody wrote `rule_packs=["we"]`.

## Excluding fields (and not rules)

When your app deliberately accepts a value that a signature blocks (a search
engine that indexes security documentation, a `template` parameter with Jinja,
a webhook), exempt **that field**, not the whole family:

```python
Config(exclude_fields=["template", "bio", "doc_*"])
```

It works on all three transports: query parameter, header (`user-agent`) and
JSON pointer (`/user/bio` or just `bio`). Detection that crosses several
fields is preserved: if you exclude `a` but the payload is split between `a`
and `b`, Gatekeeper removes `a` from the target and keeps watching `b`. The
alternative is `disabled_rules`, which turns the family off for the whole app.

## `gatekeeper report`: measure before you block

Put the middleware in front in `monitor_only=True`, let the real traffic run
and look at what fires:

```bash
monitor_only: true      # in your configuration, meanwhile
gatekeeper report gatekeeper.log          # ranking of rules, paths and fields
gatekeeper report gatekeeper.log --json   # machine-readable output
```

The report groups by (rule, field) — what repeats is noise — and proposes a
ready-to-paste `exclude_fields` or `disabled_rules`. It accepts the JSON
emitted by Gatekeeper's logger or a generic access log
(`GET /path?q=... 200`). Audit events do not include the payload content, so
this report cannot leak what the log does not carry.

## Development

```bash
pip install -e ".[dev]"
ruff check .            # style
mypy                    # strict types (src/gatekeeper)
bandit -r src -q        # static security analysis
pytest --cov=gatekeeper   # includes fuzzing with hypothesis (tests/test_fuzz.py)
python tools/evaluate.py --check     # detection and FP rates (own + CRS)
python tools/import_crs.py --check   # provenance of the external corpus
python tools/check_docs.py           # docs coherence: version, links, anchors, typos
python benchmarks/latency.py         # per-request cost
python -m build && twine check dist/*   # the package can be published
```

## Project

- [CHANGELOG.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/CHANGELOG.md) — what changes in each version.
- [SECURITY.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/SECURITY.md) — threat model, limits and how to report a vulnerability.
- [corpus/REPORT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/REPORT.md) — generated detection report.

---

> The documentation, the changelog and the issue templates are in Spanish.
> The [Spanish README](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/README.md)
> is the primary one.
