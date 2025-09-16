# Attack Generator CLI — Product Requirements Document (CLI-only, v1)

**Scope:** Defines the standalone `attack-generator-cli` tool only. ShowRunner UI/API additions will be covered separately.

**Audience:** Radware demo engineers, SEs, and maintainers.

**Purpose:** Continuously seed authorized Radware demo apps with realistic web/API attacks so WAAP dashboards always show meaningful, fresh security events during demos.

---

## 1. Problem, Goals, Success Metrics

### 1.1 Problem

Demo targets often look quiet between sessions. Spinning up meaningful events (SQLi/XSS/ATO, etc.) is manual and brittle with legacy scripts.

### 1.2 Goals

- **G1 — Consistent UX:** Mirrors `traffic-generator-cli` startup model: one resource file selected at run time (single AttackMap), continuous run by default.
- **G2 — Declarative resource:** A simple but extensible AttackMap describing target, variables, built-in presets, attacks, and (optionally) scenarios.
- **G3 — Realistic diversity:** Large built-in catalogs for web vs api User-Agents and Header presets with automatic randomization.
- **G4 — Safety first:** Domain allowlist, capped RPS, dry-run, emergency stop, audit banner. Tool refuses to run off-allowlist.
- **G5 — Observability:** JSON logs + Prometheus metrics: per-category counters, RPS, error rates; reproducible runs via seeds.
- **G6 — Extensibility:** Templating, variable substitution, auth flows; simple to add new attacks without code changes.

---

## 2. Out of Scope (v1)

- ShowRunner UI/API resource pages, selectors, and task wiring.
- Multi-map selection or orchestration (v1 = single AttackMap, like Sitemap).
- Fuzzing frameworks, exploitation tooling, or unauthorized testing.

---

## 3. Users & Top Scenarios

- **Demo Engineer / SE:** Seed Global Source Blocking by hammering from a single IP; run ATO brute force; spray injections & directory probes.
- **POC Lead:** Reproduce curated “attack pack” with controlled rates during a workshop.
- **Maintainer:** Validate new WAAP policy rules with scripted hostile inputs.

---

## 4. Product Experience

### 4.1 Run Model

- Single resource input: `--attackmap <path-or-url>` (JSON only)
- Continuous run: default; loop forever with optional cycle delay
- Dry-run: resolve & print N example requests without sending
- Deterministic mode: `--seed` for reproducibility

### 4.2 CLI Commands

```
attack-generator run                 # start continuous run with one AttackMap
attack-generator validate <file>     # schema + semantic validation
attack-generator dry-run <file>      # resolve N sample requests and print
attack-generator list-builtins       # show UA/header preset names & sizes
attack-generator version
```

### 4.3 Core Flags

```
--attackmap PATH|URL          (required)
--base-url URL                (optional override for map target)
--allowlist DOMAIN[,DOMAIN]   (required unless --unsafe-override)
--qps INT                     (global cap; default 5; hard cap 50 unless override)
--concurrency INT             (default 20)
--xff HEADER                  (default from map)
--ip-pool STR                 (e.g., random:500 | cidr:203.0.113.0/24 | file:ips.txt)
--ua-group STR                (e.g., web_desktop | web_mobile | api_clients)
--metrics-port INT            (default 9102; 0 disables)
--log-format text|json        (default json)
--seed INT                    (optional)
--dry-run N                   (print N resolved requests and exit)
--unsafe-override             (bypass hard caps for lab only; requires --i-know-what-im-doing)
```

### 4.4 Defaults

- `qps=5`, `concurrency=20`
- `ua-group=web_desktop` for web attacks; `api_clients` for api attacks
- `xff=client-ip`
- Think time jitter: 100–1500 ms (unless map override)

---

## 5. AttackMap Resource (v1)

**Principles:** Small for simple demos; powerful via optional fields.

**Format:** JSON (UTF-8). Single file at runtime.

### 5.1 Top-Level Shape

```json
{
  "version": 1,
  "name": "<string>",
  "description": "<string>",
  "target": { "base_url": "https://cwafdemo.radware.net", "xff_header": "client-ip" },
  "safety": {
    "allowlist": ["*.radware.net"],
    "global_rps_cap": 50,
    "stop_on_target_mismatch": true,
    "banner": "Authorized Radware demo targets only."
  },
  "presets": { "ua_group": "web_desktop", "headers": "auto" },
  "variables": {
    "usernames": { "type": "list", "values": ["admin", "user", "test"] },
    "passwords": { "type": "list", "values": ["123456", "password"] },
    "product_id": { "type": "int", "min": 1, "max": 100 }
  },
  "auth": {
    "type": "basic",
    "path": "/api/auth",
    "credentials": { "username": "test_user", "password": "123456" },
    "store": { "header": true, "cookie": true }
  },
  "attacks": [
    {
      "id": "A_SQLI_BODY_001",
      "name": "SQLi in JSON customer_id",
      "traffic_type": "api",
      "category": "sqli",
      "method": "POST",
      "path": "/api/customerAddress",
      "headers": "builtin.headers.api_json_v1",
      "body_type": "json",
      "body": { "customer_id": "' or 1=1 --" }
    },
    {
      "id": "A_XSS_QUERY_01",
      "name": "XSS in search query",
      "traffic_type": "web",
      "category": "xss",
      "method": "GET",
      "path": "/search?searchString=<script>alert(1)</script>",
      "headers": "builtin.headers.web_html_v1"
    }
  ],
  "scenarios": [
    {
      "id": "S_BURST",
      "name": "Global Source Blocking Burst",
      "select": { "by_ids": ["A_SQLI_BODY_001", "A_XSS_QUERY_01"] },
      "ip_pool": "single_static",
      "ua_group": "web_desktop",
      "rate": { "qps": 80, "duration_sec": 20 },
      "jitter_ms": [25, 125]
    }
  ],
  "runtime": {
    "think_time_ms": [100, 1500],
    "concurrency": 20,
    "cookie_jar": "per_ip",
    "session_reuse": true,
    "retry": { "max_attempts": 0 }
  }
}
```

### 5.2 Templates & Helpers

- Placeholders: `{{ pick('usernames') }}`, `{{ int(1,100) }}`, `{{ ua('web_desktop') }}`
- Back-compat: `@var` replacement supported inside path and string bodies
- Transforms: `{{ base64('text') }}`, `{{ urlencode('a=b') }}`

### 5.3 Identity & Pools

- IP pools: `single_static`, `random:N`, `cidr:X/Y`, `list:[...]` (file-based allowed)
- UA groups: `web_desktop`, `web_mobile`, `api_clients` (built-ins) plus custom append

### 5.4 Authentication Behaviors

- `basic` → add Authorization header
- `form` → POST to path with credentials; store cookies
- `bearer` → POST/GET to obtain token at path; store token at `json_path` or header key
- Retries: none by default; configurable via `runtime.retry`

### 5.5 Validation Rules

- Must define `target.base_url` and `safety.allowlist`
- `rate.qps` cannot exceed `safety.global_rps_cap` unless `--unsafe-override`
- `attacks[*].path` must be absolute or query path; engine joins with base_url

---

## 6. Built-in Catalogs (in binary)

### 6.1 User-Agent Groups

- `web_desktop`: 200+ realistic desktop UAs (Chrome/Edge/Firefox versions)
- `web_mobile`: 150+ Android/iOS UAs (Chrome Mobile/Safari)
- `api_clients`: 100+ clients (`python-requests`, `curl`, `okhttp`, `httpclient`, `axios`, `jQuery`, `libcurl`, `Go http`, etc.)

Selection: weighted random; deterministic with `--seed`.

### 6.2 Header Presets

- `builtin.headers.web_html_v1` → `Accept: text/html,*/*`, `Accept-Language: en-US,en;q=0.9`, etc.
- `builtin.headers.api_json_v1` → `Accept: application/json`, `Content-Type: application/json`
- `builtin.headers.api_form_v1` → `Content-Type: application/x-www-form-urlencoded`

Merge order: global defaults → scenario preset → attack headers (last wins).

---

## 7. Safety & Compliance

- Allowlist required (unless lab override). Startup fails if base_url not covered.
- Global RPS hard cap (50 by default) unless `--unsafe-override`.
- Emergency stop: SIGINT/SIGTERM → graceful halt ≤ 2s.
- Dry-run: never sends traffic; prints resolved requests.
- Audit banner: hashed AttackMap, allowlist, operator, timestamp.
- Use strictly for authorized Radware demo systems.

---

## 8. Observability

### 8.1 Logs

- Format: JSON (default) or text
- Fields: timestamp, level, attack_id, scenario_id, method, url, ip, ua, status_code, latency_ms, error

### 8.2 Metrics (Prometheus + JSON)

Counters / Gauges:

- `attack_rps` (gauge)
- `attack_sent_total{attack_id,category}` (counter)
- `http_status_total{code}` (counter)
- `scenario_sent_total{scenario_id}` (counter)
- `errors_total{type}` (counter)
- `system_cpu_percent`, `system_mem_percent` (gauges)

Endpoints (when control server enabled via container-control integration):

- `GET /metrics` (Prometheus)
- `GET /api/metrics` (JSON snapshot)

---

## 9. Non-Functional Requirements

- **Performance:** sustain 50 RPS; p95 latency < 200 ms client-side on 1 vCPU / 1GB pod (local echo)
- **Reliability:** auto-backoff on connect errors; jittered retries if `runtime.retry.max_attempts > 0`
- **Security:** no outbound if allowlist mismatch; HTTPS default; no credential logs
- **Portability:** Linux/amd64 container; Python 3.11; optional PyInstaller single binary
- **Configurability:** flags, env vars (`AG_*`), AttackMap fields (precedence: flag > env > map)

---

## 10. Interfaces (CLI & Optional HTTP)

### 10.1 CLI Examples

```bash
attack-generator run --attackmap ./attackmaps/hackazon.json \
  --allowlist "*.radware.net" --qps 8 --concurrency 20 --metrics-port 9102

attack-generator dry-run ./attackmaps/hackazon.json --dry-run 5 --seed 42

attack-generator validate ./attackmaps/hackazon.json
```

### 10.2 Optional Control (when run with `--server`)

Endpoints (provided via container-control package):

- `POST /api/start`  body: `{ "attackmap": { ... }, "config": { ... } }`
- `POST /api/stop`
- `GET  /api/health`
- `GET  /api/metrics`

---

## 11. Implementation Notes

- **Language / Stack:** Python 3.11, `httpx` (async), `anyio`, `pydantic`, `jinja2`, `prometheus_client`.
- **Control server integration:** When `--server` is enabled, HTTP control + metrics via container-control (no custom server).

**Structure:**

```
cli.py              (Typer/argparse)
models.py           (AttackMap v1, Config)
engine/             (resolver, ip_pool, ua_pool, rate_limit, scheduler, transport)
metrics.py          (Prometheus + JSON snapshot)
server.py           (optional; container-control integration)
builtins/           (ua & header catalogs, versioned)
```

- Determinism: pass seed to RNGs (pools, selection, jitter).
- Legacy migration: `tools/convert_v0.py` to transform old JSON into AttackMap v1.

---

## 12. Validation & Test Plan

- **Schema validation:** `attack-generator validate` with clear messages (line/field)
- **Unit:** variable resolver, UA/header merge, IP pool generation, rate limiter
- **Integration:** dry-run & live run vs stub server; metrics assertions
- **Safety tests:** allowlist enforcement, cap enforcement, emergency stop
- **Performance tests:** sustained 50 RPS within CPU/RAM budgets
- **Regression:** replay with fixed `--seed` for deterministic sequences

---

## 13. Deliverables & Milestones

- **D1:** AttackMap schema + validator + dry-run (Week 1)
- **D2:** Async engine (HTTP, rate limit, UA/IP pools) + metrics (Week 2)
- **D3:** Auth flows + scenarios + safety gates (Week 3)
- **D4:** Built-in catalogs v1 (web/api) + conversion tool (Week 4)
- **D5:** Docs (README + examples) + container image (Week 4)

---

## 14. Appendix — Minimal AttackMap (JSON)

```json
{
  "version": 1,
  "name": "Basic Injection Spray",
  "target": { "base_url": "https://cwafdemo.radware.net", "xff_header": "client-ip" },
  "safety": { "allowlist": ["*.radware.net"], "global_rps_cap": 20, "stop_on_target_mismatch": true },
  "presets": { "ua_group": "web_desktop", "headers": "auto" },
  "variables": { "usernames": { "type": "list", "values": ["admin", "user", "test"] } },
  "attacks": [
    {
      "id": "A_LOGIN_Sqli",
      "name": "Login SQLi",
      "traffic_type": "web",
      "category": "sqli",
      "method": "POST",
      "path": "/user/login",
      "headers": "builtin.headers.web_html_v1",
      "body_type": "form",
      "body": { "username": "' or 1=1 --", "password": "abc" }
    },
    {
      "id": "A_XSS_Search",
      "name": "XSS search param",
      "traffic_type": "web",
      "category": "xss",
      "method": "GET",
      "path": "/search?searchString=<script>alert(1)</script>"
    }
  ],
  "runtime": { "think_time_ms": [100, 1500], "concurrency": 10 }
}
```