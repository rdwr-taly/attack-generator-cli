# Attack Generator CLI

> **AUTHORIZED USE ONLY** – This tool must only operate against Radware-owned demo
> environments that appear on the configured allowlist. Misuse can violate internal
> policy and local law.

`attack-generator` continuously replays curated web/API attacks to keep WAAP demos
lively. Operators provide a single JSON AttackMap resource at runtime, optionally
override runtime settings via flags or `AG_*` environment variables, and the engine
handles templating, identity pools, rate limiting, and observability.

## Quickstart

```bash
# 1. Install in editable mode
pip install -e .

# 2. Inspect built-ins
attack-generator list-builtins

# 3. Validate and dry-run an AttackMap (JSON only)
attack-generator validate examples/basic_injection_spray.json
attack-generator dry-run examples/basic_injection_spray.json --dry-run 5 --seed 42

# 4. Launch the generator
attack-generator run   --attackmap examples/basic_injection_spray.json   --allowlist "*.radware.net"   --qps 3 --metrics-port 9102
```

All resources **must** be UTF-8 JSON. Use `tools/convert_v0.py` to bootstrap from
legacy v0 payloads; the output is schema-valid AttackMap v1.

## Configuration Precedence

Runtime settings follow **flag > environment (`AG_*`) > AttackMap** precedence.
Common overrides include:

- `--allowlist` / `AG_ALLOWLIST`
- `--qps` / `AG_QPS`
- `--concurrency` / `AG_CONCURRENCY`
- `--xff` / `AG_XFF`
- `--ip-pool` / `AG_IP_POOL`
- `--ua-group` / `AG_UA_GROUP`
- `--metrics-port` / `AG_METRICS_PORT`
- `--log-format` / `AG_LOG_FORMAT`

Defaults align with the PRD: global QPS 5 (capped by `safety.global_rps_cap`),
concurrency 20, XFF header `client-ip`, think-time jitter `[100, 1500]` ms, and
per-traffic-type UA pools (web → `web_desktop`, api → `api_clients`).

## CLI Commands

- `attack-generator run [...]` – Continuous run. Pass `--server` to enable the
  container-control HTTP surface. `--attackmap` is optional in server mode; the
  `/api/start` endpoint can provide one dynamically.
- `attack-generator dry-run <map> --dry-run N` – Resolve and print N requests without
  sending traffic.
- `attack-generator validate <map>` – Schema + semantic validation with friendly
  JSON Pointer errors on failure.
- `attack-generator list-builtins` – Show builtin UA groups and header presets with
  entry counts.
- `attack-generator version` – Display the installed package version.

Makefile helpers mirror these flows (`make test`, `make dryrun`, `make validate`).

## Metrics & Logging

Prometheus metrics and JSON logs are emitted by default:

- Counters: `attack_sent_total`, `http_status_total`, `scenario_sent_total`,
  `errors_total`
- Gauges: `attack_rps`, `system_cpu_percent`, `system_mem_percent`

Metrics listen on `--metrics-port` (default `9102`); pass `0` to disable. Logs are
JSON by default – switch to text with `--log-format text`.

## Server Mode & container-control

`attack-generator run --server` mounts container-control routes:

- `POST /api/start` – Provide `{ "attackmap": {...}, "config": {...} }` to start or
  restart the engine.
- `POST /api/stop` – Gracefully stop within two seconds.
- `GET /api/health` – Returns `running` or `stopped`.
- `GET /api/metrics` – JSON snapshot from the same Prometheus registry.

If the `container-control` dependency is missing the CLI prints a clear message and
exits non-zero; the regular CLI still works without the server.

## Resources

- Product Requirements Document: [`prd.md`](prd.md)
- Schema: [`schemas/attackmap.schema.json`](schemas/attackmap.schema.json)
- Built-ins: [`attack_generator/builtins/`](attack_generator/builtins/)
- Examples: [`examples/`](examples/)
- Legacy converter: [`tools/convert_v0.py`](tools/convert_v0.py)
