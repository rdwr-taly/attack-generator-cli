# Attack Generator CLI

> **AUTHORIZED USE ONLY** – This tool must only operate against Radware-owned demo
> environments that appear on the configured allowlist. Misuse can violate internal
> policy and local law.

`attack-generator` continuously replays curated web and API attacks to keep Radware
WAAP demos lively. Operators provide a single JSON AttackMap resource at runtime,
optionally tweak runtime controls via flags or environment variables, and the engine
handles templating, identity pools, rate limiting, and observability.

## Quickstart

1. Install dependencies and the package:

   ```bash
   pip install .
   ```

2. Validate an AttackMap:

   ```bash
   attack-generator validate examples/basic_injection_spray.json
   ```

3. Preview requests without sending traffic:

   ```bash
   attack-generator dry-run examples/basic_injection_spray.json --dry-run 5 --seed 42
   ```

4. Launch the generator:

   ```bash
   attack-generator run \
     --attackmap examples/basic_injection_spray.json \
     --allowlist "*.radware.net" \
     --qps 3 --metrics-port 9102
   ```

## Configuration

- Flags take precedence over environment variables (`AG_*`) which override values
  defined in the AttackMap file.
- Common flags: `--allowlist`, `--qps`, `--concurrency`, `--xff`, `--ip-pool`,
  `--ua-group`, `--metrics-port`, `--log-format`, `--seed`, `--unsafe-override`.
- Structured JSON logging is the default; switch to text with `--log-format text`.

## Metrics

Prometheus metrics expose counters and gauges for attack delivery, status codes,
errors, and system utilisation. By default the CLI listens on port `9102`; pass
`--metrics-port 0` to disable. The same registry powers the optional control
server exposed through container-control.

## Container-Control Integration

Run with `--server` to expose `/api/start`, `/api/stop`, `/api/health`, and
`/api/metrics` endpoints via the container-control FastAPI surface. The CLI checks
for the `container-control` package at startup; if it is missing a clear message is
printed and the command exits non-zero while the standard CLI continues to work.

## Resources

- AttackMap specification: `prd.md`
- Built-in identity/header pools: `attack_generator/builtins/`
- Example resources: `examples/`
