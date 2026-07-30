# BGP Route Analyzer

A Python tool for automated BGP table snapshot collection, time-series storage, and pre/post change window diffing across edge routers. Reduces post-change verification from 45+ minutes of manual router diff'ing to under 2 minutes.

## Features

- **SSH-based polling** via Netmiko — connects to any Netmiko-supported device type (Cisco IOS, IOS-XR, Arista EOS, Junos, etc.)
- **Parallel collection** — routers are polled concurrently through a bounded worker pool, so fleet snapshot time scales with the slowest router, not the sum of all of them
- **TextFSM parsing** — structured extraction of BGP prefix attributes (network, next_hop, as_path, local_pref, metric, weight, origin)
- **Time-series SQLite storage** — every snapshot is timestamped and persisted; historical data is never overwritten
- **Automated diff engine** — detects added/removed prefixes and attribute-level changes (next-hop shifts, AS path changes, local preference drift)
- **React admin UI** — browse snapshots, compare change windows, watch collection jobs live, and review router health from the browser
- **FastAPI REST API** — NOC-facing endpoints so incident dashboards can trigger checks programmatically
- **Audit trail** — every login, snapshot, purge, and per-router poll result is recorded with actor, source IP, and outcome
- **CLI mode** — run snapshots, diffs, and listings directly from the command line without the API server

---

## Requirements

- Python 3.12+ and Node.js 20+ — or just Docker (see [below](#docker))
- Network access to edge routers via SSH
- Routers must support `show ip bgp` (or equivalent — see [Customization](#customization))

---

## Docker

The fastest way to run the whole thing — API, UI, and database — in one container.

```bash
cp .env.example .env                          # set BGP_ANALYZER_API_KEY
cp routers.json.example routers.json

# The container runs as UID 10001, so it must own the config to read it.
sudo chown 10001:10001 routers.json && chmod 600 routers.json

# ssh_strict defaults to true, so the container needs the routers' host keys.
ssh-keyscan -H 10.0.0.1 10.0.0.2 > known_hosts

docker compose up -d
# UI: http://127.0.0.1:8000/ui
```

Two things trip people up here, both intentional:

- **`chown 10001` on `routers.json`.** A `0600` file owned by your host user is unreadable inside the container. The app logs the reason and starts with no routers rather than crashing, so check the logs if `/routers` comes back empty.
- **`known_hosts` is required.** `ssh_strict` defaults to `true` and the container ships no host keys, so without it every poll fails verification. Create the file *before* the first `docker compose up` — Docker turns a missing bind-mount source into an empty directory, and the mount then silently does nothing. Setting `ssh_strict: false` is not the fix; it disables MITM protection on your router credentials, and the analyzer logs a warning naming every router in that state.

  After rotating a router's host key, refresh its `known_hosts` entry. A *stale* entry fails the connection even for routers with `ssh_strict: false` — a mismatched key is rejected regardless of the missing-key policy, matching OpenSSH behaviour.

Or without compose:

```bash
docker build -t bgp-route-analyzer .
docker run -d --name bgp \
  -e BGP_ANALYZER_API_KEY="$(openssl rand -hex 32)" \
  -v bgp-data:/data \
  -v "$PWD/routers.json:/config/routers.json:ro" \
  -p 127.0.0.1:8000:8000 \
  bgp-route-analyzer
```

Run CLI commands against the same volume:

```bash
docker compose run --rm analyzer --snapshot
docker compose run --rm analyzer --list
docker compose run --rm analyzer --diff --before 1 --after 2
docker compose run --rm analyzer --purge 30
```

**What the image does:**

- Multi-stage build — Node compiles the UI, then is discarded; the runtime image carries only Python, the venv, `bgp_route_analyzer.py`, and `ui/dist`
- Runs as non-root (UID 10001); application files are root-owned and read-only to it
- Ships runtime dependencies only (`requirements.txt`); test tooling stays in `requirements-dev.txt`
- Healthcheck sends `X-API-Key`, so it works with authentication enabled
- Compose adds `read_only`, `cap_drop: ALL`, `no-new-privileges`, and a memory limit

**Ports and TLS.** Compose publishes on `127.0.0.1:8000` only, matching the app's own loopback default. Before exposing it more widely, set `BGP_ANALYZER_API_KEY` and put TLS in front of it.

If a reverse proxy terminates TLS, set `BGP_ASSUME_TLS=1` — otherwise the app only ever sees HTTP and will never mark session cookies `Secure` or emit HSTS. If the app terminates TLS itself, mount the certs and add `--ssl-cert`/`--ssl-key`, which sets the same flag automatically.

**Persistence.** The database lives on the `bgp-data` volume at `/data`. SQLite in WAL mode writes `-wal` and `-shm` siblings, so the directory (not just the file) must be writable — that is why `/data` is owned by the runtime user.

**Router SSH keys.** If `routers.json` uses `key_file`, mount the key directory read-only and point `key_file` at the in-container path (there is a commented-out `./keys:/keys:ro` mount in `docker-compose.yml`).

---

## Installation (without Docker)

```bash
git clone <repo-url>
cd bgp-route-analyzer

python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt   # or requirements.txt for runtime only

# Build the admin UI (optional — omit for API-only operation)
cd ui && npm ci && npm run build && cd ..
```

---

## Configuration

### Router credentials

Copy the example config and fill it in. This file is gitignored and should be `chmod 600` — the tool warns at startup if it is group- or world-readable.

```bash
cp routers.json.example routers.json
chmod 600 routers.json
```

```json
[
  {
    "host": "10.0.0.1",
    "username": "netops",
    "password": "s3cr3t",
    "device_type": "cisco_ios",
    "name": "edge-rtr-01",
    "ssh_strict": true
  },
  {
    "host": "10.0.0.2",
    "username": "netops",
    "key_file": "/home/netops/.ssh/id_rsa",
    "device_type": "cisco_xe",
    "name": "edge-rtr-02",
    "ssh_strict": true
  }
]
```

`host`, `username`, `device_type`, and `name` are required. Unknown fields are rejected, and `device_type` is validated against a supported-platform allowlist. To keep passwords out of the file entirely, omit `password` and set `BGP_ROUTER_PASSWORD` in the environment.

### Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `BGP_ROUTER_CONFIG` | Path to router credentials JSON | `routers.json` |
| `BGP_DB_PATH` | SQLite database file path | `bgp_snapshots.db` |
| `BGP_ANALYZER_API_KEY` | API key for `X-API-Key` auth and the UI login | unset (**auth disabled**) |
| `BGP_CORS_ORIGINS` | Comma-separated allowed CORS origins | unset (CORS disabled) |
| `BGP_ROUTER_PASSWORD` | Router password used when an entry omits `password` | unset |
| `BGP_ENABLE_DOCS` | Enable `/docs` and `/redoc` | unset (disabled) |
| `BGP_ASSUME_TLS` | Treat the connection as TLS-protected (proxy terminates TLS) — sets `Secure` cookies and HSTS | unset |
| `BGP_SESSION_TTL` | Absolute session lifetime, seconds | `28800` (8h) |
| `BGP_SESSION_IDLE` | Session idle timeout, seconds | `1800` (30m) |
| `BGP_POLL_WORKERS` | Max concurrent router SSH polls | `5` |
| `BGP_JOB_HISTORY` | Snapshot jobs retained in memory | `50` |
| `BGP_LIMIT_CONCURRENCY` | uvicorn concurrency limit | `100` |
| `BGP_LIMIT_MAX_REQUESTS` | uvicorn requests before exit | unset (unlimited) |

---

## Admin UI

```bash
export BGP_ANALYZER_API_KEY="$(openssl rand -hex 32)"
python bgp_route_analyzer.py --serve
# open http://127.0.0.1:8000/ui
```

Sign in with the API key. Four views:

- **Routers** — per-router health cards (last poll, prefix count and delta, last error), plus a *Take snapshot* button that streams live per-router progress as the job runs
- **Snapshots** — paginated, filterable by router and date range; drill into any snapshot for a searchable prefix table
- **Compare** — pick two snapshots and see added / removed / changed prefixes colour-coded, with attribute-level before→after
- **Audit** — who did what, from where, and whether it succeeded

If `ui/dist` has not been built, the server starts in API-only mode and logs how to build it.

---

## CLI Usage

### Capture a snapshot across all routers

```bash
python bgp_route_analyzer.py --snapshot
# Snapshots saved: [1, 2]
```

### List stored snapshots

```bash
python bgp_route_analyzer.py --list
python bgp_route_analyzer.py --list --router edge-rtr-01 --limit 50
```

```
  [   1]  edge-rtr-01                     2026-03-04T18:00:00+00:00     842 prefixes
  [   2]  edge-rtr-02                     2026-03-04T18:00:01+00:00     839 prefixes

Showing 2 of 2 snapshot(s).
```

### Router health and audit trail

```bash
python bgp_route_analyzer.py --routers
python bgp_route_analyzer.py --audit --limit 50
```

### Diff two snapshots (pre/post change window)

```bash
python bgp_route_analyzer.py --diff --before 1 --after 3
```

```json
{
  "before_snapshot_id": 1,
  "after_snapshot_id": 3,
  "summary": { "added": 1, "removed": 0, "changed": 2 },
  "added": [
    { "network": "192.0.2.0/24", "next_hop": "10.1.1.1", "as_path": "65001 65002" }
  ],
  "removed": [],
  "changed": [
    {
      "network": "203.0.113.0/24",
      "next_hop": "10.1.1.1",
      "changes": {
        "as_path": { "before": "65001", "after": "65001 65099" }
      }
    }
  ]
}
```

### Data retention

```bash
python bgp_route_analyzer.py --purge 30         # snapshots older than 30 days
python bgp_route_analyzer.py --purge-audit 365  # audit entries older than a year
```

Audit retention is separate from snapshot retention, so operational data can be aged out while the record of who did what is kept longer.

### Start the server

```bash
python bgp_route_analyzer.py --serve
python bgp_route_analyzer.py --serve --host 0.0.0.0 --port 8080
python bgp_route_analyzer.py --serve --ssl-cert cert.pem --ssl-key key.pem
```

Binds to `127.0.0.1` by default. It warns when binding to a non-loopback address without an API key, and when an API key is set without TLS.

---

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/login` | Exchange the API key for a session cookie |
| `POST` | `/auth/logout` | Destroy the current session |
| `GET` | `/auth/status` | Whether auth is required / the caller is signed in |
| `GET` | `/health` | Liveness check |
| `POST` | `/snapshots` | Start a snapshot job — returns `202` with a job ID |
| `GET` | `/jobs`, `/jobs/{id}` | Job progress and per-router results |
| `GET` | `/routers` | Router inventory and health |
| `GET` | `/snapshots` | List snapshots (`?router=&limit=&offset=&since=&until=`) |
| `GET` | `/snapshots/{id}` | Snapshot metadata + paginated prefix table |
| `GET` | `/diff?before=1&after=3` | Diff two snapshots |
| `GET` | `/audit` | Audit trail (`?action=&limit=&offset=`) |

Interactive docs are available at `/docs` when `BGP_ENABLE_DOCS=1`; they are disabled by default.

### Example: trigger a snapshot and follow it

```bash
KEY="your-api-key"

JOB=$(curl -sX POST -H "X-API-Key: $KEY" localhost:8000/snapshots | jq -r .id)
curl -s -H "X-API-Key: $KEY" "localhost:8000/jobs/$JOB" | jq '.status, .routers'
```

Scripts that need the old blocking behavior can pass `?wait=true`:

```bash
curl -sX POST -H "X-API-Key: $KEY" "localhost:8000/snapshots?wait=true"
# {"snapshot_ids":[5,6],"message":"Captured 2 snapshot(s)."}
```

### Authentication

Two mechanisms:

- **`X-API-Key` header** — for scripts and curl. Unchanged, and needs no CSRF token.
- **Session cookie** — for the browser UI. `POST /auth/login` exchanges the API key for an `HttpOnly`, `SameSite=strict` cookie that JavaScript cannot read. Mutating requests must also send the `X-CSRF-Token` header.

The `Secure` cookie flag is set only when TLS is configured, since a `Secure` cookie is never sent over plain HTTP. **Run with TLS in production** — otherwise keys and session cookies cross the network in the clear.

If `BGP_ANALYZER_API_KEY` is unset, authentication is disabled entirely and the UI displays a warning banner.

---

## Typical Change Window Workflow

```
1. Pre-change:   python bgp_route_analyzer.py --snapshot
                 # note the snapshot IDs printed (e.g. 7, 8)

2. Perform change window work

3. Post-change:  python bgp_route_analyzer.py --snapshot
                 # note the snapshot IDs printed (e.g. 9, 10)

4. Verify:       python bgp_route_analyzer.py --diff --before 7 --after 9
                 python bgp_route_analyzer.py --diff --before 8 --after 10
```

Or do steps 1, 3, and 4 from the **Compare** tab in the UI.

Diffs key on `(network, next_hop)`, so multi-path (ECMP) routes are tracked per path. A next-hop change therefore shows as one removed and one added prefix rather than a single modification. Comparing snapshots from two different routers is flagged, since the resulting large add/remove set is expected rather than an incident.

---

## Development

```bash
# Backend
.venv/bin/ruff check .
.venv/bin/flake8 bgp_route_analyzer.py --max-line-length 120
.venv/bin/mypy bgp_route_analyzer.py --ignore-missing-imports
.venv/bin/python -m pytest tests/ -v

# UI
cd ui
npm run dev     # Vite dev server on :5173, proxying the API to :8000
npm run lint    # tsc --noEmit
npm run build
```

Run the UI dev server alongside a real backend (`--serve`). The Vite proxy keeps API calls same-origin on purpose: the session cookie is `SameSite=strict` and would be dropped cross-origin.

---

## Customization

### Supporting other vendors / commands

The `TEXTFSM_TEMPLATE` constant and the `show ip bgp` command in `poll_router()` are the vendor-specific pieces. To support IOS-XR, Arista EOS, or Junos:

1. Change the command string in `poll_router()` (e.g. `show bgp ipv4 unicast` for IOS-XR)
2. Update `TEXTFSM_TEMPLATE` to match the output format, or use a template from [ntc-templates](https://github.com/networktocode/ntc-templates)
3. Add the Netmiko `device_type` to `SUPPORTED_DEVICE_TYPES`, or config validation will reject it

### Using ntc-templates

```bash
pip install ntc-templates
```

```python
from ntc_templates.parse import parse_output

def _parse_bgp_table(raw_output: str, platform: str = "cisco_ios") -> list[dict]:
    return parse_output(platform=platform, command="show ip bgp", data=raw_output)
```

---

## Operational Notes

- **Sessions are in-process.** Restarting the server signs everyone out, and running multiple workers would give each its own session and rate-limit state. Run a single process, or move both to shared storage first.
- **Job history is in memory** and bounded by `BGP_JOB_HISTORY`; completed jobs are evicted oldest-first. Snapshot data itself is always durable in SQLite.
- **`BGP_LIMIT_MAX_REQUESTS` is unset by default.** uvicorn *shuts down* when that limit is hit, and a dashboard polling job status reaches a five-digit request count within hours. Only set it if a supervisor restarts the process.
- **Concurrent polling is capped** by `BGP_POLL_WORKERS` (default 5) because many platforms rate-limit or lock out simultaneous SSH sessions. Raise it deliberately.

---

## Project Structure

```
bgp-route-analyzer/
├── bgp_route_analyzer.py   # Backend — polling, storage, diff, API, CLI
├── docker-healthcheck.py   # Container healthcheck (auth-aware)
├── Dockerfile              # Multi-stage: UI build → venv build → slim runtime
├── docker-compose.yml
├── requirements.txt        # Runtime dependencies
├── requirements-dev.txt    # Adds pytest + httpx for the test suite
├── routers.json.example    # Copy to routers.json (gitignored)
├── tests/                  # pytest suite
├── ui/                     # React admin UI (Vite + TypeScript)
│   ├── src/
│   └── dist/               # Build output, gitignored — served at /ui
└── bgp_snapshots.db        # SQLite database (created on first run)
```

---

## License

MIT
