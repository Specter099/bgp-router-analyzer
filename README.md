# BGP Route Analyzer

A Python tool for automated BGP table snapshot collection, time-series storage, and pre/post change window diffing across edge routers. Reduces post-change verification from 45+ minutes of manual router diff'ing to under 2 minutes.

## Features

- **SSH-based polling** via Netmiko — connects to any Netmiko-supported device type (Cisco IOS, IOS-XR, Arista EOS, Junos, etc.)
- **TextFSM parsing** — structured extraction of BGP prefix attributes (network, next_hop, as_path, local_pref, metric, weight, origin)
- **Time-series SQLite storage** — every snapshot is timestamped and persisted; historical data is never overwritten
- **Automated diff engine** — detects added/removed prefixes and attribute-level changes (next-hop shifts, AS path changes, local preference drift)
- **FastAPI REST API** — NOC-facing endpoints so incident dashboards can trigger checks programmatically
- **CLI mode** — run snapshots, diffs, and listings directly from the command line without the API server

---

## Requirements

- Python 3.10+
- Network access to edge routers via SSH
- Routers must support `show ip bgp` (or equivalent — see [Customization](#customization))

---

## Installation

```bash
git clone <repo-url>
cd bgp-route-analyzer

python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

---

## Configuration

Edit the `ROUTERS` list near the top of `bgp_route_analyzer.py`:

```python
ROUTERS = [
    {
        "host": "10.0.0.1",
        "username": "netops",
        "password": "s3cr3t",          # prefer key_file in production
        "device_type": "cisco_ios",    # netmiko device type string
        "name": "edge-rtr-01",
    },
    {
        "host": "10.0.0.2",
        "username": "netops",
        "key_file": "/home/netops/.ssh/id_rsa",
        "device_type": "cisco_xe",
        "name": "edge-rtr-02",
    },
]
```

The SQLite database path defaults to `bgp_snapshots.db` in the working directory. Override with `--db <path>` on the CLI or by changing `DB_PATH` in the script.

---

## CLI Usage

### Capture a snapshot across all routers

```bash
python bgp_route_analyzer.py --snapshot
# Saved snapshots: [1, 2]
```

### List stored snapshots

```bash
python bgp_route_analyzer.py --list

# Filter by router
python bgp_route_analyzer.py --list --router edge-rtr-01
```

Example output:
```
[   1]  edge-rtr-01                     2026-03-04T18:00:00+00:00
[   2]  edge-rtr-02                     2026-03-04T18:00:01+00:00
[   3]  edge-rtr-01                     2026-03-04T18:45:00+00:00
[   4]  edge-rtr-02                     2026-03-04T18:45:01+00:00
```

### Diff two snapshots (pre/post change window)

```bash
python bgp_route_analyzer.py --diff --before 1 --after 3
```

Example output:
```json
{
  "before_snapshot_id": 1,
  "after_snapshot_id": 3,
  "summary": {
    "added": 1,
    "removed": 0,
    "changed": 2
  },
  "added": [
    { "network": "192.0.2.0/24", "next_hop": "10.1.1.1", "as_path": "65001 65002", ... }
  ],
  "removed": [],
  "changed": [
    {
      "network": "203.0.113.0/24",
      "changes": {
        "next_hop": { "before": "10.1.1.1", "after": "10.2.2.2" },
        "as_path":  { "before": "65001",    "after": "65001 65099" }
      }
    }
  ]
}
```

### Start the API server

```bash
python bgp_route_analyzer.py --serve
# or with custom bind address:
python bgp_route_analyzer.py --serve --host 0.0.0.0 --port 8080
```

---

## REST API

Once the server is running, the interactive docs are available at `http://localhost:8000/docs`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Liveness check |
| `POST` | `/snapshots` | Poll all routers and store snapshots |
| `GET` | `/snapshots` | List snapshots (`?router=name&limit=20`) |
| `GET` | `/snapshots/{id}` | Get snapshot metadata + full prefix table |
| `GET` | `/diff?before=1&after=3` | Diff two snapshots |

### Example: trigger a snapshot from curl

```bash
curl -X POST http://localhost:8000/snapshots
# {"snapshot_ids":[5,6],"message":"Captured 2 snapshot(s)."}
```

### Example: run a diff

```bash
curl "http://localhost:8000/diff?before=5&after=6" | jq .
```

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

Any route leaks, unexpected next-hop changes, or missing prefixes are reported immediately in the diff output.

---

## Customization

### Supporting other vendors / commands

The `TEXTFSM_TEMPLATE` constant in `bgp_route_analyzer.py` and the `show ip bgp` command in `poll_router()` are the only vendor-specific pieces. To support IOS-XR, Arista EOS, or Junos:

1. Change the command string in `poll_router()` (e.g. `show bgp ipv4 unicast` for IOS-XR)
2. Update `TEXTFSM_TEMPLATE` to match the output format, or use a template from the [ntc-templates](https://github.com/networktocode/ntc-templates) library

### Using ntc-templates

```bash
pip install ntc-templates
```

```python
from ntc_templates.parse import parse_output

def _parse_bgp_table(raw_output: str, platform: str = "cisco_ios") -> list[dict]:
    return parse_output(platform=platform, command="show ip bgp", data=raw_output)
```

### Externalizing router config

For production use, move the `ROUTERS` list to a YAML or JSON file and load it at startup, or pull credentials from AWS Secrets Manager / HashiCorp Vault.

---

## Project Structure

```
bgp-route-analyzer/
├── bgp_route_analyzer.py   # Main script — polling, storage, diff, API, CLI
├── requirements.txt        # Python dependencies
├── README.md
└── bgp_snapshots.db        # SQLite database (created on first run)
```

---

## License

MIT
