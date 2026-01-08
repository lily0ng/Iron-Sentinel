# Iron-Sentinel (MVP)

Linux incident response and DFIR platform scaffold.

## Build

### Go CLI (iron-sentinel)

From repo root:

```bash
go build -o iron-sentinel ./core/cmd/iron-sentinel
./iron-sentinel version
```

### Rust optional accelerator (fast-hash)

```bash
cd rust-modules
cargo build --release
export PATH="$PWD/target/release:$PATH"
```

When `fast-hash` is in `PATH`, Go hashing will automatically use it.

## Rapid triage

```bash
./iron-sentinel triage --output ./evidence
```

Example stdout:

```text
case=3f6e2d2c-5b2f-4a4c-a0fe-8c8a0c3c1a2b output=./evidence/3f6e2d2c-5b2f-4a4c-a0fe-8c8a0c3c1a2b artifacts=8
```

Example evidence layout (paths will vary based on what collectors succeed on the host):

```text
evidence/<CASE_ID>/
  manifest.json
  analysis/
    timeline.jsonl
    ioc_scan.json                (only if --ioc-file is used)
  system/
    host_info.json
    os-release.txt
  proc/
    meminfo
    cpuinfo
    uptime
    loadavg
    version
  network/
    ss_tulpen.txt                (or netstat/ip/ifconfig)
  sessions/
    who_a.txt
    w.txt
    users.txt
    last_50.txt
  persistence/
    crontab
    cron.d_listing.txt
    system_listing.txt
  snapshot/
    metadata.jsonl               (only if snapshot enabled)
    files.tar.gz                 (only in snapshot copy mode)
  errors/
    <collector>.txt              (only if a collector errors)
```

Example `manifest.json` snippet:

```json
{
  "case_id": "<CASE_ID>",
  "created_at": "2026-01-08T08:30:00Z",
  "artifacts": [
    {
      "relative_path": "system/os-release.txt",
      "collector": "os_release",
      "collected_at": "2026-01-08T08:30:01Z",
      "size_bytes": 1234,
      "sha256": "<sha256>"
    },
    {
      "relative_path": "analysis/timeline.jsonl",
      "collector": "timeline",
      "collected_at": "2026-01-08T08:30:02Z",
      "size_bytes": 4567,
      "sha256": "<sha256>"
    }
  ]
}
```

Example `analysis/timeline.jsonl` snippet:

```jsonl
{"time":"2026-01-08T08:30:00Z","type":"triage_started","metadata":{"case_id":"<CASE_ID>"}}
{"time":"2026-01-08T08:30:01Z","type":"artifact_collected","artifact":"system/os-release.txt","collector":"os_release","sha256":"<sha256>","size_bytes":1234}
{"time":"2026-01-08T08:30:02Z","type":"triage_finished","metadata":{"case_id":"<CASE_ID>","artifacts":"8"}}
```

IOC scan:

```bash
./iron-sentinel triage --output ./evidence --ioc-file ./iocs.txt
```

Example IOC file (`iocs.txt`):

```text
suspicious-domain.com
malware.exe
```

Example `analysis/ioc_scan.json` snippet:

```json
{
  "ioc_file": "./iocs.txt",
  "matches": [
    {
      "pattern": "malware.exe",
      "artifact": "proc/ps_aux.txt",
      "first_line": "...",
      "collected_at": "2026-01-08T08:30:02Z"
    }
  ],
  "scanned": 8,
  "finished": "2026-01-08T08:30:02Z"
}
```

## Filesystem snapshot

Enable snapshot collection by passing one or more `--snapshot-path` flags:

```bash
./iron-sentinel triage \
  --output ./evidence \
  --snapshot-path /etc \
  --snapshot-path /var/log \
  --snapshot-mode metadata
```

Copy mode creates `snapshot/files.tar.gz` (bounded by limits):

```bash
./iron-sentinel triage \
  --output ./evidence \
  --snapshot-path /etc \
  --snapshot-mode copy \
  --snapshot-max-file-bytes $((25*1024*1024)) \
  --snapshot-max-total-bytes $((250*1024*1024))
```

Notes:
- The snapshot walker always excludes `/proc`, `/sys`, `/dev`, `/run`.

## Server + agent (MVP)

### Generate a self-signed TLS cert

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt -days 365 \
  -subj "/CN=127.0.0.1"
```

### Run server

```bash
go build -o iron-sentinel ./core/cmd/iron-sentinel
./iron-sentinel server \
  --port 8443 \
  --tls-enabled=true \
  --tls-cert ./server.crt \
  --tls-key ./server.key \
  --data-dir ./server-data \
  --psk "changeme"
```

### Run agent

```bash
go build -o iron-sentinel-agent ./agents/cmd/iron-sentinel-agent
./iron-sentinel-agent \
  -server https://127.0.0.1:8443 \
  -psk changeme \
  -insecure true \
  -triage-bin ./iron-sentinel \
  -output ./agent-evidence
```

Agent enrollment is cached locally (per server URL) under your user config directory:

- `~/.config/iron-sentinel/agent_<hash>.json` (location varies by OS)

If the server returns `401`, the agent will automatically re-enroll and refresh the cache.

### Enqueue a triage job

Replace `<AGENT_ID>` with the ID returned by enroll (server stores it in `server-data/agents.json`).

```bash
curl -k -sS -X POST https://127.0.0.1:8443/v1/jobs \
  -H 'Content-Type: application/json' \
  -H 'X-PSK: changeme' \
  -d '{"agent_id":"<AGENT_ID>","type":"triage"}'
```

#### Enqueue with job arguments

You can pass `args` to configure triage per endpoint:

- `timeout`: Go duration string (e.g. `10m`, `1h`)
- `ioc`: inline IOC patterns (will be written to a temp file locally)
- `ioc_file`: path to IOC file on the agent filesystem
- `snapshot_paths`: comma-separated paths (`/etc,/var/log`)
- `snapshot_mode`: `metadata|copy`
- `snapshot_hash`: `true|false`
- `snapshot_max_file_bytes`, `snapshot_max_total_bytes`, `snapshot_max_files`

Example:

```bash
curl -k -sS -X POST https://127.0.0.1:8443/v1/jobs \
  -H 'Content-Type: application/json' \
  -H 'X-PSK: changeme' \
  -d '{
    "agent_id":"<AGENT_ID>",
    "type":"triage",
    "args":{
      "timeout":"15m",
      "snapshot_paths":"/etc,/var/log",
      "snapshot_mode":"metadata",
      "snapshot_hash":"true",
      "ioc":"suspicious-domain.com\nmalware.exe\n"
    }
  }'
```

Uploads are stored under:

- `server-data/uploads/<JOB_ID>/case.tar.gz`

## Project layout

```text
iron-sentinel/
├── core/              # Go - orchestration CLI
├── collectors/        # Go - evidence collectors
├── analyzers/         # Go - analyzers (IOC, timeline, ...)
├── evidence/          # Go - evidence utilities (hashing, manifest)
├── agents/            # Go - lightweight endpoint agent MVP
├── rust-modules/      # Rust - performance modules (fast-hash)
└── rapid-response/    # Bash - quick wrappers
```
