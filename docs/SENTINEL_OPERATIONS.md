# Sentinel operations and data boundaries

## Start the control room

Build with the repository Makefile, then run `bin/sentinel_server` from the repository root. The server binds to `127.0.0.1` because it contains an operator approval surface. The dashboard is available at `http://127.0.0.1:8088/`.

Use `--network <file>`, `--web-root <directory>`, `--port <port>`, and `--state-dir <directory>` to select the node topology, UI files, local port, and persistent security state. The default state directory is `sentinel-state`. The process creates that directory if its parent exists.

## Node telemetry

Each node exposes a read-only `/metrics` HTTP endpoint on its configured P2P port plus `SC_NODE_METRICS_PORT_OFFSET` (10,000). Sentinel polls it every five seconds. The node process reports authenticated peer count, callback message count, accepted transaction count, consensus round, and uptime. These counters are per process; summed transaction/message counts are observations across nodes and can include duplicate gossip. A reporting endpoint indicates the process is answering, while authenticated peer count separately shows established authenticated sessions.

## Recovery boundary

The recovery page performs a live metrics endpoint check and records the result. If the endpoint is unavailable, recovery remains pending. The node software has no Sentinel control endpoint to restart a process or alter its transport. Sentinel therefore does not claim to have recovered a node. Validator membership, ledger state, and consensus configuration are never changed by this feature.

## Persistent security records

With `--state-dir`, Sentinel stores:

- `security-history.bin`: a versioned local event snapshot. Event IDs hash the recorded fields and are checked on startup. Each event is also appended as a separately signed security event vertex to every TCB peer's DAG. Capacity drops are counted and shown in the API/UI.
- `tcb-peer-0.dag`, `tcb-peer-1.dag`, `tcb-peer-2.dag`: independent, versioned snapshots of each peer DAG. Every vertex hash and Ed25519 signature is checked when loading; a corrupt snapshot prevents Sentinel startup.
- `security-agent.pem`, `operator.pem`, and `tcb-peer-*.pem`: stable identities used to keep peer signatures and operator decisions verifiable across restarts. They are unencrypted PEM files with owner-only permissions inside the state directory. Keep that directory private and backed up; never publish it.

The snapshot files are written through temporary files and renamed into place. Files are restricted to the running user's permissions. Peer DAG integrity is distinct from the local event feed's hashes: peer vertices retain their original signatures, while the local event file is not signed by a TCB key. `/api/history/dags` reports each peer's vertex hashes, integrity result, and which hashes are shared or peer-specific.

Use the **Verify peer histories** control in Security History to inspect the three independent DAGs. The audit checks vertex hashes, Ed25519 signatures, peer identity, event hashes, and shared event IDs, then compares local events with each peer's DAG. Peers can legitimately have different request and decision records; missing event copies are reported and are never silently copied into another peer's DAG.

## API additions

- `GET /api/network` returns configured nodes, node-reported metrics, and TCB peer DAG sizes.
- `GET /api/history` returns Sentinel event records, content IDs, and associated TCB request IDs when present.
- `GET /api/history/dags` verifies and compares independent TCB DAG snapshots.
- `POST /api/governance/resolve?request_id=<64-hex>&approve=true|false` resolves the specific pending request. It requires a same-origin `Origin` header.

The HTTP server is intended for local demonstration and is bound to loopback. It is not a remotely exposed operator service.

## Remaining integration limits

Sentinel and the chain node are separate processes. The current node executable does not expose authenticated message/transaction counters or a controlled recovery command, so those functions remain unavailable. Pending in-memory TCB workflow state is not reconstructed from the durable DAG after restart; prior decisions remain auditable, but a human escalation may need to be resubmitted to continue resolution.
