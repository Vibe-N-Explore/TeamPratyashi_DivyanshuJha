# SovereignChain

**A modular C17 blockchain prototype with DAG-based transaction ordering, a distributed security and governance layer, and a post-quantum cryptography demonstration stack.**

SovereignChain explores how a blockchain can combine deterministic transaction execution with independently verifiable security decisions. Its architecture separates the core chain, security intelligence, distributed Trusted Computing Base (TCB), operator governance, and experimental post-quantum cryptography (PQC).

> **Project status:** Hackathon / research prototype. The repository contains working development harnesses, test suites, a Sentinel security dashboard, and standalone PQC demonstrations. It is **not** a production blockchain, production bridge, or independently audited post-quantum network. See [Security model and limitations](#security-model-and-limitations).

---

## At a glance

| Area | What is included |
|---|---|
| Core implementation | C17, POSIX networking, OpenSSL |
| Local chain harness | Six node processes on `127.0.0.1:9000–9005` |
| Consensus prototype | DAG vertices, validator votes, certificates, deterministic commit ordering |
| Transaction security | Ed25519 signatures, SHA-256 hashing, nonce and ledger validation |
| Security layer | Security-agent incident recommendations and deterministic policy checks |
| Distributed TCB | Three-peer decision workflow, independent peer DAG histories, unanimous authorization |
| Governance | Human approval path for actions marked as requiring operator consent |
| Sentinel | Local web control room, node telemetry, security history and PQC demo endpoints |
| PQC modules | ML-DSA-65, ML-KEM-768, hybrid signatures/key establishment, AES-256-GCM session protection |
| Additional module | Post-quantum signed decentralized-compute marketplace records and agreements |

## Table of contents

- [Architecture](#architecture)
- [Core blockchain](#core-blockchain)
- [Security intelligence and distributed TCB](#security-intelligence-and-distributed-tcb)
- [Post-quantum cryptography](#post-quantum-cryptography)
- [Sentinel control room](#sentinel-control-room)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Build](#build)
- [Run the six-node local network](#run-the-six-node-local-network)
- [Run the PQC demonstration](#run-the-pqc-demonstration)
- [Run the Sentinel control room](#run-the-sentinel-control-room)
- [Run tests](#run-tests)
- [Security model and limitations](#security-model-and-limitations)
- [Development and contribution notes](#development-and-contribution-notes)

---

## Architecture

SovereignChain is organized into three logical layers.

```text
┌─────────────────────────────────────────────────────────────────────┐
│                  LAYER 3 — APPLICATIONS & SERVICES                   │
│                                                                     │
│  Sentinel Control Room  •  Computing Marketplace  •  Client Tools   │
│  Cross-chain connector prototype  •  Future application modules    │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │ telemetry / requests / records
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│              LAYER 2 — SECURITY, INTELLIGENCE & GOVERNANCE          │
│                                                                     │
│  Security Agent → Deterministic TCB Policy → TCB Peer Decisions    │
│                                      │                              │
│                         Unanimous authorization                     │
│                                      │                              │
│                         Human governance escalation                 │
│                                                                     │
│  Independent TCB DAG histories and auditable security events       │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │ bounded, authorized actions
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    LAYER 1 — CORE BLOCKCHAIN                         │
│                                                                     │
│  Authenticated P2P Networking • Transactions • Mempool              │
│  DAG Vertices • Validator Voting • Certificates • Account Ledger   │
│  Deterministic Ordering • Persistent State                          │
└─────────────────────────────────────────────────────────────────────┘
```

The central design principle is **separation of authority**:

- The core chain validates and executes deterministic state transitions.
- A security agent can analyze telemetry and recommend a bounded action.
- The deterministic policy engine checks whether the request is permitted.
- TCB peers independently evaluate the request and exchange signed decisions.
- Actions requiring human governance remain pending until an operator resolves them.

The security agent is not intended to have unrestricted authority over the blockchain node.

## Core blockchain

The chain implementation is written in **C17**.

### Network

- Six local node identities are defined in `config/network.conf`.
- The supplied local harness starts six processes on ports `9000` through `9005`.
- The configured topology contains two validator identities and four normal-node identities.
- Nodes communicate over framed TCP messages and authenticate peers using pinned Ed25519 public keys.
- The event loop uses `poll()` to handle network activity.

The included launcher is a **single-machine development harness**. Six localhost processes demonstrate multi-process networking; they do not constitute six independently operated or geographically distributed machines.

### Transaction and ledger flow

At a high level:

1. A transaction is created and signed by its sender.
2. A node validates the transaction and its signature before admitting it to the mempool.
3. Transactions are propagated to connected peers.
4. Validators create DAG vertices containing batches of pending transactions.
5. Validators exchange votes; valid votes contribute to a certificate.
6. The consensus component evaluates certificates and commit eligibility.
7. The ledger applies committed transactions in deterministic order and persists state.

The implementation includes transaction serialization, signature verification, duplicate handling, account balances, sequential nonces, fees, and persistent state snapshots.

### DAG and consensus prototype

The consensus implementation includes:

- DAG vertex creation and parent references;
- vertex hashing and signature verification;
- validator voting and certificate collection;
- alternating validator anchors;
- equivocation checks for conflicting validator activity;
- deterministic ordering for commit evaluation.

The supplied configuration is a two-validator development topology. It should not be described as a general Byzantine-fault-tolerant consensus protocol: a two-validator, 2-of-2 arrangement has no tolerance for a Byzantine validator and can lose liveness when either validator is unavailable.

## Security intelligence and distributed TCB

The security subsystem is designed around the principle:

**Agent recommends → policy evaluates → TCB peers decide → authorized component applies.**

### Security agent

The security-agent subsystem works with structured telemetry and incident records. It can produce bounded action recommendations rather than directly issuing arbitrary operating-system commands.

### Deterministic policy engine

The TCB policy layer evaluates action requests against deterministic rules and classifies actions, including actions that require human approval. A model or agent recommendation is not, by itself, authorization.

### Distributed TCB

The Sentinel implementation maintains three TCB peer instances, each with its own identity and DAG history. The workflow includes:

- signed action requests and peer decisions;
- independent policy evaluation;
- rejection when a peer dissents;
- unanimous approval for automatic authorization;
- pending status when a required peer is unavailable;
- escalation to a human operator for governance-sensitive actions;
- persistent and auditable peer history.

The TCB's unanimous rule intentionally favors safety over liveness: one unavailable peer can prevent an authorization from completing.

## Post-quantum cryptography

The repository includes a separate PQC module built on **liboqs** and **OpenSSL**. It provides cryptographic building blocks and a dedicated demonstration/test path.

### Algorithms represented

| Primitive | Standard / specification | Intended role |
|---|---|---|
| ML-DSA-65 | NIST FIPS 204 | Post-quantum digital signatures |
| ML-KEM-768 | NIST FIPS 203 | Post-quantum key encapsulation |
| Ed25519 | RFC 8032 | Classical signature component in hybrid mode |
| X25519 | RFC 7748 | Classical component in hybrid key establishment |
| HKDF-SHA-256 / HMAC-SHA-256 | RFC 5869 / RFC 2104 | Key derivation and session authentication |
| AES-256-GCM | NIST SP 800-38D | Authenticated session encryption |
| SHA-256 | FIPS 180-4 | Hashing and integrity identifiers |

### Cryptographic policy modes

The PQC module defines three policies:

- `CLASSICAL_ONLY`: classical Ed25519 verification. This mode is not post-quantum secure.
- `HYBRID`: both Ed25519 and ML-DSA-65 signatures are required for the relevant PQC-module operation.
- `PQC_REQUIRED`: ML-DSA-65 is required without the classical signature component.

The hybrid key-establishment module combines ML-KEM-768 and X25519 shared secrets through a key-derivation step. The session module provides AES-256-GCM encryption and authenticated message handling.

### Important integration boundary

The PQC code is compiled into the project executables and exercised by the dedicated PQC unit tests, demonstration, and Sentinel endpoints. However, the ordinary chain-node networking and consensus paths in `src/net.c`, `src/main.c`, and `src/consensus.c` do not currently call the PQC session or PQC transaction APIs. Therefore, **the six-node chain harness should not be represented as already running end-to-end post-quantum-protected consensus or transport**.

The PQC demonstration validates the PQC module's own operations; it does not prove that every live chain transaction, peer handshake, or consensus message uses those algorithms.

For the detailed module design, see [`docs/POST_QUANTUM_CRYPTOGRAPHY_ARCHITECTURE.md`](docs/POST_QUANTUM_CRYPTOGRAPHY_ARCHITECTURE.md).

## Sentinel control room

Sentinel is the local security operations dashboard and HTTP service.

It brings together:

- node telemetry and network status;
- security incidents and action requests;
- TCB decision and governance workflows;
- security history and peer-DAG integrity inspection;
- PQC status, benchmark, and demonstration endpoints.

### Start Sentinel

From the repository root, after building:

```bash
./bin/sentinel_server --port 8088 --web-root . --state-dir sentinel-state
```

Open:

```text
http://127.0.0.1:8088/
```

Sentinel binds to loopback by default. Keep it local unless a separately reviewed authentication and deployment layer has been added.

The server accepts optional arguments:

```text
--port <port>             HTTP port (default: 8088)
--network <file>          Node topology configuration
--web-root <directory>    Directory containing index.html
--state-dir <directory>   Persistent Sentinel state directory
```

The implementation's default network-config path is `config/nodes.conf`; this archive's six-node harness uses `config/network.conf`. If you want Sentinel to poll that topology, pass the correct file explicitly:

```bash
./bin/sentinel_server \
  --port 8088 \
  --network config/network.conf \
  --web-root . \
  --state-dir sentinel-state
```

### Selected API endpoints

The local Sentinel service includes endpoints for status, node/network information, security history, TCB peer DAG history, and PQC demonstration data. The PQC integration test probes:

```text
GET /api/pqc/status
GET /api/pqc/bench
GET /api/pqc/demo
```

The service is intended for local demonstration and operator interaction, not direct exposure to the public internet.

## Repository layout

```text
.
├── index.html                 # Sentinel dashboard frontend
├── Makefile                   # Main build and test targets
├── config/                    # Six-node network and per-node configs
├── src/
│   ├── main.c                 # Chain-node process and event loop
│   ├── config.*               # Configuration loading and validation
│   ├── net.*                  # P2P transport and peer authentication
│   ├── crypto.*               # Classical cryptographic helpers
│   ├── tx.*                   # Transaction representation and validation
│   ├── mempool.*              # Transaction admission and batching
│   ├── dag.*                  # DAG vertex handling
│   ├── consensus.*             # Validator voting and commit evaluation
│   ├── ledger.*               # Deterministic account ledger
│   ├── storage.*              # Persistent chain state
│   ├── security/              # Security incidents, agent, node guard
│   ├── tcb/                   # TCB decisions, policy, peer and DAG logic
│   └── pqc/                   # PQC primitives, sessions, transactions, demo
├── tests/
│   ├── unit/                  # Unit tests
│   └── integration/           # Multi-process and feature integration tests
├── scripts/
│   ├── keygen.sh              # Generate six Ed25519 node keypairs
│   └── run_local.sh           # Launch six local chain processes
├── docs/
│   ├── DEVNET.md
│   ├── DISTRIBUTED_TCB_PROTOCOL.md
│   ├── POST_QUANTUM_CRYPTOGRAPHY_ARCHITECTURE.md
│   ├── SENTINEL_OPERATIONS.md
│   └── SOVEREIGNCHAIN_STRATEGIC_INTEGRATION_VISION.md
├── connector/                 # Separate two-chain connector prototype
└── liboqs/                    # Open Quantum Safe source tree included in archive
```

The `connector/` directory contains a separate cross-chain connector prototype with its own Makefile, source, tests, and documentation. It is not required to run the six-node chain harness or the PQC demo described above. Consult its own documentation before using it.

## Requirements

The main project targets Linux. Windows users can use WSL2 with an Ubuntu distribution.

Required tools and libraries:

- GCC or Clang with C17 support;
- GNU Make;
- OpenSSL 3.x development headers and libraries;
- `pkg-config`;
- liboqs with ML-DSA-65 and ML-KEM-768 support;
- Bash;
- Python 3 and `curl` for selected scripts and integration tests.

On Ubuntu / Debian / WSL, install the common system packages:

```bash
sudo apt update
sudo apt install build-essential cmake ninja-build libssl-dev pkg-config \
  python3 curl openssl xxd
```

Install or build a compatible liboqs release that exposes `liboqs` through `pkg-config` (or is otherwise available to the compiler and linker). The repository Makefile looks up liboqs using `pkg-config` and otherwise falls back to `-loqs`; it does not automatically build and install the bundled `liboqs/` source tree.

Check that the dependency is discoverable before building:

```bash
pkg-config --modversion openssl
pkg-config --modversion liboqs
```

## Build

From the repository root:

```bash
make
```

The main Makefile builds:

| Binary | Purpose |
|---|---|
| `bin/node` | Blockchain node |
| `bin/injector` | Transaction / network test utility |
| `bin/sec_agent` | Security-agent executable |
| `bin/tcb_peer` | TCB peer executable |
| `bin/sentinel_server` | Sentinel HTTP service and dashboard backend |
| `bin/pqc_demo` | Standalone PQC demonstration |

The build uses C17 and warning flags. Sanitizer flags are enabled for unit-test builds when supported by the compiler.

To build the separate connector component:

```bash
make -C connector
```

## Run the six-node local network

The supplied configuration describes six localhost processes on ports `9000–9005`.

The archive contains development key files and matching public-key configuration. **Do not reuse those private keys outside a disposable local demonstration.** For a fresh setup, generate new keys:

```bash
bash scripts/keygen.sh
```

The script creates `keys/node0.key` through `keys/node5.key` and prints the corresponding public-key lines. Replace the node entries in `config/network.conf` with the newly printed lines so that the public keys match the new private keys.

Then build and start the network:

```bash
make
./scripts/run_local.sh
```

The launcher writes node logs to:

```text
logs/node_0.log
logs/node_1.log
...
logs/node_5.log
```

Press `Ctrl-C` to stop the local processes.

This harness is intended for local development and demonstration. It is not a production deployment guide.

## Run the PQC demonstration

Build and run the dedicated demonstration:

```bash
make bin/pqc_demo
./bin/pqc_demo
```

The demonstration exercises a sequence of PQC operations, including identity generation, hybrid transaction signing and verification, tamper detection, hybrid key establishment, encrypted session communication, TCB-related PQC signatures, and marketplace-related signed records.

Run the PQC unit test directly:

```bash
make build/test_pqc
./build/test_pqc
```

Or use the dedicated Make target:

```bash
make test-pqc
```

## Run tests

### Unit tests

```bash
make test-unit
```

### Integration tests

```bash
make test-integration
```

The integration target runs the phase scripts and the security, Sentinel, and PQC integration checks. These tests launch local processes and may create logs or local state.

### Full main test target

```bash
make test
```

### PQC-specific verification

```bash
make test-pqc
```

The PQC integration script also starts a temporary Sentinel server and probes the PQC HTTP endpoints:

```bash
bash tests/integration/test_pqc_integration.sh
```

Some test and development scripts create or regenerate local state. Review a script before running it against data you need to preserve.

## Security model and limitations

SovereignChain is an experimental prototype. It must not be used to custody real assets, store production secrets, or secure production infrastructure.

Known boundaries include:

1. **Consensus scope:** the included six-node topology has two validators and a 2-of-2 certification model. It does not tolerate a Byzantine validator and can lose liveness if either validator is unavailable.
2. **Local harness:** all six node processes run on one machine and share the host's operational trust boundary.
3. **PQC integration:** PQC primitives and demonstrations exist, but the ordinary node networking and consensus paths are not yet wired to use the PQC session and transaction APIs end to end.
4. **TCB liveness:** unanimous authorization means a missing peer can leave a request pending. This is a deliberate safety-over-liveness trade-off.
5. **Human governance:** actions classified as human-required need an operator decision; automated agent output is not sufficient authority.
6. **Sentinel exposure:** Sentinel is designed for loopback use. Its operator endpoints are not intended to be exposed publicly without authentication, authorization, transport security, and deployment hardening.
7. **Key management:** development private keys must be regenerated and protected. Never commit private keys, generated state, or secrets.
8. **Marketplace scope:** the PQC marketplace module signs registration, agreement, result, and settlement records; actual compute workloads are off-chain and are not executed by blockchain consensus.
9. **Connector scope:** the separate connector devnet is a prototype. Connector quorum approval must not be treated as proof of correct destination-chain execution or finality. Review `docs/DEVNET.md` and connector documentation for known gaps.

The repository's design documents describe intended architecture as well as implemented modules. Where a design document describes a future integration or broader security guarantee, verify the corresponding code path and tests before treating it as an implemented property.

## Development and contribution notes

- Keep consensus and ledger state transitions deterministic.
- Keep AI or heuristic recommendations outside the core consensus execution path.
- Require explicit policy checks and authorization for security actions.
- Use domain-separated canonical payloads for signatures.
- Add tests for both successful and rejected paths, including tampered messages and missing peer responses.
- Do not commit private keys, local state directories, logs, or generated binaries.
- Update the relevant architecture and operations documentation whenever behavior changes.

## Further documentation

- [Distributed TCB Protocol](docs/DISTRIBUTED_TCB_PROTOCOL.md)
- [Post-Quantum Cryptography Architecture](docs/POST_QUANTUM_CRYPTOGRAPHY_ARCHITECTURE.md)
- [Sentinel Operations](docs/SENTINEL_OPERATIONS.md)
- [Two-chain Devnet Notes](docs/DEVNET.md)
- [Strategic Integration Vision](docs/SOVEREIGNCHAIN_STRATEGIC_INTEGRATION_VISION.md)

---

**SovereignChain — deterministic execution, verifiable security decisions, and an experimental path toward post-quantum infrastructure.**
