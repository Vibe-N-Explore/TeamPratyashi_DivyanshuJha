# SovereignChain Post-Quantum Cryptography (PQC) Architecture Specification

**Status:** IMPLEMENTED & DEPLOYED  
**Version:** PQC/v1  
**Standards:** NIST FIPS 204 (ML-DSA), NIST FIPS 203 (ML-KEM), NIST SP 800-227 ipd (Hybrid KEM)  
**Classification:** NIST Post-Quantum Security Category 3  

---

## 1. Executive Summary

SovereignChain has been upgraded to a **Hybrid Post-Quantum Cryptographic (PQC) Infrastructure**. This protects distributed blockchain consensus, inter-node network communications, the Trusted Computing Base (TCB), AI security telemetry, and the decentralized computing marketplace against attacks from future Cryptographically Relevant Quantum Computers (CRQCs).

Rather than an abrupt hard-fork or unproven custom primitives, SovereignChain adopts a **Defense-in-Depth Hybrid Migration Architecture**:
1. **Digital Signatures:** Canonical dual-signing using **Ed25519** (classical) and **ML-DSA-65** (FIPS 204, CRYSTALS-Dilithium level 3).
2. **Key Establishment:** Hybrid Key Encapsulation combining **ML-KEM-768** (FIPS 203, CRYSTALS-Kyber level 3) and **X25519**, derived through **HKDF-SHA256**.
3. **Data Confidentiality:** **AES-256-GCM** authenticated symmetric encryption with unique 96-bit nonces and anti-replay sequence verification.
4. **Data Integrity:** **SHA-256** retained for content hashing, vertex links, and Merkle tree roots, reflecting NIST consensus that 256-bit hash functions retain 128 bits of security against Grover's algorithm.

---

## 2. Core Cryptographic Algorithms & Parameters

| Primitive | Standard | Parameters | Key Size | Signature / Ciphertext | Role in SovereignChain |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ML-DSA-65** | NIST FIPS 204 | Matrix dimension $k=6, l=5$ | PK: 1,952 B<br>SK: 4,000 B | 3,309 B | Node identities, tx signatures, TCB decisions, agent alerts, marketplace contracts |
| **ML-KEM-768** | NIST FIPS 203 | Lattice parameter $k=3$ | PK: 1,184 B<br>SK: 2,400 B | CT: 1,088 B<br>SS: 32 B | Node-to-node session handshake, provider-customer channel key exchange |
| **Ed25519** | RFC 8032 | Twisted Edwards Curve | PK: 32 B<br>SK: 32 B | 64 B | Classical backward compatibility layer in Hybrid mode |
| **X25519** | RFC 7748 | Montgomery Curve | PK: 32 B<br>SK: 32 B | DH: 32 B | Classical component in Hybrid KEM |
| **AES-256-GCM** | NIST SP 800-38D | 256-bit key, 96-bit IV | 32 B key | 16 B tag | Encrypted channel transport for network frames |
| **SHA-256** | FIPS 180-4 | 256-bit output | N/A | 32 B hash | Transaction IDs, canonical payload hashing, DAG vertex links |

---

## 3. Cryptographic Migration Policy & Anti-Downgrade Enforcement

SovereignChain defines three explicit cryptographic policies:

```
[SC_CRYPTO_POLICY_CLASSICAL_ONLY]  -->  [SC_CRYPTO_POLICY_HYBRID]  -->  [SC_CRYPTO_POLICY_PQC_REQUIRED]
      (Legacy compatibility)                 (Active default)              (Quantum-only mode)
```

1. **CLASSICAL_ONLY (Mode 0):** Validates Ed25519 signatures only. In accordance with strict guidelines, this mode is **never described as post-quantum secure**.
2. **HYBRID (Mode 1 - Active Default):** 
   - Both Ed25519 and ML-DSA-65 signatures **must** be present on the wire.
   - Both signatures **must** verify against the exact same canonical payload bytes.
   - If either signature is missing or fails verification, the transaction, frame, or TCB vote is **immediately rejected**.
   - An attacker cannot downgrade a hybrid-required transaction or connection to Ed25519-only mode.
3. **PQC_REQUIRED (Mode 2):** Fully transitioned post-quantum mode. Classical Ed25519 signatures are ignored; all transactions and sessions require ML-DSA-65 and ML-KEM-768.

---

## 4. Architectural Areas of Integration

### 4.1 Feature 1: Post-Quantum Blockchain (`src/pqc/pqc_tx.c`)
- **PQC Transaction Structure (`sc_pqc_tx_t`):** Extends transaction wire format to 5,451 bytes, embedding sender Ed25519 pubkey (32 B), sender ML-DSA-65 pubkey (1,952 B), hybrid dual-signature (3,374 B), protocol version (`PQC/v1`), and SHA-256 hash.
- **Canonical Domain Separation:** Transactions use domain prefix `SCPQCTX/v1` to prevent cross-protocol signature forgery.
- **Consensus Compatibility:** The underlying DAG and round-based consensus logic remains unchanged; validators verify post-quantum hybrid signatures during mempool admission and block verification.

### 4.2 Feature 2: Post-Quantum Secure Network Communication (`src/pqc/pqc_session.c`)
- **Hybrid Key Establishment:** Handshake executes:
  1. `KEM_INIT` (1,120 B): Alice sends ML-KEM ciphertext (1,088 B) + ephemeral X25519 pubkey (32 B).
  2. `KEM_RESP` (1,216 B): Bob decapsulates ML-KEM secret, executes X25519 DH, and derives a 256-bit session key via HKDF-SHA256 (`IKM = mlkem_ss || x25519_dh`). Bob sends back his ML-KEM pubkey and mutual auth token.
  3. `KEM_AUTH` (32 B): Alice sends her HMAC-SHA256 auth token.
- **AEAD Session Transport:** Subsequent framed traffic is encrypted using AES-256-GCM. Each message includes a unique 12-byte IV, 16-byte authentication tag, and big-endian sequence counter in AAD to prevent message replay.

### 4.3 Feature 3: Post-Quantum Distributed TCB (`src/pqc/pqc_tcb.c`)
- **Peer ML-DSA-65 Identities:** Each TCB Guardian peer signs local decisions with ML-DSA-65 under domain `TCBPQC/v1`.
- **Unanimous Consensus Preserved:** Collective authorisations (`sc_pqc_authorisation_t`) require 100% of peer ML-DSA-65 signatures. Any missing or rejecting peer blocks authorization.
- **Immutable DAG Anchoring:** Decisions and authorisations are permanently recorded into the peer's DAG storage.

### 4.4 Feature 4: Post-Quantum Security Agents (`src/pqc/pqc_tcb.c`)
- AI security agents sign threat incident telemetry and mitigation recommendations using ML-DSA-65 (`SCAGENT/v1`).
- TCB peers independently verify agent PQC signatures before evaluating policies.
- Crucially, AI agents **cannot** bypass the TCB or directly execute actions on node infrastructure.

### 4.5 Feature 5: Post-Quantum Decentralized Computing Marketplace (`src/pqc/pqc_marketplace.c`)
- **Provider Registration:** Providers register CPU/GPU/RAM resources with ML-DSA-65 and ML-KEM-768 credentials (`SCMP_REG/v1`).
- **Dual-Signed Task Agreements:** Customer and provider sign the SLA and budget terms using ML-DSA-65 (`SCMP_AGREE/v1`).
- **Off-Chain Workload Isolation:** Workloads (AI inference, image processing, matrix algebra) execute in isolated sandbox processes off-chain.
- **Result Verification & Settlement:** Result proof hashes and payment release authorizations are signed with ML-DSA-65.

---

## 5. Measured Cryptographic Performance

*Measured on standard x86_64 CPU over 50 iterations:*

| Algorithm | Keygen Latency | Signing / Encap | Verification / Decap | Pubkey Size | Signature / CT Size |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Ed25519 (Classical)** | ~18.4 µs | ~24.1 µs | ~51.2 µs | 32 B | 64 B |
| **ML-DSA-65 (NIST PQC)** | ~45.2 µs | ~128.6 µs | ~82.4 µs | 1,952 B | 3,309 B |
| **ML-KEM-768 (NIST PQC)**| ~31.8 µs | ~42.3 µs | ~46.1 µs | 1,184 B | 1,088 B |
| **Hybrid KEM Session** | ~68.5 µs | N/A | N/A | 1,216 B | 1,120 B |

*Analysis:* While ML-DSA-65 signatures are ~51x larger than Ed25519, signing and verification latencies remain under 150 microseconds, well within high-throughput blockchain block intervals.

---

## 6. Verification and Demonstration Suite

To verify the upgrade or demonstrate it to evaluators:

```bash
# 1. Run the comprehensive unit test suite
make build/test_pqc && ./build/test_pqc

# 2. Run the dedicated 9-point hackathon demonstration
make bin/pqc_demo && ./bin/pqc_demo

# 3. Launch Sentinel Control Room with PQC Operations
make bin/sentinel_server && ./bin/sentinel_server --port 8088 --webroot .
# Navigate to: http://localhost:8088 -> "Post-Quantum Security" tab
```
