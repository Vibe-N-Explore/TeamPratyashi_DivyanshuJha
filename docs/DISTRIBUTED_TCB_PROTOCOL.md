# SovereignChain Distributed TCB Protocol & Operational Specification

## 1. Overview
The SovereignChain Distributed Trusted Computing Base (TCB) provides deterministic, decentralized security policy enforcement for autonomous blockchain operations. It coordinates multiple independent peer nodes into a Byzantine-resilient consensus collective that evaluates AI Security Agent recommendations, records cryptographically immutable audit histories, and enforces collective authorization for automated mitigations while requiring human operator sign-off for governance changes.

---

## 2. Cryptographic Identities & Domain Separation

Every TCB peer and participating security agent operates using an independent Ed25519 keypair. To prevent cross-context replay attacks, all signatures bind explicit domain separators:

| Message Type | Domain Separator | Payload Length | Signature Target |
|---|---|---|---|
| **Action Request** | `"ACT_REQ/v1"` | 98 bytes + evidence | `SHA-256("ACT_REQ/v1" \| request_id \| incident_type \| proposed_action \| target_node_id \| timestamp \| evidence_hash)` |
| **TCB Decision** | `"TCB_DEC/v1"` | 112 bytes | `SHA-256("TCB_DEC/v1" \| request_id \| tcb_peer_id \| verdict \| timestamp \| category \| reason_hash)` |
| **Human Escalation Resolution** | `"HUMAN_RESOLVE/v1"` | 64 bytes | `SHA-256("HUMAN_RESOLVE/v1" \| escalation_id \| approve_byte \| timestamp \| notes_hash)` |
| **TCB DAG Vertex** | `"TCB_VTX/v1"` | Dynamic | `SHA-256("TCB_VTX/v1" \| round \| author_id \| vertex_type \| parent_hashes \| payload_hash)` |

---

## 3. Protocol State Machine

```
              [Action Request Submitted]
                          |
                          v
               [Local Policy Evaluation]
                /                     \
       (All Checks Pass)         (Check Fails)
              /                         \
    [Verdict: APPROVE]            [Verdict: REJECT]
             |                             |
      (Exchange Decisions)          (Exchange Decisions)
             |                             |
    [Collect Remote Decisions]             v
      /            \             [Status: REJECTED]
(Dissent)      (Unanimous)        (Action Aborted)
    |               \
    v                v
[Status: REJECTED]  [Check Action Category]
                   /                      \
        [AUTO_PERMITTED]              [HUMAN_REQUIRED]
               |                              |
               v                              v
     [Status: AUTHORISED]           [Status: ESCALATED]
   (Emit sc_authorisation_t)      (Wait for Operator Sign-Off)
               |                              |
               v                     /                 \
      [Node Guard Applies]      (Approved)          (Rejected)
                                     |                   |
                                     v                   v
                            [Status: AUTHORISED]  [Status: REJECTED]
```

### Protocol Rules:
1. **Zero Silent Approvals**: Any TCB peer that is unreachable, disconnected, or slow leaves the consensus status in `TCB_STATUS_PENDING`. No action is ever executed on a timeout.
2. **Instant Rejection**: A single peer submitting `TCB_VERDICT_REJECT` terminates automated consideration immediately (`TCB_STATUS_REJECTED`).
3. **Collective Authorisation Threshold**: Requires valid signatures from $N$ out of $N$ ($100\%$) configured TCB peers.

---

## 4. Configuration & Deployment Guide

### A. TCB Peer Network Setup
A minimal fault-tolerant TCB network requires 3 peers deployed across separate physical or virtual environments.

1. **Generate TCB Peer Keypairs**:
   ```bash
   # Peer 0
   openssl genpkey -algorithm ed25519 -out config/tcb_peer_0.pem
   chmod 0600 config/tcb_peer_0.pem

   # Peer 1
   openssl genpkey -algorithm ed25519 -out config/tcb_peer_1.pem
   chmod 0600 config/tcb_peer_1.pem

   # Peer 2
   openssl genpkey -algorithm ed25519 -out config/tcb_peer_2.pem
   chmod 0600 config/tcb_peer_2.pem
   ```

2. **Launch TCB Peer Daemons**:
   ```bash
   # Launch Peer 0 (configured for 3 peers)
   ./bin/tcb_peer --id 0 --peers 3 --key config/tcb_peer_0.pem &

   # Launch Peer 1
   ./bin/tcb_peer --id 1 --peers 3 --key config/tcb_peer_1.pem &

   # Launch Peer 2
   ./bin/tcb_peer --id 2 --peers 3 --key config/tcb_peer_2.pem &
   ```

3. **Launch the AI Security Agent**:
   ```bash
   ./bin/sec_agent --key config/agent_key.pem &
   ```

---

## 5. Security Model, Assumptions & Known Limitations

### Trust Assumptions:
1. **Cryptographic Primitives**: SHA-256 collision resistance and Ed25519 unforgeability are assumed secure.
2. **TCB Peer Independence**: It is assumed that TCB peers run on independent hosts or VMs so that a single host vulnerability does not compromise all peers simultaneously.
3. **Operator Identity**: The human operator keypair must be maintained in a secure enclave, HSM, or encrypted offline storage.

### Known Limitations & Trade-offs:
- **Liveness Trade-off (Unanimous Consensus)**:
  By requiring 100% agreement, the system prioritizes **Safety over Liveness**. If one TCB peer goes offline, automated mitigations are suspended until the peer recovers or is formally decommissioned through human governance.
- **Clock Drift Sensitivity**:
  Requests with timestamps diverging by more than 60 seconds from a peer's monotonic clock are rejected as potentially stale or replayed. Production deployments should maintain NTP synchronization across TCB peers.
- **In-Memory Mempool Sizing**:
  Mempool capacity is bounded at 1024 transactions to prevent memory exhaustion; extreme transaction spikes require rate-limiting backpressure at the gateway level.
