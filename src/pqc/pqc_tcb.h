/* pqc_tcb.h — Post-Quantum TCB (Trusted Computing Base) Decision Layer.
 *
 * Feature 3 & 4: Post-Quantum Distributed TCB and Security Agents.
 *
 * Extends the existing sc_tcb_decision_t with:
 *   - ML-DSA-65 signatures for each peer decision
 *   - Hybrid signature policy on collective authorisations
 *   - Canonical action-request hashing with PQC domain separator
 *   - Independent verification of each peer's post-quantum signature
 *
 * Key invariants preserved:
 *   - Unanimous approval requirement: ALL peers must approve
 *   - A rejecting or unavailable peer is NEVER treated as approving
 *   - Sensitive (HUMAN_REQUIRED) actions still need human governance
 *   - The TCB DAG architecture remains functional
 *
 * Wire format for sc_pqc_tcb_decision_t:
 *   "TCBPQC/v1" (9 bytes) domain separator
 *   request_id  (32 bytes)
 *   peer_id     (4 bytes, big-endian int32_t)
 *   mldsa_pubkey (1952 bytes)
 *   timestamp   (8 bytes, big-endian uint64_t)
 *   verdict     (2 bytes, big-endian uint16_t)
 *   category    (2 bytes, big-endian uint16_t)
 *   reason      (64 bytes, null-padded)
 *   = 2073 bytes signed
 *
 * Both the Ed25519 and ML-DSA-65 signatures sign this exact payload.
 */
#ifndef SC_PQC_TCB_H
#define SC_PQC_TCB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../err.h"
#include "../crypto.h"
#include "../tcb/decision.h"
#include "pqc_crypto.h"

#define SC_PQC_TCB_DOMAIN       "TCBPQC/v1"
#define SC_PQC_TCB_DOMAIN_LEN   9
#define SC_PQC_TCB_SIGN_LEN     (SC_PQC_TCB_DOMAIN_LEN + 32 + 4 + \
                                  SC_MLDSA_PUBKEY_LEN + 8 + 2 + 2 + 64)

/* Post-quantum enhanced TCB decision from a single peer.
 * Wraps the existing sc_tcb_decision_t with ML-DSA-65 coverage. */
typedef struct {
    /* Classic decision fields (backward compatible) */
    sc_tcb_decision_t classical_decision;

    /* PQC extension */
    uint8_t  mldsa_pubkey[SC_MLDSA_PUBKEY_LEN];
    uint8_t  mldsa_sig[SC_MLDSA_SIG_LEN];
    bool     has_mldsa_sig;
    sc_crypto_policy_t policy;
} sc_pqc_tcb_decision_t;

/* Post-quantum enhanced collective authorisation.
 * Each peer_mldsa_sigs entry covers the same canonical request payload. */
typedef struct {
    /* Classic authorisation fields */
    sc_authorisation_t classical_auth;

    /* PQC: each peer's ML-DSA-65 public key and signature */
    uint8_t peer_mldsa_pubkeys[SC_TCB_MAX_PEERS][SC_MLDSA_PUBKEY_LEN];
    uint8_t peer_mldsa_sigs[SC_TCB_MAX_PEERS][SC_MLDSA_SIG_LEN];

    sc_crypto_policy_t policy;
} sc_pqc_authorisation_t;

/* ---- Canonical signing payload ---- */

/* Compute the PQC-domain canonical payload for a TCB decision.
 * out must be at least SC_PQC_TCB_SIGN_LEN bytes. */
void pqc_tcb_decision_get_signing_bytes(
        const sc_pqc_tcb_decision_t *dec,
        uint8_t out[SC_PQC_TCB_SIGN_LEN]);

/* ---- Single-peer decision signing/verification ---- */

/* Sign a PQC TCB decision (adds ML-DSA-65 signature).
 * Also signs classically if policy is HYBRID or CLASSICAL_ONLY. */
sc_err_t pqc_tcb_decision_sign(sc_pqc_tcb_decision_t *dec,
                                 const sc_pqc_identity_t *peer_id);

/* Verify a PQC TCB decision.
 * Checks both classical and PQC signatures according to policy.
 * Returns SC_ERR_INVALID if any required signature is missing or invalid. */
sc_err_t pqc_tcb_decision_verify(const sc_pqc_tcb_decision_t *dec);

/* ---- Collective authorisation ---- */

/* Accumulate a verified peer decision into a collective authorisation.
 * Does NOT approve — that happens only when all peers have approved. */
sc_err_t pqc_tcb_auth_add_decision(sc_pqc_authorisation_t *auth,
                                    const sc_pqc_tcb_decision_t *dec,
                                    int peer_index);

/* Returns true if unanimous approval is reached (all_peer_count peers approved). */
bool pqc_tcb_auth_is_unanimous(const sc_pqc_authorisation_t *auth,
                                 uint32_t all_peer_count);

/* Verify ALL peer signatures on a completed authorisation record.
 * This is the final tamper-detection check before executing any action. */
sc_err_t pqc_tcb_auth_verify_all(const sc_pqc_authorisation_t *auth);

/* ---- Security agent PQC identity ---- */

/* Domain separator for security agent signed messages */
#define SC_PQC_AGENT_DOMAIN     "SCAGENT/v1"
#define SC_PQC_AGENT_DOMAIN_LEN 10

/* Sign an action request on behalf of an AI security agent.
 * The agent's identity (ML-DSA-65) authenticates the recommendation.
 * This does NOT grant the agent execution privileges.
 * req_canonical_hash is SHA-256 of the canonical action request bytes. */
sc_err_t pqc_agent_sign_request(const uint8_t req_canonical_hash[SC_SHA256_LEN],
                                  const sc_pqc_identity_t *agent_id,
                                  uint8_t mldsa_sig_out[SC_MLDSA_SIG_LEN]);

/* Verify an agent-signed request.
 * agent_mldsa_pubkey must be a registered agent key known to the TCB peer. */
sc_err_t pqc_agent_verify_request(const uint8_t req_canonical_hash[SC_SHA256_LEN],
                                   const uint8_t agent_mldsa_pubkey[SC_MLDSA_PUBKEY_LEN],
                                   const uint8_t mldsa_sig[SC_MLDSA_SIG_LEN]);

#endif /* SC_PQC_TCB_H */
