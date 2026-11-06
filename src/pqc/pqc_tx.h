/* pqc_tx.h — Post-Quantum enhanced transaction signatures for SovereignChain.
 *
 * Extends the existing sc_tx_t with:
 *   - ML-DSA-65 signatures (via sc_hybrid_sig_t)
 *   - Hybrid signature policy enforcement
 *   - Backward-compatible canonical encoding
 *   - Algorithm identifier anti-manipulation protection
 *
 * Wire layout upgrade (sc_pqc_tx_t):
 *   Classic tx fields (unchanged):
 *     sender_ed25519_pubkey  32 B
 *     recipient_pubkey       32 B
 *     amount                  8 B
 *     fee                     8 B
 *     nonce                   8 B
 *   PQC extension:
 *     protocol_version        4 B  big-endian (SC_PQC_TX_VERSION)
 *     crypto_policy           1 B  (sc_crypto_policy_t value)
 *     sender_mldsa_pubkey  1952 B
 *     hybrid_sig           3374 B  (pqc_hybrid_sig_encode output)
 *     tx_hash                32 B  (SHA-256 of canonical signing bytes)
 *
 * Total PQC wire length: 32+32+8+8+8 + 4+1+1952+3374+32 = 5451 bytes
 *
 * The canonical SIGNING payload is:
 *   "SCPQCTX/v1" (10 bytes) — domain separator, cannot be confused with
 *                             the classic "TX/v1" domain separator
 *   crypto_policy  (1 byte)
 *   sender_ed25519_pubkey (32 bytes)
 *   sender_mldsa_pubkey  (1952 bytes)
 *   recipient_pubkey (32 bytes)
 *   amount   (8 bytes, big-endian)
 *   fee      (8 bytes, big-endian)
 *   nonce    (8 bytes, big-endian)
 *
 * Both signatures in a HYBRID or PQC_REQUIRED transaction sign this same
 * canonical payload.  Callers MUST NOT modify fields between computing the
 * payload and signing/verifying.
 */
#ifndef SC_PQC_TX_H
#define SC_PQC_TX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../crypto.h"
#include "../err.h"
#include "../tx.h"
#include "pqc_crypto.h"

#define SC_PQC_TX_VERSION        1   /* incremented for future format changes */
#define SC_PQC_TX_DOMAIN         "SCPQCTX/v1"
#define SC_PQC_TX_DOMAIN_LEN     10

/* Canonical payload length (bytes signed by both algorithms) */
#define SC_PQC_TX_PAYLOAD_LEN \
    (SC_PQC_TX_DOMAIN_LEN + 1 + SC_ED25519_PUBKEY_LEN + SC_MLDSA_PUBKEY_LEN + \
     SC_ED25519_PUBKEY_LEN + 8 + 8 + 8)
/* = 10+1+32+1952+32+8+8+8 = 2051 bytes */

/* Total PQC wire frame size */
#define SC_PQC_TX_WIRE_LEN \
    (SC_ED25519_PUBKEY_LEN + SC_ED25519_PUBKEY_LEN + 8 + 8 + 8 + \
     4 + 1 + SC_MLDSA_PUBKEY_LEN + SC_HYBRID_SIG_WIRE_LEN + SC_SHA256_LEN)

typedef struct {
    /* Classic fields — kept for interoperability */
    uint8_t  sender_ed25519_pubkey[SC_ED25519_PUBKEY_LEN];
    uint8_t  recipient_pubkey[SC_ED25519_PUBKEY_LEN];
    uint64_t amount;
    uint64_t fee;
    uint64_t nonce;

    /* PQC extension */
    uint32_t            protocol_version;    /* SC_PQC_TX_VERSION */
    sc_crypto_policy_t  crypto_policy;
    uint8_t             sender_mldsa_pubkey[SC_MLDSA_PUBKEY_LEN];
    sc_hybrid_sig_t     hybrid_sig;
    uint8_t             tx_hash[SC_SHA256_LEN];
} sc_pqc_tx_t;

/* Compute the canonical signing payload.
 * out must be at least SC_PQC_TX_PAYLOAD_LEN bytes. */
void pqc_tx_get_signing_bytes(const sc_pqc_tx_t *tx,
                               uint8_t out[SC_PQC_TX_PAYLOAD_LEN]);

/* Create, sign, and hash a PQC transaction.
 * Either ed25519_kp or mldsa_kp may be NULL when the policy does not require
 * that algorithm, but passing NULL for a required key returns SC_ERR_INVALID. */
sc_err_t pqc_tx_create(sc_pqc_tx_t *tx,
                        sc_crypto_policy_t policy,
                        const sc_keypair_t  *sender_ed25519_kp,
                        const sc_mldsa_keypair_t *sender_mldsa_kp,
                        const uint8_t recipient[SC_ED25519_PUBKEY_LEN],
                        uint64_t amount, uint64_t fee, uint64_t nonce);

/* Verify the hybrid signature on an untrusted transaction.
 * Enforces the crypto_policy embedded in the transaction.
 * Returns SC_ERR_INVALID if the embedded policy is unrecognised. */
sc_err_t pqc_tx_verify(const sc_pqc_tx_t *tx);

/* Recompute the transaction hash and compare with stored hash. */
sc_err_t pqc_tx_verify_hash(const sc_pqc_tx_t *tx);

/* Serialize to wire format (SC_PQC_TX_WIRE_LEN bytes). */
sc_err_t pqc_tx_serialize(const sc_pqc_tx_t *tx,
                           uint8_t *buf, size_t buflen, size_t *written_out);

/* Deserialize from wire format. */
sc_err_t pqc_tx_deserialize(sc_pqc_tx_t *tx,
                              const uint8_t *buf, size_t buflen);

#endif /* SC_PQC_TX_H */
