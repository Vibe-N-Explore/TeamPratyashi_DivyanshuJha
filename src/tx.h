/* tx.h - Transaction structure, serialization, signing, and verification.
 *
 * Security improvements:
 *
 * CHAIN ID IN SIGNING PAYLOAD (Security Item 1 — Replay Protection):
 *   The signing payload now includes a network/chain identifier so that a valid
 *   transaction signature on one SovereignChain network cannot be replayed on
 *   a different network (e.g., mainnet vs testnet).
 *
 * Canonical Signing Format ("TX/v1/<chain_id>"):
 *   "TX/v1/"         (6 bytes, domain separator)
 *   chain_id         (4 bytes, big-endian uint32)
 *   sender pubkey    (32 bytes)
 *   recipient pubkey (32 bytes)
 *   amount           (8 bytes, big-endian)
 *   fee              (8 bytes, big-endian)
 *   nonce            (8 bytes, big-endian)
 *   Total = 98 bytes
 *
 * Wire format is unchanged (152 bytes) so this is a signing-layer-only change.
 *
 * Transactions represent transfer of tokens between accounts:
 *   - sender:    32-byte Ed25519 public key
 *   - recipient: 32-byte Ed25519 public key
 *   - amount:    uint64_t in base token units
 *   - fee:       uint64_t transaction fee
 *   - nonce:     uint64_t sender account sequence number (anti-replay)
 *   - signature: 64-byte Ed25519 signature over canonical payload
 *   - tx_hash:   32-byte SHA-256 of canonical payload
 *   - chain_id:  uint32_t network identifier (0 = devnet/unset, 1 = testnet, 2 = mainnet)
 */
#ifndef SC_TX_H
#define SC_TX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "err.h"

/* Default chain ID for the development network.
 * Production deployments must set this to a unique value per network. */
#define SC_CHAIN_ID_DEVNET   0U
#define SC_CHAIN_ID_TESTNET  1U
#define SC_CHAIN_ID_MAINNET  2U

/* Build-time chain ID. Override with -DSC_CHAIN_ID=N if needed. */
#ifndef SC_CHAIN_ID
#  define SC_CHAIN_ID SC_CHAIN_ID_DEVNET
#endif

#define SC_TX_DOMAIN_LEN  6                /* "TX/v1/" */
#define SC_TX_PAYLOAD_LEN (SC_TX_DOMAIN_LEN + 4 + 32 + 32 + 8 + 8 + 8) /* 98 bytes */
#define SC_TX_WIRE_LEN    (32 + 32 + 8 + 8 + 8 + 64) /* 152 bytes: no chain_id on wire */

typedef struct {
    uint8_t  sender[SC_ED25519_PUBKEY_LEN];
    uint8_t  recipient[SC_ED25519_PUBKEY_LEN];
    uint64_t amount;
    uint64_t fee;
    uint64_t nonce;
    uint32_t chain_id;                     /* network identifier included in signing */
    uint8_t  sig[SC_ED25519_SIG_LEN];
    uint8_t  hash[SC_SHA256_LEN];
} sc_tx_t;

/* Create, sign, and hash a new transaction using sender_kp.
 * Uses the compile-time SC_CHAIN_ID for the signing payload. */
sc_err_t tx_create(sc_tx_t *tx, const sc_keypair_t *sender_kp,
                   const uint8_t recipient[SC_ED25519_PUBKEY_LEN],
                   uint64_t amount, uint64_t fee, uint64_t nonce);

/* Compute canonical signing payload (98 bytes including chain_id) */
void tx_get_signing_bytes(const sc_tx_t *tx, uint8_t out[SC_TX_PAYLOAD_LEN]);

/* Verify the Ed25519 signature on an untrusted transaction.
 * Uses tx->chain_id from the struct for verification. */
sc_err_t tx_verify_sig(const sc_tx_t *tx);

/* Compute transaction hash (SHA-256 of canonical signing bytes) */
sc_err_t tx_compute_hash(const sc_tx_t *tx, uint8_t hash_out[SC_SHA256_LEN]);

/* Serialize transaction to binary wire format (152 bytes).
 * chain_id is NOT included on the wire — it is a signing-layer concept
 * that both sides must agree on out of band (via network.conf or build flag). */
sc_err_t tx_serialize(const sc_tx_t *tx, uint8_t *buf, size_t buflen,
                      size_t *written_out);

/* Deserialize transaction from binary wire format.
 * Sets chain_id to SC_CHAIN_ID (the local compile-time constant) so that
 * verify_sig will check the signature against the expected chain. */
sc_err_t tx_deserialize(sc_tx_t *tx, const uint8_t *buf, size_t buflen);

#endif /* SC_TX_H */
