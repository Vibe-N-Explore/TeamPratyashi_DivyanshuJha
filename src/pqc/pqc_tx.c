/* pqc_tx.c — Post-Quantum enhanced transaction implementation. */
#define _POSIX_C_SOURCE 200809L
#include "pqc_tx.h"

#include <string.h>
#include <stdio.h>

/* ---- Big-endian helpers ---- */
static void pack_u64_be(uint8_t *dest, uint64_t v) {
    for (int i = 7; i >= 0; i--) { dest[i] = (uint8_t)(v & 0xff); v >>= 8; }
}
static uint64_t unpack_u64_be(const uint8_t *src) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | src[i];
    return v;
}
static void pack_u32_be(uint8_t *dest, uint32_t v) {
    dest[0]=(v>>24)&0xff; dest[1]=(v>>16)&0xff;
    dest[2]=(v>>8)&0xff;  dest[3]=v&0xff;
}
static uint32_t unpack_u32_be(const uint8_t *src) {
    return ((uint32_t)src[0]<<24)|((uint32_t)src[1]<<16)|
           ((uint32_t)src[2]<<8)|(uint32_t)src[3];
}

/* =========================================================================
 * Canonical signing payload
 * ========================================================================= */

void pqc_tx_get_signing_bytes(const sc_pqc_tx_t *tx,
                               uint8_t out[SC_PQC_TX_PAYLOAD_LEN])
{
    uint8_t *p = out;

    /* Domain separator — cannot be confused with classic "TX/v1" */
    memcpy(p, SC_PQC_TX_DOMAIN, SC_PQC_TX_DOMAIN_LEN);
    p += SC_PQC_TX_DOMAIN_LEN;

    /* Crypto policy byte — prevents algorithm substitution attacks */
    *p++ = (uint8_t)tx->crypto_policy;

    /* Sender Ed25519 public key */
    memcpy(p, tx->sender_ed25519_pubkey, SC_ED25519_PUBKEY_LEN);
    p += SC_ED25519_PUBKEY_LEN;

    /* Sender ML-DSA-65 public key */
    memcpy(p, tx->sender_mldsa_pubkey, SC_MLDSA_PUBKEY_LEN);
    p += SC_MLDSA_PUBKEY_LEN;

    /* Recipient public key */
    memcpy(p, tx->recipient_pubkey, SC_ED25519_PUBKEY_LEN);
    p += SC_ED25519_PUBKEY_LEN;

    /* Transaction fields (big-endian) */
    pack_u64_be(p, tx->amount); p += 8;
    pack_u64_be(p, tx->fee);    p += 8;
    pack_u64_be(p, tx->nonce);  p += 8;

    (void)p; /* assert p - out == SC_PQC_TX_PAYLOAD_LEN */
}

/* =========================================================================
 * Create and sign
 * ========================================================================= */

sc_err_t pqc_tx_create(sc_pqc_tx_t *tx,
                        sc_crypto_policy_t policy,
                        const sc_keypair_t  *sender_ed25519_kp,
                        const sc_mldsa_keypair_t *sender_mldsa_kp,
                        const uint8_t recipient[SC_ED25519_PUBKEY_LEN],
                        uint64_t amount, uint64_t fee, uint64_t nonce)
{
    if (!tx || !recipient) return SC_ERR_INVALID;

    memset(tx, 0, sizeof(*tx));
    tx->protocol_version = SC_PQC_TX_VERSION;
    tx->crypto_policy    = policy;
    tx->amount           = amount;
    tx->fee              = fee;
    tx->nonce            = nonce;

    memcpy(tx->recipient_pubkey, recipient, SC_ED25519_PUBKEY_LEN);

    /* Extract sender public keys from keypairs */
    if (sender_ed25519_kp) {
        if (crypto_get_pubkey(sender_ed25519_kp, tx->sender_ed25519_pubkey) != SC_OK)
            return SC_ERR_IO;
    }
    if (sender_mldsa_kp) {
        if (pqc_mldsa_get_pubkey(sender_mldsa_kp, tx->sender_mldsa_pubkey) != SC_OK)
            return SC_ERR_IO;
    }

    /* Compute canonical payload */
    uint8_t payload[SC_PQC_TX_PAYLOAD_LEN];
    pqc_tx_get_signing_bytes(tx, payload);

    /* Sign under policy */
    if (pqc_hybrid_sign(&tx->hybrid_sig, payload, sizeof(payload),
                         policy, sender_ed25519_kp, sender_mldsa_kp) != SC_OK)
        return SC_ERR_IO;

    /* Hash: SHA-256 of canonical payload */
    if (crypto_sha256(payload, sizeof(payload), tx->tx_hash) != SC_OK)
        return SC_ERR_IO;

    return SC_OK;
}

/* =========================================================================
 * Verify
 * ========================================================================= */

sc_err_t pqc_tx_verify(const sc_pqc_tx_t *tx)
{
    if (!tx) return SC_ERR_INVALID;

    /* Reject unrecognised protocol versions */
    if (tx->protocol_version != SC_PQC_TX_VERSION)
        return SC_ERR_INVALID;

    /* Validate policy is a known value (prevents injection of arbitrary byte) */
    if (tx->crypto_policy != SC_CRYPTO_POLICY_CLASSICAL_ONLY &&
        tx->crypto_policy != SC_CRYPTO_POLICY_HYBRID &&
        tx->crypto_policy != SC_CRYPTO_POLICY_PQC_REQUIRED)
        return SC_ERR_INVALID;

    /* Build verifier keypair handles from embedded public keys */
    sc_keypair_t *ed_kp = NULL;
    sc_mldsa_keypair_t *mldsa_kp = NULL;
    sc_err_t rc = SC_ERR_INVALID;

    if (tx->crypto_policy == SC_CRYPTO_POLICY_CLASSICAL_ONLY ||
        tx->crypto_policy == SC_CRYPTO_POLICY_HYBRID) {
        if (crypto_pubkey_from_raw(&ed_kp, tx->sender_ed25519_pubkey) != SC_OK)
            goto cleanup;
    }
    if (tx->crypto_policy == SC_CRYPTO_POLICY_HYBRID ||
        tx->crypto_policy == SC_CRYPTO_POLICY_PQC_REQUIRED) {
        if (pqc_mldsa_pubkey_from_raw(&mldsa_kp, tx->sender_mldsa_pubkey) != SC_OK)
            goto cleanup;
    }

    /* Recompute canonical payload */
    uint8_t payload[SC_PQC_TX_PAYLOAD_LEN];
    pqc_tx_get_signing_bytes(tx, payload);

    rc = pqc_hybrid_verify(&tx->hybrid_sig, payload, sizeof(payload),
                             tx->crypto_policy, ed_kp, mldsa_kp);

cleanup:
    crypto_keypair_free(ed_kp);
    pqc_mldsa_keypair_free(mldsa_kp);
    return rc;
}

sc_err_t pqc_tx_verify_hash(const sc_pqc_tx_t *tx)
{
    if (!tx) return SC_ERR_INVALID;

    uint8_t payload[SC_PQC_TX_PAYLOAD_LEN];
    pqc_tx_get_signing_bytes(tx, payload);

    uint8_t expected[SC_SHA256_LEN];
    if (crypto_sha256(payload, sizeof(payload), expected) != SC_OK)
        return SC_ERR_IO;

    return (memcmp(expected, tx->tx_hash, SC_SHA256_LEN) == 0)
           ? SC_OK : SC_ERR_INVALID;
}

/* =========================================================================
 * Serialise / Deserialise
 * ========================================================================= */

sc_err_t pqc_tx_serialize(const sc_pqc_tx_t *tx,
                           uint8_t *buf, size_t buflen, size_t *written_out)
{
    if (!tx || !buf || buflen < SC_PQC_TX_WIRE_LEN) return SC_ERR_INVALID;

    uint8_t *p = buf;

    memcpy(p, tx->sender_ed25519_pubkey, SC_ED25519_PUBKEY_LEN);
    p += SC_ED25519_PUBKEY_LEN;

    memcpy(p, tx->recipient_pubkey, SC_ED25519_PUBKEY_LEN);
    p += SC_ED25519_PUBKEY_LEN;

    pack_u64_be(p, tx->amount); p += 8;
    pack_u64_be(p, tx->fee);    p += 8;
    pack_u64_be(p, tx->nonce);  p += 8;

    pack_u32_be(p, tx->protocol_version); p += 4;
    *p++ = (uint8_t)tx->crypto_policy;

    memcpy(p, tx->sender_mldsa_pubkey, SC_MLDSA_PUBKEY_LEN);
    p += SC_MLDSA_PUBKEY_LEN;

    pqc_hybrid_sig_encode(&tx->hybrid_sig, p);
    p += SC_HYBRID_SIG_WIRE_LEN;

    memcpy(p, tx->tx_hash, SC_SHA256_LEN);
    p += SC_SHA256_LEN;

    if (written_out) *written_out = (size_t)(p - buf);
    return SC_OK;
}

sc_err_t pqc_tx_deserialize(sc_pqc_tx_t *tx,
                              const uint8_t *buf, size_t buflen)
{
    if (!tx || !buf || buflen < SC_PQC_TX_WIRE_LEN) return SC_ERR_INVALID;

    const uint8_t *p = buf;

    memcpy(tx->sender_ed25519_pubkey, p, SC_ED25519_PUBKEY_LEN);
    p += SC_ED25519_PUBKEY_LEN;

    memcpy(tx->recipient_pubkey, p, SC_ED25519_PUBKEY_LEN);
    p += SC_ED25519_PUBKEY_LEN;

    tx->amount = unpack_u64_be(p); p += 8;
    tx->fee    = unpack_u64_be(p); p += 8;
    tx->nonce  = unpack_u64_be(p); p += 8;

    tx->protocol_version = unpack_u32_be(p); p += 4;
    tx->crypto_policy    = (sc_crypto_policy_t)*p++;

    memcpy(tx->sender_mldsa_pubkey, p, SC_MLDSA_PUBKEY_LEN);
    p += SC_MLDSA_PUBKEY_LEN;

    pqc_hybrid_sig_decode(&tx->hybrid_sig, p);
    p += SC_HYBRID_SIG_WIRE_LEN;

    memcpy(tx->tx_hash, p, SC_SHA256_LEN);

    return SC_OK;
}
