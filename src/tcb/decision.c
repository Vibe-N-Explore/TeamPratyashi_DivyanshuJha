/* decision.c - Signing and verification of TCB decisions.
 */
#define _POSIX_C_SOURCE 200809L

#include "tcb/decision.h"

#include <string.h>

static void pack_u16_be(uint8_t *dest, uint16_t val)
{
    dest[0] = (uint8_t)(val >> 8);
    dest[1] = (uint8_t)(val);
}

static void pack_u32_be(uint8_t *dest, uint32_t val)
{
    dest[0] = (uint8_t)(val >> 24);
    dest[1] = (uint8_t)(val >> 16);
    dest[2] = (uint8_t)(val >> 8);
    dest[3] = (uint8_t)(val);
}

static void pack_u64_be(uint8_t *dest, uint64_t val)
{
    dest[0] = (uint8_t)(val >> 56);
    dest[1] = (uint8_t)(val >> 48);
    dest[2] = (uint8_t)(val >> 40);
    dest[3] = (uint8_t)(val >> 32);
    dest[4] = (uint8_t)(val >> 24);
    dest[5] = (uint8_t)(val >> 16);
    dest[6] = (uint8_t)(val >> 8);
    dest[7] = (uint8_t)(val);
}

void tcb_decision_get_signing_bytes(const sc_tcb_decision_t *dec,
                                   uint8_t out[SC_TCB_DECISION_SIGN_LEN])
{
    size_t off = 0;
    memcpy(out + off, dec->request_id, SC_SHA256_LEN);
    off += SC_SHA256_LEN;

    pack_u32_be(out + off, (uint32_t)dec->tcb_peer_id);
    off += 4;

    memcpy(out + off, dec->tcb_pubkey, SC_ED25519_PUBKEY_LEN);
    off += SC_ED25519_PUBKEY_LEN;

    pack_u64_be(out + off, dec->timestamp);
    off += 8;

    pack_u16_be(out + off, dec->verdict);
    off += 2;

    pack_u16_be(out + off, dec->category);
    off += 2;

    uint8_t reason_hash[SC_SHA256_LEN];
    crypto_sha256(dec->reason, strlen(dec->reason), reason_hash);
    memcpy(out + off, reason_hash, SC_SHA256_LEN);
    off += SC_SHA256_LEN;

    (void)off;
}

sc_err_t tcb_decision_sign(sc_tcb_decision_t *dec, const sc_keypair_t *peer_kp)
{
    if (!dec || !peer_kp)
        return SC_ERR_INVALID;

    if (crypto_get_pubkey(peer_kp, dec->tcb_pubkey) != SC_OK)
        return SC_ERR_INVALID;

    uint8_t sign_bytes[SC_TCB_DECISION_SIGN_LEN];
    tcb_decision_get_signing_bytes(dec, sign_bytes);

    if (crypto_sha256(sign_bytes, sizeof(sign_bytes), dec->decision_hash) != SC_OK)
        return SC_ERR_INVALID;

    return crypto_sign(peer_kp, sign_bytes, sizeof(sign_bytes), dec->signature);
}

sc_err_t tcb_decision_verify(const sc_tcb_decision_t *dec)
{
    if (!dec)
        return SC_ERR_INVALID;

    uint8_t sign_bytes[SC_TCB_DECISION_SIGN_LEN];
    tcb_decision_get_signing_bytes(dec, sign_bytes);

    uint8_t expected_hash[SC_SHA256_LEN];
    if (crypto_sha256(sign_bytes, sizeof(sign_bytes), expected_hash) != SC_OK)
        return SC_ERR_INVALID;

    if (memcmp(expected_hash, dec->decision_hash, SC_SHA256_LEN) != 0)
        return SC_ERR_INVALID;

    sc_keypair_t *pub_handle = NULL;
    sc_err_t rc = crypto_pubkey_from_raw(&pub_handle, dec->tcb_pubkey);
    if (rc != SC_OK)
        return rc;

    rc = crypto_verify(pub_handle, sign_bytes, sizeof(sign_bytes), dec->signature);
    crypto_keypair_free(pub_handle);
    return rc;
}
