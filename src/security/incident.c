/* incident.c - Action request signing, serialization, and verification.
 *
 * Part 3: Deterministic signature checking for AI Agent requests.
 */
#define _POSIX_C_SOURCE 200809L

#include "security/incident.h"

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

void action_request_get_signing_bytes(const sc_action_request_t *req,
                                     uint8_t out[SC_ACTION_REQ_SIGN_LEN])
{
    size_t off = 0;
    memcpy(out + off, req->agent_pubkey, SC_ED25519_PUBKEY_LEN);
    off += SC_ED25519_PUBKEY_LEN;

    pack_u64_be(out + off, req->timestamp);
    off += 8;

    pack_u16_be(out + off, req->incident_type);
    off += 2;

    pack_u16_be(out + off, req->proposed_action);
    off += 2;

    pack_u16_be(out + off, req->category);
    off += 2;

    pack_u32_be(out + off, (uint32_t)req->target_node_id);
    off += 4;

    pack_u32_be(out + off, req->param_duration_sec);
    off += 4;

    pack_u32_be(out + off, req->param_rate_limit);
    off += 4;

    memcpy(out + off, req->evidence_hash, SC_SHA256_LEN);
    off += SC_SHA256_LEN;

    /* Compute reason digest so reason is bound to signature */
    uint8_t reason_hash[SC_SHA256_LEN];
    crypto_sha256(req->reason, strlen(req->reason), reason_hash);
    memcpy(out + off, reason_hash, SC_SHA256_LEN);
    off += SC_SHA256_LEN;

    (void)off;
}

sc_err_t action_request_sign(sc_action_request_t *req,
                             const sc_keypair_t *agent_kp)
{
    if (!req || !agent_kp)
        return SC_ERR_INVALID;

    if (crypto_get_pubkey(agent_kp, req->agent_pubkey) != SC_OK)
        return SC_ERR_INVALID;

    /* Compute evidence hash if not already computed */
    crypto_sha256(req->evidence, req->evidence_len, req->evidence_hash);

    uint8_t sign_bytes[SC_ACTION_REQ_SIGN_LEN];
    action_request_get_signing_bytes(req, sign_bytes);

    /* Request ID is the SHA-256 of the signing bytes */
    if (crypto_sha256(sign_bytes, sizeof(sign_bytes), req->request_id) != SC_OK)
        return SC_ERR_INVALID;

    /* Sign canonical bytes */
    return crypto_sign(agent_kp, sign_bytes, sizeof(sign_bytes), req->signature);
}

sc_err_t action_request_verify(const sc_action_request_t *req)
{
    if (!req)
        return SC_ERR_INVALID;

    /* Verify evidence hash matches evidence bytes */
    uint8_t ev_hash[SC_SHA256_LEN];
    if (crypto_sha256(req->evidence, req->evidence_len, ev_hash) != SC_OK)
        return SC_ERR_INVALID;

    if (memcmp(ev_hash, req->evidence_hash, SC_SHA256_LEN) != 0)
        return SC_ERR_INVALID;

    /* Verify request ID matches SHA-256 of signing bytes */
    uint8_t sign_bytes[SC_ACTION_REQ_SIGN_LEN];
    action_request_get_signing_bytes(req, sign_bytes);

    uint8_t req_id[SC_SHA256_LEN];
    if (crypto_sha256(sign_bytes, sizeof(sign_bytes), req_id) != SC_OK)
        return SC_ERR_INVALID;

    if (memcmp(req_id, req->request_id, SC_SHA256_LEN) != 0)
        return SC_ERR_INVALID;

    /* Verify Ed25519 signature */
    sc_keypair_t *pub_handle = NULL;
    sc_err_t rc = crypto_pubkey_from_raw(&pub_handle, req->agent_pubkey);
    if (rc != SC_OK)
        return rc;

    rc = crypto_verify(pub_handle, sign_bytes, sizeof(sign_bytes), req->signature);
    crypto_keypair_free(pub_handle);
    return rc;
}
