/* pqc_session.c — Post-Quantum Secure Session Layer implementation. */
#define _POSIX_C_SOURCE 200809L
#include "pqc_session.h"

#include <string.h>
#include <stdio.h>
#include <time.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <oqs/oqs.h>

/* ---- Internal helpers ---- */

static void pack_u64_be(uint8_t *dest, uint64_t v) {
    for (int i = 7; i >= 0; i--) { dest[i] = (uint8_t)(v & 0xff); v >>= 8; }
}

/* Compute HMAC-SHA256(key, data) → 32-byte token */
static sc_err_t hmac_sha256(const uint8_t key[SC_KEM_SESSION_LEN],
                             const void *data, size_t data_len,
                             uint8_t out[32])
{
    unsigned int len = 32;
    if (!HMAC(EVP_sha256(), key, SC_KEM_SESSION_LEN,
              (const unsigned char *)data, data_len, out, &len))
        return SC_ERR_IO;
    return SC_OK;
}

/* Compute auth token: HMAC-SHA256(session_key, "SC_KEM_AUTH" || mldsa_pubkey) */
static sc_err_t compute_auth_token(const uint8_t session_key[SC_KEM_SESSION_LEN],
                                    const uint8_t mldsa_pubkey[SC_MLDSA_PUBKEY_LEN],
                                    uint8_t token_out[32])
{
    static const char PREFIX[] = "SC_KEM_AUTH";
    uint8_t buf[11 + SC_MLDSA_PUBKEY_LEN];
    memcpy(buf, PREFIX, 11);
    memcpy(buf + 11, mldsa_pubkey, SC_MLDSA_PUBKEY_LEN);
    return hmac_sha256(session_key, buf, sizeof(buf), token_out);
}

/* Generate a random session ID */
static sc_err_t gen_session_id(uint8_t id[SC_PQC_SESSION_ID_LEN])
{
    if (RAND_bytes(id, SC_PQC_SESSION_ID_LEN) != 1)
        return SC_ERR_IO;
    return SC_OK;
}

/* =========================================================================
 * Session names
 * ========================================================================= */

const char *pqc_session_state_name(sc_pqc_session_state_t s)
{
    switch (s) {
    case SC_PQC_SESSION_NONE:          return "NONE";
    case SC_PQC_SESSION_KEM_SENT:      return "KEM_SENT";
    case SC_PQC_SESSION_KEM_RESP_SENT: return "KEM_RESP_SENT";
    case SC_PQC_SESSION_ACTIVE:        return "ACTIVE";
    case SC_PQC_SESSION_EXPIRED:       return "EXPIRED";
    }
    return "UNKNOWN";
}

/* =========================================================================
 * Initiator: Step 1 — send KEM_INIT
 * ========================================================================= */

sc_err_t pqc_session_initiate(sc_pqc_session_t *sess,
                               const sc_pqc_identity_t *my_identity,
                               const uint8_t peer_mlkem_pubkey[SC_MLKEM_PUBKEY_LEN],
                               uint8_t kem_init_msg_out[SC_KEM_INIT_MSG_LEN])
{
    if (!sess || !my_identity || !peer_mlkem_pubkey || !kem_init_msg_out)
        return SC_ERR_INVALID;

    pqc_session_reset(sess);
    sess->policy = my_identity->policy;
    sess->state  = SC_PQC_SESSION_KEM_SENT;

    /* Generate session ID */
    if (gen_session_id(sess->session_id) != SC_OK)
        return SC_ERR_IO;

    /* Store our ML-KEM public key */
    pqc_mlkem_get_pubkey(my_identity->mlkem_kp, sess->my_mlkem_pubkey);

    /* Generate KEM_INIT payload: ML-KEM ciphertext + ephemeral X25519 pubkey
     * Save ephem_x25519_sk and mlkem_ss_buf for later derive step. */
    if (pqc_hybrid_kem_initiate(peer_mlkem_pubkey,
                                  kem_init_msg_out,
                                  sess->ephem_x25519_sk,
                                  sess->mlkem_ss_buf) != SC_OK)
        return SC_ERR_IO;

    return SC_OK;
}

/* =========================================================================
 * Initiator: Step 3 — process KEM_RESP, derive session key
 * ========================================================================= */

sc_err_t pqc_session_process_resp(sc_pqc_session_t *sess,
                                   const sc_pqc_identity_t *my_identity,
                                   const uint8_t kem_resp[SC_PQC_KEM_RESP_LEN],
                                   const uint8_t peer_x25519_pk[32],
                                   uint8_t auth_token_out[SC_PQC_AUTH_TOKEN_LEN])
{
    if (!sess || !my_identity || !kem_resp || !peer_x25519_pk || !auth_token_out)
        return SC_ERR_INVALID;

    if (sess->state != SC_PQC_SESSION_KEM_SENT)
        return SC_ERR_INVALID;

    /* kem_resp = mlkem_pubkey (1184 B) || remote_auth_token (32 B) */
    const uint8_t *remote_mlkem_pk = kem_resp;
    const uint8_t *remote_auth     = kem_resp + SC_MLKEM_PUBKEY_LEN;

    /* Store expected remote auth token for later verification */
    memcpy(sess->remote_auth_token, remote_auth, 32);

    /* Derive session key: X25519(ephem_sk, peer_x25519_pk) + mlkem_ss */
    if (pqc_hybrid_kem_derive_initiator(sess->ephem_x25519_sk,
                                         peer_x25519_pk,
                                         sess->mlkem_ss_buf,
                                         sess->session_key) != SC_OK)
        return SC_ERR_IO;

    /* Wipe ephemeral secret material — no longer needed */
    OQS_MEM_cleanse(sess->ephem_x25519_sk, 32);
    OQS_MEM_cleanse(sess->mlkem_ss_buf, SC_MLKEM_SS_LEN);

    /* Compute our auth token using our ML-DSA public key */
    uint8_t my_mldsa_pk[SC_MLDSA_PUBKEY_LEN];
    pqc_mldsa_get_pubkey(my_identity->mldsa_kp, my_mldsa_pk);
    if (compute_auth_token(sess->session_key, my_mldsa_pk,
                            sess->local_auth_token) != SC_OK)
        return SC_ERR_IO;

    memcpy(auth_token_out, sess->local_auth_token, SC_PQC_AUTH_TOKEN_LEN);
    sess->local_auth_sent = true;
    sess->established_at  = (int64_t)time(NULL);
    sess->state           = SC_PQC_SESSION_ACTIVE;

    (void)remote_mlkem_pk; /* recorded for future reference if needed */
    return SC_OK;
}

/* =========================================================================
 * Responder: Step 2 — process KEM_INIT, build KEM_RESP
 * ========================================================================= */

sc_err_t pqc_session_respond(sc_pqc_session_t *sess,
                              const sc_pqc_identity_t *my_identity,
                              const uint8_t kem_init_msg[SC_KEM_INIT_MSG_LEN],
                              const uint8_t peer_x25519_pk[32],
                              uint8_t kem_resp_out[SC_PQC_KEM_RESP_LEN],
                              uint8_t auth_token_out[SC_PQC_AUTH_TOKEN_LEN])
{
    if (!sess || !my_identity || !kem_init_msg || !peer_x25519_pk ||
        !kem_resp_out || !auth_token_out)
        return SC_ERR_INVALID;

    pqc_session_reset(sess);
    sess->policy = my_identity->policy;

    /* Generate session ID */
    if (gen_session_id(sess->session_id) != SC_OK)
        return SC_ERR_IO;

    /* Store our ML-KEM public key (sent in RESP) */
    pqc_mlkem_get_pubkey(my_identity->mlkem_kp, sess->my_mlkem_pubkey);

    /* Derive session key on responder side */
    if (pqc_hybrid_kem_respond(my_identity->mlkem_kp,
                                 kem_init_msg,
                                 my_identity->x25519_sk,
                                 peer_x25519_pk,
                                 sess->session_key) != SC_OK)
        return SC_ERR_IO;

    /* Compute our auth token */
    uint8_t my_mldsa_pk[SC_MLDSA_PUBKEY_LEN];
    pqc_mldsa_get_pubkey(my_identity->mldsa_kp, my_mldsa_pk);
    if (compute_auth_token(sess->session_key, my_mldsa_pk,
                            sess->local_auth_token) != SC_OK)
        return SC_ERR_IO;

    /* Build KEM_RESP: my ML-KEM pubkey || my auth token */
    memcpy(kem_resp_out,                       sess->my_mlkem_pubkey, SC_MLKEM_PUBKEY_LEN);
    memcpy(kem_resp_out + SC_MLKEM_PUBKEY_LEN, sess->local_auth_token, 32);

    memcpy(auth_token_out, sess->local_auth_token, SC_PQC_AUTH_TOKEN_LEN);

    sess->established_at = (int64_t)time(NULL);
    sess->state          = SC_PQC_SESSION_KEM_RESP_SENT;
    return SC_OK;
}

/* =========================================================================
 * Responder: Verify initiator's auth token
 * ========================================================================= */

sc_err_t pqc_session_verify_auth(sc_pqc_session_t *sess,
                                  const uint8_t peer_mldsa_pubkey[SC_MLDSA_PUBKEY_LEN],
                                  const uint8_t auth_token[SC_PQC_AUTH_TOKEN_LEN])
{
    if (!sess || !peer_mldsa_pubkey || !auth_token)
        return SC_ERR_INVALID;

    if (sess->state != SC_PQC_SESSION_KEM_RESP_SENT &&
        sess->state != SC_PQC_SESSION_ACTIVE)
        return SC_ERR_INVALID;

    /* Recompute expected token for peer's ML-DSA key */
    uint8_t expected[32];
    if (compute_auth_token(sess->session_key, peer_mldsa_pubkey, expected) != SC_OK)
        return SC_ERR_IO;

    /* Constant-time comparison to prevent timing side-channel */
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= (expected[i] ^ auth_token[i]);

    if (diff != 0) return SC_ERR_INVALID; /* Auth failed — must drop connection */

    sess->remote_auth_verified = true;
    sess->state = SC_PQC_SESSION_ACTIVE;
    return SC_OK;
}

/* =========================================================================
 * Encrypt / Decrypt
 * ========================================================================= */

sc_err_t pqc_session_encrypt(sc_pqc_session_t *sess,
                               const void *pt, size_t pt_len,
                               uint8_t *out_buf, size_t out_buf_size,
                               size_t *out_len)
{
    if (!sess || !pt || !out_buf || !out_len) return SC_ERR_INVALID;
    if (sess->state != SC_PQC_SESSION_ACTIVE) return SC_ERR_INVALID;
    if (!pqc_session_is_valid(sess)) {
        sess->state = SC_PQC_SESSION_EXPIRED;
        return SC_ERR_INVALID;
    }

    size_t needed = pt_len + SC_PQC_ENC_OVERHEAD;
    if (out_buf_size < needed) return SC_ERR_INVALID;

    /* Generate fresh random IV for each message */
    uint8_t iv[SC_AES_IV_LEN];
    if (RAND_bytes(iv, SC_AES_IV_LEN) != 1) return SC_ERR_IO;

    /* AAD = session_id || seq_send (big-endian) */
    uint8_t aad[SC_PQC_SESSION_ID_LEN + 8];
    memcpy(aad, sess->session_id, SC_PQC_SESSION_ID_LEN);
    pack_u64_be(aad + SC_PQC_SESSION_ID_LEN, sess->seq_send);

    uint8_t tag[SC_AES_TAG_LEN];
    if (pqc_aead_encrypt(sess->session_key, iv,
                          aad, sizeof(aad),
                          pt, pt_len,
                          out_buf + SC_AES_IV_LEN + SC_AES_TAG_LEN,
                          tag) != SC_OK)
        return SC_ERR_IO;

    memcpy(out_buf,                   iv,  SC_AES_IV_LEN);
    memcpy(out_buf + SC_AES_IV_LEN,   tag, SC_AES_TAG_LEN);

    sess->seq_send++;
    *out_len = needed;
    return SC_OK;
}

sc_err_t pqc_session_decrypt(sc_pqc_session_t *sess,
                               const uint8_t *in_buf, size_t in_len,
                               void *pt_out, size_t pt_buf_size,
                               size_t *pt_len_out)
{
    if (!sess || !in_buf || !pt_out || !pt_len_out) return SC_ERR_INVALID;
    if (sess->state != SC_PQC_SESSION_ACTIVE) return SC_ERR_INVALID;
    if (in_len < SC_PQC_ENC_OVERHEAD) return SC_ERR_INVALID;

    if (!pqc_session_is_valid(sess)) {
        sess->state = SC_PQC_SESSION_EXPIRED;
        return SC_ERR_INVALID;
    }

    size_t pt_len = in_len - SC_PQC_ENC_OVERHEAD;
    if (pt_buf_size < pt_len) return SC_ERR_INVALID;

    const uint8_t *iv  = in_buf;
    const uint8_t *tag = in_buf + SC_AES_IV_LEN;
    const uint8_t *ct  = in_buf + SC_AES_IV_LEN + SC_AES_TAG_LEN;

    /* Reconstruct AAD using expected recv sequence number */
    uint8_t aad[SC_PQC_SESSION_ID_LEN + 8];
    memcpy(aad, sess->session_id, SC_PQC_SESSION_ID_LEN);
    pack_u64_be(aad + SC_PQC_SESSION_ID_LEN, sess->seq_recv);

    if (pqc_aead_decrypt(sess->session_key, iv,
                          aad, sizeof(aad),
                          ct, pt_len, tag,
                          pt_out) != SC_OK)
        return SC_ERR_INVALID; /* Replay, tampering, or wrong session */

    sess->seq_recv++;
    *pt_len_out = pt_len;
    return SC_OK;
}

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

bool pqc_session_is_valid(const sc_pqc_session_t *sess)
{
    if (!sess || sess->state != SC_PQC_SESSION_ACTIVE) return false;

    int64_t now = (int64_t)time(NULL);
    if (now - sess->established_at > SC_PQC_SESSION_MAX_LIFETIME_S) return false;
    if (sess->seq_send >= SC_PQC_SESSION_MAX_MESSAGES) return false;
    return true;
}

void pqc_session_reset(sc_pqc_session_t *sess)
{
    if (!sess) return;
    OQS_MEM_cleanse(sess->session_key, sizeof(sess->session_key));
    OQS_MEM_cleanse(sess->ephem_x25519_sk, sizeof(sess->ephem_x25519_sk));
    OQS_MEM_cleanse(sess->mlkem_ss_buf, sizeof(sess->mlkem_ss_buf));
    memset(sess, 0, sizeof(*sess));
}
