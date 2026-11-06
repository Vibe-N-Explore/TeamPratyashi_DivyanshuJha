/* pqc_session.h — Post-Quantum Secure Session Layer for SovereignChain.
 *
 * Feature 2: Post-Quantum Secure Network Communication.
 *
 * Provides an ML-KEM-768 + X25519 hybrid key-establishment handshake that
 * wraps the existing TCP frame layer (net.h / sc_net_t).  After the existing
 * Ed25519 challenge-response handshake authenticates both parties, the PQC
 * session handshake upgrades the channel to AES-256-GCM confidentiality.
 *
 * Session Handshake (runs AFTER the Ed25519 handshake):
 *
 *   Initiator → Responder:
 *     MSG_TYPE_PQC_KEM_INIT  (SC_KEM_INIT_MSG_LEN bytes)
 *
 *   Responder → Initiator:
 *     MSG_TYPE_PQC_KEM_RESP  (SC_PQC_KEM_RESP_LEN bytes)
 *       = mlkem_pubkey (1184 B) || auth_token (32 B)
 *
 *   Initiator → Responder:
 *     MSG_TYPE_PQC_KEM_AUTH  (32 bytes) — initiator auth token
 *
 * Authentication token:
 *   HMAC-SHA256(session_key, "SC_KEM_AUTH" || sender_mldsa_pubkey)
 *   Both peers verify before accepting application messages.
 *
 * Session message encryption:
 *   Each encrypted message is prefixed with:
 *     IV (12 bytes) || TAG (16 bytes) || ciphertext (variable)
 *   The AAD for each message is: session_id (32 bytes) || message_seq (8 BE)
 *   This prevents replay of individual messages within a session.
 *
 * Policy enforcement:
 *   If the connection policy is PQC_REQUIRED, a failed or absent PQC
 *   handshake MUST cause the connection to be dropped.  It MUST NOT fall
 *   back to unencrypted transport.
 *
 * Session limits:
 *   Each session has a maximum lifetime (SC_PQC_SESSION_MAX_LIFETIME_S) and
 *   a maximum message count before mandatory renegotiation.
 */
#ifndef SC_PQC_SESSION_H
#define SC_PQC_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../err.h"
#include "pqc_crypto.h"

/* New message type codes — appended to existing sc_msg_type_t range */
#define MSG_TYPE_PQC_KEM_INIT   20  /* Initiator → Responder: ML-KEM ciphertext + X25519 ephem */
#define MSG_TYPE_PQC_KEM_RESP   21  /* Responder → Initiator: ML-KEM pubkey + auth token */
#define MSG_TYPE_PQC_KEM_AUTH   22  /* Initiator → Responder: auth token */
#define MSG_TYPE_PQC_ENCRYPTED  23  /* Encrypted application payload */

#define SC_PQC_KEM_RESP_LEN     (SC_MLKEM_PUBKEY_LEN + 32)   /* 1184 + 32 = 1216 */
#define SC_PQC_AUTH_TOKEN_LEN   32
#define SC_PQC_SESSION_ID_LEN   32

#define SC_PQC_SESSION_MAX_LIFETIME_S  3600   /* 1 hour max */
#define SC_PQC_SESSION_MAX_MESSAGES    1000000ULL

typedef enum {
    SC_PQC_SESSION_NONE         = 0, /* No PQC session established */
    SC_PQC_SESSION_KEM_SENT     = 1, /* Initiator sent KEM_INIT, waiting for RESP */
    SC_PQC_SESSION_KEM_RESP_SENT = 2, /* Responder sent KEM_RESP, waiting for AUTH */
    SC_PQC_SESSION_ACTIVE       = 3, /* Fully established, messages can be encrypted */
    SC_PQC_SESSION_EXPIRED      = 4  /* Session expired, must renegotiate */
} sc_pqc_session_state_t;

typedef struct {
    sc_pqc_session_state_t state;

    uint8_t  session_id[SC_PQC_SESSION_ID_LEN];
    uint8_t  session_key[SC_KEM_SESSION_LEN];     /* 32-byte AES-256 key */
    uint64_t seq_send;                            /* outbound message counter */
    uint64_t seq_recv;                            /* inbound expected counter */
    int64_t  established_at;                      /* Unix timestamp */

    /* Ephemeral KEM state (kept during handshake, zeroed after) */
    uint8_t  ephem_x25519_sk[32];
    uint8_t  mlkem_ss_buf[SC_MLKEM_SS_LEN];

    /* Our ML-KEM public key (sent to peers) */
    uint8_t  my_mlkem_pubkey[SC_MLKEM_PUBKEY_LEN];

    /* Auth tokens */
    uint8_t  local_auth_token[SC_PQC_AUTH_TOKEN_LEN];
    uint8_t  remote_auth_token[SC_PQC_AUTH_TOKEN_LEN];
    bool     local_auth_sent;
    bool     remote_auth_verified;

    sc_crypto_policy_t policy;
    int      peer_node_id;
} sc_pqc_session_t;

/* ---- Session Initiator side ---- */

/* Build the KEM_INIT message payload (SC_KEM_INIT_MSG_LEN bytes).
 * Saves ephemeral secret state into session for use in derive step.
 * peer_mlkem_pubkey is the responder's static ML-KEM-768 public key. */
sc_err_t pqc_session_initiate(sc_pqc_session_t *sess,
                               const sc_pqc_identity_t *my_identity,
                               const uint8_t peer_mlkem_pubkey[SC_MLKEM_PUBKEY_LEN],
                               uint8_t kem_init_msg_out[SC_KEM_INIT_MSG_LEN]);

/* Process a KEM_RESP message received from the responder.
 * Derives the session key.
 * peer_x25519_pk must be the responder's authenticated static X25519 key. */
sc_err_t pqc_session_process_resp(sc_pqc_session_t *sess,
                                   const sc_pqc_identity_t *my_identity,
                                   const uint8_t kem_resp[SC_PQC_KEM_RESP_LEN],
                                   const uint8_t peer_x25519_pk[32],
                                   uint8_t auth_token_out[SC_PQC_AUTH_TOKEN_LEN]);

/* ---- Session Responder side ---- */

/* Process an incoming KEM_INIT message.
 * Builds and returns the KEM_RESP payload.
 * peer_x25519_pk is the initiator's authenticated static X25519 key. */
sc_err_t pqc_session_respond(sc_pqc_session_t *sess,
                              const sc_pqc_identity_t *my_identity,
                              const uint8_t kem_init_msg[SC_KEM_INIT_MSG_LEN],
                              const uint8_t peer_x25519_pk[32],
                              uint8_t kem_resp_out[SC_PQC_KEM_RESP_LEN],
                              uint8_t auth_token_out[SC_PQC_AUTH_TOKEN_LEN]);

/* Process the final KEM_AUTH message from the initiator.
 * Returns SC_OK if the token is valid, SC_ERR_INVALID otherwise.
 * A failed auth MUST cause connection teardown. */
sc_err_t pqc_session_verify_auth(sc_pqc_session_t *sess,
                                  const uint8_t peer_mldsa_pubkey[SC_MLDSA_PUBKEY_LEN],
                                  const uint8_t auth_token[SC_PQC_AUTH_TOKEN_LEN]);

/* ---- Encryption/Decryption ---- */

/* Encrypted wire frame:
 *   iv (12 B) || tag (16 B) || ciphertext (pt_len B)
 * Total = pt_len + 28 bytes.
 *
 * out_buf must have at least (pt_len + 28) bytes. */
#define SC_PQC_ENC_OVERHEAD  (SC_AES_IV_LEN + SC_AES_TAG_LEN)

sc_err_t pqc_session_encrypt(sc_pqc_session_t *sess,
                               const void *pt, size_t pt_len,
                               uint8_t *out_buf, size_t out_buf_size,
                               size_t *out_len);

sc_err_t pqc_session_decrypt(sc_pqc_session_t *sess,
                               const uint8_t *in_buf, size_t in_len,
                               void *pt_out, size_t pt_buf_size,
                               size_t *pt_len_out);

/* ---- Lifecycle ---- */

/* Check whether the session has expired or hit the message limit. */
bool pqc_session_is_valid(const sc_pqc_session_t *sess);

/* Zero all key material and reset to NONE state. */
void pqc_session_reset(sc_pqc_session_t *sess);

/* Return a human-readable status string */
const char *pqc_session_state_name(sc_pqc_session_state_t s);

#endif /* SC_PQC_SESSION_H */
