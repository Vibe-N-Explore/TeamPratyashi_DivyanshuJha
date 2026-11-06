/* pqc_crypto.h — Post-Quantum Cryptographic Foundation for SovereignChain.
 *
 * NIST FIPS 203: ML-KEM-768  (key encapsulation mechanism)
 * NIST FIPS 204: ML-DSA-65   (digital signature algorithm)
 *
 * Implementation strategy:
 *   We use liboqs (Open Quantum Safe) which is maintained by the OQS project
 *   and implements NIST-standardised PQC algorithms.  Where liboqs is
 *   unavailable we fall back to a compile-time error so callers cannot
 *   silently operate without the PQC layer.
 *
 * Algorithm parameters (ML-DSA-65 / CRYSTALS-Dilithium level 3):
 *   Public key:  1952 bytes
 *   Secret key:  4000 bytes
 *   Signature:   3309 bytes
 *
 * Algorithm parameters (ML-KEM-768 / CRYSTALS-Kyber level 3):
 *   Public key:  1184 bytes
 *   Secret key:  2400 bytes
 *   Ciphertext:  1088 bytes
 *   Shared secret: 32 bytes
 *
 * Cryptographic policy:
 *   CLASSICAL_ONLY  — Ed25519 signatures only  (migration phase)
 *   HYBRID          — Both Ed25519 AND ML-DSA-65 must verify
 *   PQC_REQUIRED    — ML-DSA-65 only (fully migrated nodes)
 *
 * Key management:
 *   Private keys are stored in PEM-like binary files with 0600 permissions.
 *   They are NEVER logged or exposed through any HTTP API.
 *   Key identifiers are SHA-256(algorithm_id || public_key_bytes).
 *
 * Protocol version carried in every signed message preamble:
 *   "PQC/v1" (6 bytes) — identifies this PQC wire protocol version.
 *   Future versions increment the number.
 *
 * SECURITY NOTE:
 *   We use HKDF-SHA256 (RFC 5869) to derive session keys from ML-KEM shared
 *   secrets.  Authenticated encryption uses AES-256-GCM (via OpenSSL EVP).
 *   For hybrid key establishment we XOR-then-hash the ML-KEM and X25519 shared
 *   secrets through HKDF to produce the final session key.  This is equivalent
 *   to the NIST SP 800-227 ipd "Hybrid KEM" combiner recommendation.
 */
#ifndef SC_PQC_CRYPTO_H
#define SC_PQC_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../err.h"
#include "../crypto.h"   /* sc_keypair_t, SC_ED25519_*, crypto_hex_encode */

/* =========================================================================
 * 1.  Constants
 * ========================================================================= */

/* ML-DSA-65 (CRYSTALS-Dilithium level 3) */
#define SC_MLDSA_PUBKEY_LEN    1952
#define SC_MLDSA_SECKEY_LEN    4000
#define SC_MLDSA_SIG_LEN       3309

/* ML-KEM-768 (CRYSTALS-Kyber level 3) */
#define SC_MLKEM_PUBKEY_LEN    1184
#define SC_MLKEM_SECKEY_LEN    2400
#define SC_MLKEM_CT_LEN        1088
#define SC_MLKEM_SS_LEN        32   /* shared secret */

/* AES-256-GCM parameters */
#define SC_AES_KEY_LEN         32   /* 256-bit session key */
#define SC_AES_IV_LEN          12   /* 96-bit GCM nonce */
#define SC_AES_TAG_LEN         16   /* 128-bit authentication tag */

/* Key identifier: SHA-256(algorithm_id || pubkey_bytes) */
#define SC_KEY_ID_LEN          32

/* Protocol version preamble embedded in every signed payload */
#define SC_PQC_VERSION_BYTES   6
#define SC_PQC_VERSION_STR     "PQC/v1"

/* Maximum hex-encoded lengths for display */
#define SC_MLDSA_PUBKEY_HEX_LEN  (SC_MLDSA_PUBKEY_LEN * 2)
#define SC_MLKEM_PUBKEY_HEX_LEN  (SC_MLKEM_PUBKEY_LEN * 2)

/* =========================================================================
 * 2.  Cryptographic policy enumeration
 * ========================================================================= */

typedef enum {
    /* Classical Ed25519 only. PQC layer is inactive.
     * MUST NOT be described as post-quantum protected. */
    SC_CRYPTO_POLICY_CLASSICAL_ONLY  = 0,

    /* Both Ed25519 AND ML-DSA-65 signatures must be present and valid.
     * Both must refer to the identical canonical message.
     * A missing or invalid signature causes rejection. */
    SC_CRYPTO_POLICY_HYBRID          = 1,

    /* ML-DSA-65 only. Ed25519 key material is not consulted.
     * Nodes that have not migrated cannot participate. */
    SC_CRYPTO_POLICY_PQC_REQUIRED    = 2
} sc_crypto_policy_t;

/* Human-readable policy name */
const char *pqc_policy_name(sc_crypto_policy_t p);

/* =========================================================================
 * 3.  ML-DSA-65 key type (opaque)
 * ========================================================================= */

typedef struct sc_mldsa_keypair sc_mldsa_keypair_t;

/* Generate a fresh ML-DSA-65 keypair using the system CSPRNG.
 * Caller must call pqc_mldsa_keypair_free() when done. */
sc_err_t pqc_mldsa_keygen(sc_mldsa_keypair_t **kp_out);

/* Save secret key to path (binary, mode 0600).
 * Format: "MLDSA65SK\n" (10 bytes) || raw secret key bytes.
 * Public key is derived on load; it is NOT stored separately here
 * (derive with pqc_mldsa_get_pubkey after loading). */
sc_err_t pqc_mldsa_save_seckey(const sc_mldsa_keypair_t *kp, const char *path);

/* Load secret key from path.  Derives the public key automatically. */
sc_err_t pqc_mldsa_load_seckey(sc_mldsa_keypair_t **kp_out, const char *path,
                                 char *errbuf, size_t errlen);

/* Build a verify-only handle from raw public key bytes.
 * Cannot be used for signing. */
sc_err_t pqc_mldsa_pubkey_from_raw(sc_mldsa_keypair_t **kp_out,
                                    const uint8_t pubkey[SC_MLDSA_PUBKEY_LEN]);

/* Extract raw public key bytes (works for both full and pubkey-only handles). */
sc_err_t pqc_mldsa_get_pubkey(const sc_mldsa_keypair_t *kp,
                                uint8_t out[SC_MLDSA_PUBKEY_LEN]);

/* Returns true if the handle contains a private key (can sign). */
bool pqc_mldsa_has_private(const sc_mldsa_keypair_t *kp);

/* Sign msg (of msg_len bytes).
 * sig_out must point to SC_MLDSA_SIG_LEN bytes of writable storage.
 * Returns SC_ERR_INVALID if the handle lacks a private key. */
sc_err_t pqc_mldsa_sign(const sc_mldsa_keypair_t *kp,
                          const void *msg, size_t msg_len,
                          uint8_t sig_out[SC_MLDSA_SIG_LEN]);

/* Verify signature.
 * Returns SC_OK on success, SC_ERR_INVALID on bad signature. */
sc_err_t pqc_mldsa_verify(const sc_mldsa_keypair_t *kp,
                            const void *msg, size_t msg_len,
                            const uint8_t sig[SC_MLDSA_SIG_LEN]);

/* Compute key identifier: SHA-256("MLDSA65" || public_key). */
sc_err_t pqc_mldsa_key_id(const sc_mldsa_keypair_t *kp,
                            uint8_t id_out[SC_KEY_ID_LEN]);

/* Free keypair.  NULL-safe. */
void pqc_mldsa_keypair_free(sc_mldsa_keypair_t *kp);

/* =========================================================================
 * 4.  ML-KEM-768 key type (opaque)
 * ========================================================================= */

typedef struct sc_mlkem_keypair sc_mlkem_keypair_t;

/* Generate a fresh ML-KEM-768 keypair using the system CSPRNG. */
sc_err_t pqc_mlkem_keygen(sc_mlkem_keypair_t **kp_out);

/* Save and load ML-KEM-768 key pair (private/public) */
sc_err_t pqc_mlkem_save_seckey(const sc_mlkem_keypair_t *kp, const char *path);
sc_err_t pqc_mlkem_load_seckey(sc_mlkem_keypair_t **kp_out, const char *path,
                                 char *errbuf, size_t errlen);

/* Build encapsulation-only handle from raw public key bytes.
 * Cannot decapsulate. */
sc_err_t pqc_mlkem_pubkey_from_raw(sc_mlkem_keypair_t **kp_out,
                                    const uint8_t pubkey[SC_MLKEM_PUBKEY_LEN]);

/* Extract raw public key (works for both encap-only and full handles). */
sc_err_t pqc_mlkem_get_pubkey(const sc_mlkem_keypair_t *kp,
                                uint8_t out[SC_MLKEM_PUBKEY_LEN]);

/* Encapsulate: given the recipient's public key, produce a ciphertext and
 * a shared secret known only to this caller (until decapsulated).
 * Both ct_out and ss_out must be caller-allocated. */
sc_err_t pqc_mlkem_encapsulate(const sc_mlkem_keypair_t *recipient_pk,
                                 uint8_t ct_out[SC_MLKEM_CT_LEN],
                                 uint8_t ss_out[SC_MLKEM_SS_LEN]);

/* Decapsulate: given our private key and an incoming ciphertext, recover
 * the shared secret. */
sc_err_t pqc_mlkem_decapsulate(const sc_mlkem_keypair_t *kp,
                                 const uint8_t ct[SC_MLKEM_CT_LEN],
                                 uint8_t ss_out[SC_MLKEM_SS_LEN]);

/* Free keypair.  NULL-safe. */
void pqc_mlkem_keypair_free(sc_mlkem_keypair_t *kp);

/* =========================================================================
 * 5.  Hybrid signature structures
 * ========================================================================= */

/*
 * sc_hybrid_sig_t — carries both an Ed25519 and an ML-DSA-65 signature
 * over the SAME canonical message.
 *
 * Wire layout (fixed-size, big-endian where applicable):
 *   has_ed25519 (1 byte, bool)
 *   has_mldsa   (1 byte, bool)
 *   ed25519_sig (SC_ED25519_SIG_LEN bytes = 64 bytes, zero-filled if absent)
 *   mldsa_sig   (SC_MLDSA_SIG_LEN bytes  = 3309 bytes, zero-filled if absent)
 *   Total       = 3374 bytes
 *
 * Verification semantics are controlled by sc_crypto_policy_t:
 *   CLASSICAL_ONLY : only Ed25519 is verified; mldsa field is ignored.
 *   HYBRID         : BOTH signatures must be present AND valid.
 *   PQC_REQUIRED   : only ML-DSA-65 is verified; ed25519 field is ignored.
 *
 * A HYBRID policy node MUST REJECT a message that carries only one signature.
 */
#define SC_HYBRID_SIG_WIRE_LEN  (1 + 1 + SC_ED25519_SIG_LEN + SC_MLDSA_SIG_LEN)

typedef struct {
    bool    has_ed25519;
    bool    has_mldsa;
    uint8_t ed25519_sig[SC_ED25519_SIG_LEN];
    uint8_t mldsa_sig[SC_MLDSA_SIG_LEN];
} sc_hybrid_sig_t;

/* =========================================================================
 * 6.  Hybrid signing/verification API
 * ========================================================================= */

/*
 * Sign the canonical message under the given policy.
 *
 * CLASSICAL_ONLY: fills only ed25519_sig; mldsa fields are zeroed.
 * HYBRID        : fills both signature fields.
 * PQC_REQUIRED  : fills only mldsa_sig; ed25519 fields are zeroed.
 *
 * Either ed25519_kp or mldsa_kp may be NULL when not needed by policy.
 * Returns SC_ERR_INVALID if a required key is missing.
 */
sc_err_t pqc_hybrid_sign(sc_hybrid_sig_t *sig_out,
                          const void *msg, size_t msg_len,
                          sc_crypto_policy_t policy,
                          const sc_keypair_t  *ed25519_kp,  /* may be NULL */
                          const sc_mldsa_keypair_t *mldsa_kp); /* may be NULL */

/*
 * Verify a hybrid signature against the canonical message under the
 * given policy.
 *
 * Returns SC_OK only when ALL required signatures verify.
 * Returns SC_ERR_INVALID on any missing or invalid signature.
 * Never silently falls back to a weaker policy.
 */
sc_err_t pqc_hybrid_verify(const sc_hybrid_sig_t *sig,
                             const void *msg, size_t msg_len,
                             sc_crypto_policy_t policy,
                             const sc_keypair_t  *ed25519_kp,  /* may be NULL */
                             const sc_mldsa_keypair_t *mldsa_kp); /* may be NULL */

/* Serialise sc_hybrid_sig_t to SC_HYBRID_SIG_WIRE_LEN bytes.
 * buf must be at least SC_HYBRID_SIG_WIRE_LEN bytes. */
void pqc_hybrid_sig_encode(const sc_hybrid_sig_t *sig, uint8_t *buf);

/* Deserialise from buf (exactly SC_HYBRID_SIG_WIRE_LEN bytes). */
void pqc_hybrid_sig_decode(sc_hybrid_sig_t *sig_out, const uint8_t *buf);

/* =========================================================================
 * 7.  Hybrid key-establishment (ML-KEM-768 + X25519) → AES-256-GCM session
 * ========================================================================= */

/*
 * Handshake overview (initiator → responder):
 *
 *   Step 1  Initiator calls pqc_hybrid_kem_initiate():
 *           - Generates an ephemeral X25519 keypair.
 *           - Encapsulates against responder's ML-KEM-768 public key.
 *           - Sends: kem_ciphertext (1088 B) || x25519_ephemeral_pubkey (32 B)
 *           - Keeps: x25519_secret, mlkem_shared_secret
 *
 *   Step 2  Responder calls pqc_hybrid_kem_respond():
 *           - Decapsulates ML-KEM ciphertext using its private key.
 *           - Performs X25519(own_sk, initiator_ephem_pk).
 *           - Calls pqc_hybrid_kem_derive_session() on both shared secrets.
 *
 *   Step 3  Initiator calls pqc_hybrid_kem_derive_session():
 *           - X25519(ephem_sk, responder_static_x25519_pk).
 *           - Calls pqc_hybrid_kem_derive_session() on both shared secrets.
 *
 *   Both sides now hold the same 32-byte session key.
 *
 * Handshake wire message sizes:
 *   KEM_INIT  (initiator→responder): SC_KEM_INIT_MSG_LEN bytes
 *   KEM_RESP  (responder→initiator): SC_KEM_RESP_MSG_LEN bytes  (empty — see note)
 *
 * Authentication:
 *   After key derivation each party produces an auth token using
 *   HMAC-SHA256(session_key, "SC_KEM_AUTH" || their_identity_pubkey).
 *   The peer verifies the token before accepting any application messages.
 *   This prevents a MITM from substituting keys.
 *
 * NOTE on X25519:
 *   We use OpenSSL's EVP_PKEY interface for X25519.  OpenSSL calls
 *   X25519 "EVP_PKEY_X25519".  It supports only key agreement, not
 *   signing.  We therefore keep Ed25519 (signing) and X25519 (Diffie-
 *   Hellman) as distinct key types.
 */

#define SC_KEM_INIT_MSG_LEN  (SC_MLKEM_CT_LEN + 32)  /* ct + ephem X25519 pk */
#define SC_KEM_SESSION_LEN   SC_AES_KEY_LEN           /* 32-byte AES-256 key  */

/*
 * Initiate hybrid KEM.
 *
 * recipient_mlkem_pk : responder's ML-KEM-768 public key
 * kem_msg_out        : SC_KEM_INIT_MSG_LEN bytes to send to responder
 * ephem_sk_out       : caller keeps this 32-byte ephemeral secret for step 3
 * mlkem_ss_out       : caller keeps this 32-byte ML-KEM shared secret for step 3
 */
sc_err_t pqc_hybrid_kem_initiate(
        const uint8_t recipient_mlkem_pk[SC_MLKEM_PUBKEY_LEN],
        uint8_t  kem_msg_out[SC_KEM_INIT_MSG_LEN],
        uint8_t  ephem_x25519_sk_out[32],
        uint8_t  mlkem_ss_out[SC_MLKEM_SS_LEN]);

/*
 * Respond to a KEM_INIT message.
 *
 * my_mlkem_kp        : responder's full ML-KEM-768 keypair
 * kem_msg_in         : SC_KEM_INIT_MSG_LEN bytes received from initiator
 * peer_identity_pk   : initiator's X25519 static public key (authenticated
 *                      out of band by the existing Ed25519 handshake)
 * session_key_out    : 32-byte derived session key
 */
sc_err_t pqc_hybrid_kem_respond(
        const sc_mlkem_keypair_t *my_mlkem_kp,
        const uint8_t kem_msg_in[SC_KEM_INIT_MSG_LEN],
        const uint8_t my_x25519_sk[32],
        const uint8_t peer_x25519_pk[32],
        uint8_t session_key_out[SC_KEM_SESSION_LEN]);

/*
 * Initiator derives the same session key after receiving the responder's
 * static X25519 public key (which is part of the authenticated identity).
 *
 * ephem_x25519_sk    : ephemeral secret generated in pqc_hybrid_kem_initiate
 * peer_x25519_pk     : responder's X25519 static public key
 * mlkem_ss           : the ML-KEM shared secret from pqc_hybrid_kem_initiate
 * session_key_out    : 32-byte derived session key
 */
sc_err_t pqc_hybrid_kem_derive_initiator(
        const uint8_t ephem_x25519_sk[32],
        const uint8_t peer_x25519_pk[32],
        const uint8_t mlkem_ss[SC_MLKEM_SS_LEN],
        uint8_t session_key_out[SC_KEM_SESSION_LEN]);

/* =========================================================================
 * 8.  Authenticated encryption (AES-256-GCM)
 * ========================================================================= */

/*
 * Encrypt plaintext using AES-256-GCM.
 *
 * key      : SC_AES_KEY_LEN bytes (from KEM derivation)
 * iv       : SC_AES_IV_LEN bytes (caller-provided, MUST be unique per message)
 * aad      : additional authenticated data (may be NULL if aad_len == 0)
 * ct_out   : caller-allocated buffer of at least (pt_len) bytes
 * tag_out  : caller-allocated buffer of SC_AES_TAG_LEN bytes
 */
sc_err_t pqc_aead_encrypt(const uint8_t key[SC_AES_KEY_LEN],
                            const uint8_t iv[SC_AES_IV_LEN],
                            const void *aad,  size_t aad_len,
                            const void *pt,   size_t pt_len,
                            void *ct_out,
                            uint8_t tag_out[SC_AES_TAG_LEN]);

/*
 * Decrypt and verify an AES-256-GCM ciphertext.
 * Returns SC_ERR_INVALID if the tag does not verify.
 */
sc_err_t pqc_aead_decrypt(const uint8_t key[SC_AES_KEY_LEN],
                            const uint8_t iv[SC_AES_IV_LEN],
                            const void *aad,  size_t aad_len,
                            const void *ct,   size_t ct_len,
                            const uint8_t tag[SC_AES_TAG_LEN],
                            void *pt_out);

/* =========================================================================
 * 9.  Key Management
 * ========================================================================= */

/*
 * sc_pqc_identity_t — full post-quantum identity for a node/agent/provider.
 *
 * A PQC identity contains:
 *   - An Ed25519 keypair  (classical authentication, used in CLASSICAL/HYBRID)
 *   - An ML-DSA-65 keypair (post-quantum signing)
 *   - An ML-KEM-768 keypair (post-quantum key establishment)
 *   - An X25519 keypair    (classical Diffie-Hellman, used in hybrid KEM)
 *   - A unique key identifier
 *   - The active cryptographic policy
 *
 * Private key files are stored in a designated key_dir with 0600 permissions.
 * Public keys are freely distributable.
 */
typedef struct {
    sc_keypair_t       *ed25519_kp;    /* Classical signing                    */
    sc_mldsa_keypair_t *mldsa_kp;      /* PQC signing (ML-DSA-65)              */
    sc_mlkem_keypair_t *mlkem_kp;      /* PQC key establishment (ML-KEM-768)   */

    /* X25519 key material for hybrid KEM (raw 32-byte scalars) */
    uint8_t  x25519_sk[32];            /* Private scalar (never logged)        */
    uint8_t  x25519_pk[32];            /* Public point                         */
    bool     has_x25519;

    uint8_t            key_id[SC_KEY_ID_LEN]; /* SHA-256 identifier             */
    sc_crypto_policy_t policy;                /* Active crypto policy            */
    char               label[64];             /* Human-readable label            */
} sc_pqc_identity_t;

/* Generate a complete PQC identity (all four key types).
 * label is a human-readable name (e.g. "node_0", "tcb_peer_1").
 * Does NOT save to disk — call pqc_identity_save() to persist. */
sc_err_t pqc_identity_create(sc_pqc_identity_t **id_out,
                              const char *label,
                              sc_crypto_policy_t policy);

/* Save all private keys to key_dir/<label>.{ed25519,mldsa,mlkem,x25519}.key */
sc_err_t pqc_identity_save(const sc_pqc_identity_t *id, const char *key_dir);

/* Load a previously saved identity from key_dir/<label>.*key files.
 * Falls back to classical-only if PQC key files are absent and policy
 * is CLASSICAL_ONLY; otherwise returns SC_ERR_NOT_FOUND. */
sc_err_t pqc_identity_load(sc_pqc_identity_t **id_out,
                             const char *key_dir,
                             const char *label,
                             sc_crypto_policy_t policy,
                             char *errbuf, size_t errlen);

/* Free a PQC identity and all contained key material. */
void pqc_identity_free(sc_pqc_identity_t *id);

/* =========================================================================
 * 10.  Performance benchmark
 * ========================================================================= */

typedef struct {
    /* Ed25519 */
    double ed25519_keygen_us;
    double ed25519_sign_us;
    double ed25519_verify_us;
    size_t ed25519_pubkey_bytes;
    size_t ed25519_sig_bytes;

    /* ML-DSA-65 */
    double mldsa_keygen_us;
    double mldsa_sign_us;
    double mldsa_verify_us;
    size_t mldsa_pubkey_bytes;
    size_t mldsa_sig_bytes;

    /* ML-KEM-768 */
    double mlkem_keygen_us;
    double mlkem_encap_us;
    double mlkem_decap_us;
    size_t mlkem_pubkey_bytes;
    size_t mlkem_ct_bytes;
    size_t mlkem_ss_bytes;

    /* Hybrid KEM */
    double hybrid_kem_initiate_us;
    double hybrid_kem_respond_us;
} sc_pqc_bench_t;

/* Run the benchmark suite with iterations trials. Results are real measurements.
 * Do NOT fabricate or estimate values. */
sc_err_t pqc_benchmark(sc_pqc_bench_t *bench_out, unsigned int iterations);

/* Format benchmark as JSON (for the dashboard). */
sc_err_t pqc_benchmark_json(const sc_pqc_bench_t *b, char *json_out, size_t max_len);

#endif /* SC_PQC_CRYPTO_H */
