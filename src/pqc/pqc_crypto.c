/* pqc_crypto.c — Post-Quantum Cryptographic Foundation for SovereignChain.
 *
 * Uses liboqs (Open Quantum Safe) for ML-DSA-65 and ML-KEM-768.
 * Uses OpenSSL EVP for X25519, AES-256-GCM, HKDF-SHA-256, and HMAC-SHA-256.
 *
 * Build requirements:
 *   gcc -std=c17 ... -loqs -lssl -lcrypto
 *   liboqs >= 0.10.0  (implements OQS_SIG_alg_ml_dsa_65, OQS_KEM_alg_ml_kem_768)
 *   OpenSSL >= 3.0
 *
 * NEVER implement ML-DSA or ML-KEM from scratch.
 * NEVER invent cryptographic parameters.
 * NEVER log private key material.
 */
#define _POSIX_C_SOURCE 200809L
#include "pqc_crypto.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/* OpenSSL */
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

/* liboqs */
#include <oqs/oqs.h>

/* Internal helper */
static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)(ts.tv_nsec / 1000);
}

/* =========================================================================
 * Policy name
 * ========================================================================= */

const char *pqc_policy_name(sc_crypto_policy_t p)
{
    switch (p) {
    case SC_CRYPTO_POLICY_CLASSICAL_ONLY: return "CLASSICAL_ONLY";
    case SC_CRYPTO_POLICY_HYBRID:         return "HYBRID";
    case SC_CRYPTO_POLICY_PQC_REQUIRED:   return "PQC_REQUIRED";
    }
    return "UNKNOWN";
}

/* =========================================================================
 * ML-DSA-65 opaque struct
 * ========================================================================= */

struct sc_mldsa_keypair {
    uint8_t pubkey[SC_MLDSA_PUBKEY_LEN];
    uint8_t seckey[SC_MLDSA_SECKEY_LEN]; /* all-zeros when has_priv == false */
    bool    has_priv;
};

sc_err_t pqc_mldsa_keygen(sc_mldsa_keypair_t **kp_out)
{
    if (!kp_out) return SC_ERR_INVALID;

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) return SC_ERR_IO;

    sc_mldsa_keypair_t *kp = calloc(1, sizeof(*kp));
    if (!kp) { OQS_SIG_free(sig); return SC_ERR_IO; }

    if (OQS_SIG_keypair(sig, kp->pubkey, kp->seckey) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        /* Wipe partial secret material before freeing */
        OQS_MEM_cleanse(kp->seckey, sizeof(kp->seckey));
        free(kp);
        return SC_ERR_IO;
    }

    OQS_SIG_free(sig);
    kp->has_priv = true;
    *kp_out = kp;
    return SC_OK;
}

sc_err_t pqc_mldsa_save_seckey(const sc_mldsa_keypair_t *kp, const char *path)
{
    if (!kp || !kp->has_priv || !path) return SC_ERR_INVALID;

    FILE *f = fopen(path, "wb");
    if (!f) return SC_ERR_IO;

    /* Set 0600 before writing any secret data */
    if (chmod(path, S_IRUSR | S_IWUSR) != 0) {
        fclose(f);
        return SC_ERR_IO;
    }

    /* Header: "MLDSA65SK\n" (10 bytes) */
    static const char HDR[] = "MLDSA65SK\n";
    if (fwrite(HDR, 1, 10, f) != 10 ||
        fwrite(kp->pubkey, 1, SC_MLDSA_PUBKEY_LEN, f) != SC_MLDSA_PUBKEY_LEN ||
        fwrite(kp->seckey, 1, SC_MLDSA_SECKEY_LEN, f) != SC_MLDSA_SECKEY_LEN) {
        fclose(f);
        return SC_ERR_IO;
    }

    fclose(f);
    return SC_OK;
}

sc_err_t pqc_mldsa_load_seckey(sc_mldsa_keypair_t **kp_out, const char *path,
                                 char *errbuf, size_t errlen)
{
    if (!kp_out || !path) return SC_ERR_INVALID;

    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errbuf) snprintf(errbuf, errlen, "cannot open %s: %s", path, strerror(errno));
        return SC_ERR_IO;
    }

    char hdr[10];
    if (fread(hdr, 1, 10, f) != 10 || memcmp(hdr, "MLDSA65SK\n", 10) != 0) {
        fclose(f);
        if (errbuf) snprintf(errbuf, errlen, "%s: not a valid ML-DSA-65 key file", path);
        return SC_ERR_PARSE;
    }

    sc_mldsa_keypair_t *kp = calloc(1, sizeof(*kp));
    if (!kp) { fclose(f); return SC_ERR_IO; }

    if (fread(kp->pubkey, 1, SC_MLDSA_PUBKEY_LEN, f) != SC_MLDSA_PUBKEY_LEN ||
        fread(kp->seckey, 1, SC_MLDSA_SECKEY_LEN, f) != SC_MLDSA_SECKEY_LEN) {
        fclose(f);
        OQS_MEM_cleanse(kp->seckey, sizeof(kp->seckey));
        free(kp);
        if (errbuf) snprintf(errbuf, errlen, "%s: truncated key file", path);
        return SC_ERR_PARSE;
    }

    fclose(f);
    kp->has_priv = true;
    *kp_out = kp;
    return SC_OK;
}

sc_err_t pqc_mldsa_pubkey_from_raw(sc_mldsa_keypair_t **kp_out,
                                    const uint8_t pubkey[SC_MLDSA_PUBKEY_LEN])
{
    if (!kp_out || !pubkey) return SC_ERR_INVALID;

    sc_mldsa_keypair_t *kp = calloc(1, sizeof(*kp));
    if (!kp) return SC_ERR_IO;

    memcpy(kp->pubkey, pubkey, SC_MLDSA_PUBKEY_LEN);
    kp->has_priv = false;
    *kp_out = kp;
    return SC_OK;
}

sc_err_t pqc_mldsa_get_pubkey(const sc_mldsa_keypair_t *kp,
                                uint8_t out[SC_MLDSA_PUBKEY_LEN])
{
    if (!kp || !out) return SC_ERR_INVALID;
    memcpy(out, kp->pubkey, SC_MLDSA_PUBKEY_LEN);
    return SC_OK;
}

bool pqc_mldsa_has_private(const sc_mldsa_keypair_t *kp)
{
    return kp != NULL && kp->has_priv;
}

sc_err_t pqc_mldsa_sign(const sc_mldsa_keypair_t *kp,
                          const void *msg, size_t msg_len,
                          uint8_t sig_out[SC_MLDSA_SIG_LEN])
{
    if (!kp || !kp->has_priv || !sig_out) return SC_ERR_INVALID;
    if (!msg && msg_len > 0) return SC_ERR_INVALID;

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) return SC_ERR_IO;

    const uint8_t *data = msg_len > 0 ? (const uint8_t *)msg : (const uint8_t *)"";
    size_t siglen = SC_MLDSA_SIG_LEN;

    OQS_STATUS rc = OQS_SIG_sign(sig, sig_out, &siglen, data, msg_len, kp->seckey);
    OQS_SIG_free(sig);

    if (rc != OQS_SUCCESS || siglen != SC_MLDSA_SIG_LEN)
        return SC_ERR_IO;
    return SC_OK;
}

sc_err_t pqc_mldsa_verify(const sc_mldsa_keypair_t *kp,
                            const void *msg, size_t msg_len,
                            const uint8_t sig[SC_MLDSA_SIG_LEN])
{
    if (!kp || !sig) return SC_ERR_INVALID;
    if (!msg && msg_len > 0) return SC_ERR_INVALID;

    OQS_SIG *oqs = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!oqs) return SC_ERR_IO;

    const uint8_t *data = msg_len > 0 ? (const uint8_t *)msg : (const uint8_t *)"";
    OQS_STATUS rc = OQS_SIG_verify(oqs, data, msg_len, sig, SC_MLDSA_SIG_LEN, kp->pubkey);
    OQS_SIG_free(oqs);

    if (rc == OQS_SUCCESS) return SC_OK;
    if (rc == OQS_ERROR)   return SC_ERR_INVALID; /* Bad signature */
    return SC_ERR_IO;
}

sc_err_t pqc_mldsa_key_id(const sc_mldsa_keypair_t *kp,
                            uint8_t id_out[SC_KEY_ID_LEN])
{
    if (!kp || !id_out) return SC_ERR_INVALID;

    /* SHA-256("MLDSA65" || pubkey) */
    static const uint8_t PREFIX[] = { 'M','L','D','S','A','6','5' };
    uint8_t buf[7 + SC_MLDSA_PUBKEY_LEN];
    memcpy(buf, PREFIX, 7);
    memcpy(buf + 7, kp->pubkey, SC_MLDSA_PUBKEY_LEN);

    unsigned int len = SC_KEY_ID_LEN;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return SC_ERR_IO;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) <= 0 ||
        EVP_DigestUpdate(ctx, buf, sizeof(buf)) <= 0 ||
        EVP_DigestFinal_ex(ctx, id_out, &len) <= 0) {
        EVP_MD_CTX_free(ctx);
        return SC_ERR_IO;
    }
    EVP_MD_CTX_free(ctx);
    return SC_OK;
}

void pqc_mldsa_keypair_free(sc_mldsa_keypair_t *kp)
{
    if (!kp) return;
    OQS_MEM_cleanse(kp->seckey, sizeof(kp->seckey));
    free(kp);
}

/* =========================================================================
 * ML-KEM-768 opaque struct
 * ========================================================================= */

struct sc_mlkem_keypair {
    uint8_t pubkey[SC_MLKEM_PUBKEY_LEN];
    uint8_t seckey[SC_MLKEM_SECKEY_LEN];
    bool    has_priv;
};

sc_err_t pqc_mlkem_keygen(sc_mlkem_keypair_t **kp_out)
{
    if (!kp_out) return SC_ERR_INVALID;

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return SC_ERR_IO;

    sc_mlkem_keypair_t *kp = calloc(1, sizeof(*kp));
    if (!kp) { OQS_KEM_free(kem); return SC_ERR_IO; }

    if (OQS_KEM_keypair(kem, kp->pubkey, kp->seckey) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        OQS_MEM_cleanse(kp->seckey, sizeof(kp->seckey));
        free(kp);
        return SC_ERR_IO;
    }

    OQS_KEM_free(kem);
    kp->has_priv = true;
    *kp_out = kp;
    return SC_OK;
}

sc_err_t pqc_mlkem_save_seckey(const sc_mlkem_keypair_t *kp, const char *path)
{
    if (!kp || !kp->has_priv || !path) return SC_ERR_INVALID;

    FILE *f = fopen(path, "wb");
    if (!f) return SC_ERR_IO;

    if (chmod(path, S_IRUSR | S_IWUSR) != 0) {
        fclose(f); return SC_ERR_IO;
    }

    static const char HDR[] = "MLKEM768SK\n";
    if (fwrite(HDR, 1, 11, f) != 11 ||
        fwrite(kp->pubkey, 1, SC_MLKEM_PUBKEY_LEN, f) != SC_MLKEM_PUBKEY_LEN ||
        fwrite(kp->seckey, 1, SC_MLKEM_SECKEY_LEN, f) != SC_MLKEM_SECKEY_LEN) {
        fclose(f); return SC_ERR_IO;
    }
    fclose(f);
    return SC_OK;
}

sc_err_t pqc_mlkem_load_seckey(sc_mlkem_keypair_t **kp_out, const char *path,
                                 char *errbuf, size_t errlen)
{
    if (!kp_out || !path) return SC_ERR_INVALID;

    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errbuf) snprintf(errbuf, errlen, "cannot open %s: %s", path, strerror(errno));
        return SC_ERR_IO;
    }

    char hdr[11];
    if (fread(hdr, 1, 11, f) != 11 || memcmp(hdr, "MLKEM768SK\n", 11) != 0) {
        fclose(f);
        if (errbuf) snprintf(errbuf, errlen, "%s: not a valid ML-KEM-768 key file", path);
        return SC_ERR_PARSE;
    }

    sc_mlkem_keypair_t *kp = calloc(1, sizeof(*kp));
    if (!kp) { fclose(f); return SC_ERR_IO; }

    if (fread(kp->pubkey, 1, SC_MLKEM_PUBKEY_LEN, f) != SC_MLKEM_PUBKEY_LEN ||
        fread(kp->seckey, 1, SC_MLKEM_SECKEY_LEN, f) != SC_MLKEM_SECKEY_LEN) {
        fclose(f);
        OQS_MEM_cleanse(kp->seckey, sizeof(kp->seckey));
        free(kp);
        if (errbuf) snprintf(errbuf, errlen, "%s: truncated key file", path);
        return SC_ERR_PARSE;
    }

    fclose(f);
    kp->has_priv = true;
    *kp_out = kp;
    return SC_OK;
}

sc_err_t pqc_mlkem_pubkey_from_raw(sc_mlkem_keypair_t **kp_out,
                                    const uint8_t pubkey[SC_MLKEM_PUBKEY_LEN])
{
    if (!kp_out || !pubkey) return SC_ERR_INVALID;

    sc_mlkem_keypair_t *kp = calloc(1, sizeof(*kp));
    if (!kp) return SC_ERR_IO;

    memcpy(kp->pubkey, pubkey, SC_MLKEM_PUBKEY_LEN);
    kp->has_priv = false;
    *kp_out = kp;
    return SC_OK;
}

sc_err_t pqc_mlkem_get_pubkey(const sc_mlkem_keypair_t *kp,
                                uint8_t out[SC_MLKEM_PUBKEY_LEN])
{
    if (!kp || !out) return SC_ERR_INVALID;
    memcpy(out, kp->pubkey, SC_MLKEM_PUBKEY_LEN);
    return SC_OK;
}

sc_err_t pqc_mlkem_encapsulate(const sc_mlkem_keypair_t *recipient_pk,
                                 uint8_t ct_out[SC_MLKEM_CT_LEN],
                                 uint8_t ss_out[SC_MLKEM_SS_LEN])
{
    if (!recipient_pk || !ct_out || !ss_out) return SC_ERR_INVALID;

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return SC_ERR_IO;

    OQS_STATUS rc = OQS_KEM_encaps(kem, ct_out, ss_out, recipient_pk->pubkey);
    OQS_KEM_free(kem);

    return rc == OQS_SUCCESS ? SC_OK : SC_ERR_IO;
}

sc_err_t pqc_mlkem_decapsulate(const sc_mlkem_keypair_t *kp,
                                 const uint8_t ct[SC_MLKEM_CT_LEN],
                                 uint8_t ss_out[SC_MLKEM_SS_LEN])
{
    if (!kp || !kp->has_priv || !ct || !ss_out) return SC_ERR_INVALID;

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return SC_ERR_IO;

    OQS_STATUS rc = OQS_KEM_decaps(kem, ss_out, ct, kp->seckey);
    OQS_KEM_free(kem);

    return rc == OQS_SUCCESS ? SC_OK : SC_ERR_INVALID;
}

void pqc_mlkem_keypair_free(sc_mlkem_keypair_t *kp)
{
    if (!kp) return;
    OQS_MEM_cleanse(kp->seckey, sizeof(kp->seckey));
    free(kp);
}

/* =========================================================================
 * Hybrid Signature
 * ========================================================================= */

sc_err_t pqc_hybrid_sign(sc_hybrid_sig_t *sig_out,
                          const void *msg, size_t msg_len,
                          sc_crypto_policy_t policy,
                          const sc_keypair_t  *ed25519_kp,
                          const sc_mldsa_keypair_t *mldsa_kp)
{
    if (!sig_out) return SC_ERR_INVALID;
    memset(sig_out, 0, sizeof(*sig_out));

    switch (policy) {
    case SC_CRYPTO_POLICY_CLASSICAL_ONLY:
        if (!ed25519_kp) return SC_ERR_INVALID;
        if (crypto_sign(ed25519_kp, msg, msg_len, sig_out->ed25519_sig) != SC_OK)
            return SC_ERR_IO;
        sig_out->has_ed25519 = true;
        break;

    case SC_CRYPTO_POLICY_HYBRID:
        if (!ed25519_kp || !mldsa_kp) return SC_ERR_INVALID;
        if (crypto_sign(ed25519_kp, msg, msg_len, sig_out->ed25519_sig) != SC_OK)
            return SC_ERR_IO;
        if (pqc_mldsa_sign(mldsa_kp, msg, msg_len, sig_out->mldsa_sig) != SC_OK)
            return SC_ERR_IO;
        sig_out->has_ed25519 = true;
        sig_out->has_mldsa   = true;
        break;

    case SC_CRYPTO_POLICY_PQC_REQUIRED:
        if (!mldsa_kp) return SC_ERR_INVALID;
        if (pqc_mldsa_sign(mldsa_kp, msg, msg_len, sig_out->mldsa_sig) != SC_OK)
            return SC_ERR_IO;
        sig_out->has_mldsa = true;
        break;
    }
    return SC_OK;
}

sc_err_t pqc_hybrid_verify(const sc_hybrid_sig_t *sig,
                             const void *msg, size_t msg_len,
                             sc_crypto_policy_t policy,
                             const sc_keypair_t  *ed25519_kp,
                             const sc_mldsa_keypair_t *mldsa_kp)
{
    if (!sig) return SC_ERR_INVALID;

    switch (policy) {
    case SC_CRYPTO_POLICY_CLASSICAL_ONLY:
        if (!ed25519_kp) return SC_ERR_INVALID;
        if (!sig->has_ed25519) return SC_ERR_INVALID;
        return crypto_verify(ed25519_kp, msg, msg_len, sig->ed25519_sig);

    case SC_CRYPTO_POLICY_HYBRID:
        if (!ed25519_kp || !mldsa_kp) return SC_ERR_INVALID;
        /* Both MUST be present. Reject downgrade to single signature. */
        if (!sig->has_ed25519 || !sig->has_mldsa) return SC_ERR_INVALID;
        if (crypto_verify(ed25519_kp, msg, msg_len, sig->ed25519_sig) != SC_OK)
            return SC_ERR_INVALID;
        if (pqc_mldsa_verify(mldsa_kp, msg, msg_len, sig->mldsa_sig) != SC_OK)
            return SC_ERR_INVALID;
        return SC_OK;

    case SC_CRYPTO_POLICY_PQC_REQUIRED:
        if (!mldsa_kp) return SC_ERR_INVALID;
        if (!sig->has_mldsa) return SC_ERR_INVALID;
        return pqc_mldsa_verify(mldsa_kp, msg, msg_len, sig->mldsa_sig);
    }
    return SC_ERR_INVALID;
}

void pqc_hybrid_sig_encode(const sc_hybrid_sig_t *sig, uint8_t *buf)
{
    buf[0] = sig->has_ed25519 ? 1 : 0;
    buf[1] = sig->has_mldsa   ? 1 : 0;
    memcpy(buf + 2, sig->ed25519_sig, SC_ED25519_SIG_LEN);
    memcpy(buf + 2 + SC_ED25519_SIG_LEN, sig->mldsa_sig, SC_MLDSA_SIG_LEN);
}

void pqc_hybrid_sig_decode(sc_hybrid_sig_t *sig_out, const uint8_t *buf)
{
    sig_out->has_ed25519 = buf[0] != 0;
    sig_out->has_mldsa   = buf[1] != 0;
    memcpy(sig_out->ed25519_sig, buf + 2, SC_ED25519_SIG_LEN);
    memcpy(sig_out->mldsa_sig,   buf + 2 + SC_ED25519_SIG_LEN, SC_MLDSA_SIG_LEN);
}

/* =========================================================================
 * HKDF-SHA-256 internal helper
 * =========================================================================
 * RFC 5869 HKDF: Extract + Expand.
 * We use OpenSSL's EVP_KDF interface (OpenSSL 3.x).
 */
static sc_err_t hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                              const uint8_t *salt, size_t salt_len,
                              const uint8_t *info, size_t info_len,
                              uint8_t *out, size_t out_len)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return SC_ERR_IO;

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) return SC_ERR_IO;

    OSSL_PARAM params[6];
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    params[0] = OSSL_PARAM_construct_int("mode", &mode);
    params[1] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[2] = OSSL_PARAM_construct_octet_string("key",  (void *)ikm,  ikm_len);
    params[3] = OSSL_PARAM_construct_octet_string("salt", (void *)salt, salt_len);
    params[4] = OSSL_PARAM_construct_octet_string("info", (void *)info, info_len);
    params[5] = OSSL_PARAM_construct_end();

    int rc = EVP_KDF_derive(ctx, out, out_len, params);
    EVP_KDF_CTX_free(ctx);
    return rc > 0 ? SC_OK : SC_ERR_IO;
}

/* =========================================================================
 * X25519 key-agreement internal helper
 * Returns the 32-byte shared Diffie-Hellman output.
 */
static sc_err_t x25519_dh(const uint8_t sk[32], const uint8_t pk[32],
                            uint8_t dh_out[32])
{
    EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, 32);
    if (!priv) return SC_ERR_IO;

    EVP_PKEY *pub  = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pk, 32);
    if (!pub) { EVP_PKEY_free(priv); return SC_ERR_IO; }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) { EVP_PKEY_free(priv); EVP_PKEY_free(pub); return SC_ERR_IO; }

    size_t ss_len = 32;
    int ok = (EVP_PKEY_derive_init(ctx) > 0) &&
             (EVP_PKEY_derive_set_peer(ctx, pub) > 0) &&
             (EVP_PKEY_derive(ctx, dh_out, &ss_len) > 0) &&
             (ss_len == 32);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    return ok ? SC_OK : SC_ERR_IO;
}

/* =========================================================================
 * Hybrid KEM
 * ========================================================================= */

sc_err_t pqc_hybrid_kem_initiate(
        const uint8_t recipient_mlkem_pk[SC_MLKEM_PUBKEY_LEN],
        uint8_t  kem_msg_out[SC_KEM_INIT_MSG_LEN],
        uint8_t  ephem_x25519_sk_out[32],
        uint8_t  mlkem_ss_out[SC_MLKEM_SS_LEN])
{
    if (!recipient_mlkem_pk || !kem_msg_out ||
        !ephem_x25519_sk_out || !mlkem_ss_out)
        return SC_ERR_INVALID;

    /* Generate ephemeral X25519 keypair */
    EVP_PKEY *ephem_pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return SC_ERR_IO;
    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_keygen(pctx, &ephem_pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return SC_ERR_IO;
    }
    EVP_PKEY_CTX_free(pctx);

    size_t sk_len = 32, pk_len = 32;
    uint8_t ephem_pk[32];
    if (EVP_PKEY_get_raw_private_key(ephem_pkey, ephem_x25519_sk_out, &sk_len) <= 0 ||
        EVP_PKEY_get_raw_public_key(ephem_pkey, ephem_pk, &pk_len) <= 0) {
        EVP_PKEY_free(ephem_pkey);
        return SC_ERR_IO;
    }
    EVP_PKEY_free(ephem_pkey);

    /* ML-KEM-768 encapsulation */
    sc_mlkem_keypair_t *pub_handle;
    if (pqc_mlkem_pubkey_from_raw(&pub_handle, recipient_mlkem_pk) != SC_OK)
        return SC_ERR_IO;

    uint8_t ct[SC_MLKEM_CT_LEN];
    if (pqc_mlkem_encapsulate(pub_handle, ct, mlkem_ss_out) != SC_OK) {
        pqc_mlkem_keypair_free(pub_handle);
        return SC_ERR_IO;
    }
    pqc_mlkem_keypair_free(pub_handle);

    /* Wire message: ct (1088 B) || ephem_pk (32 B) */
    memcpy(kem_msg_out,                    ct,       SC_MLKEM_CT_LEN);
    memcpy(kem_msg_out + SC_MLKEM_CT_LEN,  ephem_pk, 32);
    return SC_OK;
}

/* Internal shared helper: combine ML-KEM SS and X25519 DH output via HKDF */
static sc_err_t combine_hybrid_secrets(
        const uint8_t mlkem_ss[SC_MLKEM_SS_LEN],
        const uint8_t x25519_dh_out[32],
        uint8_t session_key_out[SC_KEM_SESSION_LEN])
{
    /* IKM = mlkem_ss || x25519_dh_out (concatenate before HKDF extract) */
    uint8_t ikm[SC_MLKEM_SS_LEN + 32];
    memcpy(ikm,                       mlkem_ss,     SC_MLKEM_SS_LEN);
    memcpy(ikm + SC_MLKEM_SS_LEN,     x25519_dh_out, 32);

    static const uint8_t SALT[] = { 'S','C','_','K','E','M','_','S','A','L','T' };
    static const uint8_t INFO[] = { 'S','C','_','S','E','S','S','I','O','N','_','K','E','Y' };

    return hkdf_sha256(ikm, sizeof(ikm),
                       SALT, sizeof(SALT),
                       INFO, sizeof(INFO),
                       session_key_out, SC_KEM_SESSION_LEN);
}

sc_err_t pqc_hybrid_kem_respond(
        const sc_mlkem_keypair_t *my_mlkem_kp,
        const uint8_t kem_msg_in[SC_KEM_INIT_MSG_LEN],
        const uint8_t my_x25519_sk[32],
        const uint8_t peer_x25519_pk[32],
        uint8_t session_key_out[SC_KEM_SESSION_LEN])
{
    if (!my_mlkem_kp || !kem_msg_in || !my_x25519_sk ||
        !peer_x25519_pk || !session_key_out)
        return SC_ERR_INVALID;

    const uint8_t *ct        = kem_msg_in;                   /* 1088 bytes */
    /* initiator's ephem X25519 pk embedded in msg — not used for DH on
     * responder side because responder does DH with initiator's STATIC pk;
     * we keep it here for future auth binding extensions. */

    /* ML-KEM decapsulate */
    uint8_t mlkem_ss[SC_MLKEM_SS_LEN];
    if (pqc_mlkem_decapsulate(my_mlkem_kp, ct, mlkem_ss) != SC_OK)
        return SC_ERR_INVALID;

    /* X25519 DH: our static sk × peer static pk */
    uint8_t dh[32];
    if (x25519_dh(my_x25519_sk, peer_x25519_pk, dh) != SC_OK) {
        OQS_MEM_cleanse(mlkem_ss, sizeof(mlkem_ss));
        return SC_ERR_IO;
    }

    sc_err_t rc = combine_hybrid_secrets(mlkem_ss, dh, session_key_out);
    OQS_MEM_cleanse(mlkem_ss, sizeof(mlkem_ss));
    OQS_MEM_cleanse(dh, sizeof(dh));
    return rc;
}

sc_err_t pqc_hybrid_kem_derive_initiator(
        const uint8_t ephem_x25519_sk[32],
        const uint8_t peer_x25519_pk[32],
        const uint8_t mlkem_ss[SC_MLKEM_SS_LEN],
        uint8_t session_key_out[SC_KEM_SESSION_LEN])
{
    if (!ephem_x25519_sk || !peer_x25519_pk || !mlkem_ss || !session_key_out)
        return SC_ERR_INVALID;

    uint8_t dh[32];
    if (x25519_dh(ephem_x25519_sk, peer_x25519_pk, dh) != SC_OK)
        return SC_ERR_IO;

    sc_err_t rc = combine_hybrid_secrets(mlkem_ss, dh, session_key_out);
    OQS_MEM_cleanse(dh, sizeof(dh));
    return rc;
}

/* =========================================================================
 * AES-256-GCM
 * ========================================================================= */

sc_err_t pqc_aead_encrypt(const uint8_t key[SC_AES_KEY_LEN],
                            const uint8_t iv[SC_AES_IV_LEN],
                            const void *aad,  size_t aad_len,
                            const void *pt,   size_t pt_len,
                            void *ct_out,
                            uint8_t tag_out[SC_AES_TAG_LEN])
{
    if (!key || !iv || !ct_out || !tag_out) return SC_ERR_INVALID;
    if (!pt && pt_len > 0) return SC_ERR_INVALID;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return SC_ERR_IO;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SC_AES_IV_LEN, NULL) <= 0 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return SC_ERR_IO;
    }

    int outl = 0;
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &outl, (const unsigned char *)aad, (int)aad_len) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            return SC_ERR_IO;
        }
    }

    if (pt_len > 0) {
        if (EVP_EncryptUpdate(ctx, (unsigned char *)ct_out, &outl,
                              (const unsigned char *)pt, (int)pt_len) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            return SC_ERR_IO;
        }
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, (unsigned char *)ct_out + outl, &final_len) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SC_AES_TAG_LEN, tag_out) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return SC_ERR_IO;
    }

    EVP_CIPHER_CTX_free(ctx);
    return SC_OK;
}

sc_err_t pqc_aead_decrypt(const uint8_t key[SC_AES_KEY_LEN],
                            const uint8_t iv[SC_AES_IV_LEN],
                            const void *aad,  size_t aad_len,
                            const void *ct,   size_t ct_len,
                            const uint8_t tag[SC_AES_TAG_LEN],
                            void *pt_out)
{
    if (!key || !iv || !tag || !pt_out) return SC_ERR_INVALID;
    if (!ct && ct_len > 0) return SC_ERR_INVALID;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return SC_ERR_IO;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SC_AES_IV_LEN, NULL) <= 0 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return SC_ERR_IO;
    }

    int outl = 0;
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &outl, (const unsigned char *)aad, (int)aad_len) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            return SC_ERR_IO;
        }
    }

    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, (unsigned char *)pt_out, &outl,
                              (const unsigned char *)ct, (int)ct_len) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            return SC_ERR_IO;
        }
    }

    /* Set expected tag before finalising */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SC_AES_TAG_LEN,
                             (void *)tag) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return SC_ERR_IO;
    }

    int final_len = 0;
    int rc = EVP_DecryptFinal_ex(ctx, (unsigned char *)pt_out + outl, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    /* rc <= 0 means tag verification failed */
    return rc > 0 ? SC_OK : SC_ERR_INVALID;
}

/* =========================================================================
 * PQC Identity Management
 * ========================================================================= */

static sc_err_t build_x25519_key(sc_pqc_identity_t *id)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) return SC_ERR_IO;
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return SC_ERR_IO;
    }
    EVP_PKEY_CTX_free(ctx);

    size_t sk_len = 32, pk_len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, id->x25519_sk, &sk_len) <= 0 ||
        EVP_PKEY_get_raw_public_key(pkey, id->x25519_pk, &pk_len) <= 0) {
        EVP_PKEY_free(pkey);
        return SC_ERR_IO;
    }
    EVP_PKEY_free(pkey);
    id->has_x25519 = true;
    return SC_OK;
}

sc_err_t pqc_identity_create(sc_pqc_identity_t **id_out,
                              const char *label,
                              sc_crypto_policy_t policy)
{
    if (!id_out || !label) return SC_ERR_INVALID;

    sc_pqc_identity_t *id = calloc(1, sizeof(*id));
    if (!id) return SC_ERR_IO;

    id->policy = policy;
    snprintf(id->label, sizeof(id->label), "%s", label);

    /* Always create Ed25519 key (needed for CLASSICAL and HYBRID) */
    if (crypto_keygen(&id->ed25519_kp) != SC_OK) {
        free(id); return SC_ERR_IO;
    }

    /* Always create ML-DSA-65 key (needed for HYBRID and PQC_REQUIRED) */
    if (pqc_mldsa_keygen(&id->mldsa_kp) != SC_OK) {
        crypto_keypair_free(id->ed25519_kp);
        free(id); return SC_ERR_IO;
    }

    /* Always create ML-KEM-768 key */
    if (pqc_mlkem_keygen(&id->mlkem_kp) != SC_OK) {
        pqc_mldsa_keypair_free(id->mldsa_kp);
        crypto_keypair_free(id->ed25519_kp);
        free(id); return SC_ERR_IO;
    }

    /* Always create X25519 key */
    if (build_x25519_key(id) != SC_OK) {
        pqc_mlkem_keypair_free(id->mlkem_kp);
        pqc_mldsa_keypair_free(id->mldsa_kp);
        crypto_keypair_free(id->ed25519_kp);
        free(id); return SC_ERR_IO;
    }

    /* Key ID = SHA-256 of ML-DSA-65 public key */
    if (pqc_mldsa_key_id(id->mldsa_kp, id->key_id) != SC_OK) {
        pqc_identity_free(id); return SC_ERR_IO;
    }

    *id_out = id;
    return SC_OK;
}

sc_err_t pqc_identity_save(const sc_pqc_identity_t *id, const char *key_dir)
{
    if (!id || !key_dir) return SC_ERR_INVALID;

    char path[512];

    /* Ed25519 */
    snprintf(path, sizeof(path), "%s/%s.ed25519.key", key_dir, id->label);
    if (crypto_save_privkey(id->ed25519_kp, path) != SC_OK) return SC_ERR_IO;

    /* ML-DSA-65 */
    snprintf(path, sizeof(path), "%s/%s.mldsa.key", key_dir, id->label);
    if (pqc_mldsa_save_seckey(id->mldsa_kp, path) != SC_OK) return SC_ERR_IO;

    /* ML-KEM-768 */
    snprintf(path, sizeof(path), "%s/%s.mlkem.key", key_dir, id->label);
    if (pqc_mlkem_save_seckey(id->mlkem_kp, path) != SC_OK) return SC_ERR_IO;

    /* X25519: "X25519SK\n" header + 32-byte sk + 32-byte pk */
    snprintf(path, sizeof(path), "%s/%s.x25519.key", key_dir, id->label);
    FILE *f = fopen(path, "wb");
    if (!f) return SC_ERR_IO;
    if (chmod(path, S_IRUSR | S_IWUSR) != 0) { fclose(f); return SC_ERR_IO; }
    static const char X25519_HDR[] = "X25519SK\n";
    if (fwrite(X25519_HDR, 1, 9, f) != 9 ||
        fwrite(id->x25519_sk, 1, 32, f) != 32 ||
        fwrite(id->x25519_pk, 1, 32, f) != 32) {
        fclose(f); return SC_ERR_IO;
    }
    fclose(f);

    return SC_OK;
}

sc_err_t pqc_identity_load(sc_pqc_identity_t **id_out,
                             const char *key_dir,
                             const char *label,
                             sc_crypto_policy_t policy,
                             char *errbuf, size_t errlen)
{
    if (!id_out || !key_dir || !label) return SC_ERR_INVALID;

    sc_pqc_identity_t *id = calloc(1, sizeof(*id));
    if (!id) return SC_ERR_IO;

    id->policy = policy;
    snprintf(id->label, sizeof(id->label), "%s", label);

    char path[512];
    char eb[256];

    /* Ed25519 */
    snprintf(path, sizeof(path), "%s/%s.ed25519.key", key_dir, label);
    if (crypto_load_privkey(&id->ed25519_kp, path, eb, sizeof(eb)) != SC_OK) {
        if (errbuf) snprintf(errbuf, errlen, "Ed25519 load: %s", eb);
        free(id); return SC_ERR_IO;
    }

    /* ML-DSA-65 */
    snprintf(path, sizeof(path), "%s/%s.mldsa.key", key_dir, label);
    if (pqc_mldsa_load_seckey(&id->mldsa_kp, path, eb, sizeof(eb)) != SC_OK) {
        if (errbuf) snprintf(errbuf, errlen, "ML-DSA load: %s", eb);
        crypto_keypair_free(id->ed25519_kp);
        free(id); return SC_ERR_IO;
    }

    /* ML-KEM-768 */
    snprintf(path, sizeof(path), "%s/%s.mlkem.key", key_dir, label);
    if (pqc_mlkem_load_seckey(&id->mlkem_kp, path, eb, sizeof(eb)) != SC_OK) {
        if (errbuf) snprintf(errbuf, errlen, "ML-KEM load: %s", eb);
        pqc_mldsa_keypair_free(id->mldsa_kp);
        crypto_keypair_free(id->ed25519_kp);
        free(id); return SC_ERR_IO;
    }

    /* X25519 */
    snprintf(path, sizeof(path), "%s/%s.x25519.key", key_dir, label);
    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errbuf) snprintf(errbuf, errlen, "cannot open %s: %s", path, strerror(errno));
        pqc_mlkem_keypair_free(id->mlkem_kp);
        pqc_mldsa_keypair_free(id->mldsa_kp);
        crypto_keypair_free(id->ed25519_kp);
        free(id); return SC_ERR_IO;
    }
    char x_hdr[9];
    if (fread(x_hdr, 1, 9, f) != 9 || memcmp(x_hdr, "X25519SK\n", 9) != 0 ||
        fread(id->x25519_sk, 1, 32, f) != 32 ||
        fread(id->x25519_pk, 1, 32, f) != 32) {
        fclose(f);
        if (errbuf) snprintf(errbuf, errlen, "%s: invalid X25519 key file", path);
        pqc_mlkem_keypair_free(id->mlkem_kp);
        pqc_mldsa_keypair_free(id->mldsa_kp);
        crypto_keypair_free(id->ed25519_kp);
        free(id); return SC_ERR_PARSE;
    }
    fclose(f);
    id->has_x25519 = true;

    /* Recompute key ID */
    if (pqc_mldsa_key_id(id->mldsa_kp, id->key_id) != SC_OK) {
        pqc_identity_free(id); return SC_ERR_IO;
    }

    *id_out = id;
    return SC_OK;
}

void pqc_identity_free(sc_pqc_identity_t *id)
{
    if (!id) return;
    crypto_keypair_free(id->ed25519_kp);
    pqc_mldsa_keypair_free(id->mldsa_kp);
    pqc_mlkem_keypair_free(id->mlkem_kp);
    OQS_MEM_cleanse(id->x25519_sk, 32);
    free(id);
}

/* =========================================================================
 * Performance Benchmark
 * ========================================================================= */

sc_err_t pqc_benchmark(sc_pqc_bench_t *b, unsigned int iterations)
{
    if (!b || iterations == 0) return SC_ERR_INVALID;
    memset(b, 0, sizeof(*b));

    static const uint8_t MSG[64] = { 0x42 };

    /* ----- Ed25519 ----- */
    b->ed25519_pubkey_bytes = SC_ED25519_PUBKEY_LEN;
    b->ed25519_sig_bytes    = SC_ED25519_SIG_LEN;

    {
        uint64_t t0 = now_us();
        for (unsigned i = 0; i < iterations; i++) {
            sc_keypair_t *kp;
            crypto_keygen(&kp);
            crypto_keypair_free(kp);
        }
        b->ed25519_keygen_us = (double)(now_us() - t0) / iterations;
    }

    sc_keypair_t *ed_kp = NULL;
    crypto_keygen(&ed_kp);
    uint8_t ed_sig[SC_ED25519_SIG_LEN];

    {
        uint64_t t0 = now_us();
        for (unsigned i = 0; i < iterations; i++)
            crypto_sign(ed_kp, MSG, sizeof(MSG), ed_sig);
        b->ed25519_sign_us = (double)(now_us() - t0) / iterations;
    }
    {
        uint64_t t0 = now_us();
        for (unsigned i = 0; i < iterations; i++)
            crypto_verify(ed_kp, MSG, sizeof(MSG), ed_sig);
        b->ed25519_verify_us = (double)(now_us() - t0) / iterations;
    }
    crypto_keypair_free(ed_kp);

    /* ----- ML-DSA-65 ----- */
    b->mldsa_pubkey_bytes = SC_MLDSA_PUBKEY_LEN;
    b->mldsa_sig_bytes    = SC_MLDSA_SIG_LEN;

    {
        uint64_t t0 = now_us();
        for (unsigned i = 0; i < iterations; i++) {
            sc_mldsa_keypair_t *kp;
            pqc_mldsa_keygen(&kp);
            pqc_mldsa_keypair_free(kp);
        }
        b->mldsa_keygen_us = (double)(now_us() - t0) / iterations;
    }

    sc_mldsa_keypair_t *mldsa_kp = NULL;
    pqc_mldsa_keygen(&mldsa_kp);
    uint8_t mldsa_sig[SC_MLDSA_SIG_LEN];

    {
        uint64_t t0 = now_us();
        for (unsigned i = 0; i < iterations; i++)
            pqc_mldsa_sign(mldsa_kp, MSG, sizeof(MSG), mldsa_sig);
        b->mldsa_sign_us = (double)(now_us() - t0) / iterations;
    }
    {
        uint64_t t0 = now_us();
        for (unsigned i = 0; i < iterations; i++)
            pqc_mldsa_verify(mldsa_kp, MSG, sizeof(MSG), mldsa_sig);
        b->mldsa_verify_us = (double)(now_us() - t0) / iterations;
    }
    pqc_mldsa_keypair_free(mldsa_kp);

    /* ----- ML-KEM-768 ----- */
    b->mlkem_pubkey_bytes = SC_MLKEM_PUBKEY_LEN;
    b->mlkem_ct_bytes     = SC_MLKEM_CT_LEN;
    b->mlkem_ss_bytes     = SC_MLKEM_SS_LEN;

    {
        uint64_t t0 = now_us();
        for (unsigned i = 0; i < iterations; i++) {
            sc_mlkem_keypair_t *kp;
            pqc_mlkem_keygen(&kp);
            pqc_mlkem_keypair_free(kp);
        }
        b->mlkem_keygen_us = (double)(now_us() - t0) / iterations;
    }

    sc_mlkem_keypair_t *kem_kp = NULL;
    pqc_mlkem_keygen(&kem_kp);
    uint8_t ct[SC_MLKEM_CT_LEN], ss_e[SC_MLKEM_SS_LEN], ss_d[SC_MLKEM_SS_LEN];

    {
        uint64_t t0 = now_us();
        for (unsigned i = 0; i < iterations; i++)
            pqc_mlkem_encapsulate(kem_kp, ct, ss_e);
        b->mlkem_encap_us = (double)(now_us() - t0) / iterations;
    }
    {
        uint64_t t0 = now_us();
        for (unsigned i = 0; i < iterations; i++)
            pqc_mlkem_decapsulate(kem_kp, ct, ss_d);
        b->mlkem_decap_us = (double)(now_us() - t0) / iterations;
    }

    /* Hybrid KEM benchmark */
    uint8_t mlkem_pk[SC_MLKEM_PUBKEY_LEN];
    pqc_mlkem_get_pubkey(kem_kp, mlkem_pk);

    uint8_t kem_msg[SC_KEM_INIT_MSG_LEN];
    uint8_t ephem_sk[32], mlkem_ss_buf[SC_MLKEM_SS_LEN];
    uint8_t my_x25519_sk[32], my_x25519_pk[32];

    /* Generate a static X25519 pair for responder */
    {
        EVP_PKEY *p = NULL;
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
        EVP_PKEY_keygen_init(c); EVP_PKEY_keygen(c, &p); EVP_PKEY_CTX_free(c);
        size_t l = 32; EVP_PKEY_get_raw_private_key(p, my_x25519_sk, &l);
        l = 32; EVP_PKEY_get_raw_public_key(p, my_x25519_pk, &l);
        EVP_PKEY_free(p);
    }

    {
        uint64_t t0 = now_us();
        for (unsigned i = 0; i < iterations; i++)
            pqc_hybrid_kem_initiate(mlkem_pk, kem_msg, ephem_sk, mlkem_ss_buf);
        b->hybrid_kem_initiate_us = (double)(now_us() - t0) / iterations;
    }

    /* For respond bench: use a fixed kem_msg from last initiate */
    /* The x25519 pk embedded in kem_msg is NOT my_x25519_pk on purpose:
     * in the benchmark we just measure wall time, not cross-party agreement. */
    uint8_t session_key[SC_KEM_SESSION_LEN];
    {
        uint64_t t0 = now_us();
        for (unsigned i = 0; i < iterations; i++)
            pqc_hybrid_kem_respond(kem_kp, kem_msg, my_x25519_sk, my_x25519_pk, session_key);
        b->hybrid_kem_respond_us = (double)(now_us() - t0) / iterations;
    }

    pqc_mlkem_keypair_free(kem_kp);
    return SC_OK;
}

sc_err_t pqc_benchmark_json(const sc_pqc_bench_t *b, char *json_out, size_t max_len)
{
    if (!b || !json_out || max_len < 512) return SC_ERR_INVALID;

    int n = snprintf(json_out, max_len,
        "{"
        "\"ed25519\":{"
          "\"keygen_us\":%.2f,"
          "\"sign_us\":%.2f,"
          "\"verify_us\":%.2f,"
          "\"pubkey_bytes\":%zu,"
          "\"sig_bytes\":%zu"
        "},"
        "\"ml_dsa_65\":{"
          "\"keygen_us\":%.2f,"
          "\"sign_us\":%.2f,"
          "\"verify_us\":%.2f,"
          "\"pubkey_bytes\":%zu,"
          "\"sig_bytes\":%zu"
        "},"
        "\"ml_kem_768\":{"
          "\"keygen_us\":%.2f,"
          "\"encap_us\":%.2f,"
          "\"decap_us\":%.2f,"
          "\"pubkey_bytes\":%zu,"
          "\"ciphertext_bytes\":%zu,"
          "\"shared_secret_bytes\":%zu"
        "},"
        "\"hybrid_kem\":{"
          "\"initiate_us\":%.2f,"
          "\"respond_us\":%.2f"
        "}"
        "}",
        b->ed25519_keygen_us, b->ed25519_sign_us, b->ed25519_verify_us,
        b->ed25519_pubkey_bytes, b->ed25519_sig_bytes,
        b->mldsa_keygen_us, b->mldsa_sign_us, b->mldsa_verify_us,
        b->mldsa_pubkey_bytes, b->mldsa_sig_bytes,
        b->mlkem_keygen_us, b->mlkem_encap_us, b->mlkem_decap_us,
        b->mlkem_pubkey_bytes, b->mlkem_ct_bytes, b->mlkem_ss_bytes,
        b->hybrid_kem_initiate_us, b->hybrid_kem_respond_us);

    return (n > 0 && (size_t)n < max_len) ? SC_OK : SC_ERR_IO;
}
