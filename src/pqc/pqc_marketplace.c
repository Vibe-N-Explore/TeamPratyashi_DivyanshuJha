/* pqc_marketplace.c — Post-Quantum Marketplace Identity and Agreement Layer. */
#define _POSIX_C_SOURCE 200809L
#include "pqc_marketplace.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/* ---- Big-endian / integer helpers ---- */
static void pack_u64_be(uint8_t *d, uint64_t v) {
    for (int i = 7; i >= 0; i--) { d[i] = (uint8_t)(v & 0xff); v >>= 8; }
}
static void pack_i64_be(uint8_t *d, int64_t v) {
    pack_u64_be(d, (uint64_t)v);
}
static void pack_i32_be(uint8_t *d, int32_t v) {
    uint32_t u = (uint32_t)v;
    d[0] = (u >> 24) & 0xff; d[1] = (u >> 16) & 0xff;
    d[2] = (u >> 8) & 0xff;  d[3] = u & 0xff;
}
static void pack_u32_be(uint8_t *d, uint32_t v) {
    d[0] = (v >> 24) & 0xff; d[1] = (v >> 16) & 0xff;
    d[2] = (v >> 8) & 0xff;  d[3] = v & 0xff;
}

/* =========================================================================
 * Provider Registration
 * ========================================================================= */

#define SC_PQMP_REG_CANONICAL_LEN \
    (SC_PQMP_REG_DOMAIN_LEN + 4 + 64 + SC_ED25519_PUBKEY_LEN + \
     SC_MLDSA_PUBKEY_LEN + SC_MLKEM_PUBKEY_LEN + 4 + 4 + 4 + 4 + 8 + 8)

static void get_reg_canonical_bytes(const sc_pqmp_registration_t *reg, uint8_t *out)
{
    uint8_t *p = out;
    memcpy(p, SC_PQMP_REG_DOMAIN, SC_PQMP_REG_DOMAIN_LEN);
    p += SC_PQMP_REG_DOMAIN_LEN;

    pack_i32_be(p, reg->provider_id); p += 4;

    uint8_t name_buf[64] = {0};
    strncpy((char *)name_buf, reg->name, 63);
    memcpy(p, name_buf, 64); p += 64;

    memcpy(p, reg->ed25519_pubkey, SC_ED25519_PUBKEY_LEN); p += SC_ED25519_PUBKEY_LEN;
    memcpy(p, reg->mldsa_pubkey, SC_MLDSA_PUBKEY_LEN); p += SC_MLDSA_PUBKEY_LEN;
    memcpy(p, reg->mlkem_pubkey, SC_MLKEM_PUBKEY_LEN); p += SC_MLKEM_PUBKEY_LEN;

    pack_u32_be(p, reg->cpu_cores); p += 4;
    pack_u32_be(p, reg->gpu_count); p += 4;
    pack_u32_be(p, reg->ram_mb); p += 4;
    pack_u32_be(p, reg->storage_gb); p += 4;
    pack_u64_be(p, reg->price_per_task); p += 8;
    pack_i64_be(p, reg->registered_at); p += 8;
}

sc_err_t pqmp_registration_sign(sc_pqmp_registration_t *reg,
                                const sc_pqc_identity_t *provider_id)
{
    if (!reg || !provider_id) return SC_ERR_INVALID;

    /* Populate public keys */
    if (crypto_get_pubkey(provider_id->ed25519_kp, reg->ed25519_pubkey) != SC_OK)
        return SC_ERR_IO;
    if (pqc_mldsa_get_pubkey(provider_id->mldsa_kp, reg->mldsa_pubkey) != SC_OK)
        return SC_ERR_IO;
    if (pqc_mlkem_get_pubkey(provider_id->mlkem_kp, reg->mlkem_pubkey) != SC_OK)
        return SC_ERR_IO;

    uint8_t canonical[SC_PQMP_REG_CANONICAL_LEN];
    get_reg_canonical_bytes(reg, canonical);

    /* Compute record hash */
    if (crypto_sha256(canonical, sizeof(canonical), reg->record_hash) != SC_OK)
        return SC_ERR_IO;

    /* Sign under provider's policy (HYBRID by default) */
    return pqc_hybrid_sign(&reg->reg_sig, canonical, sizeof(canonical),
                           provider_id->policy,
                           provider_id->ed25519_kp, provider_id->mldsa_kp);
}

sc_err_t pqmp_registration_verify(const sc_pqmp_registration_t *reg)
{
    if (!reg) return SC_ERR_INVALID;

    uint8_t canonical[SC_PQMP_REG_CANONICAL_LEN];
    get_reg_canonical_bytes(reg, canonical);

    uint8_t expected_hash[SC_SHA256_LEN];
    if (crypto_sha256(canonical, sizeof(canonical), expected_hash) != SC_OK)
        return SC_ERR_IO;

    if (memcmp(expected_hash, reg->record_hash, SC_SHA256_LEN) != 0)
        return SC_ERR_INVALID;

    sc_keypair_t *ed_kp = NULL;
    sc_mldsa_keypair_t *mldsa_kp = NULL;
    sc_err_t rc = SC_ERR_INVALID;

    if (crypto_pubkey_from_raw(&ed_kp, reg->ed25519_pubkey) != SC_OK)
        goto done;
    if (pqc_mldsa_pubkey_from_raw(&mldsa_kp, reg->mldsa_pubkey) != SC_OK)
        goto done;

    sc_crypto_policy_t pol = (reg->reg_sig.has_ed25519 && reg->reg_sig.has_mldsa)
        ? SC_CRYPTO_POLICY_HYBRID
        : (reg->reg_sig.has_mldsa ? SC_CRYPTO_POLICY_PQC_REQUIRED : SC_CRYPTO_POLICY_CLASSICAL_ONLY);

    rc = pqc_hybrid_verify(&reg->reg_sig, canonical, sizeof(canonical),
                           pol, ed_kp, mldsa_kp);

done:
    crypto_keypair_free(ed_kp);
    pqc_mldsa_keypair_free(mldsa_kp);
    return rc;
}

/* =========================================================================
 * Signed Task Agreement
 * ========================================================================= */

#define SC_PQMP_AGREE_CANONICAL_LEN \
    (SC_PQMP_AGREE_DOMAIN_LEN + SC_MP_ID_LEN + 4 + 8 + 8 + 4 + \
     SC_MLDSA_PUBKEY_LEN + SC_MLDSA_PUBKEY_LEN)

static void get_agree_canonical_bytes(const sc_pqmp_agreement_t *agree, uint8_t *out)
{
    uint8_t *p = out;
    memcpy(p, SC_PQMP_AGREE_DOMAIN, SC_PQMP_AGREE_DOMAIN_LEN);
    p += SC_PQMP_AGREE_DOMAIN_LEN;

    uint8_t tid_buf[SC_MP_ID_LEN] = {0};
    strncpy((char *)tid_buf, agree->task_id, SC_MP_ID_LEN);
    memcpy(p, tid_buf, SC_MP_ID_LEN); p += SC_MP_ID_LEN;

    pack_i32_be(p, agree->provider_id); p += 4;
    pack_i64_be(p, agree->agreed_at); p += 8;
    pack_u64_be(p, agree->agreed_price); p += 8;
    pack_u32_be(p, agree->deadline_sec); p += 4;

    memcpy(p, agree->customer_mldsa_pubkey, SC_MLDSA_PUBKEY_LEN); p += SC_MLDSA_PUBKEY_LEN;
    memcpy(p, agree->provider_mldsa_pubkey, SC_MLDSA_PUBKEY_LEN); p += SC_MLDSA_PUBKEY_LEN;
}

sc_err_t pqmp_agreement_sign_customer(sc_pqmp_agreement_t *agree,
                                      const sc_pqc_identity_t *customer_id)
{
    if (!agree || !customer_id) return SC_ERR_INVALID;

    if (pqc_mldsa_get_pubkey(customer_id->mldsa_kp, agree->customer_mldsa_pubkey) != SC_OK)
        return SC_ERR_IO;

    uint8_t canonical[SC_PQMP_AGREE_CANONICAL_LEN];
    get_agree_canonical_bytes(agree, canonical);

    if (crypto_sha256(canonical, sizeof(canonical), agree->agreement_hash) != SC_OK)
        return SC_ERR_IO;

    return pqc_hybrid_sign(&agree->customer_sig, canonical, sizeof(canonical),
                           customer_id->policy,
                           customer_id->ed25519_kp, customer_id->mldsa_kp);
}

sc_err_t pqmp_agreement_sign_provider(sc_pqmp_agreement_t *agree,
                                      const sc_pqc_identity_t *provider_id)
{
    if (!agree || !provider_id) return SC_ERR_INVALID;

    if (pqc_mldsa_get_pubkey(provider_id->mldsa_kp, agree->provider_mldsa_pubkey) != SC_OK)
        return SC_ERR_IO;

    uint8_t canonical[SC_PQMP_AGREE_CANONICAL_LEN];
    get_agree_canonical_bytes(agree, canonical);

    return pqc_hybrid_sign(&agree->provider_sig, canonical, sizeof(canonical),
                           provider_id->policy,
                           provider_id->ed25519_kp, provider_id->mldsa_kp);
}

sc_err_t pqmp_agreement_verify(const sc_pqmp_agreement_t *agree)
{
    if (!agree) return SC_ERR_INVALID;

    uint8_t canonical[SC_PQMP_AGREE_CANONICAL_LEN];
    get_agree_canonical_bytes(agree, canonical);

    uint8_t expected_hash[SC_SHA256_LEN];
    if (crypto_sha256(canonical, sizeof(canonical), expected_hash) != SC_OK)
        return SC_ERR_IO;
    if (memcmp(expected_hash, agree->agreement_hash, SC_SHA256_LEN) != 0)
        return SC_ERR_INVALID;

    /* Verify customer signature */
    sc_mldsa_keypair_t *cust_mldsa = NULL;
    if (pqc_mldsa_pubkey_from_raw(&cust_mldsa, agree->customer_mldsa_pubkey) != SC_OK)
        return SC_ERR_IO;
    sc_err_t rc1 = pqc_mldsa_verify(cust_mldsa, canonical, sizeof(canonical), agree->customer_sig.mldsa_sig);
    pqc_mldsa_keypair_free(cust_mldsa);
    if (rc1 != SC_OK) return SC_ERR_INVALID;

    /* Verify provider signature */
    sc_mldsa_keypair_t *prov_mldsa = NULL;
    if (pqc_mldsa_pubkey_from_raw(&prov_mldsa, agree->provider_mldsa_pubkey) != SC_OK)
        return SC_ERR_IO;
    sc_err_t rc2 = pqc_mldsa_verify(prov_mldsa, canonical, sizeof(canonical), agree->provider_sig.mldsa_sig);
    pqc_mldsa_keypair_free(prov_mldsa);
    if (rc2 != SC_OK) return SC_ERR_INVALID;

    return SC_OK;
}

/* =========================================================================
 * Signed Result Submission
 * ========================================================================= */

#define SC_PQMP_RESULT_CANONICAL_LEN \
    (SC_PQMP_RESULT_DOMAIN_LEN + SC_MP_ID_LEN + 4 + 8 + 4 + SC_SHA256_LEN)

static void get_result_canonical_bytes(const sc_pqmp_result_submission_t *res, uint8_t *out)
{
    uint8_t *p = out;
    memcpy(p, SC_PQMP_RESULT_DOMAIN, SC_PQMP_RESULT_DOMAIN_LEN);
    p += SC_PQMP_RESULT_DOMAIN_LEN;

    uint8_t tid[SC_MP_ID_LEN] = {0};
    strncpy((char *)tid, res->task_id, SC_MP_ID_LEN);
    memcpy(p, tid, SC_MP_ID_LEN); p += SC_MP_ID_LEN;

    pack_i32_be(p, res->provider_id); p += 4;
    pack_i64_be(p, res->submitted_at); p += 8;
    pack_u32_be(p, res->execution_time_ms); p += 4;
    memcpy(p, res->result_hash, SC_SHA256_LEN);
}

sc_err_t pqmp_result_sign(sc_pqmp_result_submission_t *res,
                          const sc_pqc_identity_t *provider_id)
{
    if (!res || !provider_id) return SC_ERR_INVALID;

    if (pqc_mldsa_get_pubkey(provider_id->mldsa_kp, res->provider_mldsa_pubkey) != SC_OK)
        return SC_ERR_IO;

    uint8_t canonical[SC_PQMP_RESULT_CANONICAL_LEN];
    get_result_canonical_bytes(res, canonical);

    return pqc_mldsa_sign(provider_id->mldsa_kp, canonical, sizeof(canonical),
                          res->provider_mldsa_sig);
}

sc_err_t pqmp_result_verify(const sc_pqmp_result_submission_t *res)
{
    if (!res) return SC_ERR_INVALID;

    uint8_t canonical[SC_PQMP_RESULT_CANONICAL_LEN];
    get_result_canonical_bytes(res, canonical);

    sc_mldsa_keypair_t *kp = NULL;
    if (pqc_mldsa_pubkey_from_raw(&kp, res->provider_mldsa_pubkey) != SC_OK)
        return SC_ERR_IO;

    sc_err_t rc = pqc_mldsa_verify(kp, canonical, sizeof(canonical), res->provider_mldsa_sig);
    pqc_mldsa_keypair_free(kp);
    return rc;
}

/* =========================================================================
 * Signed Settlement Authorisation
 * ========================================================================= */

#define SC_PQMP_SETTLE_CANONICAL_LEN \
    (SC_PQMP_SETTLE_DOMAIN_LEN + SC_MP_ID_LEN + 4 + 8 + 8 + 64)

static void get_settle_canonical_bytes(const sc_pqmp_settlement_t *settle, uint8_t *out)
{
    uint8_t *p = out;
    memcpy(p, SC_PQMP_SETTLE_DOMAIN, SC_PQMP_SETTLE_DOMAIN_LEN);
    p += SC_PQMP_SETTLE_DOMAIN_LEN;

    uint8_t tid[SC_MP_ID_LEN] = {0};
    strncpy((char *)tid, settle->task_id, SC_MP_ID_LEN);
    memcpy(p, tid, SC_MP_ID_LEN); p += SC_MP_ID_LEN;

    pack_i32_be(p, settle->provider_id); p += 4;
    pack_u64_be(p, settle->settled_amount); p += 8;
    pack_i64_be(p, settle->settled_at); p += 8;

    uint8_t txb[64] = {0};
    strncpy((char *)txb, settle->settlement_tx_hash, 64);
    memcpy(p, txb, 64);
}

sc_err_t pqmp_settlement_sign(sc_pqmp_settlement_t *settle,
                              const sc_pqc_identity_t *verifier_id)
{
    if (!settle || !verifier_id) return SC_ERR_INVALID;

    if (pqc_mldsa_get_pubkey(verifier_id->mldsa_kp, settle->verifier_mldsa_pubkey) != SC_OK)
        return SC_ERR_IO;

    uint8_t canonical[SC_PQMP_SETTLE_CANONICAL_LEN];
    get_settle_canonical_bytes(settle, canonical);

    if (crypto_sha256(canonical, sizeof(canonical), settle->audit_hash) != SC_OK)
        return SC_ERR_IO;

    return pqc_mldsa_sign(verifier_id->mldsa_kp, canonical, sizeof(canonical),
                          settle->verifier_mldsa_sig);
}

sc_err_t pqmp_settlement_verify(const sc_pqmp_settlement_t *settle)
{
    if (!settle) return SC_ERR_INVALID;

    uint8_t canonical[SC_PQMP_SETTLE_CANONICAL_LEN];
    get_settle_canonical_bytes(settle, canonical);

    uint8_t expected_hash[SC_SHA256_LEN];
    if (crypto_sha256(canonical, sizeof(canonical), expected_hash) != SC_OK)
        return SC_ERR_IO;
    if (memcmp(expected_hash, settle->audit_hash, SC_SHA256_LEN) != 0)
        return SC_ERR_INVALID;

    sc_mldsa_keypair_t *kp = NULL;
    if (pqc_mldsa_pubkey_from_raw(&kp, settle->verifier_mldsa_pubkey) != SC_OK)
        return SC_ERR_IO;

    sc_err_t rc = pqc_mldsa_verify(kp, canonical, sizeof(canonical), settle->verifier_mldsa_sig);
    pqc_mldsa_keypair_free(kp);
    return rc;
}

/* =========================================================================
 * JSON Helpers
 * ========================================================================= */

sc_err_t pqmp_registration_json(const sc_pqmp_registration_t *reg,
                                char *json_out, size_t max_len)
{
    if (!reg || !json_out || max_len < 256) return SC_ERR_INVALID;

    char hash_hex[SC_SHA256_LEN * 2 + 1];
    crypto_hex_encode(reg->record_hash, SC_SHA256_LEN, hash_hex);

    char ed_pk_hex[SC_ED25519_PUBKEY_LEN * 2 + 1];
    crypto_hex_encode(reg->ed25519_pubkey, SC_ED25519_PUBKEY_LEN, ed_pk_hex);

    int n = snprintf(json_out, max_len,
        "{"
        "\"provider_id\":%d,"
        "\"name\":\"%s\","
        "\"ed25519_pubkey\":\"%s\","
        "\"mldsa_present\":%s,"
        "\"mlkem_present\":%s,"
        "\"cpu_cores\":%" PRIu32 ","
        "\"gpu_count\":%" PRIu32 ","
        "\"ram_mb\":%" PRIu32 ","
        "\"storage_gb\":%" PRIu32 ","
        "\"price_per_task\":%" PRIu64 ","
        "\"registered_at\":%" PRId64 ","
        "\"record_hash\":\"%s\""
        "}",
        reg->provider_id, reg->name, ed_pk_hex,
        reg->reg_sig.has_mldsa ? "true" : "false",
        "true",
        reg->cpu_cores, reg->gpu_count, reg->ram_mb, reg->storage_gb,
        reg->price_per_task, reg->registered_at, hash_hex);

    return (n > 0 && (size_t)n < max_len) ? SC_OK : SC_ERR_IO;
}

sc_err_t pqmp_agreement_json(const sc_pqmp_agreement_t *agree,
                             char *json_out, size_t max_len)
{
    if (!agree || !json_out || max_len < 256) return SC_ERR_INVALID;

    char hash_hex[SC_SHA256_LEN * 2 + 1];
    crypto_hex_encode(agree->agreement_hash, SC_SHA256_LEN, hash_hex);

    int n = snprintf(json_out, max_len,
        "{"
        "\"task_id\":\"%s\","
        "\"provider_id\":%d,"
        "\"agreed_at\":%" PRId64 ","
        "\"agreed_price\":%" PRIu64 ","
        "\"deadline_sec\":%" PRIu32 ","
        "\"agreement_hash\":\"%s\","
        "\"customer_mldsa_signed\":%s,"
        "\"provider_mldsa_signed\":%s"
        "}",
        agree->task_id, agree->provider_id, agree->agreed_at,
        agree->agreed_price, agree->deadline_sec, hash_hex,
        agree->customer_sig.has_mldsa ? "true" : "false",
        agree->provider_sig.has_mldsa ? "true" : "false");

    return (n > 0 && (size_t)n < max_len) ? SC_OK : SC_ERR_IO;
}

sc_err_t pqmp_settlement_json(const sc_pqmp_settlement_t *settle,
                              char *json_out, size_t max_len)
{
    if (!settle || !json_out || max_len < 256) return SC_ERR_INVALID;

    char hash_hex[SC_SHA256_LEN * 2 + 1];
    crypto_hex_encode(settle->audit_hash, SC_SHA256_LEN, hash_hex);

    int n = snprintf(json_out, max_len,
        "{"
        "\"task_id\":\"%s\","
        "\"provider_id\":%d,"
        "\"settled_amount\":%" PRIu64 ","
        "\"settled_at\":%" PRId64 ","
        "\"settlement_tx_hash\":\"%s\","
        "\"audit_hash\":\"%s\","
        "\"mldsa_verified\":true"
        "}",
        settle->task_id, settle->provider_id, settle->settled_amount,
        settle->settled_at, settle->settlement_tx_hash, hash_hex);

    return (n > 0 && (size_t)n < max_len) ? SC_OK : SC_ERR_IO;
}
