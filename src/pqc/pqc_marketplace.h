/* pqc_marketplace.h — Post-Quantum Marketplace Identity and Agreement Layer.
 *
 * Feature 5: Post-Quantum Computing Marketplace.
 *
 * Extends the existing marketplace.h with:
 *   - Post-quantum provider identities (ML-DSA-65)
 *   - Authenticated provider registration records
 *   - Signed task agreements and acceptance records
 *   - Signed result submissions
 *   - Signed settlement authorisations
 *   - Integrity-protected audit records
 *
 * The actual computing workloads remain off-chain.
 * No large AI computations are run inside the blockchain consensus process.
 *
 * Canonical domain separators (prevent cross-domain signature confusion):
 *   Provider registration:  "SCMP_REG/v1"   (11 bytes)
 *   Task agreement:         "SCMP_AGREE/v1" (13 bytes)
 *   Task acceptance:        "SCMP_ACCEPT/v1" (14 bytes)
 *   Result submission:      "SCMP_RESULT/v1" (14 bytes)
 *   Settlement auth:        "SCMP_SETTLE/v1" (14 bytes)
 */
#ifndef SC_PQC_MARKETPLACE_H
#define SC_PQC_MARKETPLACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../err.h"
#include "../crypto.h"
#include "../marketplace.h"
#include "pqc_crypto.h"

/* =========================================================================
 * Signed provider registration record
 * ========================================================================= */

#define SC_PQMP_REG_DOMAIN      "SCMP_REG/v1"
#define SC_PQMP_REG_DOMAIN_LEN  11

typedef struct {
    int32_t  provider_id;
    char     name[64];

    /* Classical Ed25519 identity (embedded in existing marketplace) */
    uint8_t  ed25519_pubkey[SC_ED25519_PUBKEY_LEN];

    /* Post-quantum ML-DSA-65 identity */
    uint8_t  mldsa_pubkey[SC_MLDSA_PUBKEY_LEN];

    /* ML-KEM-768 public key (for secure provider ↔ customer comms) */
    uint8_t  mlkem_pubkey[SC_MLKEM_PUBKEY_LEN];

    uint32_t cpu_cores;
    uint32_t gpu_count;
    uint32_t ram_mb;
    uint32_t storage_gb;
    uint64_t price_per_task;
    int64_t  registered_at;

    /* Hybrid signature covering canonical registration payload */
    sc_hybrid_sig_t reg_sig;

    /* SHA-256 of canonical registration payload */
    uint8_t  record_hash[SC_SHA256_LEN];
} sc_pqmp_registration_t;

/* Sign a provider registration record.
 * provider_id must register itself; this proves key possession. */
sc_err_t pqmp_registration_sign(sc_pqmp_registration_t *reg,
                                  const sc_pqc_identity_t *provider_id);

/* Verify a provider registration record. */
sc_err_t pqmp_registration_verify(const sc_pqmp_registration_t *reg);

/* =========================================================================
 * Signed task agreement
 * ========================================================================= */

#define SC_PQMP_AGREE_DOMAIN     "SCMP_AGREE/v1"
#define SC_PQMP_AGREE_DOMAIN_LEN 13

typedef struct {
    char     task_id[SC_MP_ID_LEN + 1];
    int32_t  provider_id;
    int64_t  agreed_at;
    uint64_t agreed_price;
    uint32_t deadline_sec;

    /* Customer's ML-DSA-65 public key (signs the offer) */
    uint8_t  customer_mldsa_pubkey[SC_MLDSA_PUBKEY_LEN];
    /* Provider's ML-DSA-65 public key (signs acceptance) */
    uint8_t  provider_mldsa_pubkey[SC_MLDSA_PUBKEY_LEN];

    /* Customer signs the task parameters */
    sc_hybrid_sig_t customer_sig;
    /* Provider signs the acceptance */
    sc_hybrid_sig_t provider_sig;

    uint8_t  agreement_hash[SC_SHA256_LEN];
} sc_pqmp_agreement_t;

/* Customer signs the task agreement offer. */
sc_err_t pqmp_agreement_sign_customer(sc_pqmp_agreement_t *agree,
                                       const sc_pqc_identity_t *customer_id);

/* Provider signs the task agreement acceptance. */
sc_err_t pqmp_agreement_sign_provider(sc_pqmp_agreement_t *agree,
                                       const sc_pqc_identity_t *provider_id);

/* Verify both customer and provider signatures on an agreement. */
sc_err_t pqmp_agreement_verify(const sc_pqmp_agreement_t *agree);

/* =========================================================================
 * Signed result submission
 * ========================================================================= */

#define SC_PQMP_RESULT_DOMAIN     "SCMP_RESULT/v1"
#define SC_PQMP_RESULT_DOMAIN_LEN 14

typedef struct {
    char     task_id[SC_MP_ID_LEN + 1];
    int32_t  provider_id;
    int64_t  submitted_at;
    uint32_t execution_time_ms;

    /* SHA-256 of the actual computation result payload */
    uint8_t  result_hash[SC_SHA256_LEN];
    char     result_hash_hex[SC_SHA256_LEN * 2 + 1];

    /* Provider's ML-DSA-65 signature over (domain || task_id || result_hash) */
    uint8_t  provider_mldsa_pubkey[SC_MLDSA_PUBKEY_LEN];
    uint8_t  provider_mldsa_sig[SC_MLDSA_SIG_LEN];
} sc_pqmp_result_submission_t;

sc_err_t pqmp_result_sign(sc_pqmp_result_submission_t *res,
                            const sc_pqc_identity_t *provider_id);

sc_err_t pqmp_result_verify(const sc_pqmp_result_submission_t *res);

/* =========================================================================
 * Signed settlement authorisation
 * ========================================================================= */

#define SC_PQMP_SETTLE_DOMAIN     "SCMP_SETTLE/v1"
#define SC_PQMP_SETTLE_DOMAIN_LEN 14

typedef struct {
    char     task_id[SC_MP_ID_LEN + 1];
    int32_t  provider_id;
    uint64_t settled_amount;
    int64_t  settled_at;
    char     settlement_tx_hash[SC_SHA256_LEN * 2 + 1];

    /* Verifier's ML-DSA-65 signature confirms the result was verified correct */
    uint8_t  verifier_mldsa_pubkey[SC_MLDSA_PUBKEY_LEN];
    uint8_t  verifier_mldsa_sig[SC_MLDSA_SIG_LEN];

    /* SHA-256 audit record hash */
    uint8_t  audit_hash[SC_SHA256_LEN];
} sc_pqmp_settlement_t;

sc_err_t pqmp_settlement_sign(sc_pqmp_settlement_t *settle,
                                const sc_pqc_identity_t *verifier_id);

sc_err_t pqmp_settlement_verify(const sc_pqmp_settlement_t *settle);

/* =========================================================================
 * JSON serialisation for dashboard
 * ========================================================================= */

sc_err_t pqmp_registration_json(const sc_pqmp_registration_t *reg,
                                  char *json_out, size_t max_len);

sc_err_t pqmp_agreement_json(const sc_pqmp_agreement_t *agree,
                               char *json_out, size_t max_len);

sc_err_t pqmp_settlement_json(const sc_pqmp_settlement_t *settle,
                                char *json_out, size_t max_len);

#endif /* SC_PQC_MARKETPLACE_H */
