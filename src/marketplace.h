/* marketplace.h - SovereignChain Decentralised Computing Marketplace.
 *
 * Implements the economic and operational computing layer:
 *   - Provider registration, resource discovery, capability catalog
 *   - Task creation, requirements specification, provider matching
 *   - Off-chain isolated workload execution (Math, Data, Image, AI)
 *   - Result verification (deterministic recomputation & proof verification)
 *   - Escrow reservation and settlement release
 *   - Provider reputation scoring and SLA tracking
 *   - Integration with Sovereign Security Control Room, TCB, and Permanent History
 */
#ifndef SC_MARKETPLACE_H
#define SC_MARKETPLACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "err.h"

#define SC_MP_MAX_PROVIDERS    32
#define SC_MP_MAX_TASKS        128
#define SC_MP_ID_LEN           64
#define SC_MP_PAYLOAD_MAX      4096
#define SC_SHA256_HEX_LEN      (SC_SHA256_LEN * 2)

typedef enum {
    SC_WORKLOAD_MATH   = 1, /* Matrix multiplication & deterministic algebra */
    SC_WORKLOAD_DATA   = 2, /* Dataset statistical aggregation and anomaly filtering */
    SC_WORKLOAD_IMAGE  = 3, /* Convolutional kernel & edge detection matrix */
    SC_WORKLOAD_AI     = 4  /* Neural network MLP forward pass & embedding inference */
} sc_workload_type_t;

typedef enum {
    SC_TASK_STATE_OPEN                = 0,
    SC_TASK_STATE_ASSIGNED            = 1,
    SC_TASK_STATE_ESCROW_RESERVED     = 2,
    SC_TASK_STATE_COMPUTING           = 3,
    SC_TASK_STATE_RESULT_SUBMITTED    = 4,
    SC_TASK_STATE_VERIFIED_SUCCESS    = 5,
    SC_TASK_STATE_SETTLED             = 6,
    SC_TASK_STATE_VERIFICATION_FAILED = 7,
    SC_TASK_STATE_DISPUTED            = 8
} sc_task_state_t;

typedef struct {
    int32_t  id;
    char     name[64];
    uint8_t  pubkey[SC_ED25519_PUBKEY_LEN];
    char     pubkey_hex[SC_PUBKEY_HEX_LEN + 1];
    uint32_t cpu_cores;
    char     gpu_model[64];
    uint32_t gpu_count;
    uint32_t ram_mb;
    uint32_t storage_gb;
    uint64_t price_per_task;
    bool     available;
    uint32_t tasks_completed;
    uint32_t tasks_failed;
    double   reputation_score; /* 0.0 to 100.0 */
    uint64_t total_earned;
    int64_t  registered_at;
} sc_mp_provider_t;

typedef struct {
    char               task_id[SC_MP_ID_LEN + 1];
    char               title[96];
    char               customer_name[64];
    uint8_t            customer_pubkey[SC_ED25519_PUBKEY_LEN];
    char               customer_pubkey_hex[SC_PUBKEY_HEX_LEN + 1];
    sc_workload_type_t workload;
    uint32_t           required_cpu;
    uint32_t           required_gpu;
    uint32_t           required_ram_mb;
    uint32_t           required_storage_gb;
    uint64_t           budget;
    uint32_t           deadline_sec;
    int64_t            created_at;
    
    int32_t            assigned_provider_id;
    sc_task_state_t    state;

    char               input_params[SC_MP_PAYLOAD_MAX];
    char               result_payload[SC_MP_PAYLOAD_MAX];
    uint8_t            proof_hash[SC_SHA256_LEN];
    char               proof_hash_hex[SC_SHA256_HEX_LEN + 1];
    uint32_t           execution_time_ms;

    char               verification_method[48];
    bool               verification_passed;
    char               verification_notes[256];

    uint64_t           settled_amount;
    char               settlement_tx_hash[SC_SHA256_HEX_LEN + 1];
    int64_t            settled_at;
} sc_mp_task_t;

typedef struct sc_marketplace sc_marketplace_t;

/* Initialize marketplace engine */
sc_err_t marketplace_create(sc_marketplace_t **mp_out, const char *state_dir);
void marketplace_free(sc_marketplace_t *mp);

/* Provider management */
sc_err_t marketplace_register_provider(sc_marketplace_t *mp,
                                       const char *name,
                                       const uint8_t pubkey[SC_ED25519_PUBKEY_LEN],
                                       uint32_t cpu_cores,
                                       const char *gpu_model,
                                       uint32_t gpu_count,
                                       uint32_t ram_mb,
                                       uint32_t storage_gb,
                                       uint64_t price_per_task,
                                       int32_t *provider_id_out);

/* Task management */
sc_err_t marketplace_create_task(sc_marketplace_t *mp,
                                 const char *title,
                                 const char *customer_name,
                                 const uint8_t customer_pubkey[SC_ED25519_PUBKEY_LEN],
                                 sc_workload_type_t workload,
                                 uint32_t req_cpu,
                                 uint32_t req_gpu,
                                 uint32_t req_ram_mb,
                                 uint32_t req_storage_gb,
                                 uint64_t budget,
                                 uint32_t deadline_sec,
                                 const char *input_params,
                                 char task_id_out[SC_MP_ID_LEN + 1]);

/* Matching and Allocation */
sc_err_t marketplace_find_matches_json(sc_marketplace_t *mp,
                                       const char *task_id,
                                       char *json_out,
                                       size_t max_len);

sc_err_t marketplace_assign_task(sc_marketplace_t *mp,
                                 const char *task_id,
                                 int32_t provider_id);

/* Task Execution */
sc_err_t marketplace_execute_task(sc_marketplace_t *mp,
                                  const char *task_id,
                                  bool simulate_fraud);

/* Result Verification */
sc_err_t marketplace_verify_task(sc_marketplace_t *mp,
                                 const char *task_id,
                                 bool *passed_out,
                                 char *notes_out,
                                 size_t notes_len);

/* Settlement Release */
sc_err_t marketplace_settle_task(sc_marketplace_t *mp,
                                 const char *task_id,
                                 char *tx_hash_out,
                                 size_t tx_hash_len);

/* JSON serialization helpers for HTTP API */
sc_err_t marketplace_get_overview_json(sc_marketplace_t *mp, char *json_out, size_t max_len);
sc_err_t marketplace_get_providers_json(sc_marketplace_t *mp, char *json_out, size_t max_len);
sc_err_t marketplace_get_tasks_json(sc_marketplace_t *mp, char *json_out, size_t max_len);
sc_err_t marketplace_get_task_detail_json(sc_marketplace_t *mp, const char *task_id, char *json_out, size_t max_len);
sc_err_t marketplace_get_reputation_json(sc_marketplace_t *mp, char *json_out, size_t max_len);

/* Persistence */
sc_err_t marketplace_save(sc_marketplace_t *mp);
sc_err_t marketplace_load(sc_marketplace_t *mp);

#endif /* SC_MARKETPLACE_H */
