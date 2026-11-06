/* test_marketplace.c - Unit tests for SovereignChain Decentralised Computing Marketplace.
 *
 * Verifies:
 *   - Provider registration, resource discovery, capability catalog
 *   - Task creation, requirements specification, provider matching
 *   - Off-chain isolated workload execution (Math, Data, Image, AI)
 *   - Result verification (deterministic recomputation & proof verification)
 *   - Fraud detection and reputation slashing
 *   - Escrow reservation and settlement release
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "err.h"
#include "log.h"
#include "marketplace.h"
#include "testutil.h"

static void test_marketplace_lifecycle(void)
{
    sc_marketplace_t *mp = NULL;
    CHECK(marketplace_create(&mp, "/tmp/mp_test_dir") == SC_OK);
    CHECK(mp != NULL);

    char overview[512];
    CHECK(marketplace_get_overview_json(mp, overview, sizeof(overview)) == SC_OK);
    CHECK(strstr(overview, "\"providers_count\":3") != NULL);
    CHECK(strstr(overview, "\"total_gpus\":3") != NULL);

    marketplace_free(mp);
}

static void test_marketplace_provider_registration(void)
{
    sc_marketplace_t *mp = NULL;
    CHECK(marketplace_create(&mp, "/tmp/mp_test_dir") == SC_OK);

    int32_t new_id = -1;
    sc_keypair_t *kp = NULL;
    crypto_keygen(&kp);
    uint8_t pubkey[SC_ED25519_PUBKEY_LEN];
    crypto_get_pubkey(kp, pubkey);

    CHECK(marketplace_register_provider(mp, "Decentralized-DGX-Node", pubkey, 128,
                                       "NVIDIA H100", 8, 524288, 8192, 500, &new_id) == SC_OK);
    CHECK(new_id == 3);

    char providers_json[8192];
    CHECK(marketplace_get_providers_json(mp, providers_json, sizeof(providers_json)) == SC_OK);
    CHECK(strstr(providers_json, "Decentralized-DGX-Node") != NULL);
    CHECK(strstr(providers_json, "NVIDIA H100") != NULL);

    crypto_keypair_free(kp);
    marketplace_free(mp);
}

static void test_marketplace_task_lifecycle_verified(void)
{
    sc_marketplace_t *mp = NULL;
    CHECK(marketplace_create(&mp, "/tmp/mp_test_dir") == SC_OK);

    char task_id[SC_MP_ID_LEN + 1];
    CHECK(marketplace_create_task(mp, "DeepSeek-Financial-Inference", "Goldman-AI-Lab", NULL,
                                 SC_WORKLOAD_AI, 16, 1, 32768, 100, 300, 3600,
                                 NULL, task_id) == SC_OK);
    CHECK(strlen(task_id) > 0);

    /* Match and Ranking */
    char matches_json[4096];
    CHECK(marketplace_find_matches_json(mp, task_id, matches_json, sizeof(matches_json)) == SC_OK);
    CHECK(strstr(matches_json, "\"eligible\":true") != NULL);

    /* Assign to Provider 1 */
    CHECK(marketplace_assign_task(mp, task_id, 1) == SC_OK);

    /* Execute without fraud */
    CHECK(marketplace_execute_task(mp, task_id, false) == SC_OK);

    /* Verify Result */
    bool passed = false;
    char notes[256];
    CHECK(marketplace_verify_task(mp, task_id, &passed, notes, sizeof(notes)) == SC_OK);
    CHECK(passed == true);
    CHECK(strstr(notes, "PASSED") != NULL);

    /* Settle Payment */
    char tx_hash[SC_SHA256_HEX_LEN + 1];
    CHECK(marketplace_settle_task(mp, task_id, tx_hash, sizeof(tx_hash)) == SC_OK);
    CHECK(strlen(tx_hash) == 64);

    marketplace_free(mp);
}

static void test_marketplace_fraud_detection(void)
{
    sc_marketplace_t *mp = NULL;
    CHECK(marketplace_create(&mp, "/tmp/mp_test_dir") == SC_OK);

    char task_id[SC_MP_ID_LEN + 1];
    CHECK(marketplace_create_task(mp, "Autonomous-Driving-Perception", "RoboTaxi-Corp", NULL,
                                 SC_WORKLOAD_IMAGE, 8, 0, 16384, 50, 150, 3600,
                                 NULL, task_id) == SC_OK);

    CHECK(marketplace_assign_task(mp, task_id, 2) == SC_OK);

    /* Dishonest provider attempts to submit spoofed/tampered result */
    CHECK(marketplace_execute_task(mp, task_id, true) == SC_OK);

    bool passed = true;
    char notes[256];
    CHECK(marketplace_verify_task(mp, task_id, &passed, notes, sizeof(notes)) == SC_OK);
    CHECK(passed == false);
    CHECK(strstr(notes, "FAILED") != NULL);

    /* Settle should be rejected on failed task */
    char tx_hash[SC_SHA256_HEX_LEN + 1];
    CHECK(marketplace_settle_task(mp, task_id, tx_hash, sizeof(tx_hash)) == SC_ERR_INVALID);

    marketplace_free(mp);
}

static void test_all_workload_types(void)
{
    sc_marketplace_t *mp = NULL;
    CHECK(marketplace_create(&mp, "/tmp/mp_test_dir") == SC_OK);

    sc_workload_type_t workloads[4] = {
        SC_WORKLOAD_MATH,
        SC_WORKLOAD_DATA,
        SC_WORKLOAD_IMAGE,
        SC_WORKLOAD_AI
    };

    for (int i = 0; i < 4; i++) {
        char task_id[SC_MP_ID_LEN + 1];
        CHECK(marketplace_create_task(mp, "Multi-Workload-Bench", "TestClient", NULL,
                                     workloads[i], 4, 0, 4096, 10, 200, 1800,
                                     NULL, task_id) == SC_OK);
        CHECK(marketplace_assign_task(mp, task_id, 0) == SC_OK);
        CHECK(marketplace_execute_task(mp, task_id, false) == SC_OK);

        bool passed = false;
        char notes[256];
        CHECK(marketplace_verify_task(mp, task_id, &passed, notes, sizeof(notes)) == SC_OK);
        CHECK(passed == true);

        char tx_hash[SC_SHA256_HEX_LEN + 1];
        CHECK(marketplace_settle_task(mp, task_id, tx_hash, sizeof(tx_hash)) == SC_OK);
    }

    marketplace_free(mp);
}

int main(void)
{
    log_init(-1);
    printf("=== Running Marketplace Unit Tests ===\n");

    RUN(test_marketplace_lifecycle);
    RUN(test_marketplace_provider_registration);
    RUN(test_marketplace_task_lifecycle_verified);
    RUN(test_marketplace_fraud_detection);
    RUN(test_all_workload_types);

    return TEST_SUMMARY();
}
