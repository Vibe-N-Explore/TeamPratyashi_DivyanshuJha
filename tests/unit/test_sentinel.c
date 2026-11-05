/* test_sentinel.c - Unit tests for SovereignChain Project Sentinel
 *
 * Verifies all 5 Sentinel Advanced Security Features:
 *   Feature 1: Sovereign Security Control Room (Lifecycle & Telemetry)
 *   Feature 2: Unanimous Trust Demonstration (Disagreement, Unanimous, Human)
 *   Feature 3: Controlled Attack Replay Simulator (Replay Auth, Invalid Tx, Equivocation)
 *   Feature 4: Autonomous Self-Healing Network (Failure, Detection, Bounded Recovery)
 *   Feature 5: Permanent Security Memory & TCB DAG Auditing
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "err.h"
#include "log.h"
#include "sentinel_server.h"
#include "testutil.h"

static void test_sentinel_lifecycle(void)
{
    sc_sentinel_server_t *srv = NULL;
    CHECK(sentinel_server_create(&srv, "config/nodes.conf", 9988, ".") == SC_OK);
    CHECK(srv != NULL);

    /* Single poll step should succeed */
    CHECK(sentinel_server_poll_step(srv, 10) == SC_OK);

    sentinel_server_free(srv);
}

static void test_sentinel_trust_disagreement(void)
{
    sc_sentinel_server_t *srv = NULL;
    CHECK(sentinel_server_create(&srv, "config/nodes.conf", 9989, ".") == SC_OK);

    char json[4096];
    CHECK(sentinel_demo_trust_disagreement(srv, json, sizeof(json)) == SC_OK);

    /* Must contain prominent denial message and peer details */
    CHECK(strstr(json, "AUTHORISATION DENIED") != NULL);
    CHECK(strstr(json, "UNANIMOUS APPROVAL NOT ACHIEVED") != NULL);
    CHECK(strstr(json, "dissenting_peer\":1") != NULL);
    CHECK(strstr(json, "insufficient_anomaly_duration_threshold") != NULL);

    sentinel_server_free(srv);
}

static void test_sentinel_trust_unanimous(void)
{
    sc_sentinel_server_t *srv = NULL;
    CHECK(sentinel_server_create(&srv, "config/nodes.conf", 9990, ".") == SC_OK);

    char json[4096];
    CHECK(sentinel_demo_trust_unanimous(srv, json, sizeof(json)) == SC_OK);

    /* Must verify unanimous approval and DAG inclusion */
    CHECK(strstr(json, "UNANIMOUS AUTHORISATION ACHIEVED") != NULL);
    CHECK(strstr(json, "peer_count\":3") != NULL);
    CHECK(strstr(json, "TEMP_QUARANTINE") != NULL);
    CHECK(strstr(json, "AUTHORISED") != NULL);

    sentinel_server_free(srv);
}

static void test_sentinel_trust_human_and_resolve(void)
{
    sc_sentinel_server_t *srv = NULL;
    CHECK(sentinel_server_create(&srv, "config/nodes.conf", 9991, ".") == SC_OK);

    char json[4096];
    CHECK(sentinel_demo_trust_human(srv, json, sizeof(json)) == SC_OK);

    /* Must require human approval and remain pending */
    CHECK(strstr(json, "MANDATORY OPERATOR SIGN-OFF REQUIRED") != NULL);
    CHECK(strstr(json, "REVOKE_VALIDATOR") != NULL);
    CHECK(strstr(json, "ESCALATED") != NULL);

    /* Extract the request_id from json */
    char *p = strstr(json, "\"request_id\":\"");
    CHECK(p != NULL);
    p += 14;
    uint8_t req_bytes[SC_SHA256_LEN];
    for (int i = 0; i < SC_SHA256_LEN; i++) {
        unsigned int val = 0;
        sscanf(p + i * 2, "%02x", &val);
        req_bytes[i] = (uint8_t)val;
    }

    /* Operator resolves governance with legitimate escalated request ID */
    char resolve_json[2048];
    CHECK(sentinel_resolve_governance(srv, req_bytes, true, "Operator unit test sign-off",
                                      resolve_json, sizeof(resolve_json)) == SC_OK);
    CHECK(strstr(resolve_json, "APPROVED") != NULL);
    CHECK(strstr(resolve_json, "recorded_in_dag\":true") != NULL);

    sentinel_server_free(srv);
}

static void test_sentinel_attack_scenarios(void)
{
    sc_sentinel_server_t *srv = NULL;
    CHECK(sentinel_server_create(&srv, "config/nodes.conf", 9992, ".") == SC_OK);

    char json[4096];

    /* Scenario A: Replay Auth Handshake */
    CHECK(sentinel_demo_attack_replay_auth(srv, json, sizeof(json)) == SC_OK);
    CHECK(strstr(json, "REPLAY_AUTH") != NULL);
    CHECK(strstr(json, "DEFENDED") != NULL);

    /* Scenario B: Invalid Transaction Signature */
    CHECK(sentinel_demo_attack_invalid_tx(srv, json, sizeof(json)) == SC_OK);
    CHECK(strstr(json, "TAMPERED_TX_SIGNATURE") != NULL);
    CHECK(strstr(json, "DEFENDED") != NULL);

    /* Scenario C: Validator Equivocation */
    CHECK(sentinel_demo_attack_equivocation(srv, json, sizeof(json)) == SC_OK);
    CHECK(strstr(json, "VALIDATOR_EQUIVOCATION") != NULL);
    CHECK(strstr(json, "DETECTED") != NULL);

    sentinel_server_free(srv);
}

static void test_sentinel_self_healing(void)
{
    sc_sentinel_server_t *srv = NULL;
    CHECK(sentinel_server_create(&srv, "config/nodes.conf", 9993, ".") == SC_OK);

    char json[4096];
    CHECK(sentinel_demo_self_healing(srv, 3, json, sizeof(json)) == SC_OK);

    CHECK(strstr(json, "SELF_HEALING") != NULL);
    CHECK(strstr(json, "OPERATIONAL") != NULL);
    CHECK(strstr(json, "recovered_node\":3") != NULL);

    sentinel_server_free(srv);
}

int main(void)
{
    log_init(-1);
    printf("=== Running Sentinel Unit Tests ===\n");

    test_sentinel_lifecycle();
    test_sentinel_trust_disagreement();
    test_sentinel_trust_unanimous();
    test_sentinel_trust_human_and_resolve();
    test_sentinel_attack_scenarios();
    test_sentinel_self_healing();

    printf("ALL SENTINEL TESTS PASSED (6/6 suites)\n");
    return 0;
}
