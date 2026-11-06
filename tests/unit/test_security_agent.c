/* test_security_agent.c - Unit tests for AI Security Agent and Telemetry.
 *
 * Part 3 Verification.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "err.h"
#include "log.h"
#include "security/incident.h"
#include "security/node_guard.h"
#include "security/sec_agent.h"
#include "testutil.h"

static void test_agent_dos_anomaly_detection(void)
{
    sc_keypair_t *agent_kp = NULL;
    CHECK(crypto_keygen(&agent_kp) == SC_OK);

    sc_sec_agent_t *agent = NULL;
    CHECK(sec_agent_create(&agent, agent_kp) == SC_OK);

    /* Normal traffic below threshold should NOT trigger incident */
    for (int i = 0; i < SC_AGENT_CONN_THRESHOLD - 2; i++) {
        sc_telemetry_event_t evt = {
            .peer_id = 3,
            .event_type = SC_EVT_CONN_ATTEMPT,
            .timestamp_ms = 1000
        };
        CHECK(sec_agent_process_event(agent, &evt) == SC_OK);
    }

    sc_action_request_t req;
    CHECK(sec_agent_generate_recommendation(agent, 3, &req) == SC_ERR_NOT_FOUND);

    /* Now exceed threshold */
    for (int i = 0; i < 4; i++) {
        sc_telemetry_event_t evt = {
            .peer_id = 3,
            .event_type = SC_EVT_CONN_ATTEMPT,
            .timestamp_ms = 1500
        };
        CHECK(sec_agent_process_event(agent, &evt) == SC_OK);
    }

    /* Recommendation MUST be generated */
    CHECK(sec_agent_generate_recommendation(agent, 3, &req) == SC_OK);
    CHECK(req.incident_type == SC_INCIDENT_DOS_FLOOD);
    CHECK(req.proposed_action == SC_ACT_TEMP_QUARANTINE);
    CHECK(req.category == SC_ACT_CAT_AUTO_PERMITTED);
    CHECK(req.target_node_id == 3);
    CHECK(req.param_duration_sec == 120);

    /* Verify signature is cryptographically valid */
    CHECK(action_request_verify(&req) == SC_OK);

    /* Tamper with target ID: verification MUST fail */
    req.target_node_id = 4;
    CHECK(action_request_verify(&req) == SC_ERR_INVALID);

    sec_agent_free(agent);
    crypto_keypair_free(agent_kp);
}

static void test_agent_equivocation_proof(void)
{
    sc_keypair_t *agent_kp = NULL;
    CHECK(crypto_keygen(&agent_kp) == SC_OK);

    sc_sec_agent_t *agent = NULL;
    CHECK(sec_agent_create(&agent, agent_kp) == SC_OK);

    const char *header1 = "VERTEX_HEADER_ROUND_5_HASH_AAA";
    const char *header2 = "VERTEX_HEADER_ROUND_5_HASH_BBB";

    sc_action_request_t req;
    CHECK(sec_agent_create_equivocation_request(agent, 0,
                                               header1, strlen(header1),
                                               header2, strlen(header2),
                                               &req) == SC_OK);

    CHECK(req.incident_type == SC_INCIDENT_VALIDATOR_EQUIVOCATION);
    CHECK(req.proposed_action == SC_ACT_REVOKE_VALIDATOR);
    /* MUST be categorized as HUMAN_REQUIRED */
    CHECK(req.category == SC_ACT_CAT_HUMAN_REQUIRED);
    CHECK(req.target_node_id == 0);

    /* Verify cryptographic signature over proof */
    CHECK(action_request_verify(&req) == SC_OK);

    sec_agent_free(agent);
    crypto_keypair_free(agent_kp);
}

static void test_node_guard_enforcement(void)
{
    sc_node_guard_t *guard = NULL;
    CHECK(node_guard_create(&guard, 0) == SC_OK);

    CHECK(!node_guard_is_quarantined(guard, 2));

    /* Apply a quarantine authorisation */
    sc_authorisation_t auth = {
        .action = SC_ACT_TEMP_QUARANTINE,
        .target_node_id = 2,
        .param_duration_sec = 60
    };
    CHECK(node_guard_apply_authorisation(guard, &auth) == SC_OK);

    CHECK(node_guard_is_quarantined(guard, 2));
    CHECK(!node_guard_is_quarantined(guard, 1));

    /* Apply a rate limit */
    sc_authorisation_t rate_auth = {
        .action = SC_ACT_APPLY_RATE_LIMIT,
        .target_node_id = 3,
        .param_rate_limit = 25
    };
    CHECK(node_guard_apply_authorisation(guard, &rate_auth) == SC_OK);
    CHECK(node_guard_get_rate_limit(guard, 3) == 25);
    CHECK(node_guard_get_rate_limit(guard, 4) == 500);

    node_guard_free(guard);
}

int main(void)
{
    log_init(-1);
    printf("test_security_agent\n");
    RUN(test_agent_dos_anomaly_detection);
    RUN(test_agent_equivocation_proof);
    RUN(test_node_guard_enforcement);
    return TEST_SUMMARY();
}
