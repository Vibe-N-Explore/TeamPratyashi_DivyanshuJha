/* test_tcb_policy.c - Unit tests for Deterministic TCB Policy Engine.
 *
 * Part 3 Verification: Anti-replay, untrusted agent rejection, evidence checks,
 * parameter bounds, and governance boundary enforcement.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto.h"
#include "err.h"
#include "log.h"
#include "security/incident.h"
#include "security/sec_agent.h"
#include "tcb/decision.h"
#include "tcb/tcb_policy.h"
#include "testutil.h"

static void test_policy_trusted_agent_and_signature(void)
{
    sc_keypair_t *agent_kp = NULL;
    sc_keypair_t *rogue_kp = NULL;
    sc_keypair_t *tcb_kp = NULL;
    CHECK(crypto_keygen(&agent_kp) == SC_OK);
    CHECK(crypto_keygen(&rogue_kp) == SC_OK);
    CHECK(crypto_keygen(&tcb_kp) == SC_OK);

    uint8_t agent_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(agent_kp, agent_pub) == SC_OK);

    sc_tcb_policy_t policy;
    CHECK(tcb_policy_init(&policy) == SC_OK);
    CHECK(tcb_policy_add_agent(&policy, agent_pub) == SC_OK);

    /* Case A: Trusted agent creates valid action request */
    sc_action_request_t req;
    memset(&req, 0, sizeof(req));
    req.timestamp = (uint64_t)time(NULL);
    req.incident_type = SC_INCIDENT_DOS_FLOOD;
    req.proposed_action = SC_ACT_TEMP_QUARANTINE;
    req.category = SC_ACT_CAT_AUTO_PERMITTED;
    req.target_node_id = 3;
    req.param_duration_sec = 60;
    snprintf(req.reason, sizeof(req.reason), "Excessive connection flood");
    snprintf((char *)req.evidence, sizeof(req.evidence), "peer=3 count=50");
    req.evidence_len = (uint32_t)strlen((char *)req.evidence);

    CHECK(action_request_sign(&req, agent_kp) == SC_OK);

    sc_tcb_decision_t decision;
    CHECK(tcb_policy_evaluate(&policy, tcb_kp, 0, &req, &decision) == SC_OK);
    CHECK(decision.verdict == TCB_VERDICT_APPROVE);
    CHECK(tcb_decision_verify(&decision) == SC_OK);

    /* Case B: Rogue agent not registered in policy */
    sc_action_request_t rogue_req;
    memset(&rogue_req, 0, sizeof(rogue_req));
    rogue_req.timestamp = (uint64_t)time(NULL);
    rogue_req.incident_type = SC_INCIDENT_DOS_FLOOD;
    rogue_req.proposed_action = SC_ACT_TEMP_QUARANTINE;
    rogue_req.category = SC_ACT_CAT_AUTO_PERMITTED;
    rogue_req.target_node_id = 3;
    rogue_req.param_duration_sec = 60;
    snprintf(rogue_req.reason, sizeof(rogue_req.reason), "Fake incident");
    snprintf((char *)rogue_req.evidence, sizeof(rogue_req.evidence), "fake");
    rogue_req.evidence_len = 4;

    CHECK(action_request_sign(&rogue_req, rogue_kp) == SC_OK);

    sc_tcb_decision_t rogue_decision;
    CHECK(tcb_policy_evaluate(&policy, tcb_kp, 0, &rogue_req, &rogue_decision) == SC_OK);
    CHECK(rogue_decision.verdict == TCB_VERDICT_REJECT);
    CHECK(strstr(rogue_decision.reason, "untrusted_agent") != NULL);

    crypto_keypair_free(agent_kp);
    crypto_keypair_free(rogue_kp);
    crypto_keypair_free(tcb_kp);
}

static void test_policy_anti_replay_and_freshness(void)
{
    sc_keypair_t *agent_kp = NULL;
    sc_keypair_t *tcb_kp = NULL;
    CHECK(crypto_keygen(&agent_kp) == SC_OK);
    CHECK(crypto_keygen(&tcb_kp) == SC_OK);

    uint8_t agent_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(agent_kp, agent_pub) == SC_OK);

    sc_tcb_policy_t policy;
    CHECK(tcb_policy_init(&policy) == SC_OK);
    CHECK(tcb_policy_add_agent(&policy, agent_pub) == SC_OK);

    sc_action_request_t req;
    memset(&req, 0, sizeof(req));
    req.timestamp = (uint64_t)time(NULL);
    req.incident_type = SC_INCIDENT_DOS_FLOOD;
    req.proposed_action = SC_ACT_APPLY_RATE_LIMIT;
    req.category = SC_ACT_CAT_AUTO_PERMITTED;
    req.target_node_id = 4;
    req.param_rate_limit = 50;
    snprintf(req.reason, sizeof(req.reason), "High rate of transactions");
    snprintf((char *)req.evidence, sizeof(req.evidence), "tx_rate=500");
    req.evidence_len = (uint32_t)strlen((char *)req.evidence);

    CHECK(action_request_sign(&req, agent_kp) == SC_OK);

    /* First evaluation: APPROVED */
    sc_tcb_decision_t dec1;
    CHECK(tcb_policy_evaluate(&policy, tcb_kp, 0, &req, &dec1) == SC_OK);
    CHECK(dec1.verdict == TCB_VERDICT_APPROVE);

    /* Replaying same request: MUST BE REJECTED */
    sc_tcb_decision_t dec2;
    CHECK(tcb_policy_evaluate(&policy, tcb_kp, 0, &req, &dec2) == SC_OK);
    CHECK(dec2.verdict == TCB_VERDICT_REJECT);
    CHECK(strstr(dec2.reason, "replayed_request") != NULL);

    /* Test Stale Timestamp */
    sc_action_request_t stale_req;
    memset(&stale_req, 0, sizeof(stale_req));
    stale_req.timestamp = (uint64_t)time(NULL) - 3600; /* 1 hour in the past */
    stale_req.incident_type = SC_INCIDENT_DOS_FLOOD;
    stale_req.proposed_action = SC_ACT_APPLY_RATE_LIMIT;
    stale_req.category = SC_ACT_CAT_AUTO_PERMITTED;
    stale_req.target_node_id = 5;
    stale_req.param_rate_limit = 50;
    snprintf(stale_req.reason, sizeof(stale_req.reason), "Stale event");
    snprintf((char *)stale_req.evidence, sizeof(stale_req.evidence), "evidence");
    stale_req.evidence_len = 8;
    CHECK(action_request_sign(&stale_req, agent_kp) == SC_OK);

    sc_tcb_decision_t dec3;
    CHECK(tcb_policy_evaluate(&policy, tcb_kp, 0, &stale_req, &dec3) == SC_OK);
    CHECK(dec3.verdict == TCB_VERDICT_REJECT);
    CHECK(strstr(dec3.reason, "stale_request_timestamp") != NULL);

    crypto_keypair_free(agent_kp);
    crypto_keypair_free(tcb_kp);
}

static void test_policy_governance_boundary_and_bounds(void)
{
    sc_keypair_t *agent_kp = NULL;
    sc_keypair_t *tcb_kp = NULL;
    CHECK(crypto_keygen(&agent_kp) == SC_OK);
    CHECK(crypto_keygen(&tcb_kp) == SC_OK);

    uint8_t agent_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(agent_kp, agent_pub) == SC_OK);

    sc_tcb_policy_t policy;
    CHECK(tcb_policy_init(&policy) == SC_OK);
    CHECK(tcb_policy_add_agent(&policy, agent_pub) == SC_OK);

    /* Attack: Trying to revoke validator as AUTO_PERMITTED without human escalation */
    sc_action_request_t bad_gov_req;
    memset(&bad_gov_req, 0, sizeof(bad_gov_req));
    bad_gov_req.timestamp = (uint64_t)time(NULL);
    bad_gov_req.incident_type = SC_INCIDENT_VALIDATOR_EQUIVOCATION;
    bad_gov_req.proposed_action = SC_ACT_REVOKE_VALIDATOR;
    bad_gov_req.category = SC_ACT_CAT_AUTO_PERMITTED; /* ILLEGAL: Governance cannot be auto! */
    bad_gov_req.target_node_id = 1;
    snprintf(bad_gov_req.reason, sizeof(bad_gov_req.reason), "Unauthorized auto revoke attempt");
    snprintf((char *)bad_gov_req.evidence, sizeof(bad_gov_req.evidence), "equivocation_proof");
    bad_gov_req.evidence_len = 18;
    CHECK(action_request_sign(&bad_gov_req, agent_kp) == SC_OK);

    sc_tcb_decision_t dec;
    CHECK(tcb_policy_evaluate(&policy, tcb_kp, 0, &bad_gov_req, &dec) == SC_OK);
    CHECK(dec.verdict == TCB_VERDICT_REJECT);
    CHECK(strstr(dec.reason, "requires_human") != NULL);

    /* Test Quarantine Parameter Bounds: 100,000 seconds exceeds max 600s */
    sc_action_request_t bad_bound_req;
    memset(&bad_bound_req, 0, sizeof(bad_bound_req));
    bad_bound_req.timestamp = (uint64_t)time(NULL);
    bad_bound_req.incident_type = SC_INCIDENT_DOS_FLOOD;
    bad_bound_req.proposed_action = SC_ACT_TEMP_QUARANTINE;
    bad_bound_req.category = SC_ACT_CAT_AUTO_PERMITTED;
    bad_bound_req.target_node_id = 2;
    bad_bound_req.param_duration_sec = 100000; /* OUT OF BOUNDS */
    snprintf(bad_bound_req.reason, sizeof(bad_bound_req.reason), "Excessive quarantine");
    snprintf((char *)bad_bound_req.evidence, sizeof(bad_bound_req.evidence), "evidence");
    bad_bound_req.evidence_len = 8;
    CHECK(action_request_sign(&bad_bound_req, agent_kp) == SC_OK);

    CHECK(tcb_policy_evaluate(&policy, tcb_kp, 0, &bad_bound_req, &dec) == SC_OK);
    CHECK(dec.verdict == TCB_VERDICT_REJECT);
    CHECK(strstr(dec.reason, "out_of_bounds") != NULL);

    crypto_keypair_free(agent_kp);
    crypto_keypair_free(tcb_kp);
}

int main(void)
{
    log_init(-1);
    printf("test_tcb_policy\n");
    RUN(test_policy_trusted_agent_and_signature);
    RUN(test_policy_anti_replay_and_freshness);
    RUN(test_policy_governance_boundary_and_bounds);
    return TEST_SUMMARY();
}
