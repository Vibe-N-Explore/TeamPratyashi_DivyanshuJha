/* test_tcb_consensus.c - Unit tests for Distributed TCB consensus and human escalation.
 *
 * Part 3 & 4 Verification:
 *   1. Unanimous approval requirement (all 3 peers must approve)
 *   2. Safe pending state (missing/silent peer prevents execution)
 *   3. Disagreement / single peer rejection stops action
 *   4. Human governance escalation for validator revocation
 *   5. Node guard execution of unanimous authorisations
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
#include "security/node_guard.h"
#include "security/sec_agent.h"
#include "tcb/decision.h"
#include "tcb/tcb_peer.h"
#include "testutil.h"

static void test_tcb_unanimous_approval_and_pending(void)
{
    sc_keypair_t *agent_kp = NULL;
    sc_keypair_t *peer_kp[3];
    uint8_t peer_pub[3][SC_ED25519_PUBKEY_LEN];

    CHECK(crypto_keygen(&agent_kp) == SC_OK);
    uint8_t agent_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(agent_kp, agent_pub) == SC_OK);

    for (int i = 0; i < 3; i++) {
        CHECK(crypto_keygen(&peer_kp[i]) == SC_OK);
        CHECK(crypto_get_pubkey(peer_kp[i], peer_pub[i]) == SC_OK);
    }

    sc_tcb_peer_t *peers[3];
    for (int i = 0; i < 3; i++) {
        CHECK(tcb_peer_create(&peers[i], i, peer_kp[i], 3) == SC_OK);
        CHECK(tcb_peer_register_agent(peers[i], agent_pub) == SC_OK);
        for (int j = 0; j < 3; j++) {
            CHECK(tcb_peer_register_network_peer(peers[i], j, peer_pub[j]) == SC_OK);
        }
    }

    /* Agent generates signed action request for temporary quarantine */
    sc_action_request_t req;
    memset(&req, 0, sizeof(req));
    req.timestamp = (uint64_t)time(NULL);
    req.incident_type = SC_INCIDENT_DOS_FLOOD;
    req.proposed_action = SC_ACT_TEMP_QUARANTINE;
    req.category = SC_ACT_CAT_AUTO_PERMITTED;
    req.target_node_id = 4;
    req.param_duration_sec = 180;
    snprintf(req.reason, sizeof(req.reason), "High rate connection flood");
    snprintf((char *)req.evidence, sizeof(req.evidence), "peer=4 attempts=25");
    req.evidence_len = (uint32_t)strlen((char *)req.evidence);

    CHECK(action_request_sign(&req, agent_kp) == SC_OK);

    /* Step 1: Peer 0 receives and processes request */
    sc_tcb_decision_t dec0;
    CHECK(tcb_peer_handle_request(peers[0], &req, &dec0) == SC_OK);
    CHECK(dec0.verdict == TCB_VERDICT_APPROVE);

    /* At this moment, Peer 0 is the only peer that approved:
     * Status MUST BE PENDING! (One peer cannot authorize alone) */
    CHECK(tcb_peer_query_status(peers[0], req.request_id, NULL, NULL) == TCB_STATUS_PENDING);

    /* Step 2: Peer 1 receives request and remote decision from Peer 0 */
    sc_tcb_decision_t dec1;
    CHECK(tcb_peer_handle_request(peers[1], &req, &dec1) == SC_OK);
    CHECK(dec1.verdict == TCB_VERDICT_APPROVE);
    CHECK(tcb_peer_handle_remote_decision(peers[0], &dec1) == SC_OK);
    CHECK(tcb_peer_handle_remote_decision(peers[1], &dec0) == SC_OK);

    /* 2 out of 3 peers approved: Peer 2 is silent/offline.
     * Status MUST REMAIN PENDING! Silence/timeout is not approval! */
    CHECK(tcb_peer_query_status(peers[0], req.request_id, NULL, NULL) == TCB_STATUS_PENDING);
    CHECK(tcb_peer_query_status(peers[1], req.request_id, NULL, NULL) == TCB_STATUS_PENDING);

    /* Step 3: Peer 2 comes online and approves */
    sc_tcb_decision_t dec2;
    CHECK(tcb_peer_handle_request(peers[2], &req, &dec2) == SC_OK);
    CHECK(dec2.verdict == TCB_VERDICT_APPROVE);

    CHECK(tcb_peer_handle_remote_decision(peers[0], &dec2) == SC_OK);

    /* Now all 3 configured peers have approved: Unanimous consensus reached! */
    sc_authorisation_t auth;
    CHECK(tcb_peer_query_status(peers[0], req.request_id, &auth, NULL) == TCB_STATUS_AUTHORISED);
    CHECK(auth.action == SC_ACT_TEMP_QUARANTINE);
    CHECK(auth.target_node_id == 4);
    CHECK(auth.peer_count == 3);

    /* Verify on Node Guard: Peer 4 is now quarantined */
    sc_node_guard_t *guard = NULL;
    CHECK(node_guard_create(&guard, 0) == SC_OK);
    CHECK(!node_guard_is_quarantined(guard, 4));
    CHECK(node_guard_apply_authorisation(guard, &auth) == SC_OK);
    CHECK(node_guard_is_quarantined(guard, 4));

    node_guard_free(guard);
    for (int i = 0; i < 3; i++) {
        tcb_peer_free(peers[i]);
        crypto_keypair_free(peer_kp[i]);
    }
    crypto_keypair_free(agent_kp);
}

static void test_tcb_disagreement_rejection(void)
{
    sc_keypair_t *agent_kp = NULL;
    sc_keypair_t *peer_kp[3];
    uint8_t peer_pub[3][SC_ED25519_PUBKEY_LEN];

    CHECK(crypto_keygen(&agent_kp) == SC_OK);
    uint8_t agent_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(agent_kp, agent_pub) == SC_OK);

    for (int i = 0; i < 3; i++) {
        CHECK(crypto_keygen(&peer_kp[i]) == SC_OK);
        CHECK(crypto_get_pubkey(peer_kp[i], peer_pub[i]) == SC_OK);
    }

    sc_tcb_peer_t *peers[3];
    for (int i = 0; i < 3; i++) {
        CHECK(tcb_peer_create(&peers[i], i, peer_kp[i], 3) == SC_OK);
        CHECK(tcb_peer_register_agent(peers[i], agent_pub) == SC_OK);
        for (int j = 0; j < 3; j++) {
            CHECK(tcb_peer_register_network_peer(peers[i], j, peer_pub[j]) == SC_OK);
        }
    }

    sc_action_request_t req;
    memset(&req, 0, sizeof(req));
    req.timestamp = (uint64_t)time(NULL);
    req.incident_type = SC_INCIDENT_DOS_FLOOD;
    req.proposed_action = SC_ACT_APPLY_RATE_LIMIT;
    req.category = SC_ACT_CAT_AUTO_PERMITTED;
    req.target_node_id = 2;
    req.param_rate_limit = 20;
    snprintf(req.reason, sizeof(req.reason), "Rate limit test");
    snprintf((char *)req.evidence, sizeof(req.evidence), "tx_rate=150");
    req.evidence_len = (uint32_t)strlen((char *)req.evidence);

    CHECK(action_request_sign(&req, agent_kp) == SC_OK);

    sc_tcb_decision_t dec0;
    CHECK(tcb_peer_handle_request(peers[0], &req, &dec0) == SC_OK);
    CHECK(dec0.verdict == TCB_VERDICT_APPROVE);

    /* Peer 1 decides to REJECT the request (e.g. policy disagreement) */
    sc_tcb_decision_t dec1;
    memset(&dec1, 0, sizeof(dec1));
    memcpy(dec1.request_id, req.request_id, SC_SHA256_LEN);
    dec1.tcb_peer_id = 1;
    dec1.timestamp = (uint64_t)time(NULL);
    dec1.verdict = TCB_VERDICT_REJECT;
    dec1.category = SC_ACT_CAT_AUTO_PERMITTED;
    snprintf(dec1.reason, sizeof(dec1.reason), "disagree_with_rate_limit");
    CHECK(tcb_decision_sign(&dec1, peer_kp[1]) == SC_OK);

    /* Remote rejection delivered to Peer 0 */
    CHECK(tcb_peer_handle_remote_decision(peers[0], &dec1) == SC_OK);

    /* Action status MUST transition to REJECTED */
    CHECK(tcb_peer_query_status(peers[0], req.request_id, NULL, NULL) == TCB_STATUS_REJECTED);

    for (int i = 0; i < 3; i++) {
        tcb_peer_free(peers[i]);
        crypto_keypair_free(peer_kp[i]);
    }
    crypto_keypair_free(agent_kp);
}

static void test_tcb_human_governance_escalation(void)
{
    sc_keypair_t *agent_kp = NULL;
    sc_keypair_t *operator_kp = NULL;
    sc_keypair_t *peer_kp[2];
    uint8_t peer_pub[2][SC_ED25519_PUBKEY_LEN];

    CHECK(crypto_keygen(&agent_kp) == SC_OK);
    CHECK(crypto_keygen(&operator_kp) == SC_OK);
    uint8_t agent_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(agent_kp, agent_pub) == SC_OK);

    for (int i = 0; i < 2; i++) {
        CHECK(crypto_keygen(&peer_kp[i]) == SC_OK);
        CHECK(crypto_get_pubkey(peer_kp[i], peer_pub[i]) == SC_OK);
    }

    sc_tcb_peer_t *peers[2];
    for (int i = 0; i < 2; i++) {
        CHECK(tcb_peer_create(&peers[i], i, peer_kp[i], 2) == SC_OK);
        CHECK(tcb_peer_register_agent(peers[i], agent_pub) == SC_OK);
        for (int j = 0; j < 2; j++) {
            CHECK(tcb_peer_register_network_peer(peers[i], j, peer_pub[j]) == SC_OK);
        }
    }

    /* AI Agent detects validator 1 equivocation */
    sc_sec_agent_t *agent = NULL;
    CHECK(sec_agent_create(&agent, agent_kp) == SC_OK);

    sc_action_request_t req;
    const char *h1 = "VERTEX_HASH_1";
    const char *h2 = "VERTEX_HASH_2";
    CHECK(sec_agent_create_equivocation_request(agent, 1, h1, strlen(h1), h2, strlen(h2), &req) == SC_OK);

    /* Both peers approve the equivocation evidence */
    sc_tcb_decision_t dec0, dec1;
    CHECK(tcb_peer_handle_request(peers[0], &req, &dec0) == SC_OK);
    CHECK(tcb_peer_handle_request(peers[1], &req, &dec1) == SC_OK);

    CHECK(tcb_peer_handle_remote_decision(peers[0], &dec1) == SC_OK);

    /* Because this is a governance action (REVOKE_VALIDATOR),
     * TCB consensus MUST NOT auto-authorize! It MUST enter ESCALATED state */
    sc_human_escalation_t esc;
    CHECK(tcb_peer_query_status(peers[0], req.request_id, NULL, &esc) == TCB_STATUS_ESCALATED);
    CHECK(esc.proposed_action == SC_ACT_REVOKE_VALIDATOR);
    CHECK(esc.affected_node_id == 1);
    CHECK(esc.peer_count == 2);
    CHECK(!esc.operator_resolved);

    /* Human operator explicitly reviews audit record and signs approval */
    sc_authorisation_t auth;
    CHECK(tcb_peer_resolve_human_escalation(peers[0], req.request_id,
                                            operator_kp, true,
                                            "Equivocation confirmed by operator. Revocation authorized.",
                                            &auth) == SC_OK);

    /* After human approval, status becomes AUTHORISED */
    CHECK(tcb_peer_query_status(peers[0], req.request_id, NULL, NULL) == TCB_STATUS_AUTHORISED);

    /* Enforce on Node Guard */
    sc_node_guard_t *guard = NULL;
    CHECK(node_guard_create(&guard, 0) == SC_OK);
    CHECK(!node_guard_is_validator_revoked(guard, 1));
    CHECK(node_guard_apply_authorisation(guard, &auth) == SC_OK);
    CHECK(node_guard_is_validator_revoked(guard, 1));

    node_guard_free(guard);
    sec_agent_free(agent);
    for (int i = 0; i < 2; i++) {
        tcb_peer_free(peers[i]);
        crypto_keypair_free(peer_kp[i]);
    }
    crypto_keypair_free(agent_kp);
    crypto_keypair_free(operator_kp);
}

int main(void)
{
    log_init(-1);
    printf("test_tcb_consensus\n");
    RUN(test_tcb_unanimous_approval_and_pending);
    RUN(test_tcb_disagreement_rejection);
    RUN(test_tcb_human_governance_escalation);
    return TEST_SUMMARY();
}
