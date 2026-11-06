/* tcb_policy.c - Deterministic policy enforcement.
 *
 * Implements strict, verifiable rule evaluation for incoming action requests.
 */
#define _POSIX_C_SOURCE 200809L

#include "tcb/tcb_policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"

sc_err_t tcb_policy_init(sc_tcb_policy_t *policy)
{
    if (!policy)
        return SC_ERR_INVALID;

    memset(policy, 0, sizeof(*policy));
    policy->max_quarantine_sec = SC_TCB_MAX_QUARANTINE_SEC;
    policy->max_rate_limit = SC_TCB_MAX_RATE_LIMIT;
    policy->max_time_drift_sec = SC_TCB_MAX_TIME_DRIFT_SEC;
    return SC_OK;
}

sc_err_t tcb_policy_add_agent(sc_tcb_policy_t *policy,
                              const uint8_t pubkey[SC_ED25519_PUBKEY_LEN])
{
    if (!policy || !pubkey)
        return SC_ERR_INVALID;

    if (policy->trusted_agent_count >= SC_TCB_MAX_TRUSTED_AGENTS)
        return SC_ERR_INVALID;

    memcpy(policy->trusted_agents[policy->trusted_agent_count++],
           pubkey, SC_ED25519_PUBKEY_LEN);
    return SC_OK;
}

static bool is_trusted_agent(const sc_tcb_policy_t *policy,
                            const uint8_t pubkey[SC_ED25519_PUBKEY_LEN])
{
    for (size_t i = 0; i < policy->trusted_agent_count; i++) {
        if (memcmp(policy->trusted_agents[i], pubkey, SC_ED25519_PUBKEY_LEN) == 0)
            return true;
    }
    return false;
}

static bool is_replayed_request(const sc_tcb_policy_t *policy,
                                const uint8_t request_id[SC_SHA256_LEN])
{
    for (size_t i = 0; i < policy->replay_count; i++) {
        if (memcmp(policy->replay_cache[i], request_id, SC_SHA256_LEN) == 0)
            return true;
    }
    return false;
}

static void record_request(sc_tcb_policy_t *policy,
                           const uint8_t request_id[SC_SHA256_LEN])
{
    if (policy->replay_count >= SC_TCB_REPLAY_CACHE_SIZE) {
        memmove(&policy->replay_cache[0], &policy->replay_cache[1],
                (SC_TCB_REPLAY_CACHE_SIZE - 1) * SC_SHA256_LEN);
        policy->replay_count = SC_TCB_REPLAY_CACHE_SIZE - 1;
    }
    memcpy(policy->replay_cache[policy->replay_count++], request_id, SC_SHA256_LEN);
}

sc_err_t tcb_policy_evaluate(sc_tcb_policy_t *policy,
                             const sc_keypair_t *my_tcb_kp,
                             int32_t my_tcb_peer_id,
                             const sc_action_request_t *req,
                             sc_tcb_decision_t *decision_out)
{
    if (!policy || !my_tcb_kp || !req || !decision_out)
        return SC_ERR_INVALID;

    memset(decision_out, 0, sizeof(*decision_out));
    memcpy(decision_out->request_id, req->request_id, SC_SHA256_LEN);
    decision_out->tcb_peer_id = my_tcb_peer_id;
    decision_out->timestamp = (uint64_t)time(NULL);
    decision_out->category = req->category;

    /* Check 1: Request signature validity */
    if (action_request_verify(req) != SC_OK) {
        decision_out->verdict = TCB_VERDICT_REJECT;
        snprintf(decision_out->reason, sizeof(decision_out->reason), "invalid_signature");
        return tcb_decision_sign(decision_out, my_tcb_kp);
    }

    /* Check 2: Agent authorization */
    if (!is_trusted_agent(policy, req->agent_pubkey)) {
        decision_out->verdict = TCB_VERDICT_REJECT;
        snprintf(decision_out->reason, sizeof(decision_out->reason), "untrusted_agent");
        return tcb_decision_sign(decision_out, my_tcb_kp);
    }

    /* Check 3: Anti-replay */
    if (is_replayed_request(policy, req->request_id)) {
        decision_out->verdict = TCB_VERDICT_REJECT;
        snprintf(decision_out->reason, sizeof(decision_out->reason), "replayed_request");
        return tcb_decision_sign(decision_out, my_tcb_kp);
    }

    /* Check 4: Freshness check */
    uint64_t now = (uint64_t)time(NULL);
    int64_t drift = (int64_t)now - (int64_t)req->timestamp;
    if (drift < 0) drift = -drift;
    if ((uint64_t)drift > policy->max_time_drift_sec) {
        decision_out->verdict = TCB_VERDICT_REJECT;
        snprintf(decision_out->reason, sizeof(decision_out->reason), "stale_request_timestamp");
        return tcb_decision_sign(decision_out, my_tcb_kp);
    }

    /* Check 5: Evidence integrity */
    if (req->evidence_len == 0) {
        decision_out->verdict = TCB_VERDICT_REJECT;
        snprintf(decision_out->reason, sizeof(decision_out->reason), "missing_evidence");
        return tcb_decision_sign(decision_out, my_tcb_kp);
    }

    /* Check 6: Governance boundary enforcement */
    if (req->proposed_action == SC_ACT_REVOKE_VALIDATOR ||
        req->proposed_action == SC_ACT_CHANGE_VALIDATORS) {
        if (req->category != SC_ACT_CAT_HUMAN_REQUIRED) {
            /* Attacker or errant AI tried to auto-execute governance action */
            decision_out->verdict = TCB_VERDICT_REJECT;
            snprintf(decision_out->reason, sizeof(decision_out->reason), "governance_action_requires_human_category");
            return tcb_decision_sign(decision_out, my_tcb_kp);
        }
    }

    /* Check 7: Parameter bounds for automated actions */
    if (req->proposed_action == SC_ACT_TEMP_QUARANTINE) {
        if (req->param_duration_sec == 0 ||
            req->param_duration_sec > policy->max_quarantine_sec) {
            decision_out->verdict = TCB_VERDICT_REJECT;
            snprintf(decision_out->reason, sizeof(decision_out->reason), "quarantine_duration_out_of_bounds");
            return tcb_decision_sign(decision_out, my_tcb_kp);
        }
    } else if (req->proposed_action == SC_ACT_APPLY_RATE_LIMIT) {
        if (req->param_rate_limit < SC_TCB_MIN_RATE_LIMIT ||
            req->param_rate_limit > policy->max_rate_limit) {
            decision_out->verdict = TCB_VERDICT_REJECT;
            snprintf(decision_out->reason, sizeof(decision_out->reason), "rate_limit_out_of_bounds");
            return tcb_decision_sign(decision_out, my_tcb_kp);
        }
    }

    /* All deterministic checks passed: Record in replay cache and approve */
    record_request(policy, req->request_id);
    decision_out->verdict = TCB_VERDICT_APPROVE;
    snprintf(decision_out->reason, sizeof(decision_out->reason), "policy_approved");
    return tcb_decision_sign(decision_out, my_tcb_kp);
}
