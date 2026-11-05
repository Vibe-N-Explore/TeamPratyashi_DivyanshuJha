/* tcb_policy.h - Deterministic TCB Policy Evaluation and Evidence Verification.
 *
 * Part 3: Policy rules, permission boundaries, evidence checks, anti-replay.
 */
#ifndef SC_TCB_POLICY_H
#define SC_TCB_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "err.h"
#include "security/incident.h"
#include "tcb/decision.h"

#define SC_TCB_MAX_TRUSTED_AGENTS 4
#define SC_TCB_REPLAY_CACHE_SIZE  1024
#define SC_TCB_MAX_TIME_DRIFT_SEC 60
#define SC_TCB_MAX_QUARANTINE_SEC 600 /* Max 10 minutes auto-quarantine */
#define SC_TCB_MIN_RATE_LIMIT     5
#define SC_TCB_MAX_RATE_LIMIT     2000

typedef struct {
    uint8_t  trusted_agents[SC_TCB_MAX_TRUSTED_AGENTS][SC_ED25519_PUBKEY_LEN];
    size_t   trusted_agent_count;
    uint32_t max_quarantine_sec;
    uint32_t max_rate_limit;
    uint32_t max_time_drift_sec;
    uint8_t  replay_cache[SC_TCB_REPLAY_CACHE_SIZE][SC_SHA256_LEN];
    size_t   replay_count;
} sc_tcb_policy_t;

/* Initialize TCB policy with safe defaults */
sc_err_t tcb_policy_init(sc_tcb_policy_t *policy);

/* Register a trusted AI Security Agent public key */
sc_err_t tcb_policy_add_agent(sc_tcb_policy_t *policy,
                              const uint8_t pubkey[SC_ED25519_PUBKEY_LEN]);

/* Evaluate an action request against policy, evidence, and replay rules.
 * Emits an independent, signed sc_tcb_decision_t. */
sc_err_t tcb_policy_evaluate(sc_tcb_policy_t *policy,
                             const sc_keypair_t *my_tcb_kp,
                             int32_t my_tcb_peer_id,
                             const sc_action_request_t *req,
                             sc_tcb_decision_t *decision_out);

#endif /* SC_TCB_POLICY_H */
