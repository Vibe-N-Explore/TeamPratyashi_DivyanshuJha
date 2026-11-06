/* decision.h - TCB decision, collective authorisation, and human escalation structures.
 *
 * Part 3 & 4: Independent TCB peer decisions, collective unanimous authorisation,
 * and human governance escalation.
 */
#ifndef SC_TCB_DECISION_H
#define SC_TCB_DECISION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "err.h"
#include "security/incident.h"

#define SC_TCB_MAX_PEERS 8

typedef enum {
    TCB_VERDICT_NONE    = 0,
    TCB_VERDICT_APPROVE = 1,
    TCB_VERDICT_REJECT  = 2
} sc_tcb_verdict_t;

/* Independent decision emitted by a single TCB peer */
typedef struct {
    uint8_t  decision_hash[SC_SHA256_LEN];
    uint8_t  request_id[SC_SHA256_LEN];
    int32_t  tcb_peer_id;
    uint8_t  tcb_pubkey[SC_ED25519_PUBKEY_LEN];
    uint64_t timestamp;
    uint16_t verdict;  /* TCB_VERDICT_APPROVE or TCB_VERDICT_REJECT */
    uint16_t category; /* AUTO_PERMITTED or HUMAN_REQUIRED */
    char     reason[64];
    uint8_t  signature[SC_ED25519_SIG_LEN];
} sc_tcb_decision_t;

#define SC_TCB_DECISION_SIGN_LEN (32 + 4 + 32 + 8 + 2 + 2 + 32)

void tcb_decision_get_signing_bytes(const sc_tcb_decision_t *dec,
                                   uint8_t out[SC_TCB_DECISION_SIGN_LEN]);

sc_err_t tcb_decision_sign(sc_tcb_decision_t *dec, const sc_keypair_t *peer_kp);

sc_err_t tcb_decision_verify(const sc_tcb_decision_t *dec);

/* Collective Authorisation: Issued ONLY when 100% of configured TCB peers approve */
typedef struct {
    uint8_t  auth_id[SC_SHA256_LEN];
    uint8_t  request_id[SC_SHA256_LEN];
    uint16_t action;
    uint16_t category;
    int32_t  target_node_id;
    uint32_t param_duration_sec;
    uint32_t param_rate_limit;
    uint64_t timestamp;
    uint32_t peer_count;
    int32_t  peer_ids[SC_TCB_MAX_PEERS];
    uint8_t  peer_signatures[SC_TCB_MAX_PEERS][SC_ED25519_SIG_LEN];
} sc_authorisation_t;

/* Human Escalation Record: For governance actions requiring manual operator sign-off */
typedef struct {
    uint8_t  escalation_id[SC_SHA256_LEN];
    uint8_t  request_id[SC_SHA256_LEN];
    uint16_t incident_type;
    uint16_t proposed_action;
    int32_t  affected_node_id;
    uint64_t timestamp;
    char     reason[SC_REASON_MAX_LEN];
    uint8_t  evidence_hash[SC_SHA256_LEN];
    uint32_t peer_count;
    int32_t  peer_ids[SC_TCB_MAX_PEERS];
    uint8_t  peer_signatures[SC_TCB_MAX_PEERS][SC_ED25519_SIG_LEN];

    /* Operator resolution */
    bool     operator_resolved;
    bool     operator_approved;
    uint8_t  operator_pubkey[SC_ED25519_PUBKEY_LEN];
    uint8_t  operator_signature[SC_ED25519_SIG_LEN];
    uint64_t resolution_timestamp;
    char     operator_notes[128];
} sc_human_escalation_t;

#endif /* SC_TCB_DECISION_H */
