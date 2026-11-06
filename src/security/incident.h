/* incident.h - Security incident, telemetry event, and action request data structures.
 *
 * Part 3: AI Security Agent & TCB Telemetry Integration.
 */
#ifndef SC_INCIDENT_H
#define SC_INCIDENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "err.h"

/* Telemetry Event Types emitted by Blockchain Nodes */
typedef enum {
    SC_EVT_CONN_ATTEMPT       = 1, /* Peer connection attempt */
    SC_EVT_CONN_FLOOD         = 2, /* Rapid excessive connection attempts */
    SC_EVT_OVERSIZED_FRAME    = 3, /* Wire frame exceeds payload size threshold */
    SC_EVT_MALFORMED_TX       = 4, /* Invalid signature, bad nonce, balance wrap */
    SC_EVT_EQUIVOCATION       = 5, /* Conflicting votes/proposals from validator */
    SC_EVT_RATE_LIMIT_TRIPPED = 6, /* Peer exceeded sliding window rate limit */
    SC_EVT_INVALID_HANDSHAKE  = 7  /* Impostor or unpinned public key presented */
} sc_telemetry_event_type_t;

#define SC_TELEMETRY_MAX_EVIDENCE 512

/* Telemetry event emitted by node guard */
typedef struct {
    uint8_t  event_id[SC_SHA256_LEN];
    int32_t  source_node_id;
    int32_t  peer_id;
    uint16_t event_type;
    uint64_t timestamp_ms;
    uint64_t metric_val;
    uint32_t evidence_len;
    uint8_t  evidence[SC_TELEMETRY_MAX_EVIDENCE];
} sc_telemetry_event_t;

/* Incident Classification */
typedef enum {
    SC_INCIDENT_DOS_FLOOD             = 1,
    SC_INCIDENT_VALIDATOR_EQUIVOCATION = 2,
    SC_INCIDENT_TX_MALFORMED_SPAM     = 3,
    SC_INCIDENT_AUTH_IMPOSTOR         = 4
} sc_incident_type_t;

typedef enum {
    SC_SEV_INFO     = 1,
    SC_SEV_LOW      = 2,
    SC_SEV_MEDIUM   = 3,
    SC_SEV_HIGH     = 4,
    SC_SEV_CRITICAL = 5
} sc_incident_severity_t;

/* Security Action Types */
typedef enum {
    SC_ACT_NOOP               = 0,
    SC_ACT_REJECT_MESSAGE     = 1, /* Auto-permitted: Drop offending message */
    SC_ACT_APPLY_RATE_LIMIT   = 2, /* Auto-permitted: Restrict peer message rate */
    SC_ACT_TEMP_QUARANTINE    = 3, /* Auto-permitted: Bounded temporary quarantine */
    SC_ACT_REVOKE_VALIDATOR   = 4, /* Human-required: Revoke validator key */
    SC_ACT_CHANGE_VALIDATORS  = 5  /* Human-required: Modify active validator set */
} sc_action_type_t;

/* Action Category Boundary */
typedef enum {
    SC_ACT_CAT_AUTO_PERMITTED = 1, /* Can be executed automatically upon unanimous TCB approval */
    SC_ACT_CAT_HUMAN_REQUIRED = 2  /* Requires explicit human operator escalation & sign-off */
} sc_action_category_t;

#define SC_REASON_MAX_LEN 128

/* Structured Action Request submitted by AI Security Agent to TCB */
typedef struct {
    uint8_t  request_id[SC_SHA256_LEN];
    uint8_t  agent_pubkey[SC_ED25519_PUBKEY_LEN];
    uint64_t timestamp;
    uint16_t incident_type;
    uint16_t proposed_action;
    uint16_t category;
    int32_t  target_node_id;
    uint32_t param_duration_sec;
    uint32_t param_rate_limit;
    uint8_t  evidence_hash[SC_SHA256_LEN];
    uint32_t evidence_len;
    uint8_t  evidence[SC_TELEMETRY_MAX_EVIDENCE];
    char     reason[SC_REASON_MAX_LEN];
    uint8_t  signature[SC_ED25519_SIG_LEN];
} sc_action_request_t;

/* Canonical payload format for signing an action request */
#define SC_ACTION_REQ_SIGN_LEN (32 + 8 + 2 + 2 + 2 + 4 + 4 + 4 + 32 + 32)

void action_request_get_signing_bytes(const sc_action_request_t *req,
                                     uint8_t out[SC_ACTION_REQ_SIGN_LEN]);

sc_err_t action_request_sign(sc_action_request_t *req,
                             const sc_keypair_t *agent_kp);

sc_err_t action_request_verify(const sc_action_request_t *req);

#endif /* SC_INCIDENT_H */
