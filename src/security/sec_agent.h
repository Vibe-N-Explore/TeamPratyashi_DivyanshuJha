/* sec_agent.h - AI Security Agent telemetry monitor & recommendation engine.
 *
 * Part 3: Autonomous threat intelligence, telemetry analysis, incident generation.
 *
 * CRITICAL ARCHITECTURAL CONSTRAINT:
 * The AI Security Agent monitors activity and generates signed recommendation requests.
 * It NEVER directly executes actions on the blockchain nodes, and NEVER overrides consensus.
 */
#ifndef SC_SEC_AGENT_H
#define SC_SEC_AGENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "err.h"
#include "security/incident.h"

#define SC_AGENT_MAX_TRACKED_PEERS 32
#define SC_AGENT_WINDOW_MS         10000 /* 10-second sliding window */
#define SC_AGENT_CONN_THRESHOLD    10    /* >10 conn attempts in window = DoS */
#define SC_AGENT_TX_BAD_THRESHOLD  5     /* >5 malformed txs = spam attack */

typedef struct {
    int32_t  peer_id;
    uint32_t conn_attempts;
    uint32_t malformed_tx_count;
    uint32_t oversized_frames;
    uint64_t last_event_ms;
} sc_peer_telemetry_stat_t;

typedef struct sc_sec_agent sc_sec_agent_t;

/* Create security agent with Ed25519 identity keypair */
sc_err_t sec_agent_create(sc_sec_agent_t **agent_out,
                          const sc_keypair_t *agent_kp);

void sec_agent_free(sc_sec_agent_t *agent);

/* Ingest one telemetry event from a node */
sc_err_t sec_agent_process_event(sc_sec_agent_t *agent,
                                 const sc_telemetry_event_t *evt);

/* Check if any incident threshold was crossed, and formulate an action request if so.
 * Returns SC_OK if an action request is produced, SC_ERR_NOT_FOUND if no incident. */
sc_err_t sec_agent_generate_recommendation(sc_sec_agent_t *agent,
                                           int32_t target_peer_id,
                                           sc_action_request_t *req_out);

/* Helper to generate an equivocation incident request with proof */
sc_err_t sec_agent_create_equivocation_request(sc_sec_agent_t *agent,
                                               int32_t validator_id,
                                               const void *vtx_header1, size_t len1,
                                               const void *vtx_header2, size_t len2,
                                               sc_action_request_t *req_out);

#endif /* SC_SEC_AGENT_H */
