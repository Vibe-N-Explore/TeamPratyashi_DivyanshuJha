/* sentinel_server.h - SovereignChain Sentinel Security Operations Center HTTP API.
 *
 * Project Sentinel: Implementation of Five Advanced Security Features
 *   - Feature 1: Sovereign Security Control Room
 *   - Feature 2: Unanimous Trust Demonstration (Disagreement, Unanimous, Human)
 *   - Feature 3: Controlled Attack Replay Simulator
 *   - Feature 4: Autonomous Self-Healing Network
 *   - Feature 5: Permanent Security Memory & TCB DAG Auditing
 */
#ifndef SC_SENTINEL_SERVER_H
#define SC_SENTINEL_SERVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "crypto.h"
#include "err.h"
#include "security/incident.h"
#include "security/node_guard.h"
#include "security/sec_agent.h"
#include "tcb/decision.h"
#include "tcb/tcb_dag.h"
#include "tcb/tcb_peer.h"
#include "tcb/tcb_policy.h"

#define SC_SENTINEL_DEFAULT_PORT 8088
#define SC_SENTINEL_MAX_NODES    6
#define SC_SENTINEL_TCB_PEERS    3
#define SC_SENTINEL_MAX_EVENTS   256
#define SC_SENTINEL_MAX_INCIDENTS 64

/* Node state in Sentinel topology */
typedef enum {
    NODE_STATE_UNKNOWN       = 0,
    NODE_STATE_OPERATIONAL   = 1,
    NODE_STATE_INVESTIGATING = 2,
    NODE_STATE_SUSPICIOUS    = 3,
    NODE_STATE_QUARANTINED   = 4,
    NODE_STATE_DISCONNECTED  = 5,
    NODE_STATE_REACHABLE     = 6
} sc_node_state_t;

typedef struct {
    int             id;
    node_role_t     role;
    char            host[SC_MAX_HOST];
    uint16_t        port;
    uint8_t         pubkey[SC_ED25519_PUBKEY_LEN];
    sc_node_state_t state;
    uint64_t        msg_count;
    uint64_t        tx_count;
    uint32_t        ping_ms;
    bool            telemetry_observed;
    bool            metrics_online;
    bool            metrics_observed;
    int64_t         metrics_timestamp;
    size_t          authenticated_peers;
    uint64_t        consensus_round;
    uint64_t        quarantine_expiry;
} sc_sentinel_node_info_t;

typedef struct {
    uint8_t  event_id[SC_SHA256_LEN];
    uint64_t timestamp;
    int32_t  node_id;
    char     category[32];
    char     action[64];
    char     detail[256];
    char     tcb_status[32];
    uint8_t  request_id[SC_SHA256_LEN];
    bool     has_request;
} sc_sentinel_history_entry_t;

typedef struct sc_sentinel_server sc_sentinel_server_t;

/* Initialize Sentinel Operations Engine */
sc_err_t sentinel_server_create(sc_sentinel_server_t **server_out,
                                const char *network_conf_path,
                                uint16_t http_port,
                                const char *web_root);

void sentinel_server_free(sc_sentinel_server_t *server);

/* Step the HTTP event loop and telemetry engine */
sc_err_t sentinel_server_poll_step(sc_sentinel_server_t *server, int timeout_ms);
/* Enable durable Sentinel and per-peer TCB DAG storage. Call before polling. */
sc_err_t sentinel_server_set_state_dir(sc_sentinel_server_t *server, const char *state_dir);

/* Run interactive demonstration scenarios (real cryptographic execution) */
sc_err_t sentinel_demo_trust_disagreement(sc_sentinel_server_t *s, char *json_out, size_t max_len);
sc_err_t sentinel_demo_trust_unanimous(sc_sentinel_server_t *s, char *json_out, size_t max_len);
sc_err_t sentinel_demo_trust_human(sc_sentinel_server_t *s, char *json_out, size_t max_len);

sc_err_t sentinel_demo_attack_replay_auth(sc_sentinel_server_t *s, char *json_out, size_t max_len);
sc_err_t sentinel_demo_attack_invalid_tx(sc_sentinel_server_t *s, char *json_out, size_t max_len);
sc_err_t sentinel_demo_attack_equivocation(sc_sentinel_server_t *s, char *json_out, size_t max_len);

sc_err_t sentinel_demo_self_healing(sc_sentinel_server_t *s, int target_node_id, char *json_out, size_t max_len);

sc_err_t sentinel_resolve_governance(sc_sentinel_server_t *s,
                                     const uint8_t req_id[SC_SHA256_LEN],
                                     bool approve,
                                     const char *notes,
                                     char *json_out, size_t max_len);

#endif /* SC_SENTINEL_SERVER_H */
