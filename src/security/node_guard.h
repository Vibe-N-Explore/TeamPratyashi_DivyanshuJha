/* node_guard.h - Blockchain Node runtime security guard and policy enforcer.
 *
 * Part 3: Node-side telemetry generation and authorized action execution.
 */
#ifndef SC_NODE_GUARD_H
#define SC_NODE_GUARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "err.h"
#include "security/incident.h"
#include "tcb/decision.h"

#define SC_GUARD_MAX_QUARANTINED 64
#define SC_GUARD_MAX_PEER_RATES  64

typedef struct {
    int32_t  peer_id;
    uint64_t unquarantine_time_ms;
} sc_quarantine_entry_t;

typedef struct {
    int32_t  peer_id;
    uint32_t max_msgs_per_sec;
} sc_peer_rate_entry_t;

typedef struct sc_node_guard sc_node_guard_t;

sc_err_t node_guard_create(sc_node_guard_t **guard_out, int32_t my_node_id);
void node_guard_free(sc_node_guard_t *guard);

/* Emit a telemetry event */
sc_err_t node_guard_record_event(sc_node_guard_t *guard,
                                 sc_telemetry_event_type_t event_type,
                                 int32_t peer_id,
                                 uint64_t metric_val,
                                 const void *evidence,
                                 size_t evidence_len,
                                 sc_telemetry_event_t *evt_out);

/* Apply an authorized action verified by unanimous TCB approval */
sc_err_t node_guard_apply_authorisation(sc_node_guard_t *guard,
                                        const sc_authorisation_t *auth);

/* Check if a peer is currently quarantined (reject packets if true) */
bool node_guard_is_quarantined(sc_node_guard_t *guard, int32_t peer_id);

/* Check active rate limit for a peer (returns default limit if unset) */
uint32_t node_guard_get_rate_limit(const sc_node_guard_t *guard, int32_t peer_id);

/* Check if a validator's key has been revoked by governance */
bool node_guard_is_validator_revoked(const sc_node_guard_t *guard, int32_t validator_id);

#endif /* SC_NODE_GUARD_H */
