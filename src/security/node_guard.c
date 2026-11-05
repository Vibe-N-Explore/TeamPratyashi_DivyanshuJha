/* node_guard.c - Blockchain node guard implementation.
 */
#define _POSIX_C_SOURCE 200809L

#include "security/node_guard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto.h"
#include "log.h"

struct sc_node_guard {
    int32_t               my_node_id;
    sc_quarantine_entry_t quarantined[SC_GUARD_MAX_QUARANTINED];
    size_t                quarantine_count;
    sc_peer_rate_entry_t  rates[SC_GUARD_MAX_PEER_RATES];
    size_t                rate_count;
    bool                  revoked_validators[64];
};

static uint64_t current_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

sc_err_t node_guard_create(sc_node_guard_t **guard_out, int32_t my_node_id)
{
    if (!guard_out)
        return SC_ERR_INVALID;

    sc_node_guard_t *guard = calloc(1, sizeof(*guard));
    if (!guard)
        return SC_ERR_IO;

    guard->my_node_id = my_node_id;
    *guard_out = guard;
    return SC_OK;
}

void node_guard_free(sc_node_guard_t *guard)
{
    if (guard)
        free(guard);
}

sc_err_t node_guard_record_event(sc_node_guard_t *guard,
                                 sc_telemetry_event_type_t event_type,
                                 int32_t peer_id,
                                 uint64_t metric_val,
                                 const void *evidence,
                                 size_t evidence_len,
                                 sc_telemetry_event_t *evt_out)
{
    if (!guard || !evt_out)
        return SC_ERR_INVALID;

    memset(evt_out, 0, sizeof(*evt_out));
    evt_out->source_node_id = guard->my_node_id;
    evt_out->peer_id = peer_id;
    evt_out->event_type = (uint16_t)event_type;
    evt_out->timestamp_ms = current_time_ms();
    evt_out->metric_val = metric_val;

    if (evidence && evidence_len > 0) {
        if (evidence_len > SC_TELEMETRY_MAX_EVIDENCE)
            evidence_len = SC_TELEMETRY_MAX_EVIDENCE;
        memcpy(evt_out->evidence, evidence, evidence_len);
        evt_out->evidence_len = (uint32_t)evidence_len;
    }

    /* Compute unique event ID */
    crypto_sha256(evt_out, sizeof(sc_telemetry_event_t) - SC_SHA256_LEN, evt_out->event_id);
    return SC_OK;
}

sc_err_t node_guard_apply_authorisation(sc_node_guard_t *guard,
                                        const sc_authorisation_t *auth)
{
    if (!guard || !auth)
        return SC_ERR_INVALID;

    int32_t target = auth->target_node_id;

    switch (auth->action) {
    case SC_ACT_TEMP_QUARANTINE: {
        uint64_t unquarantine_at = current_time_ms() + ((uint64_t)auth->param_duration_sec * 1000ULL);
        bool found = false;
        for (size_t i = 0; i < guard->quarantine_count; i++) {
            if (guard->quarantined[i].peer_id == target) {
                guard->quarantined[i].unquarantine_time_ms = unquarantine_at;
                found = true;
                break;
            }
        }
        if (!found && guard->quarantine_count < SC_GUARD_MAX_QUARANTINED) {
            guard->quarantined[guard->quarantine_count].peer_id = target;
            guard->quarantined[guard->quarantine_count].unquarantine_time_ms = unquarantine_at;
            guard->quarantine_count++;
        }
        break;
    }

    case SC_ACT_APPLY_RATE_LIMIT: {
        bool found = false;
        for (size_t i = 0; i < guard->rate_count; i++) {
            if (guard->rates[i].peer_id == target) {
                guard->rates[i].max_msgs_per_sec = auth->param_rate_limit;
                found = true;
                break;
            }
        }
        if (!found && guard->rate_count < SC_GUARD_MAX_PEER_RATES) {
            guard->rates[guard->rate_count].peer_id = target;
            guard->rates[guard->rate_count].max_msgs_per_sec = auth->param_rate_limit;
            guard->rate_count++;
        }
        break;
    }

    case SC_ACT_REVOKE_VALIDATOR: {
        if (target >= 0 && target < 64) {
            guard->revoked_validators[target] = true;
        }
        break;
    }

    default:
        break;
    }

    return SC_OK;
}

bool node_guard_is_quarantined(sc_node_guard_t *guard, int32_t peer_id)
{
    if (!guard)
        return false;

    uint64_t now = current_time_ms();
    for (size_t i = 0; i < guard->quarantine_count; i++) {
        if (guard->quarantined[i].peer_id == peer_id) {
            if (now < guard->quarantined[i].unquarantine_time_ms) {
                return true;
            }
        }
    }
    return false;
}

uint32_t node_guard_get_rate_limit(const sc_node_guard_t *guard, int32_t peer_id)
{
    if (!guard)
        return 500; /* default fallback */

    for (size_t i = 0; i < guard->rate_count; i++) {
        if (guard->rates[i].peer_id == peer_id) {
            return guard->rates[i].max_msgs_per_sec;
        }
    }
    return 500;
}

bool node_guard_is_validator_revoked(const sc_node_guard_t *guard, int32_t validator_id)
{
    if (!guard || validator_id < 0 || validator_id >= 64)
        return false;

    return guard->revoked_validators[validator_id];
}
