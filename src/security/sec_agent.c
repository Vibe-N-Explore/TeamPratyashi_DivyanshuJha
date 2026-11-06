/* sec_agent.c - AI Security Agent implementation.
 *
 * Implements telemetry ingestion, sliding-window threat tracking, and
 * cryptographically signed action recommendations.
 */
#define _POSIX_C_SOURCE 200809L

#include "security/sec_agent.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"

struct sc_sec_agent {
    sc_keypair_t            *keypair;
    uint8_t                  pubkey[SC_ED25519_PUBKEY_LEN];
    sc_peer_telemetry_stat_t stats[SC_AGENT_MAX_TRACKED_PEERS];
    size_t                   stat_count;
};

static uint64_t current_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

sc_err_t sec_agent_create(sc_sec_agent_t **agent_out,
                          const sc_keypair_t *agent_kp)
{
    if (!agent_out || !agent_kp)
        return SC_ERR_INVALID;

    sc_sec_agent_t *agent = calloc(1, sizeof(*agent));
    if (!agent)
        return SC_ERR_IO;

    /* Duplicate keypair: for simplicity we store pubkey and verify it can sign */
    if (crypto_get_pubkey(agent_kp, agent->pubkey) != SC_OK) {
        free(agent);
        return SC_ERR_INVALID;
    }

    /* We save the keypair handle reference or shallow copy */
    agent->keypair = (sc_keypair_t *)agent_kp;
    agent->stat_count = 0;

    *agent_out = agent;
    return SC_OK;
}

void sec_agent_free(sc_sec_agent_t *agent)
{
    if (agent) {
        free(agent);
    }
}

static sc_peer_telemetry_stat_t *get_or_create_peer_stat(sc_sec_agent_t *agent, int32_t peer_id)
{
    for (size_t i = 0; i < agent->stat_count; i++) {
        if (agent->stats[i].peer_id == peer_id)
            return &agent->stats[i];
    }
    if (agent->stat_count >= SC_AGENT_MAX_TRACKED_PEERS) {
        /* Evict slot 0 */
        memmove(&agent->stats[0], &agent->stats[1],
                (SC_AGENT_MAX_TRACKED_PEERS - 1) * sizeof(sc_peer_telemetry_stat_t));
        agent->stat_count = SC_AGENT_MAX_TRACKED_PEERS - 1;
    }
    sc_peer_telemetry_stat_t *st = &agent->stats[agent->stat_count++];
    memset(st, 0, sizeof(*st));
    st->peer_id = peer_id;
    return st;
}

sc_err_t sec_agent_process_event(sc_sec_agent_t *agent,
                                 const sc_telemetry_event_t *evt)
{
    if (!agent || !evt)
        return SC_ERR_INVALID;

    uint64_t now = evt->timestamp_ms ? evt->timestamp_ms : current_time_ms();
    sc_peer_telemetry_stat_t *st = get_or_create_peer_stat(agent, evt->peer_id);

    /* Sliding window reset if gap > window */
    if (now > st->last_event_ms + SC_AGENT_WINDOW_MS) {
        st->conn_attempts = 0;
        st->malformed_tx_count = 0;
        st->oversized_frames = 0;
    }
    st->last_event_ms = now;

    switch (evt->event_type) {
    case SC_EVT_CONN_ATTEMPT:
        st->conn_attempts++;
        break;
    case SC_EVT_CONN_FLOOD:
        st->conn_attempts += 10;
        break;
    case SC_EVT_OVERSIZED_FRAME:
        st->oversized_frames++;
        break;
    case SC_EVT_MALFORMED_TX:
        st->malformed_tx_count++;
        break;
    case SC_EVT_RATE_LIMIT_TRIPPED:
        st->conn_attempts += 5;
        break;
    default:
        break;
    }

    return SC_OK;
}

sc_err_t sec_agent_generate_recommendation(sc_sec_agent_t *agent,
                                           int32_t target_peer_id,
                                           sc_action_request_t *req_out)
{
    if (!agent || !req_out)
        return SC_ERR_INVALID;

    sc_peer_telemetry_stat_t *st = NULL;
    for (size_t i = 0; i < agent->stat_count; i++) {
        if (agent->stats[i].peer_id == target_peer_id) {
            st = &agent->stats[i];
            break;
        }
    }

    if (!st)
        return SC_ERR_NOT_FOUND;

    memset(req_out, 0, sizeof(*req_out));
    req_out->timestamp = (uint64_t)time(NULL);
    req_out->target_node_id = target_peer_id;

    /* Rule 1: Oversized frame / DoS flood -> temporary quarantine */
    if (st->conn_attempts >= SC_AGENT_CONN_THRESHOLD || st->oversized_frames > 0) {
        req_out->incident_type = SC_INCIDENT_DOS_FLOOD;
        req_out->proposed_action = SC_ACT_TEMP_QUARANTINE;
        req_out->category = SC_ACT_CAT_AUTO_PERMITTED;
        req_out->param_duration_sec = 120; /* 2 minutes quarantine */
        snprintf(req_out->reason, sizeof(req_out->reason),
                 "Excessive connection flood (%u attempts, %u oversized frames)",
                 st->conn_attempts, st->oversized_frames);

        /* Evidence payload */
        snprintf((char *)req_out->evidence, sizeof(req_out->evidence),
                 "peer=%d attempts=%u oversized=%u window_ms=%d",
                 target_peer_id, st->conn_attempts, st->oversized_frames, SC_AGENT_WINDOW_MS);
        req_out->evidence_len = (uint32_t)strlen((char *)req_out->evidence);

        return action_request_sign(req_out, agent->keypair);
    }

    /* Rule 2: Malformed transaction spam -> apply rate limit */
    if (st->malformed_tx_count >= SC_AGENT_TX_BAD_THRESHOLD) {
        req_out->incident_type = SC_INCIDENT_TX_MALFORMED_SPAM;
        req_out->proposed_action = SC_ACT_APPLY_RATE_LIMIT;
        req_out->category = SC_ACT_CAT_AUTO_PERMITTED;
        req_out->param_rate_limit = 10; /* clamp down to 10 msg/sec */
        snprintf(req_out->reason, sizeof(req_out->reason),
                 "High rate of invalid transactions (%u in window)",
                 st->malformed_tx_count);

        snprintf((char *)req_out->evidence, sizeof(req_out->evidence),
                 "peer=%d bad_txs=%u threshold=%d",
                 target_peer_id, st->malformed_tx_count, SC_AGENT_TX_BAD_THRESHOLD);
        req_out->evidence_len = (uint32_t)strlen((char *)req_out->evidence);

        return action_request_sign(req_out, agent->keypair);
    }

    return SC_ERR_NOT_FOUND;
}

sc_err_t sec_agent_create_equivocation_request(sc_sec_agent_t *agent,
                                               int32_t validator_id,
                                               const void *vtx_header1, size_t len1,
                                               const void *vtx_header2, size_t len2,
                                               sc_action_request_t *req_out)
{
    if (!agent || !vtx_header1 || !vtx_header2 || !req_out)
        return SC_ERR_INVALID;

    if (len1 + len2 > SC_TELEMETRY_MAX_EVIDENCE)
        return SC_ERR_INVALID;

    memset(req_out, 0, sizeof(*req_out));
    req_out->timestamp = (uint64_t)time(NULL);
    req_out->target_node_id = validator_id;
    req_out->incident_type = SC_INCIDENT_VALIDATOR_EQUIVOCATION;
    req_out->proposed_action = SC_ACT_REVOKE_VALIDATOR;
    req_out->category = SC_ACT_CAT_HUMAN_REQUIRED; /* CRITICAL GOVERNANCE ACTION */

    snprintf(req_out->reason, sizeof(req_out->reason),
             "Validator %d equivocation: two conflicting vertices proposed for same round",
             validator_id);

    /* Concatenate the two conflicting headers as proof evidence */
    memcpy(req_out->evidence, vtx_header1, len1);
    memcpy(req_out->evidence + len1, vtx_header2, len2);
    req_out->evidence_len = (uint32_t)(len1 + len2);

    return action_request_sign(req_out, agent->keypair);
}
