/* tcb_peer.c - Distributed TCB peer coordinator and consensus implementation.
 */
#define _POSIX_C_SOURCE 200809L

#include "tcb/tcb_peer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"

struct sc_tcb_peer {
    int32_t               my_id;
    sc_keypair_t         *my_kp;
    size_t                total_network_peers;
    uint8_t               peer_pubkeys[SC_TCB_MAX_PEERS][SC_ED25519_PUBKEY_LEN];
    bool                  peer_registered[SC_TCB_MAX_PEERS];

    sc_tcb_policy_t       policy;
    sc_tcb_dag_t         *dag;

    sc_tcb_pending_item_t pending[SC_TCB_MAX_PENDING_REQUESTS];
    size_t                pending_count;
};

sc_err_t tcb_peer_create(sc_tcb_peer_t **peer_out,
                         int32_t my_peer_id,
                         const sc_keypair_t *my_kp,
                         size_t total_tcb_network_peers)
{
    if (!peer_out || !my_kp || total_tcb_network_peers == 0 ||
        total_tcb_network_peers > SC_TCB_MAX_PEERS)
        return SC_ERR_INVALID;

    sc_tcb_peer_t *peer = calloc(1, sizeof(*peer));
    if (!peer)
        return SC_ERR_IO;

    peer->my_id = my_peer_id;
    peer->my_kp = (sc_keypair_t *)my_kp;
    peer->total_network_peers = total_tcb_network_peers;

    tcb_policy_init(&peer->policy);

    sc_err_t rc = tcb_dag_create(&peer->dag, my_peer_id, my_kp);
    if (rc != SC_OK) {
        free(peer);
        return rc;
    }

    /* Register own public key */
    uint8_t my_pub[SC_ED25519_PUBKEY_LEN];
    crypto_get_pubkey(my_kp, my_pub);
    tcb_peer_register_network_peer(peer, my_peer_id, my_pub);

    *peer_out = peer;
    return SC_OK;
}

void tcb_peer_free(sc_tcb_peer_t *peer)
{
    if (peer) {
        if (peer->dag)
            tcb_dag_free(peer->dag);
        free(peer);
    }
}

sc_err_t tcb_peer_register_network_peer(sc_tcb_peer_t *peer,
                                        int32_t peer_id,
                                        const uint8_t pubkey[SC_ED25519_PUBKEY_LEN])
{
    if (!peer || peer_id < 0 || (size_t)peer_id >= SC_TCB_MAX_PEERS || !pubkey)
        return SC_ERR_INVALID;

    memcpy(peer->peer_pubkeys[peer_id], pubkey, SC_ED25519_PUBKEY_LEN);
    peer->peer_registered[peer_id] = true;
    return SC_OK;
}

sc_err_t tcb_peer_register_agent(sc_tcb_peer_t *peer,
                                 const uint8_t pubkey[SC_ED25519_PUBKEY_LEN])
{
    if (!peer || !pubkey)
        return SC_ERR_INVALID;

    return tcb_policy_add_agent(&peer->policy, pubkey);
}

static sc_tcb_pending_item_t *get_or_create_pending(sc_tcb_peer_t *peer,
                                                    const uint8_t req_id[SC_SHA256_LEN])
{
    for (size_t i = 0; i < peer->pending_count; i++) {
        if (memcmp(peer->pending[i].request.request_id, req_id, SC_SHA256_LEN) == 0)
            return &peer->pending[i];
    }
    if (peer->pending_count >= SC_TCB_MAX_PENDING_REQUESTS) {
        /* Evict slot 0 */
        memmove(&peer->pending[0], &peer->pending[1],
                (SC_TCB_MAX_PENDING_REQUESTS - 1) * sizeof(sc_tcb_pending_item_t));
        peer->pending_count = SC_TCB_MAX_PENDING_REQUESTS - 1;
    }
    sc_tcb_pending_item_t *item = &peer->pending[peer->pending_count++];
    memset(item, 0, sizeof(*item));
    memcpy(item->request.request_id, req_id, SC_SHA256_LEN);
    item->status = TCB_STATUS_PENDING;
    return item;
}

static void update_consensus_state(sc_tcb_peer_t *peer, sc_tcb_pending_item_t *item)
{
    if (!item->has_request)
        return;

    /* Check if any peer rejected */
    for (size_t i = 0; i < peer->total_network_peers; i++) {
        if (item->decision_received[i] &&
            item->decisions[i].verdict == TCB_VERDICT_REJECT) {
            item->status = TCB_STATUS_REJECTED;
            return;
        }
    }

    /* Check if all configured peers have submitted APPROVE */
    for (size_t i = 0; i < peer->total_network_peers; i++) {
        if (!item->decision_received[i] ||
            item->decisions[i].verdict != TCB_VERDICT_APPROVE) {
            /* Missing or unapproved peer: Remains PENDING (unanimous requirement) */
            item->status = TCB_STATUS_PENDING;
            return;
        }
    }

    /* ALL PEERS APPROVED UNANIMOUSLY! */
    if (item->request.category == SC_ACT_CAT_AUTO_PERMITTED) {
        item->status = TCB_STATUS_AUTHORISED;

        sc_authorisation_t *auth = &item->authorisation;
        memset(auth, 0, sizeof(*auth));
        memcpy(auth->request_id, item->request.request_id, SC_SHA256_LEN);
        auth->action = item->request.proposed_action;
        auth->category = item->request.category;
        auth->target_node_id = item->request.target_node_id;
        auth->param_duration_sec = item->request.param_duration_sec;
        auth->param_rate_limit = item->request.param_rate_limit;
        auth->timestamp = (uint64_t)time(NULL);
        auth->peer_count = (uint32_t)peer->total_network_peers;

        for (size_t i = 0; i < peer->total_network_peers; i++) {
            auth->peer_ids[i] = (int32_t)i;
            memcpy(auth->peer_signatures[i], item->decisions[i].signature, SC_ED25519_SIG_LEN);
        }

        /* Compute unique auth_id */
        crypto_sha256(auth->peer_signatures, sizeof(auth->peer_signatures), auth->auth_id);

        /* Record in DAG */
        tcb_dag_append(peer->dag, TCB_VTX_AUTHORISATION, auth, sizeof(*auth), NULL);
    } else {
        /* Category is HUMAN_REQUIRED: Escalate to human operator */
        item->status = TCB_STATUS_ESCALATED;

        sc_human_escalation_t *esc = &item->escalation;
        memset(esc, 0, sizeof(*esc));
        memcpy(esc->request_id, item->request.request_id, SC_SHA256_LEN);
        esc->incident_type = item->request.incident_type;
        esc->proposed_action = item->request.proposed_action;
        esc->affected_node_id = item->request.target_node_id;
        esc->timestamp = (uint64_t)time(NULL);
        snprintf(esc->reason, sizeof(esc->reason), "%s", item->request.reason);
        memcpy(esc->evidence_hash, item->request.evidence_hash, SC_SHA256_LEN);
        esc->peer_count = (uint32_t)peer->total_network_peers;

        for (size_t i = 0; i < peer->total_network_peers; i++) {
            esc->peer_ids[i] = (int32_t)i;
            memcpy(esc->peer_signatures[i], item->decisions[i].signature, SC_ED25519_SIG_LEN);
        }

        crypto_sha256(esc->peer_signatures, sizeof(esc->peer_signatures), esc->escalation_id);

        /* Record escalation in DAG */
        tcb_dag_append(peer->dag, TCB_VTX_ESCALATION, esc, sizeof(*esc), NULL);
    }
}

sc_err_t tcb_peer_handle_request(sc_tcb_peer_t *peer,
                                 const sc_action_request_t *req,
                                 sc_tcb_decision_t *my_decision_out)
{
    if (!peer || !req)
        return SC_ERR_INVALID;

    sc_tcb_pending_item_t *item = get_or_create_pending(peer, req->request_id);
    item->request = *req;
    item->has_request = true;

    /* Append request to this peer's DAG */
    tcb_dag_append(peer->dag, TCB_VTX_REQUEST, req, sizeof(*req), NULL);

    /* Evaluate locally using deterministic policy engine */
    sc_tcb_decision_t my_dec;
    sc_err_t rc = tcb_policy_evaluate(&peer->policy, peer->my_kp, peer->my_id, req, &my_dec);
    if (rc != SC_OK)
        return rc;

    /* Store local decision */
    item->decisions[peer->my_id] = my_dec;
    item->decision_received[peer->my_id] = true;

    /* Append local decision to this peer's DAG */
    tcb_dag_append(peer->dag, TCB_VTX_DECISION, &my_dec, sizeof(my_dec), NULL);

    update_consensus_state(peer, item);

    if (my_decision_out)
        *my_decision_out = my_dec;

    return SC_OK;
}

sc_err_t tcb_peer_handle_remote_decision(sc_tcb_peer_t *peer,
                                         const sc_tcb_decision_t *remote_decision)
{
    if (!peer || !remote_decision)
        return SC_ERR_INVALID;

    int32_t sender_id = remote_decision->tcb_peer_id;
    if (sender_id < 0 || (size_t)sender_id >= peer->total_network_peers)
        return SC_ERR_INVALID;

    /* Check that remote peer is registered and signature matches pinned key */
    if (!peer->peer_registered[sender_id])
        return SC_ERR_INVALID;

    if (memcmp(peer->peer_pubkeys[sender_id], remote_decision->tcb_pubkey, SC_ED25519_PUBKEY_LEN) != 0)
        return SC_ERR_INVALID; /* Unpinned key presented */

    /* Cryptographic verification of decision */
    if (tcb_decision_verify(remote_decision) != SC_OK)
        return SC_ERR_INVALID;

    sc_tcb_pending_item_t *item = get_or_create_pending(peer, remote_decision->request_id);
    item->decisions[sender_id] = *remote_decision;
    item->decision_received[sender_id] = true;

    /* Record remote decision in DAG */
    tcb_dag_append(peer->dag, TCB_VTX_DECISION, remote_decision, sizeof(*remote_decision), NULL);

    update_consensus_state(peer, item);
    return SC_OK;
}

sc_tcb_consensus_status_t tcb_peer_query_status(const sc_tcb_peer_t *peer,
                                                const uint8_t request_id[SC_SHA256_LEN],
                                                sc_authorisation_t *auth_out,
                                                sc_human_escalation_t *esc_out)
{
    if (!peer || !request_id)
        return TCB_STATUS_PENDING;

    for (size_t i = 0; i < peer->pending_count; i++) {
        if (memcmp(peer->pending[i].request.request_id, request_id, SC_SHA256_LEN) == 0) {
            if (auth_out && peer->pending[i].status == TCB_STATUS_AUTHORISED)
                *auth_out = peer->pending[i].authorisation;
            if (esc_out && peer->pending[i].status == TCB_STATUS_ESCALATED)
                *esc_out = peer->pending[i].escalation;
            return peer->pending[i].status;
        }
    }

    return TCB_STATUS_PENDING;
}

sc_err_t tcb_peer_resolve_human_escalation(sc_tcb_peer_t *peer,
                                           const uint8_t request_id[SC_SHA256_LEN],
                                           const sc_keypair_t *operator_kp,
                                           bool approve,
                                           const char *operator_notes,
                                           sc_authorisation_t *auth_out)
{
    if (!peer || !request_id || !operator_kp)
        return SC_ERR_INVALID;

    sc_tcb_pending_item_t *item = NULL;
    for (size_t i = 0; i < peer->pending_count; i++) {
        if (memcmp(peer->pending[i].request.request_id, request_id, SC_SHA256_LEN) == 0) {
            item = &peer->pending[i];
            break;
        }
    }

    if (!item || item->status != TCB_STATUS_ESCALATED)
        return SC_ERR_INVALID;

    sc_human_escalation_t *esc = &item->escalation;
    esc->operator_resolved = true;
    esc->operator_approved = approve;
    esc->resolution_timestamp = (uint64_t)time(NULL);
    if (operator_notes)
        snprintf(esc->operator_notes, sizeof(esc->operator_notes), "%s", operator_notes);

    if (crypto_get_pubkey(operator_kp, esc->operator_pubkey) != SC_OK)
        return SC_ERR_INVALID;

    /* Sign resolution */
    uint8_t sign_payload[64];
    memcpy(sign_payload, esc->escalation_id, 32);
    sign_payload[32] = approve ? 1 : 0;
    crypto_sha256(sign_payload, 33, sign_payload + 32);

    if (crypto_sign(operator_kp, sign_payload, 64, esc->operator_signature) != SC_OK)
        return SC_ERR_INVALID;

    /* Append human resolution vertex to DAG */
    tcb_dag_append(peer->dag, TCB_VTX_HUMAN_RESOLVE, esc, sizeof(*esc), NULL);

    if (!approve) {
        item->status = TCB_STATUS_REJECTED;
        return SC_OK;
    }

    /* Human approved: Authorisation is unlocked! */
    item->status = TCB_STATUS_AUTHORISED;
    sc_authorisation_t *auth = &item->authorisation;
    memset(auth, 0, sizeof(*auth));
    memcpy(auth->request_id, item->request.request_id, SC_SHA256_LEN);
    auth->action = item->request.proposed_action;
    auth->category = item->request.category;
    auth->target_node_id = item->request.target_node_id;
    auth->timestamp = esc->resolution_timestamp;
    auth->peer_count = (uint32_t)peer->total_network_peers;

    for (size_t i = 0; i < peer->total_network_peers; i++) {
        auth->peer_ids[i] = (int32_t)i;
        memcpy(auth->peer_signatures[i], item->decisions[i].signature, SC_ED25519_SIG_LEN);
    }
    crypto_sha256(auth->peer_signatures, sizeof(auth->peer_signatures), auth->auth_id);

    tcb_dag_append(peer->dag, TCB_VTX_AUTHORISATION, auth, sizeof(*auth), NULL);

    if (auth_out)
        *auth_out = *auth;

    return SC_OK;
}

sc_tcb_dag_t *tcb_peer_get_dag(sc_tcb_peer_t *peer)
{
    return peer ? peer->dag : NULL;
}
