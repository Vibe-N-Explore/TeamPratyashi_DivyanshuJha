/* tcb_peer.h - Distributed TCB Peer node and unanimous consensus engine.
 *
 * Part 3 & 4: Independent peer consensus, collective unanimous authorisation,
 * safe pending states, and human operator escalation.
 */
#ifndef SC_TCB_PEER_H
#define SC_TCB_PEER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "err.h"
#include "security/incident.h"
#include "tcb/decision.h"
#include "tcb/tcb_dag.h"
#include "tcb/tcb_policy.h"

typedef enum {
    TCB_STATUS_PENDING    = 0, /* Waiting for all peer decisions (silence != approval) */
    TCB_STATUS_AUTHORISED = 1, /* Unanimous approval for auto-permitted action */
    TCB_STATUS_ESCALATED  = 2, /* Unanimous approval for human-governance action */
    TCB_STATUS_REJECTED   = 3  /* One or more peers rejected the action */
} sc_tcb_consensus_status_t;

typedef struct {
    sc_action_request_t       request;
    bool                      has_request;
    sc_tcb_decision_t         decisions[SC_TCB_MAX_PEERS];
    bool                      decision_received[SC_TCB_MAX_PEERS];
    sc_tcb_consensus_status_t status;
    sc_authorisation_t        authorisation;
    sc_human_escalation_t     escalation;
} sc_tcb_pending_item_t;

#define SC_TCB_MAX_PENDING_REQUESTS 64

typedef struct sc_tcb_peer sc_tcb_peer_t;

/* Create TCB peer node */
sc_err_t tcb_peer_create(sc_tcb_peer_t **peer_out,
                         int32_t my_peer_id,
                         const sc_keypair_t *my_kp,
                         size_t total_tcb_network_peers);

void tcb_peer_free(sc_tcb_peer_t *peer);

/* Register a peer in the TCB network */
sc_err_t tcb_peer_register_network_peer(sc_tcb_peer_t *peer,
                                        int32_t peer_id,
                                        const uint8_t pubkey[SC_ED25519_PUBKEY_LEN]);

/* Register a trusted AI agent */
sc_err_t tcb_peer_register_agent(sc_tcb_peer_t *peer,
                                 const uint8_t pubkey[SC_ED25519_PUBKEY_LEN]);

/* Receive an action request from an AI agent or peer.
 * Evaluates policy locally, records request and local decision in DAG. */
sc_err_t tcb_peer_handle_request(sc_tcb_peer_t *peer,
                                 const sc_action_request_t *req,
                                 sc_tcb_decision_t *my_decision_out);

/* Receive an independent decision from another TCB peer */
sc_err_t tcb_peer_handle_remote_decision(sc_tcb_peer_t *peer,
                                         const sc_tcb_decision_t *remote_decision);

/* Query current consensus status for a request ID */
sc_tcb_consensus_status_t tcb_peer_query_status(const sc_tcb_peer_t *peer,
                                                const uint8_t request_id[SC_SHA256_LEN],
                                                sc_authorisation_t *auth_out,
                                                sc_human_escalation_t *esc_out);

/* Human operator signs off on an escalated governance action */
sc_err_t tcb_peer_resolve_human_escalation(sc_tcb_peer_t *peer,
                                           const uint8_t request_id[SC_SHA256_LEN],
                                           const sc_keypair_t *operator_kp,
                                           bool approve,
                                           const char *operator_notes,
                                           sc_authorisation_t *auth_out);

/* Access this peer's DAG */
sc_tcb_dag_t *tcb_peer_get_dag(sc_tcb_peer_t *peer);

#endif /* SC_TCB_PEER_H */
