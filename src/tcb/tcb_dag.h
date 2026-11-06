/* tcb_dag.h - Independent TCB DAG for verifiable audit history.
 *
 * Part 3 & 4: Append-only directed acyclic graph maintaining immutable audit trail
 * of all requests, evidence hashes, peer decisions, authorisations, and human escalations.
 */
#ifndef SC_TCB_DAG_H
#define SC_TCB_DAG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "err.h"

#define SC_TCB_MAX_PARENTS     4
#define SC_TCB_MAX_VERTICES    2048
#define SC_TCB_MAX_PAYLOAD_LEN 1024

typedef enum {
    TCB_VTX_REQUEST       = 1,
    TCB_VTX_DECISION      = 2,
    TCB_VTX_AUTHORISATION = 3,
    TCB_VTX_ESCALATION    = 4,
    TCB_VTX_HUMAN_RESOLVE = 5,
    TCB_VTX_SECURITY_EVENT = 6
} sc_tcb_vtx_type_t;

typedef struct {
    uint8_t  hash[SC_SHA256_LEN];
    uint64_t round;
    int32_t  author_tcb_id;
    uint8_t  author_pubkey[SC_ED25519_PUBKEY_LEN];
    uint16_t vertex_type;
    size_t   parent_count;
    uint8_t  parents[SC_TCB_MAX_PARENTS][SC_SHA256_LEN];
    size_t   payload_len;
    uint8_t  payload[SC_TCB_MAX_PAYLOAD_LEN];
    uint8_t  signature[SC_ED25519_SIG_LEN];
} sc_tcb_vertex_t;

typedef struct sc_tcb_dag sc_tcb_dag_t;

sc_err_t tcb_dag_create(sc_tcb_dag_t **dag_out,
                        int32_t my_tcb_id,
                        const sc_keypair_t *my_kp);

void tcb_dag_free(sc_tcb_dag_t *dag);

/* Append a new vertex to this peer's DAG referencing current tip(s) */
sc_err_t tcb_dag_append(sc_tcb_dag_t *dag,
                        sc_tcb_vtx_type_t type,
                        const void *payload,
                        size_t payload_len,
                        sc_tcb_vertex_t *vtx_out);

/* Insert a foreign vertex received from another TCB peer (validates hash and sig) */
sc_err_t tcb_dag_insert_peer_vertex(sc_tcb_dag_t *dag,
                                    const sc_tcb_vertex_t *vtx);

/* Find a vertex by its hash */
const sc_tcb_vertex_t *tcb_dag_get(const sc_tcb_dag_t *dag,
                                   const uint8_t hash[SC_SHA256_LEN]);
const sc_tcb_vertex_t *tcb_dag_at(const sc_tcb_dag_t *dag, size_t index);

/* Versioned snapshot persistence; loading verifies every vertex signature/hash. */
sc_err_t tcb_dag_save_file(const sc_tcb_dag_t *dag, const char *path);
sc_err_t tcb_dag_load_file(sc_tcb_dag_t *dag, const char *path);

/* Verify cryptographic integrity of entire DAG history */
sc_err_t tcb_dag_verify_integrity(const sc_tcb_dag_t *dag);

size_t tcb_dag_size(const sc_tcb_dag_t *dag);

#endif /* SC_TCB_DAG_H */
