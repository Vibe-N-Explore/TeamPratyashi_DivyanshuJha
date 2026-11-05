/* tcb_dag.c - Append-only independent TCB DAG implementation.
 */
#define _POSIX_C_SOURCE 200809L

#include "tcb/tcb_dag.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

struct sc_tcb_dag {
    int32_t         my_id;
    sc_keypair_t   *my_kp;
    uint8_t         my_pubkey[SC_ED25519_PUBKEY_LEN];
    sc_tcb_vertex_t vertices[SC_TCB_MAX_VERTICES];
    size_t          count;
    uint64_t        current_round;
    uint8_t         tip_hash[SC_SHA256_LEN];
    bool            has_tip;
};

static void pack_u16_be(uint8_t *dest, uint16_t val)
{
    dest[0] = (uint8_t)(val >> 8);
    dest[1] = (uint8_t)(val);
}

static void pack_u32_be(uint8_t *dest, uint32_t val)
{
    dest[0] = (uint8_t)(val >> 24);
    dest[1] = (uint8_t)(val >> 16);
    dest[2] = (uint8_t)(val >> 8);
    dest[3] = (uint8_t)(val);
}

static void pack_u64_be(uint8_t *dest, uint64_t val)
{
    dest[0] = (uint8_t)(val >> 56);
    dest[1] = (uint8_t)(val >> 48);
    dest[2] = (uint8_t)(val >> 40);
    dest[3] = (uint8_t)(val >> 32);
    dest[4] = (uint8_t)(val >> 24);
    dest[5] = (uint8_t)(val >> 16);
    dest[6] = (uint8_t)(val >> 8);
    dest[7] = (uint8_t)(val);
}

static sc_err_t compute_vertex_hash(const sc_tcb_vertex_t *vtx,
                                    uint8_t hash_out[SC_SHA256_LEN])
{
    /* Canonical buffer */
    uint8_t buf[256];
    size_t off = 0;

    pack_u64_be(buf + off, vtx->round);
    off += 8;

    pack_u32_be(buf + off, (uint32_t)vtx->author_tcb_id);
    off += 4;

    memcpy(buf + off, vtx->author_pubkey, SC_ED25519_PUBKEY_LEN);
    off += SC_ED25519_PUBKEY_LEN;

    pack_u16_be(buf + off, vtx->vertex_type);
    off += 2;

    pack_u16_be(buf + off, (uint16_t)vtx->parent_count);
    off += 2;

    for (size_t i = 0; i < vtx->parent_count; i++) {
        memcpy(buf + off, vtx->parents[i], SC_SHA256_LEN);
        off += SC_SHA256_LEN;
    }

    uint8_t payload_hash[SC_SHA256_LEN];
    crypto_sha256(vtx->payload, vtx->payload_len, payload_hash);
    memcpy(buf + off, payload_hash, SC_SHA256_LEN);
    off += SC_SHA256_LEN;

    return crypto_sha256(buf, off, hash_out);
}

sc_err_t tcb_dag_create(sc_tcb_dag_t **dag_out,
                        int32_t my_tcb_id,
                        const sc_keypair_t *my_kp)
{
    if (!dag_out || !my_kp)
        return SC_ERR_INVALID;

    sc_tcb_dag_t *dag = calloc(1, sizeof(*dag));
    if (!dag)
        return SC_ERR_IO;

    dag->my_id = my_tcb_id;
    dag->my_kp = (sc_keypair_t *)my_kp;
    if (crypto_get_pubkey(my_kp, dag->my_pubkey) != SC_OK) {
        free(dag);
        return SC_ERR_INVALID;
    }
    dag->current_round = 0;
    dag->has_tip = false;

    *dag_out = dag;
    return SC_OK;
}

void tcb_dag_free(sc_tcb_dag_t *dag)
{
    if (dag)
        free(dag);
}

sc_err_t tcb_dag_append(sc_tcb_dag_t *dag,
                        sc_tcb_vtx_type_t type,
                        const void *payload,
                        size_t payload_len,
                        sc_tcb_vertex_t *vtx_out)
{
    if (!dag || !payload || payload_len > SC_TCB_MAX_PAYLOAD_LEN)
        return SC_ERR_INVALID;

    if (dag->count >= SC_TCB_MAX_VERTICES)
        return SC_ERR_INVALID;

    sc_tcb_vertex_t *vtx = &dag->vertices[dag->count];
    memset(vtx, 0, sizeof(*vtx));

    vtx->round = ++dag->current_round;
    vtx->author_tcb_id = dag->my_id;
    memcpy(vtx->author_pubkey, dag->my_pubkey, SC_ED25519_PUBKEY_LEN);
    vtx->vertex_type = (uint16_t)type;

    if (dag->has_tip) {
        vtx->parent_count = 1;
        memcpy(vtx->parents[0], dag->tip_hash, SC_SHA256_LEN);
    } else {
        vtx->parent_count = 0;
    }

    vtx->payload_len = payload_len;
    memcpy(vtx->payload, payload, payload_len);

    if (compute_vertex_hash(vtx, vtx->hash) != SC_OK)
        return SC_ERR_INVALID;

    /* Sign vertex hash */
    if (crypto_sign(dag->my_kp, vtx->hash, SC_SHA256_LEN, vtx->signature) != SC_OK)
        return SC_ERR_INVALID;

    memcpy(dag->tip_hash, vtx->hash, SC_SHA256_LEN);
    dag->has_tip = true;
    dag->count++;

    if (vtx_out)
        *vtx_out = *vtx;

    return SC_OK;
}

sc_err_t tcb_dag_insert_peer_vertex(sc_tcb_dag_t *dag,
                                    const sc_tcb_vertex_t *vtx)
{
    if (!dag || !vtx || vtx->payload_len > SC_TCB_MAX_PAYLOAD_LEN)
        return SC_ERR_INVALID;

    if (dag->count >= SC_TCB_MAX_VERTICES)
        return SC_ERR_INVALID;

    /* Check duplicate */
    for (size_t i = 0; i < dag->count; i++) {
        if (memcmp(dag->vertices[i].hash, vtx->hash, SC_SHA256_LEN) == 0)
            return SC_OK; /* already present */
    }

    /* Verify hash */
    uint8_t expected_hash[SC_SHA256_LEN];
    if (compute_vertex_hash(vtx, expected_hash) != SC_OK)
        return SC_ERR_INVALID;

    if (memcmp(expected_hash, vtx->hash, SC_SHA256_LEN) != 0)
        return SC_ERR_INVALID;

    /* Verify signature */
    sc_keypair_t *pub_handle = NULL;
    if (crypto_pubkey_from_raw(&pub_handle, vtx->author_pubkey) != SC_OK)
        return SC_ERR_INVALID;

    sc_err_t rc = crypto_verify(pub_handle, vtx->hash, SC_SHA256_LEN, vtx->signature);
    crypto_keypair_free(pub_handle);
    if (rc != SC_OK)
        return rc;

    /* Store vertex */
    dag->vertices[dag->count++] = *vtx;
    return SC_OK;
}

const sc_tcb_vertex_t *tcb_dag_get(const sc_tcb_dag_t *dag,
                                   const uint8_t hash[SC_SHA256_LEN])
{
    if (!dag || !hash)
        return NULL;

    for (size_t i = 0; i < dag->count; i++) {
        if (memcmp(dag->vertices[i].hash, hash, SC_SHA256_LEN) == 0)
            return &dag->vertices[i];
    }
    return NULL;
}

sc_err_t tcb_dag_verify_integrity(const sc_tcb_dag_t *dag)
{
    if (!dag)
        return SC_ERR_INVALID;

    for (size_t i = 0; i < dag->count; i++) {
        const sc_tcb_vertex_t *vtx = &dag->vertices[i];

        uint8_t expected_hash[SC_SHA256_LEN];
        if (compute_vertex_hash(vtx, expected_hash) != SC_OK)
            return SC_ERR_INVALID;

        if (memcmp(expected_hash, vtx->hash, SC_SHA256_LEN) != 0)
            return SC_ERR_INVALID;

        sc_keypair_t *pub = NULL;
        if (crypto_pubkey_from_raw(&pub, vtx->author_pubkey) != SC_OK)
            return SC_ERR_INVALID;

        sc_err_t rc = crypto_verify(pub, vtx->hash, SC_SHA256_LEN, vtx->signature);
        crypto_keypair_free(pub);
        if (rc != SC_OK)
            return rc;
    }
    return SC_OK;
}

size_t tcb_dag_size(const sc_tcb_dag_t *dag)
{
    return dag ? dag->count : 0;
}
