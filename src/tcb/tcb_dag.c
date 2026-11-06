/* tcb_dag.c - Append-only independent TCB DAG implementation.
 */
#define _POSIX_C_SOURCE 200809L

#include "tcb/tcb_dag.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

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
    if (!dag || !vtx || vtx->payload_len > SC_TCB_MAX_PAYLOAD_LEN || vtx->parent_count > SC_TCB_MAX_PARENTS)
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

const sc_tcb_vertex_t *tcb_dag_at(const sc_tcb_dag_t *dag, size_t index)
{
    if (!dag || index >= dag->count)
        return NULL;
    return &dag->vertices[index];
}

sc_err_t tcb_dag_verify_integrity(const sc_tcb_dag_t *dag)
{
    if (!dag)
        return SC_ERR_INVALID;

    for (size_t i = 0; i < dag->count; i++) {
        const sc_tcb_vertex_t *vtx = &dag->vertices[i];

        if (vtx->parent_count > SC_TCB_MAX_PARENTS || vtx->payload_len > SC_TCB_MAX_PAYLOAD_LEN)
            return SC_ERR_INVALID;
        for (size_t p = 0; p < vtx->parent_count; p++) {
            bool parent_found = false;
            for (size_t j = 0; j < i; j++) {
                if (memcmp(dag->vertices[j].hash, vtx->parents[p], SC_SHA256_LEN) == 0 &&
                    dag->vertices[j].round < vtx->round) { parent_found = true; break; }
            }
            if (!parent_found) return SC_ERR_INVALID;
            for (size_t q = 0; q < p; q++)
                if (memcmp(vtx->parents[p], vtx->parents[q], SC_SHA256_LEN) == 0) return SC_ERR_INVALID;
        }

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

static void write_u16(FILE *f, uint16_t v)
{
    fputc((int)(v >> 8), f); fputc((int)v, f);
}

static void write_u32(FILE *f, uint32_t v)
{
    for (int shift = 24; shift >= 0; shift -= 8) fputc((int)(v >> shift), f);
}

static void write_u64(FILE *f, uint64_t v)
{
    for (int shift = 56; shift >= 0; shift -= 8) fputc((int)(v >> shift), f);
}

static bool read_u16(FILE *f, uint16_t *v)
{
    int a = fgetc(f), b = fgetc(f);
    if (a == EOF || b == EOF) return false;
    *v = (uint16_t)(((uint16_t)a << 8) | (uint16_t)b);
    return true;
}

static bool read_u32(FILE *f, uint32_t *v)
{
    *v = 0;
    for (int i = 0; i < 4; i++) { int c = fgetc(f); if (c == EOF) return false; *v = (*v << 8) | (uint32_t)c; }
    return true;
}

static bool read_u64(FILE *f, uint64_t *v)
{
    *v = 0;
    for (int i = 0; i < 8; i++) { int c = fgetc(f); if (c == EOF) return false; *v = (*v << 8) | (uint64_t)c; }
    return true;
}

static bool write_vertex(FILE *f, const sc_tcb_vertex_t *v)
{
    if (fwrite(v->hash, 1, SC_SHA256_LEN, f) != SC_SHA256_LEN) return false;
    write_u64(f, v->round); write_u32(f, (uint32_t)v->author_tcb_id);
    if (fwrite(v->author_pubkey, 1, SC_ED25519_PUBKEY_LEN, f) != SC_ED25519_PUBKEY_LEN) return false;
    write_u16(f, v->vertex_type); write_u16(f, (uint16_t)v->parent_count);
    for (size_t i = 0; i < v->parent_count; i++)
        if (fwrite(v->parents[i], 1, SC_SHA256_LEN, f) != SC_SHA256_LEN) return false;
    write_u32(f, (uint32_t)v->payload_len);
    if (fwrite(v->payload, 1, v->payload_len, f) != v->payload_len) return false;
    return fwrite(v->signature, 1, SC_ED25519_SIG_LEN, f) == SC_ED25519_SIG_LEN;
}

static bool read_vertex(FILE *f, sc_tcb_vertex_t *v)
{
    uint32_t author, payload_len;
    uint16_t parents;
    memset(v, 0, sizeof(*v));
    if (fread(v->hash, 1, SC_SHA256_LEN, f) != SC_SHA256_LEN ||
        !read_u64(f, &v->round) || !read_u32(f, &author) ||
        fread(v->author_pubkey, 1, SC_ED25519_PUBKEY_LEN, f) != SC_ED25519_PUBKEY_LEN ||
        !read_u16(f, &v->vertex_type) || !read_u16(f, &parents) || parents > SC_TCB_MAX_PARENTS)
        return false;
    v->author_tcb_id = (int32_t)author;
    v->parent_count = parents;
    for (size_t i = 0; i < v->parent_count; i++)
        if (fread(v->parents[i], 1, SC_SHA256_LEN, f) != SC_SHA256_LEN) return false;
    if (!read_u32(f, &payload_len) || payload_len > SC_TCB_MAX_PAYLOAD_LEN) return false;
    v->payload_len = payload_len;
    if (fread(v->payload, 1, v->payload_len, f) != v->payload_len) return false;
    return fread(v->signature, 1, SC_ED25519_SIG_LEN, f) == SC_ED25519_SIG_LEN;
}

sc_err_t tcb_dag_save_file(const sc_tcb_dag_t *dag, const char *path)
{
    if (!dag || !path || strlen(path) > 400) return SC_ERR_INVALID;
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "wb");
    if (!f) return SC_ERR_IO;
    (void)fchmod(fileno(f), S_IRUSR | S_IWUSR);
    bool ok = fwrite("SCTCBDAG", 1, 8, f) == 8;
    write_u32(f, 1); write_u32(f, (uint32_t)dag->count);
    for (size_t i = 0; ok && i < dag->count; i++) ok = write_vertex(f, &dag->vertices[i]);
    if (fflush(f) != 0 || fsync(fileno(f)) != 0) ok = false;
    if (fclose(f) != 0) ok = false;
    if (!ok || rename(tmp, path) != 0) { unlink(tmp); return SC_ERR_IO; }
    return SC_OK;
}

sc_err_t tcb_dag_load_file(sc_tcb_dag_t *dag, const char *path)
{
    if (!dag || !path) return SC_ERR_INVALID;
    FILE *f = fopen(path, "rb");
    if (!f) return errno == ENOENT ? SC_OK : SC_ERR_IO;
    char magic[8]; uint32_t version, count;
    bool ok = fread(magic, 1, sizeof(magic), f) == sizeof(magic) &&
              memcmp(magic, "SCTCBDAG", 8) == 0 && read_u32(f, &version) && version == 1 &&
              read_u32(f, &count) && count <= SC_TCB_MAX_VERTICES;
    /* Only load into an empty DAG to avoid merging unrelated histories. */
    if (dag->count != 0) ok = false;
    if (ok) {
        if (fseek(f, 12, SEEK_SET) != 0 || !read_u32(f, &count)) ok = false;
        for (uint32_t i = 0; ok && i < count; i++) {
            sc_tcb_vertex_t v;
            size_t prior_size = tcb_dag_size(dag);
            if (!read_vertex(f, &v) || tcb_dag_insert_peer_vertex(dag, &v) != SC_OK ||
                tcb_dag_size(dag) != prior_size + 1) ok = false;
            else if (v.author_tcb_id == dag->my_id) {
                dag->has_tip = true;
                memcpy(dag->tip_hash, v.hash, SC_SHA256_LEN);
                if (v.round > dag->current_round) dag->current_round = v.round;
            }
        }
        if (ok && fgetc(f) != EOF) ok = false;
    }
    if (fclose(f) != 0) ok = false;
    if (!ok || tcb_dag_verify_integrity(dag) != SC_OK) return SC_ERR_INVALID;
    return SC_OK;
}
