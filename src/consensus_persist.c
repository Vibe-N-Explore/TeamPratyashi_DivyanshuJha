/* consensus_persist.c - Persistent validator signing safety record. */
#define _POSIX_C_SOURCE 200809L

#include "consensus_persist.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "log.h"

/* ------------------------------------------------------------------ */
/* Internal structure                                                  */
/* ------------------------------------------------------------------ */

struct sc_vstate {
    char         data_dir[256];
    int          node_id;
    sc_vsigned_t entries[SC_VSTATE_MAX_ENTRIES];
    size_t       entry_count;
};

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void set_err(char *errbuf, size_t errlen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void set_err(char *errbuf, size_t errlen, const char *fmt, ...)
{
    if (!errbuf || errlen == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(errbuf, errlen, fmt, ap);
    va_end(ap);
}

static void pack_u64_be(uint8_t *dest, uint64_t val)
{
    dest[0] = (uint8_t)(val >> 56); dest[1] = (uint8_t)(val >> 48);
    dest[2] = (uint8_t)(val >> 40); dest[3] = (uint8_t)(val >> 32);
    dest[4] = (uint8_t)(val >> 24); dest[5] = (uint8_t)(val >> 16);
    dest[6] = (uint8_t)(val >>  8); dest[7] = (uint8_t)(val);
}

static uint64_t unpack_u64_be(const uint8_t *src)
{
    return ((uint64_t)src[0] << 56) | ((uint64_t)src[1] << 48) |
           ((uint64_t)src[2] << 40) | ((uint64_t)src[3] << 32) |
           ((uint64_t)src[4] << 24) | ((uint64_t)src[5] << 16) |
           ((uint64_t)src[6] <<  8) | ((uint64_t)src[7]);
}

static void pack_u32_be(uint8_t *dest, uint32_t val)
{
    dest[0] = (uint8_t)(val >> 24); dest[1] = (uint8_t)(val >> 16);
    dest[2] = (uint8_t)(val >>  8); dest[3] = (uint8_t)(val);
}

static uint32_t unpack_u32_be(const uint8_t *src)
{
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] <<  8) | ((uint32_t)src[3]);
}

static void build_path(const sc_vstate_t *vs, char *buf, size_t len, const char *suffix)
{
    snprintf(buf, len, "%s/validator_state_%d%s", vs->data_dir, vs->node_id, suffix);
}

/* ------------------------------------------------------------------ */
/* Serialization                                                       */
/* ------------------------------------------------------------------ */

/* Write the full state to a temporary file, fsync, rename.
 * Returns SC_OK on success. */
static sc_err_t write_state(const sc_vstate_t *vs)
{
    char tmp_path[512], final_path[512];
    build_path(vs, tmp_path,   sizeof(tmp_path),   ".tmp");
    build_path(vs, final_path, sizeof(final_path), ".dat");

    mkdir(vs->data_dir, 0700);

    FILE *f = fopen(tmp_path, "wb");
    if (!f) {
        log_eventf(LOG_ERROR, "vstate", "open_failed", "path=%s err=%s",
                   tmp_path, strerror(errno));
        return SC_ERR_IO;
    }
    /* Restrict permissions: only the owner may read the validator state. */
    if (chmod(tmp_path, S_IRUSR | S_IWUSR) != 0) {
        fclose(f);
        unlink(tmp_path);
        return SC_ERR_IO;
    }

    /* Header: 4+4+4+4 = 16 bytes */
    uint8_t hdr[16];
    pack_u32_be(hdr + 0,  SC_VSTATE_MAGIC);
    pack_u32_be(hdr + 4,  SC_VSTATE_VERSION);
    pack_u32_be(hdr + 8,  (uint32_t)vs->node_id);
    pack_u32_be(hdr + 12, (uint32_t)vs->entry_count);

    if (fwrite(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        fclose(f); unlink(tmp_path); return SC_ERR_IO;
    }

    /* Entries: each = 8+4+32 = 44 bytes */
    for (size_t i = 0; i < vs->entry_count; i++) {
        uint8_t rec[44];
        pack_u64_be(rec + 0,  vs->entries[i].round);
        pack_u32_be(rec + 8,  (uint32_t)vs->entries[i].author);
        memcpy(rec + 12, vs->entries[i].vertex_hash, SC_SHA256_LEN);
        if (fwrite(rec, 1, sizeof(rec), f) != sizeof(rec)) {
            fclose(f); unlink(tmp_path); return SC_ERR_IO;
        }
    }

    /* Trailing SHA-256 checksum of everything written so far.
     * Calculated by re-reading would require seeking; instead we
     * compute it over our in-memory representation which is equivalent. */
    size_t body_len = 16 + vs->entry_count * 44;
    uint8_t *body = malloc(body_len > 0 ? body_len : 1);
    if (!body) { fclose(f); unlink(tmp_path); return SC_ERR_IO; }

    memcpy(body, hdr, 16);
    for (size_t i = 0; i < vs->entry_count; i++) {
        uint8_t *p = body + 16 + i * 44;
        pack_u64_be(p + 0,  vs->entries[i].round);
        pack_u32_be(p + 8,  (uint32_t)vs->entries[i].author);
        memcpy(p + 12, vs->entries[i].vertex_hash, SC_SHA256_LEN);
    }
    uint8_t checksum[SC_SHA256_LEN];
    crypto_sha256(body, body_len, checksum);
    free(body);

    if (fwrite(checksum, 1, SC_SHA256_LEN, f) != SC_SHA256_LEN) {
        fclose(f); unlink(tmp_path); return SC_ERR_IO;
    }

    fflush(f);
    int fd = fileno(f);
    if (fd >= 0) fsync(fd);
    fclose(f);

    if (rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
        return SC_ERR_IO;
    }

    return SC_OK;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

sc_err_t vstate_load(sc_vstate_t **out, const char *data_dir, int node_id,
                     char *errbuf, size_t errlen)
{
    if (!out || !data_dir) {
        set_err(errbuf, errlen, "invalid_arguments");
        return SC_ERR_INVALID;
    }

    sc_vstate_t *vs = calloc(1, sizeof(*vs));
    if (!vs) return SC_ERR_IO;

    snprintf(vs->data_dir, sizeof(vs->data_dir), "%s", data_dir);
    vs->node_id = node_id;

    char path[512];
    build_path(vs, path, sizeof(path), ".dat");

    FILE *f = fopen(path, "rb");
    if (!f) {
        /* No existing file: start fresh (normal for first run). */
        *out = vs;
        return SC_OK;
    }

    /* Read header */
    uint8_t hdr[16];
    if (fread(hdr, 1, 16, f) != 16) {
        set_err(errbuf, errlen, "corrupt_header");
        fclose(f); free(vs); return SC_ERR_PARSE;
    }

    uint32_t magic   = unpack_u32_be(hdr + 0);
    uint32_t version = unpack_u32_be(hdr + 4);
    uint32_t nid     = unpack_u32_be(hdr + 8);
    uint32_t count   = unpack_u32_be(hdr + 12);

    if (magic != SC_VSTATE_MAGIC) {
        set_err(errbuf, errlen, "invalid_magic");
        fclose(f); free(vs); return SC_ERR_INVALID;
    }
    if (version != SC_VSTATE_VERSION) {
        set_err(errbuf, errlen, "unsupported_version %u", version);
        fclose(f); free(vs); return SC_ERR_INVALID;
    }
    if ((int)nid != node_id) {
        set_err(errbuf, errlen, "node_id_mismatch file=%u expected=%d", nid, node_id);
        fclose(f); free(vs); return SC_ERR_INVALID;
    }
    if (count > SC_VSTATE_MAX_ENTRIES) {
        set_err(errbuf, errlen, "entry_count_too_large %u", count);
        fclose(f); free(vs); return SC_ERR_INVALID;
    }

    /* Read entries */
    for (uint32_t i = 0; i < count; i++) {
        uint8_t rec[44];
        if (fread(rec, 1, 44, f) != 44) {
            set_err(errbuf, errlen, "truncated_at_entry_%u", i);
            fclose(f); free(vs); return SC_ERR_PARSE;
        }
        vs->entries[i].round  = unpack_u64_be(rec + 0);
        vs->entries[i].author = (int)unpack_u32_be(rec + 8);
        memcpy(vs->entries[i].vertex_hash, rec + 12, SC_SHA256_LEN);
    }
    vs->entry_count = count;

    /* Read and verify checksum */
    uint8_t stored_cksum[SC_SHA256_LEN];
    if (fread(stored_cksum, 1, SC_SHA256_LEN, f) != SC_SHA256_LEN) {
        set_err(errbuf, errlen, "missing_checksum");
        fclose(f); free(vs); return SC_ERR_PARSE;
    }
    fclose(f);

    size_t body_len = 16 + count * 44;
    uint8_t *body = malloc(body_len > 0 ? body_len : 1);
    if (!body) { free(vs); return SC_ERR_IO; }

    memcpy(body, hdr, 16);
    for (size_t i = 0; i < count; i++) {
        uint8_t *p = body + 16 + i * 44;
        pack_u64_be(p + 0,  vs->entries[i].round);
        pack_u32_be(p + 8,  (uint32_t)vs->entries[i].author);
        memcpy(p + 12, vs->entries[i].vertex_hash, SC_SHA256_LEN);
    }
    uint8_t computed_cksum[SC_SHA256_LEN];
    crypto_sha256(body, body_len, computed_cksum);
    free(body);

    if (memcmp(stored_cksum, computed_cksum, SC_SHA256_LEN) != 0) {
        set_err(errbuf, errlen, "checksum_mismatch — validator state file is corrupt");
        free(vs); return SC_ERR_INVALID;
    }

    log_eventf(LOG_INFO, "vstate", "loaded",
               "node=%d entries=%zu", node_id, vs->entry_count);
    *out = vs;
    return SC_OK;
}

bool vstate_already_signed(const sc_vstate_t *vs,
                           uint64_t round, int author,
                           const uint8_t vertex_hash[SC_SHA256_LEN])
{
    if (!vs || !vertex_hash) return false;
    for (size_t i = 0; i < vs->entry_count; i++) {
        if (vs->entries[i].round == round &&
            vs->entries[i].author == author &&
            memcmp(vs->entries[i].vertex_hash, vertex_hash, SC_SHA256_LEN) == 0) {
            return true;
        }
    }
    return false;
}

bool vstate_has_conflict(const sc_vstate_t *vs,
                         uint64_t round, int author,
                         const uint8_t vertex_hash[SC_SHA256_LEN])
{
    /* Returns true if we have already signed a DIFFERENT vertex for
     * this (round, author) pair — i.e., the new vote would be equivocation. */
    if (!vs || !vertex_hash) return false;
    for (size_t i = 0; i < vs->entry_count; i++) {
        if (vs->entries[i].round == round &&
            vs->entries[i].author == author &&
            memcmp(vs->entries[i].vertex_hash, vertex_hash, SC_SHA256_LEN) != 0) {
            return true;
        }
    }
    return false;
}

sc_err_t vstate_record(sc_vstate_t *vs,
                       uint64_t round, int author,
                       const uint8_t vertex_hash[SC_SHA256_LEN])
{
    if (!vs || !vertex_hash) return SC_ERR_INVALID;

    /* Idempotent: don't record duplicate entries. */
    if (vstate_already_signed(vs, round, author, vertex_hash))
        return SC_OK;

    if (vs->entry_count >= SC_VSTATE_MAX_ENTRIES) {
        log_event(LOG_WARN, "vstate", "entry_table_full");
        return SC_ERR_IO;
    }

    /* Step 1: add to in-memory table FIRST */
    vs->entries[vs->entry_count].round  = round;
    vs->entries[vs->entry_count].author = author;
    memcpy(vs->entries[vs->entry_count].vertex_hash, vertex_hash, SC_SHA256_LEN);
    vs->entry_count++;

    /* Step 2: persist to disk BEFORE the caller releases the signature.
     * If the write fails, we still have the record in memory for this
     * session, but we log a critical error because the safety guarantee
     * is weakened. */
    sc_err_t rc = write_state(vs);
    if (rc != SC_OK) {
        log_event(LOG_ERROR, "vstate", "persist_failed — validator safety weakened");
        /* Revert in-memory addition on persist failure so we don't have
         * a phantom record that will never reach disk. */
        vs->entry_count--;
        return rc;
    }

    log_eventf(LOG_INFO, "vstate", "recorded",
               "round=%llu author=%d", (unsigned long long)round, author);
    return SC_OK;
}

void vstate_free(sc_vstate_t *vs)
{
    free(vs);
}
