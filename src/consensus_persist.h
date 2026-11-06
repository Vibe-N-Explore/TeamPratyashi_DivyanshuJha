/* consensus_persist.h - Persistent validator signing safety record.
 *
 * Security Improvement 5 — Consensus and DAG Security:
 *
 * Problem:
 *   After a node restart, a validator has no memory of which vertices it
 *   previously voted on.  Without this information, a restarted validator
 *   could be tricked into signing a conflicting vote for the same round,
 *   creating an equivocation that an attacker might exploit.
 *
 * Solution:
 *   Before a validator releases any vote signature, it durably records
 *   the (round, author, vertex_hash) tuple it is about to sign.  On
 *   restart the consensus engine reads this record and refuses to sign
 *   any vote that conflicts with the persisted history.
 *
 * File format: data_dir/validator_state.dat
 *   magic(4)        "VSTA"
 *   version(4)      uint32_be = 1
 *   node_id(4)      uint32_be
 *   entry_count(4)  uint32_be
 *   entries[N]:
 *     round(8)      uint64_be
 *     author(4)     uint32_be
 *     vertex_hash(32)
 *   checksum(32)    SHA-256 of all preceding bytes
 */
#ifndef SC_CONSENSUS_PERSIST_H
#define SC_CONSENSUS_PERSIST_H

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "err.h"

#define SC_VSTATE_MAGIC   0x56535441U  /* "VSTA" */
#define SC_VSTATE_VERSION 1U
#define SC_VSTATE_MAX_ENTRIES 2048

typedef struct {
    uint64_t round;
    int      author;
    uint8_t  vertex_hash[SC_SHA256_LEN];
} sc_vsigned_t;

typedef struct sc_vstate sc_vstate_t;

/* Load or create the validator state file for 'node_id' in 'data_dir'.
 * On first run (no file) returns an empty state. */
sc_err_t vstate_load(sc_vstate_t **out, const char *data_dir, int node_id,
                     char *errbuf, size_t errlen);

/* Return true if this (round, author, vertex_hash) combination was
 * already signed.  Returns false if the hash is new but notes if
 * there is an existing conflicting record for (round, author). */
bool vstate_already_signed(const sc_vstate_t *vs,
                           uint64_t round, int author,
                           const uint8_t vertex_hash[SC_SHA256_LEN]);

bool vstate_has_conflict(const sc_vstate_t *vs,
                         uint64_t round, int author,
                         const uint8_t vertex_hash[SC_SHA256_LEN]);

/* Durably record that we are about to sign (round, author, vertex_hash).
 * Writes are atomic: .tmp → fsync → rename. */
sc_err_t vstate_record(sc_vstate_t *vs,
                       uint64_t round, int author,
                       const uint8_t vertex_hash[SC_SHA256_LEN]);

void vstate_free(sc_vstate_t *vs);

#endif /* SC_CONSENSUS_PERSIST_H */
