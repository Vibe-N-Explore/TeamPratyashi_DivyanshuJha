/* ledger.h - SovereignChain account ledger and state root engine.
 *
 * Security improvements (Phase 9):
 *   - ledger_apply_tx / ledger_apply_block now accept (errbuf, errlen) so callers
 *     and test suites receive machine-readable error reasons.
 *   - Overflow protection for recipient balance and amount+fee sum.
 *   - ledger_account_count() helper for tests.
 *   - executed_transfers table enforced in ledger_apply_tx (replay prevention).
 */
#ifndef SC_LEDGER_H
#define SC_LEDGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "err.h"
#include "tx.h"

#define SC_MAX_ACCOUNTS 1024
#define SC_MAX_EXECUTED_TRANSFERS 4096
#define SC_TRANSFER_ID_LEN 32

typedef struct {
    uint8_t  pubkey[SC_ED25519_PUBKEY_LEN];
    uint64_t balance;
    uint64_t nonce;
    bool     active;
} sc_account_t;

typedef struct sc_ledger sc_ledger_t;

sc_err_t ledger_create(sc_ledger_t **ledger_out);
void ledger_free(sc_ledger_t *ledger);
void ledger_clear(sc_ledger_t *ledger);

sc_err_t ledger_get_account(const sc_ledger_t *ledger,
                           const uint8_t pubkey[SC_ED25519_PUBKEY_LEN],
                           sc_account_t *account_out);

sc_err_t ledger_set_account(sc_ledger_t *ledger,
                           const uint8_t pubkey[SC_ED25519_PUBKEY_LEN],
                           uint64_t balance,
                           uint64_t nonce);

/* Apply one transaction.
 * On failure, writes a machine-readable reason into errbuf (if non-NULL).
 * Error strings: "invalid_signature", "sender_not_found", "nonce_too_low",
 *   "nonce_too_high", "insufficient_funds", "amount_fee_overflow",
 *   "recipient_balance_overflow", "ledger_full", "already_executed". */
sc_err_t ledger_apply_tx(sc_ledger_t *ledger, const sc_tx_t *tx,
                         char *errbuf, size_t errlen);

/* Apply a block of transactions.
 * stop_on_failure: if true, halt and return first error code without
 *   applying any further transactions.  The ledger state may be partially
 *   modified; callers that need atomicity must snapshot before calling.
 * errbuf receives the reason for the first failure. */
sc_err_t ledger_apply_block(sc_ledger_t *ledger,
                            const sc_tx_t *txs,
                            size_t count,
                            bool stop_on_failure,
                            size_t *applied_count_out,
                            char *errbuf, size_t errlen);

sc_err_t ledger_compute_state_hash(const sc_ledger_t *ledger,
                                   uint8_t hash_out[SC_SHA256_LEN]);

/* Replay-prevention executed-transfer table */
bool ledger_has_executed_transfer(const sc_ledger_t *ledger,
                                  const uint8_t transfer_id[SC_TRANSFER_ID_LEN]);
sc_err_t ledger_record_executed_transfer(sc_ledger_t *ledger,
                                         const uint8_t transfer_id[SC_TRANSFER_ID_LEN]);

/* Raw account access (for storage serialisation) */
const sc_account_t *ledger_get_accounts_raw(const sc_ledger_t *ledger,
                                            size_t *count_out);

/* Return number of active accounts (used by tests). */
size_t ledger_account_count(const sc_ledger_t *ledger);

#endif /* SC_LEDGER_H */
