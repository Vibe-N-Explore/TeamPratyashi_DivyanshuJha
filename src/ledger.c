/* ledger.c - SovereignChain state engine implementation.
 *
 * Security improvements implemented here:
 *
 * 1. REPLAY ATTACK PROTECTION (Security Item 1):
 *    - Nonce enforcement: tx.nonce must equal sender.nonce exactly.
 *    - Machine-readable error "nonce_too_low" / "nonce_too_high".
 *    - executed_transfers table: each tx hash is recorded after execution;
 *      a second application of the same tx hash is rejected immediately.
 *
 * 4. CRYPTOGRAPHIC CORRECTNESS (Security Item 4):
 *    - Overflow check for (amount + fee): detected before deduction.
 *    - Overflow check for recipient balance: detected before credit.
 *    - Both produce machine-readable error messages.
 *
 * 6. DETERMINISTIC EXECUTION (Security Item 6):
 *    - All arithmetic is strictly integer (uint64_t), no floating point.
 *    - No clock, no RNG, no environment dependency in execution path.
 *    - Consistent ordering enforced by callers (ledger itself is order-agnostic).
 */
#define _POSIX_C_SOURCE 200809L

#include "ledger.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "log.h"

struct sc_ledger {
    sc_account_t accounts[SC_MAX_ACCOUNTS];
    size_t       account_count;

    uint8_t      executed_transfers[SC_MAX_EXECUTED_TRANSFERS][SC_TRANSFER_ID_LEN];
    size_t       executed_transfer_count;
};

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
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

static sc_account_t *find_account(sc_ledger_t *l,
                                  const uint8_t pubkey[SC_ED25519_PUBKEY_LEN])
{
    for (size_t i = 0; i < l->account_count; i++) {
        if (l->accounts[i].active &&
            memcmp(l->accounts[i].pubkey, pubkey, SC_ED25519_PUBKEY_LEN) == 0) {
            return &l->accounts[i];
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

sc_err_t ledger_create(sc_ledger_t **ledger_out)
{
    if (!ledger_out)
        return SC_ERR_INVALID;

    sc_ledger_t *l = calloc(1, sizeof(*l));
    if (!l)
        return SC_ERR_IO;

    *ledger_out = l;
    return SC_OK;
}

void ledger_free(sc_ledger_t *ledger)
{
    free(ledger);
}

void ledger_clear(sc_ledger_t *ledger)
{
    if (!ledger)
        return;
    memset(ledger->accounts, 0, sizeof(ledger->accounts));
    ledger->account_count = 0;
    ledger->executed_transfer_count = 0;
}

/* ------------------------------------------------------------------ */
/* Account access                                                      */
/* ------------------------------------------------------------------ */

sc_err_t ledger_get_account(const sc_ledger_t *ledger,
                           const uint8_t pubkey[SC_ED25519_PUBKEY_LEN],
                           sc_account_t *account_out)
{
    if (!ledger || !pubkey || !account_out)
        return SC_ERR_INVALID;

    for (size_t i = 0; i < ledger->account_count; i++) {
        if (ledger->accounts[i].active &&
            memcmp(ledger->accounts[i].pubkey, pubkey, SC_ED25519_PUBKEY_LEN) == 0) {
            *account_out = ledger->accounts[i];
            return SC_OK;
        }
    }
    return SC_ERR_NOT_FOUND;
}

sc_err_t ledger_set_account(sc_ledger_t *ledger,
                           const uint8_t pubkey[SC_ED25519_PUBKEY_LEN],
                           uint64_t balance,
                           uint64_t nonce)
{
    if (!ledger || !pubkey)
        return SC_ERR_INVALID;

    sc_account_t *acc = find_account(ledger, pubkey);
    if (acc) {
        acc->balance = balance;
        acc->nonce = nonce;
        return SC_OK;
    }

    if (ledger->account_count >= SC_MAX_ACCOUNTS)
        return SC_ERR_IO;

    acc = &ledger->accounts[ledger->account_count++];
    memcpy(acc->pubkey, pubkey, SC_ED25519_PUBKEY_LEN);
    acc->balance = balance;
    acc->nonce = nonce;
    acc->active = true;

    return SC_OK;
}

size_t ledger_account_count(const sc_ledger_t *ledger)
{
    if (!ledger)
        return 0;
    size_t n = 0;
    for (size_t i = 0; i < ledger->account_count; i++) {
        if (ledger->accounts[i].active)
            n++;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Replay-prevention: executed-transfer table                          */
/* ------------------------------------------------------------------ */

bool ledger_has_executed_transfer(const sc_ledger_t *ledger,
                                  const uint8_t transfer_id[SC_TRANSFER_ID_LEN])
{
    if (!ledger || !transfer_id)
        return false;

    for (size_t i = 0; i < ledger->executed_transfer_count; i++) {
        if (memcmp(ledger->executed_transfers[i], transfer_id, SC_TRANSFER_ID_LEN) == 0)
            return true;
    }
    return false;
}

sc_err_t ledger_record_executed_transfer(sc_ledger_t *ledger,
                                         const uint8_t transfer_id[SC_TRANSFER_ID_LEN])
{
    if (!ledger || !transfer_id)
        return SC_ERR_INVALID;

    if (ledger_has_executed_transfer(ledger, transfer_id))
        return SC_OK; /* idempotent */

    if (ledger->executed_transfer_count >= SC_MAX_EXECUTED_TRANSFERS)
        return SC_ERR_IO;

    memcpy(ledger->executed_transfers[ledger->executed_transfer_count++],
           transfer_id, SC_TRANSFER_ID_LEN);
    return SC_OK;
}

/* ------------------------------------------------------------------ */
/* Transaction execution                                               */
/* ------------------------------------------------------------------ */

sc_err_t ledger_apply_tx(sc_ledger_t *ledger, const sc_tx_t *tx,
                         char *errbuf, size_t errlen)
{
    if (!ledger || !tx) {
        set_err(errbuf, errlen, "invalid_arguments");
        return SC_ERR_INVALID;
    }

    /* 1. Replay check: reject any tx we have already executed.
     *    The tx hash is computed over the canonical signing payload,
     *    which includes domain separator, sender, recipient, amount,
     *    fee, and nonce. Even if an attacker replays an identical tx
     *    with a matching nonce, the hash will be the same and will be
     *    rejected here. */
    if (ledger_has_executed_transfer(ledger, tx->hash)) {
        set_err(errbuf, errlen, "already_executed");
        log_event(LOG_WARN, "ledger", "apply_tx_already_executed");
        return SC_ERR_INVALID;
    }

    /* 2. Cryptographic signature verification. */
    if (tx_verify_sig(tx) != SC_OK) {
        set_err(errbuf, errlen, "invalid_signature");
        log_event(LOG_WARN, "ledger", "apply_tx_invalid_sig");
        return SC_ERR_INVALID;
    }

    /* 3. Sender must exist. */
    sc_account_t *sender = find_account(ledger, tx->sender);
    if (!sender) {
        set_err(errbuf, errlen, "sender_not_found");
        log_event(LOG_WARN, "ledger", "apply_tx_sender_not_found");
        return SC_ERR_NOT_FOUND;
    }

    /* 4. Nonce enforcement (strict sequential ordering).
     *    tx.nonce must equal the sender's current nonce exactly.
     *    - If tx.nonce < sender.nonce: this tx was already applied (replay).
     *    - If tx.nonce > sender.nonce: out-of-order or skipped nonce. */
    if (tx->nonce < sender->nonce) {
        set_err(errbuf, errlen, "nonce_too_low expected=%llu got=%llu",
                (unsigned long long)sender->nonce,
                (unsigned long long)tx->nonce);
        log_eventf(LOG_WARN, "ledger", "apply_tx_bad_nonce",
                   "expected=%llu got=%llu",
                   (unsigned long long)sender->nonce,
                   (unsigned long long)tx->nonce);
        return SC_ERR_INVALID;
    }
    if (tx->nonce > sender->nonce) {
        set_err(errbuf, errlen, "nonce_too_high expected=%llu got=%llu",
                (unsigned long long)sender->nonce,
                (unsigned long long)tx->nonce);
        log_eventf(LOG_WARN, "ledger", "apply_tx_bad_nonce",
                   "expected=%llu got=%llu",
                   (unsigned long long)sender->nonce,
                   (unsigned long long)tx->nonce);
        return SC_ERR_INVALID;
    }

    /* 5. Overflow check: amount + fee must not wrap around uint64_t.
     *    Without this check, a malicious tx with amount=UINT64_MAX, fee=1
     *    would compute total=0, pass the balance check, and steal tokens. */
    if (tx->amount > UINT64_MAX - tx->fee) {
        set_err(errbuf, errlen, "amount_fee_overflow amount=%llu fee=%llu",
                (unsigned long long)tx->amount,
                (unsigned long long)tx->fee);
        log_event(LOG_WARN, "ledger", "apply_tx_amount_fee_overflow");
        return SC_ERR_INVALID;
    }
    uint64_t total = tx->amount + tx->fee;

    /* 6. Sender must have enough balance. */
    if (sender->balance < total) {
        set_err(errbuf, errlen, "insufficient_funds balance=%llu required=%llu",
                (unsigned long long)sender->balance,
                (unsigned long long)total);
        log_eventf(LOG_WARN, "ledger", "apply_tx_insufficient_funds",
                   "balance=%llu required=%llu",
                   (unsigned long long)sender->balance,
                   (unsigned long long)total);
        return SC_ERR_INVALID;
    }

    /* 7. Find or create recipient account. */
    sc_account_t *recipient = find_account(ledger, tx->recipient);
    if (!recipient) {
        if (ledger->account_count >= SC_MAX_ACCOUNTS) {
            set_err(errbuf, errlen, "ledger_full");
            log_event(LOG_WARN, "ledger", "apply_tx_ledger_full");
            return SC_ERR_IO;
        }
        recipient = &ledger->accounts[ledger->account_count++];
        memcpy(recipient->pubkey, tx->recipient, SC_ED25519_PUBKEY_LEN);
        recipient->balance = 0;
        recipient->nonce = 0;
        recipient->active = true;
    }

    /* 8. Recipient balance overflow check.
     *    Adding tx->amount to a near-UINT64_MAX balance would wrap around,
     *    crediting the recipient with almost zero while debiting the sender. */
    if (recipient->balance > UINT64_MAX - tx->amount) {
        set_err(errbuf, errlen, "recipient_balance_overflow current=%llu amount=%llu",
                (unsigned long long)recipient->balance,
                (unsigned long long)tx->amount);
        log_event(LOG_WARN, "ledger", "apply_tx_recipient_overflow");
        return SC_ERR_INVALID;
    }

    /* 9. Apply the state changes. */
    sender->balance    -= total;
    sender->nonce      += 1;
    recipient->balance += tx->amount;

    /* 10. Record this tx hash in the executed-transfers table.
     *     Subsequent replays of this exact tx (same hash) will be caught
     *     immediately at step 1, even across rounds. */
    ledger_record_executed_transfer(ledger, tx->hash);

    return SC_OK;
}

sc_err_t ledger_apply_block(sc_ledger_t *ledger,
                            const sc_tx_t *txs,
                            size_t count,
                            bool stop_on_failure,
                            size_t *applied_count_out,
                            char *errbuf, size_t errlen)
{
    if (applied_count_out)
        *applied_count_out = 0;

    if (!ledger || (!txs && count > 0)) {
        set_err(errbuf, errlen, "invalid_arguments");
        return SC_ERR_INVALID;
    }

    size_t applied = 0;
    sc_ledger_t backup;
    if (stop_on_failure) {
        backup = *ledger;
    }
    for (size_t i = 0; i < count; i++) {
        char tx_err[256];
        tx_err[0] = '\0';
        sc_err_t rc = ledger_apply_tx(ledger, &txs[i], tx_err, sizeof(tx_err));
        if (rc == SC_OK) {
            applied++;
        } else if (stop_on_failure) {
            *ledger = backup;
            /* Propagate the first error message to the caller */
            if (errbuf && errlen > 0 && tx_err[0] != '\0')
                snprintf(errbuf, errlen, "%s", tx_err);
            if (applied_count_out)
                *applied_count_out = 0;
            return rc;
        }
        /* In non-stop mode, continue applying remaining transactions */
    }

    if (applied_count_out)
        *applied_count_out = applied;

    return SC_OK;
}

/* ------------------------------------------------------------------ */
/* State root hash                                                     */
/* ------------------------------------------------------------------ */

static int compare_accounts_by_pubkey(const void *a, const void *b)
{
    const sc_account_t *acc1 = (const sc_account_t *)a;
    const sc_account_t *acc2 = (const sc_account_t *)b;
    return memcmp(acc1->pubkey, acc2->pubkey, SC_ED25519_PUBKEY_LEN);
}

sc_err_t ledger_compute_state_hash(const sc_ledger_t *ledger,
                                   uint8_t hash_out[SC_SHA256_LEN])
{
    if (!ledger || !hash_out)
        return SC_ERR_INVALID;

    /* Collect only active accounts and sort deterministically by pubkey.
     * This ensures that every honest node computes the same state root
     * regardless of insertion order. */
    sc_account_t active[SC_MAX_ACCOUNTS];
    size_t count = 0;

    for (size_t i = 0; i < ledger->account_count; i++) {
        if (ledger->accounts[i].active) {
            active[count++] = ledger->accounts[i];
        }
    }

    qsort(active, count, sizeof(sc_account_t), compare_accounts_by_pubkey);

    /* Each record: pubkey(32) + balance(8) + nonce(8) = 48 bytes */
    size_t buf_size = count * 48;
    uint8_t *buf = malloc(buf_size > 0 ? buf_size : 1);
    if (!buf)
        return SC_ERR_IO;

    for (size_t i = 0; i < count; i++) {
        uint8_t *p = buf + (i * 48);
        memcpy(p, active[i].pubkey, SC_ED25519_PUBKEY_LEN);

        /* Big-endian encoding for cross-platform consistency */
        p[32] = (uint8_t)(active[i].balance >> 56);
        p[33] = (uint8_t)(active[i].balance >> 48);
        p[34] = (uint8_t)(active[i].balance >> 40);
        p[35] = (uint8_t)(active[i].balance >> 32);
        p[36] = (uint8_t)(active[i].balance >> 24);
        p[37] = (uint8_t)(active[i].balance >> 16);
        p[38] = (uint8_t)(active[i].balance >>  8);
        p[39] = (uint8_t)(active[i].balance);

        p[40] = (uint8_t)(active[i].nonce >> 56);
        p[41] = (uint8_t)(active[i].nonce >> 48);
        p[42] = (uint8_t)(active[i].nonce >> 40);
        p[43] = (uint8_t)(active[i].nonce >> 32);
        p[44] = (uint8_t)(active[i].nonce >> 24);
        p[45] = (uint8_t)(active[i].nonce >> 16);
        p[46] = (uint8_t)(active[i].nonce >>  8);
        p[47] = (uint8_t)(active[i].nonce);
    }

    crypto_sha256(buf, buf_size, hash_out);
    free(buf);

    return SC_OK;
}

/* ------------------------------------------------------------------ */
/* Raw access (for storage)                                            */
/* ------------------------------------------------------------------ */

const sc_account_t *ledger_get_accounts_raw(const sc_ledger_t *ledger,
                                            size_t *count_out)
{
    if (!ledger || !count_out)
        return NULL;
    *count_out = ledger->account_count;
    return ledger->accounts;
}
