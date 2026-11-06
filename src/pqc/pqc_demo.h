/* pqc_demo.h — Dedicated Post-Quantum Security Demonstration for SovereignChain.
 *
 * Implements the 9-point demonstration required by Part 10:
 *   1. A node generating a post-quantum identity.
 *   2. A transaction being signed using ML-DSA-65.
 *   3. The signature being independently verified.
 *   4. An altered transaction being rejected.
 *   5. Two participants establishing a shared secret using ML-KEM-768.
 *   6. An authenticated encrypted session being established.
 *   7. TCB peers exchanging post-quantum signed decisions.
 *   8. A computing provider authenticating and accepting a signed task agreement.
 *   9. Performance comparisons between Ed25519 and ML-DSA-65.
 */
#ifndef SC_PQC_DEMO_H
#define SC_PQC_DEMO_H

#include <stdbool.h>
#include <stddef.h>
#include "pqc_crypto.h"
#include "pqc_tx.h"
#include "pqc_session.h"
#include "pqc_tcb.h"
#include "pqc_marketplace.h"

typedef struct {
    bool   success;
    char   step_name[64];
    char   details[1024];
    double elapsed_ms;
} sc_pqc_demo_step_result_t;

typedef struct {
    sc_pqc_demo_step_result_t steps[9];
    size_t count;
    bool   all_passed;
    sc_pqc_bench_t bench;
} sc_pqc_demo_report_t;

/* Run the full 9-point demonstration using real cryptographic operations. */
sc_err_t pqc_run_full_demonstration(sc_pqc_demo_report_t *report);

/* Format demonstration report into JSON for HTTP API / Dashboard */
sc_err_t pqc_demo_report_to_json(const sc_pqc_demo_report_t *report,
                                 char *json_out, size_t max_len);

/* Print demonstration report to stdout with nice formatting */
void pqc_demo_report_print(const sc_pqc_demo_report_t *report);

#endif /* SC_PQC_DEMO_H */
