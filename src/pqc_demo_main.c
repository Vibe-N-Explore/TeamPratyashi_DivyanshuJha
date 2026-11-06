/* pqc_demo_main.c — Standalone Post-Quantum Security demonstration executable. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include "pqc/pqc_demo.h"

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    sc_pqc_demo_report_t report;
    printf("[*] Executing SovereignChain Post-Quantum Security Demonstration...\n");
    sc_err_t rc = pqc_run_full_demonstration(&report);
    if (rc != SC_OK) {
        fprintf(stderr, "[-] Fatal error during demonstration execution: %s\n", sc_err_str(rc));
        return 1;
    }

    pqc_demo_report_print(&report);
    return report.all_passed ? 0 : 1;
}
