/* test_tcb_dag.c - Unit tests for Independent TCB DAG.
 *
 * Part 3 & 4 Verification: DAG vertex creation, parent chaining, and cryptographic tamper detection.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "err.h"
#include "log.h"
#include "tcb/tcb_dag.h"
#include "testutil.h"

static void test_dag_creation_and_append(void)
{
    sc_keypair_t *kp = NULL;
    CHECK(crypto_keygen(&kp) == SC_OK);

    sc_tcb_dag_t *dag = NULL;
    CHECK(tcb_dag_create(&dag, 0, kp) == SC_OK);
    CHECK(tcb_dag_size(dag) == 0);

    const char *payload1 = "REQUEST_ID_001_DATA";
    sc_tcb_vertex_t vtx1;
    CHECK(tcb_dag_append(dag, TCB_VTX_REQUEST, payload1, strlen(payload1), &vtx1) == SC_OK);
    CHECK(tcb_dag_size(dag) == 1);
    CHECK(vtx1.round == 1);
    CHECK(vtx1.parent_count == 0); /* Genesis vertex in TCB DAG */

    const char *payload2 = "DECISION_ID_001_APPROVED";
    sc_tcb_vertex_t vtx2;
    CHECK(tcb_dag_append(dag, TCB_VTX_DECISION, payload2, strlen(payload2), &vtx2) == SC_OK);
    CHECK(tcb_dag_size(dag) == 2);
    CHECK(vtx2.round == 2);
    CHECK(vtx2.parent_count == 1);
    CHECK(memcmp(vtx2.parents[0], vtx1.hash, SC_SHA256_LEN) == 0);

    /* Verify full DAG integrity */
    CHECK(tcb_dag_verify_integrity(dag) == SC_OK);

    tcb_dag_free(dag);
    crypto_keypair_free(kp);
}

static void test_dag_tamper_detection(void)
{
    sc_keypair_t *kp = NULL;
    CHECK(crypto_keygen(&kp) == SC_OK);

    sc_tcb_dag_t *dag = NULL;
    CHECK(tcb_dag_create(&dag, 1, kp) == SC_OK);

    const char *payload = "SECURITY_AUTHORISATION_RECORD";
    sc_tcb_vertex_t vtx;
    CHECK(tcb_dag_append(dag, TCB_VTX_AUTHORISATION, payload, strlen(payload), &vtx) == SC_OK);
    CHECK(tcb_dag_verify_integrity(dag) == SC_OK);

    /* Tamper with payload byte */
    vtx.payload[0] ^= 0xFF;

    /* Inserting tampered vertex into another DAG MUST fail */
    sc_keypair_t *kp2 = NULL;
    CHECK(crypto_keygen(&kp2) == SC_OK);
    sc_tcb_dag_t *dag2 = NULL;
    CHECK(tcb_dag_create(&dag2, 2, kp2) == SC_OK);

    CHECK(tcb_dag_insert_peer_vertex(dag2, &vtx) == SC_ERR_INVALID);

    tcb_dag_free(dag);
    tcb_dag_free(dag2);
    crypto_keypair_free(kp);
    crypto_keypair_free(kp2);
}

int main(void)
{
    log_init(-1);
    printf("test_tcb_dag\n");
    RUN(test_dag_creation_and_append);
    RUN(test_dag_tamper_detection);
    return TEST_SUMMARY();
}
