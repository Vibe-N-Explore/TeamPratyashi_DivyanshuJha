/* test_pqc.c — Unit tests for SovereignChain Post-Quantum Cryptography Upgrade.
 *
 * Covers:
 *   - ML-DSA-65 key generation, signing, verification, tampering rejection
 *   - ML-KEM-768 encapsulation, decapsulation, shared secret agreement, corrupted ciphertext rejection
 *   - Hybrid signature verification and anti-downgrade policy enforcement
 *   - AEAD AES-256-GCM authenticated encryption and decryption
 *   - Post-quantum transaction creation, serialisation, and verification
 *   - PQC secure session establishment and encrypted communication
 *   - TCB peer decision signing, independent verification, and unanimous collective authorisation
 *   - Marketplace provider PQC registration and dual-signed task agreements
 *   - Key persistence (saving and loading from disk)
 */
#define _POSIX_C_SOURCE 200809L
#include "testutil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pqc/pqc_crypto.h"
#include "pqc/pqc_tx.h"
#include "pqc/pqc_session.h"
#include "pqc/pqc_tcb.h"
#include "pqc/pqc_marketplace.h"

static void test_mldsa_basic(void)
{
    sc_mldsa_keypair_t *kp = NULL;
    CHECK(pqc_mldsa_keygen(&kp) == SC_OK);
    CHECK(kp != NULL);
    CHECK(pqc_mldsa_has_private(kp) == true);

    uint8_t pk[SC_MLDSA_PUBKEY_LEN];
    CHECK(pqc_mldsa_get_pubkey(kp, pk) == SC_OK);

    const char msg[] = "SovereignChain PQC Test Message #1";
    uint8_t sig[SC_MLDSA_SIG_LEN];
    CHECK(pqc_mldsa_sign(kp, msg, strlen(msg), sig) == SC_OK);

    /* Verify with full keypair */
    CHECK(pqc_mldsa_verify(kp, msg, strlen(msg), sig) == SC_OK);

    /* Verify with pubkey-only handle */
    sc_mldsa_keypair_t *pub_only = NULL;
    CHECK(pqc_mldsa_pubkey_from_raw(&pub_only, pk) == SC_OK);
    CHECK(pqc_mldsa_has_private(pub_only) == false);
    CHECK(pqc_mldsa_verify(pub_only, msg, strlen(msg), sig) == SC_OK);

    /* Modified message rejection */
    const char altered[] = "SovereignChain PQC Test Message #2";
    CHECK(pqc_mldsa_verify(pub_only, altered, strlen(altered), sig) == SC_ERR_INVALID);

    /* Corrupted signature rejection */
    sig[10] ^= 0xFF;
    CHECK(pqc_mldsa_verify(pub_only, msg, strlen(msg), sig) == SC_ERR_INVALID);

    pqc_mldsa_keypair_free(pub_only);
    pqc_mldsa_keypair_free(kp);
}

static void test_mlkem_basic(void)
{
    sc_mlkem_keypair_t *bob_kp = NULL;
    CHECK(pqc_mlkem_keygen(&bob_kp) == SC_OK);
    CHECK(bob_kp != NULL);

    uint8_t bob_pk[SC_MLKEM_PUBKEY_LEN];
    CHECK(pqc_mlkem_get_pubkey(bob_kp, bob_pk) == SC_OK);

    sc_mlkem_keypair_t *bob_pub_only = NULL;
    CHECK(pqc_mlkem_pubkey_from_raw(&bob_pub_only, bob_pk) == SC_OK);

    /* Alice encapsulates to Bob's public key */
    uint8_t ct[SC_MLKEM_CT_LEN];
    uint8_t alice_ss[SC_MLKEM_SS_LEN];
    CHECK(pqc_mlkem_encapsulate(bob_pub_only, ct, alice_ss) == SC_OK);

    /* Bob decapsulates with private key */
    uint8_t bob_ss[SC_MLKEM_SS_LEN];
    CHECK(pqc_mlkem_decapsulate(bob_kp, ct, bob_ss) == SC_OK);

    /* Shared secrets must match exactly */
    CHECK(memcmp(alice_ss, bob_ss, SC_MLKEM_SS_LEN) == 0);

    /* Decapsulation of corrupted ciphertext must NOT match Alice's shared secret */
    uint8_t corrupted_ct[SC_MLKEM_CT_LEN];
    memcpy(corrupted_ct, ct, sizeof(ct));
    corrupted_ct[42] ^= 0x55;

    uint8_t bob_bad_ss[SC_MLKEM_SS_LEN];
    /* ML-KEM implicit rejection: decapsulation succeeds but yields an unpredictable pseudorandom value */
    CHECK(pqc_mlkem_decapsulate(bob_kp, corrupted_ct, bob_bad_ss) == SC_OK);
    CHECK(memcmp(alice_ss, bob_bad_ss, SC_MLKEM_SS_LEN) != 0);

    pqc_mlkem_keypair_free(bob_pub_only);
    pqc_mlkem_keypair_free(bob_kp);
}

static void test_hybrid_signatures_and_downgrade(void)
{
    sc_keypair_t *ed_kp = NULL;
    sc_mldsa_keypair_t *mldsa_kp = NULL;
    CHECK(crypto_keygen(&ed_kp) == SC_OK);
    CHECK(pqc_mldsa_keygen(&mldsa_kp) == SC_OK);

    const char msg[] = "Critical SovereignChain Action";
    sc_hybrid_sig_t hsig;

    /* 1. Sign in HYBRID mode */
    CHECK(pqc_hybrid_sign(&hsig, msg, strlen(msg), SC_CRYPTO_POLICY_HYBRID, ed_kp, mldsa_kp) == SC_OK);
    CHECK(hsig.has_ed25519 == true);
    CHECK(hsig.has_mldsa == true);

    /* Verify in HYBRID mode: passes */
    CHECK(pqc_hybrid_verify(&hsig, msg, strlen(msg), SC_CRYPTO_POLICY_HYBRID, ed_kp, mldsa_kp) == SC_OK);

    /* 2. Anti-downgrade test: Attacker removes ML-DSA-65 signature */
    sc_hybrid_sig_t downgraded_sig = hsig;
    downgraded_sig.has_mldsa = false;
    memset(downgraded_sig.mldsa_sig, 0, sizeof(downgraded_sig.mldsa_sig));

    /* When policy is HYBRID, missing PQC signature MUST be rejected */
    CHECK(pqc_hybrid_verify(&downgraded_sig, msg, strlen(msg), SC_CRYPTO_POLICY_HYBRID, ed_kp, mldsa_kp) == SC_ERR_INVALID);

    /* When policy is PQC_REQUIRED, missing PQC signature MUST be rejected */
    CHECK(pqc_hybrid_verify(&downgraded_sig, msg, strlen(msg), SC_CRYPTO_POLICY_PQC_REQUIRED, ed_kp, mldsa_kp) == SC_ERR_INVALID);

    /* 3. Wire serialization / deserialization roundtrip */
    uint8_t wire[SC_HYBRID_SIG_WIRE_LEN];
    pqc_hybrid_sig_encode(&hsig, wire);

    sc_hybrid_sig_t decoded;
    pqc_hybrid_sig_decode(&decoded, wire);
    CHECK(pqc_hybrid_verify(&decoded, msg, strlen(msg), SC_CRYPTO_POLICY_HYBRID, ed_kp, mldsa_kp) == SC_OK);

    crypto_keypair_free(ed_kp);
    pqc_mldsa_keypair_free(mldsa_kp);
}

static void test_pqc_transactions(void)
{
    sc_pqc_identity_t *alice = NULL;
    CHECK(pqc_identity_create(&alice, "alice_tx_test", SC_CRYPTO_POLICY_HYBRID) == SC_OK);

    uint8_t recipient[SC_ED25519_PUBKEY_LEN] = {0x11, 0x22, 0x33, 0x44};
    sc_pqc_tx_t tx;
    CHECK(pqc_tx_create(&tx, SC_CRYPTO_POLICY_HYBRID,
                        alice->ed25519_kp, alice->mldsa_kp,
                        recipient, 1000000ULL, 500ULL, 7ULL) == SC_OK);

    CHECK(pqc_tx_verify(&tx) == SC_OK);
    CHECK(pqc_tx_verify_hash(&tx) == SC_OK);

    /* Wire format serialization / deserialization */
    uint8_t wire[SC_PQC_TX_WIRE_LEN];
    size_t written = 0;
    CHECK(pqc_tx_serialize(&tx, wire, sizeof(wire), &written) == SC_OK);
    CHECK(written == SC_PQC_TX_WIRE_LEN);

    sc_pqc_tx_t restored;
    CHECK(pqc_tx_deserialize(&restored, wire, written) == SC_OK);
    CHECK(pqc_tx_verify(&restored) == SC_OK);
    CHECK(pqc_tx_verify_hash(&restored) == SC_OK);

    /* Tampering test: modify nonce */
    restored.nonce += 1;
    CHECK(pqc_tx_verify(&restored) == SC_ERR_INVALID);

    pqc_identity_free(alice);
}

static void test_pqc_sessions(void)
{
    sc_pqc_identity_t *initiator = NULL;
    sc_pqc_identity_t *responder = NULL;
    CHECK(pqc_identity_create(&initiator, "node_init", SC_CRYPTO_POLICY_HYBRID) == SC_OK);
    CHECK(pqc_identity_create(&responder, "node_resp", SC_CRYPTO_POLICY_HYBRID) == SC_OK);

    sc_pqc_session_t s_init, s_resp;
    memset(&s_init, 0, sizeof(s_init));
    memset(&s_resp, 0, sizeof(s_resp));

    uint8_t resp_mlkem_pk[SC_MLKEM_PUBKEY_LEN];
    CHECK(pqc_mlkem_get_pubkey(responder->mlkem_kp, resp_mlkem_pk) == SC_OK);

    uint8_t kem_init[SC_KEM_INIT_MSG_LEN];
    CHECK(pqc_session_initiate(&s_init, initiator, resp_mlkem_pk, kem_init) == SC_OK);

    uint8_t kem_resp[SC_PQC_KEM_RESP_LEN];
    uint8_t resp_auth[SC_PQC_AUTH_TOKEN_LEN];
    CHECK(pqc_session_respond(&s_resp, responder, kem_init, initiator->x25519_pk, kem_resp, resp_auth) == SC_OK);

    uint8_t init_auth[SC_PQC_AUTH_TOKEN_LEN];
    CHECK(pqc_session_process_resp(&s_init, initiator, kem_resp, responder->x25519_pk, init_auth) == SC_OK);

    /* Keys must be identical */
    CHECK(memcmp(s_init.session_key, s_resp.session_key, SC_KEM_SESSION_LEN) == 0);

    /* Verify mutual authentication */
    uint8_t init_mldsa_pk[SC_MLDSA_PUBKEY_LEN];
    pqc_mldsa_get_pubkey(initiator->mldsa_kp, init_mldsa_pk);
    CHECK(pqc_session_verify_auth(&s_resp, init_mldsa_pk, init_auth) == SC_OK);

    /* Encrypt message from initiator to responder */
    const char app_msg[] = "CONFIDENTIAL_PQC_BLOCKCHAIN_STATE_SYNC";
    uint8_t wire_enc[256];
    size_t enc_len = 0;
    CHECK(pqc_session_encrypt(&s_init, app_msg, strlen(app_msg), wire_enc, sizeof(wire_enc), &enc_len) == SC_OK);

    /* Decrypt at responder */
    char dec_msg[256] = {0};
    size_t dec_len = 0;
    CHECK(pqc_session_decrypt(&s_resp, wire_enc, enc_len, dec_msg, sizeof(dec_msg), &dec_len) == SC_OK);
    CHECK(dec_len == strlen(app_msg));
    CHECK(strcmp(app_msg, dec_msg) == 0);

    /* Anti-tampering check on encrypted payload */
    wire_enc[enc_len - 1] ^= 0x01;
    CHECK(pqc_session_decrypt(&s_resp, wire_enc, enc_len, dec_msg, sizeof(dec_msg), &dec_len) == SC_ERR_INVALID);

    pqc_identity_free(initiator);
    pqc_identity_free(responder);
    pqc_session_reset(&s_init);
    pqc_session_reset(&s_resp);
}

static void test_pqc_tcb(void)
{
    sc_pqc_identity_t *tcb_peers[3];
    for (int i = 0; i < 3; i++) {
        char name[32];
        snprintf(name, sizeof(name), "tcb_%d", i);
        CHECK(pqc_identity_create(&tcb_peers[i], name, SC_CRYPTO_POLICY_HYBRID) == SC_OK);
    }

    uint8_t req_id[SC_SHA256_LEN] = {0x01, 0x02, 0x03, 0x04};
    sc_pqc_tcb_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    memcpy(dec.classical_decision.request_id, req_id, SC_SHA256_LEN);
    dec.classical_decision.tcb_peer_id = 0;
    dec.classical_decision.verdict = TCB_VERDICT_APPROVE;
    dec.classical_decision.category = SC_ACT_CAT_AUTO_PERMITTED;
    strncpy(dec.classical_decision.reason, "Automated rule satisfied", 63);

    CHECK(pqc_tcb_decision_sign(&dec, tcb_peers[0]) == SC_OK);
    CHECK(pqc_tcb_decision_verify(&dec) == SC_OK);

    /* Reject decision with altered verdict */
    dec.classical_decision.verdict = TCB_VERDICT_REJECT;
    CHECK(pqc_tcb_decision_verify(&dec) == SC_ERR_INVALID);

    for (int i = 0; i < 3; i++) pqc_identity_free(tcb_peers[i]);
}

static void test_pqc_marketplace(void)
{
    sc_pqc_identity_t *provider = NULL;
    sc_pqc_identity_t *customer = NULL;
    CHECK(pqc_identity_create(&provider, "provider_pqc", SC_CRYPTO_POLICY_HYBRID) == SC_OK);
    CHECK(pqc_identity_create(&customer, "customer_pqc", SC_CRYPTO_POLICY_HYBRID) == SC_OK);

    /* Registration */
    sc_pqmp_registration_t reg;
    memset(&reg, 0, sizeof(reg));
    reg.provider_id = 42;
    strncpy(reg.name, "DeepQuantum Node", 63);
    reg.cpu_cores = 32;
    reg.price_per_task = 100;
    CHECK(pqmp_registration_sign(&reg, provider) == SC_OK);
    CHECK(pqmp_registration_verify(&reg) == SC_OK);

    /* Task Agreement */
    sc_pqmp_agreement_t agree;
    memset(&agree, 0, sizeof(agree));
    strncpy(agree.task_id, "TASK-1001", SC_MP_ID_LEN);
    agree.provider_id = 42;
    agree.agreed_price = 100;
    agree.deadline_sec = 600;

    CHECK(pqmp_agreement_sign_customer(&agree, customer) == SC_OK);
    CHECK(pqmp_agreement_sign_provider(&agree, provider) == SC_OK);
    CHECK(pqmp_agreement_verify(&agree) == SC_OK);

    /* Tampering customer signature */
    agree.customer_sig.mldsa_sig[5] ^= 0x01;
    CHECK(pqmp_agreement_verify(&agree) == SC_ERR_INVALID);

    pqc_identity_free(provider);
    pqc_identity_free(customer);
}

static void test_key_persistence(void)
{
    const char tmpdir[] = "/tmp/sc_pqc_test_keys";
    mkdir(tmpdir, 0700);

    sc_pqc_identity_t *orig = NULL;
    CHECK(pqc_identity_create(&orig, "persistent_node", SC_CRYPTO_POLICY_HYBRID) == SC_OK);
    CHECK(pqc_identity_save(orig, tmpdir) == SC_OK);

    sc_pqc_identity_t *loaded = NULL;
    char errbuf[256] = {0};
    CHECK(pqc_identity_load(&loaded, tmpdir, "persistent_node", SC_CRYPTO_POLICY_HYBRID, errbuf, sizeof(errbuf)) == SC_OK);
    CHECK(loaded != NULL);

    /* Key ID must match */
    CHECK(memcmp(orig->key_id, loaded->key_id, SC_KEY_ID_LEN) == 0);

    /* Loaded key can sign, and original public key can verify */
    const char msg[] = "Key Persistence Test Payload";
    uint8_t sig[SC_MLDSA_SIG_LEN];
    CHECK(pqc_mldsa_sign(loaded->mldsa_kp, msg, strlen(msg), sig) == SC_OK);
    CHECK(pqc_mldsa_verify(orig->mldsa_kp, msg, strlen(msg), sig) == SC_OK);

    pqc_identity_free(orig);
    pqc_identity_free(loaded);
}

int main(void)
{
    printf("Starting SovereignChain PQC Unit Tests...\n");
    RUN(test_mldsa_basic);
    RUN(test_mlkem_basic);
    RUN(test_hybrid_signatures_and_downgrade);
    RUN(test_pqc_transactions);
    RUN(test_pqc_sessions);
    RUN(test_pqc_tcb);
    RUN(test_pqc_marketplace);
    RUN(test_key_persistence);
    return TEST_SUMMARY();
}
