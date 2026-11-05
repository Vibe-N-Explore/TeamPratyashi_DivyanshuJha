/* tcb_main.c - SovereignChain Distributed TCB Peer process.
 *
 * Part 3 & 4: Distributed TCB Peer Node.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"
#include "err.h"
#include "log.h"
#include "security/incident.h"
#include "tcb/decision.h"
#include "tcb/tcb_peer.h"

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s --id <peer_id> --key <peer_key.pem> [--peers <count>]\n", prog);
}

int main(int argc, char **argv)
{
    int peer_id = 0;
    int total_peers = 3;
    const char *key_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
            peer_id = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--peers") == 0 && i + 1 < argc) {
            total_peers = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    log_init(100 + peer_id);

    sc_keypair_t *kp = NULL;
    if (key_path) {
        char err[128];
        if (crypto_load_privkey(&kp, key_path, err, sizeof(err)) != SC_OK) {
            fprintf(stderr, "Failed to load TCB peer key: %s\n", err);
            return 1;
        }
    } else {
        if (crypto_keygen(&kp) != SC_OK) {
            fprintf(stderr, "Failed to generate ephemeral TCB keypair\n");
            return 1;
        }
    }

    sc_tcb_peer_t *tcb = NULL;
    if (tcb_peer_create(&tcb, peer_id, kp, (size_t)total_peers) != SC_OK) {
        fprintf(stderr, "Failed to initialize TCB peer\n");
        crypto_keypair_free(kp);
        return 1;
    }

    uint8_t pubkey[SC_ED25519_PUBKEY_LEN];
    crypto_get_pubkey(kp, pubkey);
    char hex[SC_PUBKEY_HEX_LEN + 1];
    crypto_hex_encode(pubkey, SC_ED25519_PUBKEY_LEN, hex);

    printf("TCB Peer %d initialized. Pubkey: %s. Network peers configured: %d\n",
           peer_id, hex, total_peers);

    tcb_peer_free(tcb);
    crypto_keypair_free(kp);
    return 0;
}
