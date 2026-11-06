/* sec_agent_main.c - SovereignChain AI Security Agent standalone process.
 *
 * Part 3: AI Security Agent daemon.
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
#include "security/sec_agent.h"

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s --key <agent_key.pem> [--test-anomaly <target_peer_id>]\n", prog);
}

int main(int argc, char **argv)
{
    const char *key_path = NULL;
    int test_target = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key_path = argv[++i];
        } else if (strcmp(argv[i], "--test-anomaly") == 0 && i + 1 < argc) {
            test_target = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    log_init(99); /* Agent log ID */

    sc_keypair_t *kp = NULL;
    if (key_path) {
        char err[128];
        if (crypto_load_privkey(&kp, key_path, err, sizeof(err)) != SC_OK) {
            fprintf(stderr, "Failed to load agent private key: %s\n", err);
            return 1;
        }
    } else {
        if (crypto_keygen(&kp) != SC_OK) {
            fprintf(stderr, "Failed to generate ephemeral agent keypair\n");
            return 1;
        }
    }

    sc_sec_agent_t *agent = NULL;
    if (sec_agent_create(&agent, kp) != SC_OK) {
        fprintf(stderr, "Failed to initialize security agent\n");
        crypto_keypair_free(kp);
        return 1;
    }

    printf("SovereignChain AI Security Agent started successfully.\n");

    if (test_target >= 0) {
        printf("Simulating DoS anomaly detection for peer %d...\n", test_target);
        for (int i = 0; i < SC_AGENT_CONN_THRESHOLD + 2; i++) {
            sc_telemetry_event_t evt = {
                .peer_id = test_target,
                .event_type = SC_EVT_CONN_ATTEMPT,
                .timestamp_ms = 1000
            };
            sec_agent_process_event(agent, &evt);
        }

        sc_action_request_t req;
        if (sec_agent_generate_recommendation(agent, test_target, &req) == SC_OK) {
            printf("INCIDENT DETECTED! Formulated Action Request:\n");
            printf("  Request ID: ");
            for (int i = 0; i < 8; i++) printf("%02x", req.request_id[i]);
            printf("...\n");
            printf("  Proposed Action: %u (Category: %s)\n",
                   req.proposed_action,
                   req.category == SC_ACT_CAT_AUTO_PERMITTED ? "AUTO_PERMITTED" : "HUMAN_REQUIRED");
            printf("  Reason: %s\n", req.reason);
        }
    }

    sec_agent_free(agent);
    crypto_keypair_free(kp);
    return 0;
}
