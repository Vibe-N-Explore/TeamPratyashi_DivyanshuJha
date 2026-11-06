/* sentinel_main.c - SovereignChain Sentinel Operations Center executable.
 *
 * Project Sentinel: Five Advanced Security Features
 * Serves the Institutional Control Room dashboard and cryptographic demo APIs.
 */
#define _POSIX_C_SOURCE 200809L

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "err.h"
#include "log.h"
#include "sentinel_server.h"

static volatile sig_atomic_t g_running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "Options:\n"
            "  --port <port>         Local HTTP listen port (default: 8088)\n"
            "  --network <file>      Path to nodes.conf (default: config/nodes.conf)\n"
            "  --web-root <path>     Directory containing index.html (default: .)\n"
            "  --state-dir <path>    Directory for durable Sentinel history (default: sentinel-state)\n"
            "  -h, --help            Show this help message\n",
            prog);
}

int main(int argc, char **argv)
{
    uint16_t port = SC_SENTINEL_DEFAULT_PORT;
    const char *net_path = "config/nodes.conf";
    const char *web_root = ".";
    const char *state_dir = "sentinel-state";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--network") == 0 && i + 1 < argc) {
            net_path = argv[++i];
        } else if (strcmp(argv[i], "--web-root") == 0 && i + 1 < argc) {
            web_root = argv[++i];
        } else if (strcmp(argv[i], "--state-dir") == 0 && i + 1 < argc) {
            state_dir = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Setup signal handling for clean shutdown */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    log_init(-1);

    printf("====================================================================\n");
    printf("  SOVEREIGNCHAIN - PROJECT SENTINEL\n");
    printf("  Institutional Cybersecurity Operations Center (SOC)\n");
    printf("  Control Room listening on: http://127.0.0.1:%u\n", port);
    printf("  Web Root: %s | Network Config: %s\n", web_root, net_path);
    printf("====================================================================\n");

    sc_sentinel_server_t *srv = NULL;
    sc_err_t err = sentinel_server_create(&srv, net_path, port, web_root);
    if (err != SC_OK) {
        fprintf(stderr, "Failed to initialize Sentinel server: %s (%d)\n",
                sc_err_str(err), err);
        return 1;
    }
    err = sentinel_server_set_state_dir(srv, state_dir);
    if (err != SC_OK) {
        fprintf(stderr, "Failed to load Sentinel security history from %s: %s (%d)\n",
                state_dir, sc_err_str(err), err);
        sentinel_server_free(srv);
        return 1;
    }

    while (g_running) {
        err = sentinel_server_poll_step(srv, 50);
        if (err != SC_OK) {
            fprintf(stderr, "Poll step error: %s (%d)\n", sc_err_str(err), err);
            break;
        }
    }

    printf("\nShutting down Sentinel Operations Center...\n");
    sentinel_server_free(srv);
    printf("Shutdown complete.\n");

    return 0;
}
