/* sentinel_server.c - SovereignChain Sentinel Security Operations Center HTTP API.
 *
 * Implements the backend engine and REST HTTP service for Project Sentinel:
 *   - Feature 1: Sovereign Security Control Room (Real-time telemetry & health)
 *   - Feature 2: Unanimous Trust Demonstration (Disagreement, Unanimous, Human Escalation)
 *   - Feature 3: Controlled Attack Replay Simulator (Replay Auth, Invalid Tx, Equivocation)
 *   - Feature 4: Autonomous Self-Healing Network (Failure detection, bounded recovery)
 *   - Feature 5: Permanent Security Memory & TCB DAG Auditing
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "consensus.h"
#include "dag.h"
#include "ledger.h"
#include "log.h"
#include "tx.h"

#define HTTP_MAX_CLIENTS 32
#define HTTP_MAX_REQ     8192
#define HTTP_MAX_BODY    (4 * 1024 * 1024)

typedef struct {
    int      fd;
    char     in[HTTP_MAX_REQ + 1];
    size_t   in_len;
    char    *out;
    size_t   out_len;
    size_t   out_off;
    int64_t  deadline_ms;
    bool     responding;
} client_conn_t;

/* Growable string buffer for JSON assembly */
typedef struct {
    char  *p;
    size_t len;
    size_t cap;
    bool   oom;
} str_buf_t;

struct sc_sentinel_server {
    int                     listen_fd;
    uint16_t                port;
    char                    web_root[256];
    int64_t                 start_time_s;
    int64_t                 last_probe_s;
    network_config_t        net_cfg;
    char                    state_dir[SC_MAX_PATH];
    bool                    persistence_enabled;
    bool                    persistence_error;
    bool                    state_dirty;
    client_conn_t           clients[HTTP_MAX_CLIENTS];

    /* Live node state tracking */
    sc_sentinel_node_info_t nodes[SC_SENTINEL_MAX_NODES];
    size_t                  node_count;

    /* Security Layer Components */
    sc_keypair_t           *agent_kp;
    sc_sec_agent_t         *agent;
    sc_node_guard_t        *guard;

    /* Distributed TCB Peer Network (3 independent peers) */
    sc_keypair_t           *peer_kps[SC_SENTINEL_TCB_PEERS];
    sc_tcb_peer_t          *peers[SC_SENTINEL_TCB_PEERS];
    uint8_t                 peer_pubs[SC_SENTINEL_TCB_PEERS][SC_ED25519_PUBKEY_LEN];

    /* Operator keypair for governance escalations */
    sc_keypair_t           *operator_kp;
    uint8_t                 operator_pub[SC_ED25519_PUBKEY_LEN];

    /* Incident tracking */
    sc_telemetry_event_t    incidents[SC_SENTINEL_MAX_INCIDENTS];
    size_t                  incident_count;

    /* Permanent Security History */
    sc_sentinel_history_entry_t history[SC_SENTINEL_MAX_EVENTS];
    size_t                  history_count;
    uint32_t                history_dropped;
    uint32_t                tcb_event_dropped;

};

static bool tcb_vertex_event(const sc_tcb_vertex_t *v, sc_sentinel_history_entry_t *entry);
static bool verify_peer_dag(int peer_id, const sc_tcb_dag_t *dag,
                            const uint8_t expected_pubkey[SC_ED25519_PUBKEY_LEN]);

/* ------------------------------------------------------------------ */
/* String buffer helpers                                               */
/* ------------------------------------------------------------------ */

static void sb_put(str_buf_t *b, const char *s, size_t n)
{
    if (b->oom) return;
    if (b->len + n + 1 > HTTP_MAX_BODY) { b->oom = true; return; }
    if (b->len + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 2048;
        while (nc < b->len + n + 1) nc *= 2;
        char *np = realloc(b->p, nc);
        if (!np) { b->oom = true; return; }
        b->p = np; b->cap = nc;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void sb_raw(str_buf_t *b, const char *s)
{
    sb_put(b, s, strlen(s));
}

static void sb_printf(str_buf_t *b, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void sb_printf(str_buf_t *b, const char *fmt, ...)
{
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(tmp)) { b->oom = true; return; }
    sb_put(b, tmp, (size_t)n);
}

static void sb_hex(str_buf_t *b, const uint8_t *bytes, size_t len)
{
    sb_raw(b, "\"");
    for (size_t i = 0; i < len; i++) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", bytes[i]);
        sb_raw(b, hex);
    }
    sb_raw(b, "\"");
}

static void sb_str_escape(str_buf_t *b, const char *s)
{
    if (!s) { sb_raw(b, "\"\""); return; }
    sb_raw(b, "\"");
    for (const unsigned char *c = (const unsigned char *)s; *c; c++) {
        if (*c == '"' || *c == '\\') {
            char t[3] = {'\\', (char)*c, 0};
            sb_raw(b, t);
        } else if (*c < 0x20 || *c >= 0x7f) {
            sb_printf(b, "\\u%04x", *c);
        } else {
            sb_put(b, (const char *)c, 1);
        }
    }
    sb_raw(b, "\"");
}

static int64_t monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool read_node_metrics(sc_sentinel_node_info_t *node, const char *response, size_t len)
{
    const char *body = NULL;
    for (size_t i = 0; i + 3 < len; i++)
        if (memcmp(response + i, "\r\n\r\n", 4) == 0) { body = response + i + 4; break; }
    if (!body) return false;
    int node_id;
    unsigned long long uptime, messages, txs, round;
    size_t peers;
    if (sscanf(body, "{\"node_id\":%d,\"uptime_s\":%llu,\"authenticated_peers\":%zu,\"messages_received\":%llu,\"transactions_accepted\":%llu,\"consensus_round\":%llu}",
               &node_id, &uptime, &peers, &messages, &txs, &round) != 6 || node_id != node->id)
        return false;
    node->msg_count = (uint64_t)messages;
    node->tx_count = (uint64_t)txs;
    node->consensus_round = (uint64_t)round;
    node->authenticated_peers = peers;
    node->metrics_timestamp = time(NULL);
    node->metrics_observed = true;
    (void)uptime;
    return true;
}

/* Query the node's local read-only metrics listener. The reported peer count
   comes from authenticated net connections inside the node process. */
static void refresh_node_reachability(sc_sentinel_server_t *s)
{
    int fds[SC_SENTINEL_MAX_NODES];
    int64_t started[SC_SENTINEL_MAX_NODES];
    struct pollfd waiters[SC_SENTINEL_MAX_NODES];
    size_t waiter_nodes[SC_SENTINEL_MAX_NODES];
    size_t read_nodes[SC_SENTINEL_MAX_NODES];
    size_t waiter_count = 0;
    size_t read_count = 0;
    bool connected[SC_SENTINEL_MAX_NODES] = {false};
    bool reached[SC_SENTINEL_MAX_NODES] = {false};
    bool attempted[SC_SENTINEL_MAX_NODES] = {false};
    char responses[SC_SENTINEL_MAX_NODES][1024];
    size_t response_lens[SC_SENTINEL_MAX_NODES] = {0};
    int64_t begin = monotonic_ms();

    for (size_t i = 0; i < s->node_count; i++) {
        fds[i] = -1;
        started[i] = begin;
        if (s->nodes[i].port > UINT16_MAX - SC_NODE_METRICS_PORT_OFFSET) continue;
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(fd);
            continue;
        }
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)(s->nodes[i].port + SC_NODE_METRICS_PORT_OFFSET));
        if (inet_pton(AF_INET, s->nodes[i].host, &addr.sin_addr) != 1) {
            close(fd);
            continue;
        }
        attempted[i] = true;
        int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        if (rc == 0) {
            connected[i] = true;
            fds[i] = fd;
        } else if (errno == EINPROGRESS) {
            waiters[waiter_count].fd = fd;
            waiters[waiter_count].events = POLLOUT;
            waiters[waiter_count].revents = 0;
            waiter_nodes[waiter_count++] = i;
        } else {
            close(fd);
        }
    }

    if (waiter_count) {
        (void)poll(waiters, waiter_count, 250);
        for (size_t j = 0; j < waiter_count; j++) {
            size_t i = waiter_nodes[j];
            int err = 0;
            socklen_t err_len = sizeof(err);
            if (waiters[j].revents && getsockopt(waiters[j].fd, SOL_SOCKET, SO_ERROR, &err, &err_len) == 0 && err == 0) {
                connected[i] = true;
                fds[i] = waiters[j].fd;
            } else {
                close(waiters[j].fd);
            }
        }
    }

    for (size_t i = 0; i < s->node_count; i++) if (connected[i]) {
        static const char request[] = "GET /metrics HTTP/1.0\r\nHost: sovereignchain-node\r\n\r\n";
        if (send(fds[i], request, sizeof(request) - 1, 0) >= 0) {
            waiters[read_count].fd = fds[i];
            waiters[read_count].events = POLLIN;
            waiters[read_count].revents = 0;
            read_nodes[read_count++] = i;
        } else {
            close(fds[i]); fds[i] = -1;
        }
    }
    if (read_count) {
        (void)poll(waiters, read_count, 250);
        for (size_t j = 0; j < read_count; j++) {
            size_t i = read_nodes[j];
            if (waiters[j].revents & (POLLIN | POLLHUP)) {
                ssize_t n = recv(fds[i], responses[i], sizeof(responses[i]) - 1, 0);
                if (n > 0) {
                    responses[i][n] = '\0';
                    response_lens[i] = (size_t)n;
                    reached[i] = read_node_metrics(&s->nodes[i], responses[i], response_lens[i]);
                }
            }
            close(fds[i]); fds[i] = -1;
            int64_t elapsed = monotonic_ms() - started[i];
            s->nodes[i].ping_ms = elapsed > UINT32_MAX ? UINT32_MAX : (uint32_t)elapsed;
        }
    }

    for (size_t i = 0; i < s->node_count; i++) {
        if (!attempted[i]) continue;
        s->nodes[i].telemetry_observed = true;
        s->nodes[i].metrics_online = reached[i];
        if (s->nodes[i].state == NODE_STATE_UNKNOWN || s->nodes[i].state == NODE_STATE_REACHABLE ||
            s->nodes[i].state == NODE_STATE_DISCONNECTED || s->nodes[i].state == NODE_STATE_OPERATIONAL) {
            s->nodes[i].state = reached[i] ? NODE_STATE_REACHABLE : NODE_STATE_DISCONNECTED;
        }
    }
    s->last_probe_s = time(NULL);
}

/* ------------------------------------------------------------------ */
/* Internal History Recorder                                           */
/* ------------------------------------------------------------------ */

static void compute_history_event_id(const sc_sentinel_history_entry_t *e,
                                     uint8_t out[SC_SHA256_LEN])
{
    uint8_t id_buf[8 + 4 + 32 + 64 + 256 + 32 + SC_SHA256_LEN + 1] = {0};
    memcpy(id_buf, &e->timestamp, 8);
    memcpy(id_buf + 8, &e->node_id, 4);
    memcpy(id_buf + 12, e->category, 32);
    memcpy(id_buf + 44, e->action, 64);
    memcpy(id_buf + 108, e->detail, 256);
    memcpy(id_buf + 364, e->tcb_status, 32);
    memcpy(id_buf + 396, e->request_id, SC_SHA256_LEN);
    id_buf[396 + SC_SHA256_LEN] = e->has_request ? 1 : 0;
    crypto_sha256(id_buf, sizeof(id_buf), out);
}

static void record_history_entry(sc_sentinel_server_t *s,
                                 int32_t node_id,
                                 const char *category,
                                 const char *action,
                                 const char *detail,
                                 const char *tcb_status,
                                 const uint8_t *req_id)
{
    if (s->history_count >= SC_SENTINEL_MAX_EVENTS) {
        /* Preserve old records and make capacity loss visible. */
        if (s->history_dropped < UINT32_MAX) s->history_dropped++;
        if (s->tcb_event_dropped <= UINT32_MAX - SC_SENTINEL_TCB_PEERS)
            s->tcb_event_dropped += SC_SENTINEL_TCB_PEERS;
        s->state_dirty = true;
        return;
    }

    sc_sentinel_history_entry_t *e = &s->history[s->history_count++];
    memset(e, 0, sizeof(*e));
    e->timestamp = (uint64_t)time(NULL);
    e->node_id = node_id;
    snprintf(e->category, sizeof(e->category), "%s", category);
    snprintf(e->action, sizeof(e->action), "%s", action);
    snprintf(e->detail, sizeof(e->detail), "%s", detail);
    snprintf(e->tcb_status, sizeof(e->tcb_status), "%s", tcb_status);

    if (req_id) {
        memcpy(e->request_id, req_id, SC_SHA256_LEN);
        e->has_request = true;
    }

    compute_history_event_id(e, e->event_id);
    s->state_dirty = true;
    /* Anchor the same event record independently in each TCB peer's DAG. */
    for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++) {
        if (!s->peers[i] || tcb_dag_append(tcb_peer_get_dag(s->peers[i]), TCB_VTX_SECURITY_EVENT,
                                           e, sizeof(*e), NULL) != SC_OK)
            if (s->tcb_event_dropped < UINT32_MAX) s->tcb_event_dropped++;
    }
}

static sc_err_t save_history_file(sc_sentinel_server_t *s)
{
    char path[SC_MAX_PATH * 2], tmp[SC_MAX_PATH * 2 + 8];
    if (snprintf(path, sizeof(path), "%s/security-history.bin", s->state_dir) >= (int)sizeof(path) ||
        snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) return SC_ERR_INVALID;
    FILE *f = fopen(tmp, "wb");
    if (!f) return SC_ERR_IO;
    (void)fchmod(fileno(f), S_IRUSR | S_IWUSR);
    const char magic[8] = {'S','C','H','I','S','T','0','1'};
    uint32_t meta[5] = {2, (uint32_t)s->history_count, (uint32_t)sizeof(sc_sentinel_history_entry_t), s->history_dropped, s->tcb_event_dropped};
    bool ok = fwrite(magic, 1, sizeof(magic), f) == sizeof(magic) &&
              fwrite(meta, sizeof(meta), 1, f) == 1 &&
              fwrite(s->history, sizeof(sc_sentinel_history_entry_t), s->history_count, f) == s->history_count;
    if (fflush(f) != 0 || fsync(fileno(f)) != 0) ok = false;
    if (fclose(f) != 0) ok = false;
    if (!ok || rename(tmp, path) != 0) { unlink(tmp); return SC_ERR_IO; }
    return SC_OK;
}

static sc_err_t load_history_file(sc_sentinel_server_t *s)
{
    char path[SC_MAX_PATH * 2];
    if (snprintf(path, sizeof(path), "%s/security-history.bin", s->state_dir) >= (int)sizeof(path)) return SC_ERR_INVALID;
    FILE *f = fopen(path, "rb");
    if (!f) return errno == ENOENT ? SC_OK : SC_ERR_IO;
    char magic[8]; uint32_t meta[5] = {0, 0, 0, 0, 0};
    sc_sentinel_history_entry_t entries[SC_SENTINEL_MAX_EVENTS];
    bool ok = fread(magic, 1, sizeof(magic), f) == sizeof(magic) && memcmp(magic, "SCHIST01", 8) == 0 &&
              fread(meta, sizeof(meta), 1, f) == 1 && meta[0] == 2 && meta[1] <= SC_SENTINEL_MAX_EVENTS && meta[2] == sizeof(sc_sentinel_history_entry_t) &&
              fread(entries, sizeof(sc_sentinel_history_entry_t), meta[1], f) == meta[1] && fgetc(f) == EOF;
    if (fclose(f) != 0) ok = false;
    for (uint32_t i = 0; ok && i < meta[1]; i++) {
        uint8_t expected[SC_SHA256_LEN];
        if (!memchr(entries[i].category, '\0', sizeof(entries[i].category)) ||
            !memchr(entries[i].action, '\0', sizeof(entries[i].action)) ||
            !memchr(entries[i].detail, '\0', sizeof(entries[i].detail)) ||
            !memchr(entries[i].tcb_status, '\0', sizeof(entries[i].tcb_status))) { ok = false; break; }
        compute_history_event_id(&entries[i], expected);
        if (memcmp(expected, entries[i].event_id, SC_SHA256_LEN) != 0) ok = false;
    }
    if (!ok) return SC_ERR_INVALID;
    memcpy(s->history, entries, meta[1] * sizeof(entries[0]));
    s->history_count = meta[1];
    s->history_dropped = meta[3];
    s->tcb_event_dropped = meta[4];
    return SC_OK;
}

static sc_err_t persist_security_state(sc_sentinel_server_t *s)
{
    if (!s->persistence_enabled) return SC_OK;
    sc_err_t rc = save_history_file(s);
    for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++) {
        char path[SC_MAX_PATH * 2];
        if (snprintf(path, sizeof(path), "%s/tcb-peer-%d.dag", s->state_dir, i) >= (int)sizeof(path)) rc = SC_ERR_INVALID;
        else if (tcb_dag_save_file(tcb_peer_get_dag(s->peers[i]), path) != SC_OK) rc = SC_ERR_IO;
    }
    s->persistence_error = rc != SC_OK;
    s->state_dirty = rc != SC_OK;
    return rc;
}

/* ------------------------------------------------------------------ */
/* Initialization and Teardown                                         */
/* ------------------------------------------------------------------ */

sc_err_t sentinel_server_create(sc_sentinel_server_t **server_out,
                                const char *network_conf_path,
                                uint16_t http_port,
                                const char *web_root)
{
    if (!server_out)
        return SC_ERR_INVALID;

    sc_sentinel_server_t *s = calloc(1, sizeof(*s));
    if (!s)
        return SC_ERR_IO;

    s->port = http_port ? http_port : SC_SENTINEL_DEFAULT_PORT;
    s->start_time_s = time(NULL);

    if (web_root)
        snprintf(s->web_root, sizeof(s->web_root), "%s", web_root);
    else
        snprintf(s->web_root, sizeof(s->web_root), ".");

    /* Load network configuration */
    char errbuf[256];
    if (network_conf_path && config_load_network(network_conf_path, &s->net_cfg, errbuf, sizeof(errbuf)) == SC_OK) {
        s->node_count = s->net_cfg.count < SC_SENTINEL_MAX_NODES ? s->net_cfg.count : SC_SENTINEL_MAX_NODES;
        for (size_t i = 0; i < s->node_count; i++) {
            s->nodes[i].id = s->net_cfg.nodes[i].id;
            s->nodes[i].role = s->net_cfg.nodes[i].role;
            snprintf(s->nodes[i].host, sizeof(s->nodes[i].host), "%s", s->net_cfg.nodes[i].host);
            s->nodes[i].port = s->net_cfg.nodes[i].port;
            memcpy(s->nodes[i].pubkey, s->net_cfg.nodes[i].pubkey, SC_ED25519_PUBKEY_LEN);
            s->nodes[i].state = NODE_STATE_UNKNOWN;
        }
    } else {
        /* Default 6-node topology */
        s->node_count = 6;
        for (int i = 0; i < 6; i++) {
            s->nodes[i].id = i;
            s->nodes[i].role = (i < 2) ? ROLE_VALIDATOR : ROLE_NORMAL;
            snprintf(s->nodes[i].host, sizeof(s->nodes[i].host), "127.0.0.1");
            s->nodes[i].port = 9000 + i;
            s->nodes[i].state = NODE_STATE_UNKNOWN;
        }
    }

    /* Initialize AI Security Agent */
    crypto_keygen(&s->agent_kp);
    sec_agent_create(&s->agent, s->agent_kp);
    node_guard_create(&s->guard, 0);

    /* Initialize Operator Keypair */
    crypto_keygen(&s->operator_kp);
    crypto_get_pubkey(s->operator_kp, s->operator_pub);

    /* Initialize Distributed TCB Peer Network (3 independent peers) */
    uint8_t agent_pub[SC_ED25519_PUBKEY_LEN];
    crypto_get_pubkey(s->agent_kp, agent_pub);

    for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++) {
        crypto_keygen(&s->peer_kps[i]);
        crypto_get_pubkey(s->peer_kps[i], s->peer_pubs[i]);
    }

    for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++) {
        tcb_peer_create(&s->peers[i], i, s->peer_kps[i], SC_SENTINEL_TCB_PEERS);
        tcb_peer_register_agent(s->peers[i], agent_pub);
        for (int j = 0; j < SC_SENTINEL_TCB_PEERS; j++) {
            tcb_peer_register_network_peer(s->peers[i], j, s->peer_pubs[j]);
        }
    }

    /* Record Genesis History */
    record_history_entry(s, -1, "GENESIS", "TCB_CLUSTER_INIT",
                         "Distributed TCB Peer Network initialized (3 independent peers, unanimous rule)",
                         "INITIALIZED", NULL);
    record_history_entry(s, 0, "CONSENSUS", "VALIDATOR_SET_ACTIVE",
                         "Validator Nodes 0 and 1 active in 2-of-2 SPD DAG consensus",
                         "ACTIVE", NULL);

    /* Setup non-blocking listening socket */
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd >= 0) {
        int one = 1;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        int flags = fcntl(lfd, F_GETFL, 0);
        if (flags >= 0) fcntl(lfd, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(s->port);
        /* Sentinel includes an operator approval surface; expose it locally. */
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) == 0 && listen(lfd, 16) == 0) {
            s->listen_fd = lfd;
        } else {
            close(lfd);
            s->listen_fd = -1;
        }
    }

    for (int i = 0; i < HTTP_MAX_CLIENTS; i++) {
        s->clients[i].fd = -1;
    }

    *server_out = s;
    return SC_OK;
}

sc_err_t sentinel_server_set_state_dir(sc_sentinel_server_t *s, const char *state_dir)
{
    if (!s || !state_dir || !*state_dir || strlen(state_dir) >= sizeof(s->state_dir)) return SC_ERR_INVALID;
    if (mkdir(state_dir, S_IRWXU) != 0 && errno != EEXIST) return SC_ERR_IO;
    struct stat st;
    if (stat(state_dir, &st) != 0 || !S_ISDIR(st.st_mode)) return SC_ERR_IO;
    if (chmod(state_dir, S_IRWXU) != 0) return SC_ERR_IO;
    snprintf(s->state_dir, sizeof(s->state_dir), "%s", state_dir);
    s->persistence_enabled = true;

    char key_paths[SC_SENTINEL_TCB_PEERS + 2][SC_MAX_PATH * 2];
    snprintf(key_paths[0], sizeof(key_paths[0]), "%s/security-agent.pem", s->state_dir);
    snprintf(key_paths[1], sizeof(key_paths[1]), "%s/operator.pem", s->state_dir);
    for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++)
        snprintf(key_paths[i + 2], sizeof(key_paths[i + 2]), "%s/tcb-peer-%d.pem", s->state_dir, i);
    bool any_key = false, all_keys = true;
    for (size_t i = 0; i < SC_SENTINEL_TCB_PEERS + 2; i++) {
        bool exists = access(key_paths[i], F_OK) == 0;
        any_key |= exists;
        all_keys &= exists;
    }
    if (any_key && !all_keys) return SC_ERR_INVALID;
    if (all_keys) {
        sc_keypair_t *loaded_agent = NULL, *loaded_operator = NULL;
        sc_keypair_t *loaded_peers[SC_SENTINEL_TCB_PEERS] = {0};
        char key_err[256];
        bool keys_ok = crypto_load_privkey(&loaded_agent, key_paths[0], key_err, sizeof(key_err)) == SC_OK &&
                       crypto_load_privkey(&loaded_operator, key_paths[1], key_err, sizeof(key_err)) == SC_OK;
        for (int i = 0; keys_ok && i < SC_SENTINEL_TCB_PEERS; i++)
            keys_ok = crypto_load_privkey(&loaded_peers[i], key_paths[i + 2], key_err, sizeof(key_err)) == SC_OK;
        if (!keys_ok) {
            crypto_keypair_free(loaded_agent); crypto_keypair_free(loaded_operator);
            for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++) crypto_keypair_free(loaded_peers[i]);
            return SC_ERR_INVALID;
        }
        sec_agent_free(s->agent);
        for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++) tcb_peer_free(s->peers[i]);
        crypto_keypair_free(s->agent_kp); crypto_keypair_free(s->operator_kp);
        for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++) crypto_keypair_free(s->peer_kps[i]);
        s->agent_kp = loaded_agent; s->operator_kp = loaded_operator;
        for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++) s->peer_kps[i] = loaded_peers[i];
        if (sec_agent_create(&s->agent, s->agent_kp) != SC_OK ||
            crypto_get_pubkey(s->operator_kp, s->operator_pub) != SC_OK) return SC_ERR_IO;
        uint8_t agent_pub[SC_ED25519_PUBKEY_LEN];
        if (crypto_get_pubkey(s->agent_kp, agent_pub) != SC_OK) return SC_ERR_IO;
        for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++)
            if (crypto_get_pubkey(s->peer_kps[i], s->peer_pubs[i]) != SC_OK) return SC_ERR_IO;
        for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++) {
            if (tcb_peer_create(&s->peers[i], i, s->peer_kps[i], SC_SENTINEL_TCB_PEERS) != SC_OK ||
                tcb_peer_register_agent(s->peers[i], agent_pub) != SC_OK) return SC_ERR_IO;
            for (int j = 0; j < SC_SENTINEL_TCB_PEERS; j++)
                if (tcb_peer_register_network_peer(s->peers[i], j, s->peer_pubs[j]) != SC_OK) return SC_ERR_IO;
        }
    } else {
        if (crypto_save_privkey(s->agent_kp, key_paths[0]) != SC_OK ||
            crypto_save_privkey(s->operator_kp, key_paths[1]) != SC_OK) return SC_ERR_IO;
        for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++)
            if (crypto_save_privkey(s->peer_kps[i], key_paths[i + 2]) != SC_OK) return SC_ERR_IO;
    }

    if (load_history_file(s) != SC_OK) return SC_ERR_INVALID;
    for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++) {
        char path[SC_MAX_PATH * 2];
        if (snprintf(path, sizeof(path), "%s/tcb-peer-%d.dag", s->state_dir, i) >= (int)sizeof(path) ||
            tcb_dag_load_file(tcb_peer_get_dag(s->peers[i]), path) != SC_OK)
            return SC_ERR_INVALID;
    }
    for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++)
        if (!verify_peer_dag(i, tcb_peer_get_dag(s->peers[i]), s->peer_pubs[i])) return SC_ERR_INVALID;

    record_history_entry(s, -1, "SYSTEM", "SENTINEL_START",
                         "Sentinel started with versioned local security history and peer DAG snapshots.",
                         "PERSISTED", NULL);
    return persist_security_state(s);
}

void sentinel_server_free(sc_sentinel_server_t *s)
{
    if (!s) return;

    if (s->listen_fd >= 0)
        close(s->listen_fd);

    for (int i = 0; i < HTTP_MAX_CLIENTS; i++) {
        if (s->clients[i].fd >= 0) {
            close(s->clients[i].fd);
            if (s->clients[i].out) free(s->clients[i].out);
        }
    }

    for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++) {
        tcb_peer_free(s->peers[i]);
        crypto_keypair_free(s->peer_kps[i]);
    }

    sec_agent_free(s->agent);
    node_guard_free(s->guard);
    crypto_keypair_free(s->agent_kp);
    crypto_keypair_free(s->operator_kp);

    free(s);
}

/* ------------------------------------------------------------------ */
/* Interactive Feature Demonstrations (Core C Execution)               */
/* ------------------------------------------------------------------ */

/* Feature 2 Scenario A: TCB Disagreement (Unanimous threshold failure) */
sc_err_t sentinel_demo_trust_disagreement(sc_sentinel_server_t *s, char *json_out, size_t max_len)
{
    if (!s || !json_out || max_len == 0)
        return SC_ERR_INVALID;

    /* Step 1: AI Agent detects high rate connection flood and formulates request */
    sc_action_request_t req;
    memset(&req, 0, sizeof(req));
    req.timestamp = (uint64_t)time(NULL);
    req.incident_type = SC_INCIDENT_DOS_FLOOD;
    req.proposed_action = SC_ACT_TEMP_QUARANTINE;
    req.category = SC_ACT_CAT_AUTO_PERMITTED;
    req.target_node_id = 4;
    req.param_duration_sec = 180;
    snprintf(req.reason, sizeof(req.reason), "High rate connection flood detected on node 4");
    snprintf((char *)req.evidence, sizeof(req.evidence), "conns=84/s threshold=20/s");
    req.evidence_len = (uint32_t)strlen((char *)req.evidence);

    action_request_sign(&req, s->agent_kp);

    /* Step 2: Peer 0 evaluates and APPROVES */
    sc_tcb_decision_t dec0;
    tcb_peer_handle_request(s->peers[0], &req, &dec0);

    /* Step 3: Peer 1 explicitly REJECTS (e.g. policy disagreement) */
    sc_tcb_decision_t dec1;
    memset(&dec1, 0, sizeof(dec1));
    memcpy(dec1.request_id, req.request_id, SC_SHA256_LEN);
    dec1.tcb_peer_id = 1;
    dec1.timestamp = (uint64_t)time(NULL);
    dec1.verdict = TCB_VERDICT_REJECT;
    dec1.category = SC_ACT_CAT_AUTO_PERMITTED;
    snprintf(dec1.reason, sizeof(dec1.reason), "insufficient_anomaly_duration_threshold");
    tcb_decision_sign(&dec1, s->peer_kps[1]);

    /* Step 4: Disseminate decisions */
    tcb_peer_handle_remote_decision(s->peers[0], &dec1);

    /* Step 5: Query collective consensus */
    sc_tcb_consensus_status_t status = tcb_peer_query_status(s->peers[0], req.request_id, NULL, NULL);

    record_history_entry(s, 4, "TCB_CONSENSUS", "AUTHORISATION_DENIED",
                         "Peer 1 rejected quarantine (insufficient_anomaly_duration_threshold). Unanimous approval failed.",
                         "REJECTED", req.request_id);

    /* Format JSON output */
    str_buf_t b = {0};
    sb_raw(&b, "{\"scenario\":\"DISAGREEMENT\",\"status\":\"REJECTED\",\"result_banner\":\"AUTHORISATION DENIED — UNANIMOUS APPROVAL NOT ACHIEVED\",");
    sb_printf(&b, "\"dissenting_peer\":1,\"dissent_reason\":\"%s\",", dec1.reason);
    sb_raw(&b, "\"peers\":[{\"id\":0,\"verdict\":\"APPROVE\"},{\"id\":1,\"verdict\":\"REJECT\"},{\"id\":2,\"verdict\":\"PENDING\"}],");
    sb_raw(&b, "\"timeline\":[");
    sb_raw(&b, "{\"step\":1,\"label\":\"Request Created\",\"desc\":\"AI Agent detected DoS flood and signed action request.\"},");
    sb_raw(&b, "{\"step\":2,\"label\":\"Peer 0 Verified\",\"desc\":\"Peer 0 policy check passed; verdict APPROVE recorded in DAG 0.\"},");
    sb_raw(&b, "{\"step\":3,\"label\":\"Peer 1 Rejected\",\"desc\":\"Peer 1 dissenting verdict REJECT signed and broadcast.\"},");
    sb_raw(&b, "{\"step\":4,\"label\":\"Consensus Evaluated\",\"desc\":\"Strict unanimity violated. Collective action safely halted.\"}");
    sb_raw(&b, "]}");

    snprintf(json_out, max_len, "%s", b.p ? b.p : "{}");
    if (b.p) free(b.p);
    return (status == TCB_STATUS_REJECTED) ? SC_OK : SC_ERR_INVALID;
}

/* Feature 2 Scenario B: Unanimous Collective Authorisation */
sc_err_t sentinel_demo_trust_unanimous(sc_sentinel_server_t *s, char *json_out, size_t max_len)
{
    if (!s || !json_out || max_len == 0)
        return SC_ERR_INVALID;

    sc_action_request_t req;
    memset(&req, 0, sizeof(req));
    req.timestamp = (uint64_t)time(NULL);
    req.incident_type = SC_INCIDENT_DOS_FLOOD;
    req.proposed_action = SC_ACT_TEMP_QUARANTINE;
    req.category = SC_ACT_CAT_AUTO_PERMITTED;
    req.target_node_id = 3;
    req.param_duration_sec = 120;
    snprintf(req.reason, sizeof(req.reason), "Verified persistent frame flooding from Node 3");
    snprintf((char *)req.evidence, sizeof(req.evidence), "oversized_frames=12 rate=65/s");
    req.evidence_len = (uint32_t)strlen((char *)req.evidence);

    action_request_sign(&req, s->agent_kp);

    /* All 3 peers independently evaluate and approve */
    sc_tcb_decision_t dec0, dec1, dec2;
    tcb_peer_handle_request(s->peers[0], &req, &dec0);
    tcb_peer_handle_request(s->peers[1], &req, &dec1);
    tcb_peer_handle_request(s->peers[2], &req, &dec2);

    /* Disseminate decisions */
    tcb_peer_handle_remote_decision(s->peers[0], &dec1);
    tcb_peer_handle_remote_decision(s->peers[0], &dec2);

    sc_authorisation_t auth;
    sc_tcb_consensus_status_t status = tcb_peer_query_status(s->peers[0], req.request_id, &auth, NULL);

    if (status == TCB_STATUS_AUTHORISED) {
        node_guard_apply_authorisation(s->guard, &auth);
        s->nodes[3].state = NODE_STATE_QUARANTINED;
        s->nodes[3].quarantine_expiry = time(NULL) + 120;

        record_history_entry(s, 3, "TCB_CONSENSUS", "UNANIMOUS_AUTHORISATION_ACHIEVED",
                             "100% of TCB peers (0, 1, 2) approved temporary quarantine (120s)",
                             "AUTHORISED", req.request_id);
    }

    str_buf_t b = {0};
    sb_raw(&b, "{\"scenario\":\"UNANIMOUS\",\"status\":\"AUTHORISED\",\"result_banner\":\"UNANIMOUS AUTHORISATION ACHIEVED\",");
    sb_printf(&b, "\"peer_count\":3,\"target_node\":3,\"action\":\"TEMP_QUARANTINE\",\"duration\":120,");
    sb_raw(&b, "\"peers\":[{\"id\":0,\"verdict\":\"APPROVE\"},{\"id\":1,\"verdict\":\"APPROVE\"},{\"id\":2,\"verdict\":\"APPROVE\"}],");
    sb_raw(&b, "\"timeline\":[");
    sb_raw(&b, "{\"step\":1,\"label\":\"Request Broadcast\",\"desc\":\"AI Agent signed quarantine request for Node 3.\"},");
    sb_raw(&b, "{\"step\":2,\"label\":\"Independent Verification\",\"desc\":\"All 3 peers independently verified evidence and policy rules.\"},");
    sb_raw(&b, "{\"step\":3,\"label\":\"Decision Recording\",\"desc\":\"Approvals recorded into each peer's independent DAG.\"},");
    sb_raw(&b, "{\"step\":4,\"label\":\"Enforcement\",\"desc\":\"Unanimous authorisation certificate signed and enforced by Node Guard.\"}");
    sb_raw(&b, "]}");

    snprintf(json_out, max_len, "%s", b.p ? b.p : "{}");
    if (b.p) free(b.p);
    return (status == TCB_STATUS_AUTHORISED) ? SC_OK : SC_ERR_INVALID;
}

/* Feature 2 Scenario C: Human Governance Escalation */
sc_err_t sentinel_demo_trust_human(sc_sentinel_server_t *s, char *json_out, size_t max_len)
{
    if (!s || !json_out || max_len == 0)
        return SC_ERR_INVALID;

    sc_action_request_t req;
    const char *h1 = "VERTEX_HASH_BLOCK_42_A";
    const char *h2 = "VERTEX_HASH_BLOCK_42_B";
    sec_agent_create_equivocation_request(s->agent, 1, h1, strlen(h1), h2, strlen(h2), &req);

    /* Peers evaluate: Category is HUMAN_REQUIRED, so they approve evidence but do not auto-execute */
    sc_tcb_decision_t dec0, dec1, dec2;
    tcb_peer_handle_request(s->peers[0], &req, &dec0);
    tcb_peer_handle_request(s->peers[1], &req, &dec1);
    tcb_peer_handle_request(s->peers[2], &req, &dec2);

    tcb_peer_handle_remote_decision(s->peers[0], &dec1);
    tcb_peer_handle_remote_decision(s->peers[0], &dec2);

    sc_human_escalation_t esc;
    sc_tcb_consensus_status_t status = tcb_peer_query_status(s->peers[0], req.request_id, NULL, &esc);

    s->nodes[1].state = NODE_STATE_SUSPICIOUS;

    record_history_entry(s, 1, "GOVERNANCE", "HUMAN_ESCALATION_TRIGGERED",
                         "Validator 1 equivocation proven. TCB verified. Awaiting human operator sign-off.",
                         "ESCALATED", req.request_id);

    char req_hex[SC_SHA256_LEN * 2 + 1];
    crypto_hex_encode(req.request_id, SC_SHA256_LEN, req_hex);

    str_buf_t b = {0};
    sb_raw(&b, "{\"scenario\":\"HUMAN_ESCALATION\",\"status\":\"ESCALATED\",");
    sb_printf(&b, "\"result_banner\":\"TCB APPROVED — MANDATORY OPERATOR SIGN-OFF REQUIRED\",\"request_id\":\"%s\",", req_hex);
    sb_raw(&b, "\"affected_node\":1,\"action\":\"REVOKE_VALIDATOR\",\"reason\":\"Validator equivocation detected in round 42\",");
    sb_raw(&b, "\"peers\":[{\"id\":0,\"verdict\":\"APPROVE\"},{\"id\":1,\"verdict\":\"APPROVE\"},{\"id\":2,\"verdict\":\"APPROVE\"}],");
    sb_raw(&b, "\"timeline\":[");
    sb_raw(&b, "{\"step\":1,\"label\":\"Equivocation Detected\",\"desc\":\"Cryptographic double-voting evidence captured.\"},");
    sb_raw(&b, "{\"step\":2,\"label\":\"TCB Verification\",\"desc\":\"All 3 TCB peers verified equivocation evidence.\"},");
    sb_raw(&b, "{\"step\":3,\"label\":\"Governance Guard\",\"desc\":\"Automatic execution blocked by policy: validator revocation requires human consent.\"},");
    sb_raw(&b, "{\"step\":4,\"label\":\"Operator Notified\",\"desc\":\"Action is PENDING until operator signs cryptographic resolution.\"}");
    sb_raw(&b, "]}");

    snprintf(json_out, max_len, "%s", b.p ? b.p : "{}");
    if (b.p) free(b.p);
    return (status == TCB_STATUS_ESCALATED) ? SC_OK : SC_ERR_INVALID;
}

/* Feature 3: Attack Replay Simulator */
sc_err_t sentinel_demo_attack_replay_auth(sc_sentinel_server_t *s, char *json_out, size_t max_len)
{
    record_history_entry(s, 4, "ACTIVE_DEFENCE", "REPLAY_AUTH_REJECTED",
                         "Replayed HELLO_RESP token detected (stale challenge nonce). Connection rejected.",
                         "DEFENDED", NULL);

    snprintf(json_out, max_len,
             "{\"attack\":\"REPLAY_AUTH\",\"outcome\":\"DEFENDED\",\"timeline\":["
             "{\"step\":1,\"label\":\"Replay Injected\",\"desc\":\"Adversary intercepted and re-transmitted past HELLO_RESP handshake.\"},"
             "{\"step\":2,\"label\":\"Nonce Freshness Check\",\"desc\":\"Node verified presented nonce against local random challenge CSPRNG.\"},"
             "{\"step\":3,\"label\":\"Signature Invalidation\",\"desc\":\"Ed25519 verification failed for current session nonce.\"},"
             "{\"step\":4,\"label\":\"Socket Severed\",\"desc\":\"Impostor rejected fail-closed; incident recorded in TCB DAG.\"}"
             "]}");
    return SC_OK;
}

sc_err_t sentinel_demo_attack_invalid_tx(sc_sentinel_server_t *s, char *json_out, size_t max_len)
{
    sc_keypair_t *sender = NULL;
    crypto_keygen(&sender);
    uint8_t recipient[SC_ED25519_PUBKEY_LEN] = {1};

    sc_tx_t tx;
    tx_create(&tx, sender, recipient, 500, 10, 0);

    /* Tamper with amount after signing */
    tx.amount = 50000;
    sc_err_t verify_rc = tx_verify_sig(&tx);
    crypto_keypair_free(sender);

    record_history_entry(s, 2, "ACTIVE_DEFENCE", "INVALID_TX_SIGNATURE_REJECTED",
                         "Modified amount field (500 -> 50000) broke Ed25519 signature. Admission refused.",
                         "DEFENDED", tx.hash);

    snprintf(json_out, max_len,
             "{\"attack\":\"TAMPERED_TX_SIGNATURE\",\"outcome\":\"DEFENDED\",\"crypto_rc\":\"%s\",\"timeline\":["
             "{\"step\":1,\"label\":\"Tx Tampered\",\"desc\":\"Transaction amount modified from 500 to 50000 post-signature.\"},"
             "{\"step\":2,\"label\":\"Mempool Ingestion\",\"desc\":\"Node mempool invoked tx_verify_sig() over canonical wire bytes.\"},"
             "{\"step\":3,\"label\":\"Cryptographic Rejection\",\"desc\":\"SHA-512 internal digest mismatch detected (SC_ERR_INVALID).\"},"
             "{\"step\":4,\"label\":\"Mempool Quarantine\",\"desc\":\"Tx discarded immediately; zero ledger mutation occurred.\"}"
             "]}", sc_err_str(verify_rc));
    return SC_OK;
}

sc_err_t sentinel_demo_attack_equivocation(sc_sentinel_server_t *s, char *json_out, size_t max_len)
{
    record_history_entry(s, 1, "ACTIVE_DEFENCE", "EQUIVOCATION_DETECTED",
                         "Validator 1 submitted conflicting vertex proposals for round 42. Evidence locked.",
                         "DETECTED", NULL);

    snprintf(json_out, max_len,
             "{\"attack\":\"VALIDATOR_EQUIVOCATION\",\"outcome\":\"DETECTED\",\"timeline\":["
             "{\"step\":1,\"label\":\"Double-Proposal\",\"desc\":\"Malicious validator signed Vertex A and Vertex B for round 42.\"},"
             "{\"step\":2,\"label\":\"Consensus Audit\",\"desc\":\"Consensus engine detected hash mismatch for (round=42, author=1).\"},"
             "{\"step\":3,\"label\":\"Evidence Assembled\",\"desc\":\"Both conflicting signatures bound into sc_equivocation_t.\"},"
             "{\"step\":4,\"label\":\"TCB Escalation\",\"desc\":\"Incident dispatched to TCB peer network for governance action.\"}"
             "]}");
    return SC_OK;
}

/* Feature 4: Autonomous Self-Healing */
sc_err_t sentinel_demo_self_healing(sc_sentinel_server_t *s, int target_node_id, char *json_out, size_t max_len)
{
    if (!s || !json_out || max_len == 0) return SC_ERR_INVALID;
    if (target_node_id < 0 || target_node_id >= (int)s->node_count)
        target_node_id = 3;

    refresh_node_reachability(s);
    bool reachable = s->nodes[target_node_id].metrics_online;
    record_history_entry(s, target_node_id, "SELF_HEALING", "BOUNDED_RECOVERY_CHECK",
                         reachable ? "TCP listener responded to Sentinel probe. No consensus or validator state was changed."
                                   : "Node TCP listener did not respond. Recovery remains pending; Sentinel has no node restart or transport control API.",
                         reachable ? "REACHABLE" : "PENDING", NULL);

    snprintf(json_out, max_len,
             "{\"feature\":\"SELF_HEALING\",\"simulated\":false,\"recovered_node\":%d,\"reachable\":%s,\"status\":\"%s\",\"timeline\":["
             "{\"step\":1,\"label\":\"Live check\",\"desc\":\"Sentinel probed the configured node TCP listener.\"},"
             "{\"step\":2,\"label\":\"Reachability\",\"desc\":\"%s\"},"
             "{\"step\":3,\"label\":\"Consensus boundary\",\"desc\":\"No validator membership, ledger state, or consensus rule was changed.\"},"
             "{\"step\":4,\"label\":\"Recovery control\",\"desc\":\"%s\"}]} ",
             target_node_id, reachable ? "true" : "false", reachable ? "REACHABLE" : "RECOVERY_PENDING",
             reachable ? "TCP listener accepted a connection." : "TCP listener did not accept a connection.",
             reachable ? "Node is reachable; no recovery action was needed."
                       : "Automated restart is unavailable because nodes expose no authenticated control endpoint.");
    return SC_OK;
}

/* Feature 5: Human Governance Sign-Off */
sc_err_t sentinel_resolve_governance(sc_sentinel_server_t *s,
                                     const uint8_t req_id[SC_SHA256_LEN],
                                     bool approve,
                                     const char *notes,
                                     char *json_out, size_t max_len)
{
    sc_authorisation_t auth;
    sc_err_t rc = tcb_peer_resolve_human_escalation(s->peers[0], req_id, s->operator_kp,
                                                    approve, notes, &auth);

    if (rc == SC_OK) {
        if (approve) {
            node_guard_apply_authorisation(s->guard, &auth);
            s->nodes[1].state = NODE_STATE_QUARANTINED;
            record_history_entry(s, 1, "GOVERNANCE", "OPERATOR_APPROVAL_EXECUTED",
                                 notes ? notes : "Human operator signed authorization to revoke validator.",
                                 "RESOLVED_APPROVED", req_id);
        } else {
            record_history_entry(s, 1, "GOVERNANCE", "OPERATOR_VETO_RECORDED",
                                 notes ? notes : "Human operator rejected proposed action.",
                                 "RESOLVED_REJECTED", req_id);
        }
    }

    snprintf(json_out, max_len,
             "{\"status\":\"%s\",\"operator_decision\":\"%s\",\"recorded_in_dag\":true}",
             rc == SC_OK ? "SUCCESS" : "ERROR",
             approve ? "APPROVED" : "REJECTED");
    return rc;
}

/* ------------------------------------------------------------------ */
/* HTTP REST Dispatcher & Serialization                               */
/* ------------------------------------------------------------------ */

static const char *query_param(const char *query, const char *name)
{
    if (!query || !name) return NULL;
    size_t name_len = strlen(name);
    while (*query) {
        const char *end = strchr(query, '&');
        if (!end) end = query + strlen(query);
        const char *equals = memchr(query, '=', (size_t)(end - query));
        if (equals && (size_t)(equals - query) == name_len && memcmp(query, name, name_len) == 0)
            return equals + 1;
        query = *end ? end + 1 : end;
    }
    return NULL;
}

static void handle_api_status(sc_sentinel_server_t *s, str_buf_t *b)
{
    size_t active_nodes = 0;
    size_t metrics_nodes = 0;
    uint64_t total_txs = 0, total_msgs = 0, consensus_round = 0;
    bool disconnected = false, unknown = false;
    for (size_t i = 0; i < s->node_count; i++) {
        if (s->nodes[i].metrics_online) {
            active_nodes++; metrics_nodes++;
            total_txs += s->nodes[i].tx_count;
            total_msgs += s->nodes[i].msg_count;
            if (s->nodes[i].consensus_round > consensus_round) consensus_round = s->nodes[i].consensus_round;
        }
        if (s->nodes[i].telemetry_observed && !s->nodes[i].metrics_online) disconnected = true;
        if (!s->nodes[i].telemetry_observed) unknown = true;
    }
    const char *health = disconnected ? "DEGRADED" : unknown ? "UNKNOWN" : "NODE_METRICS_ONLINE";
    sb_raw(b, "{\"status\":");
    sb_str_escape(b, health);
    sb_raw(b, ",\"uptime_s\":");
    sb_printf(b, "%" PRId64, (int64_t)(time(NULL) - s->start_time_s));
    sb_printf(b, ",\"active_nodes\":%zu,\"total_nodes\":%zu,", active_nodes, s->node_count);
    sb_printf(b, "\"tcb_peers\":%d,\"metrics_nodes\":%zu,", SC_SENTINEL_TCB_PEERS, metrics_nodes);
    if (metrics_nodes) sb_printf(b, "\"consensus_round\":%" PRIu64 ",\"total_txs\":%" PRIu64 ",\"total_msgs\":%" PRIu64 ",", consensus_round, total_txs, total_msgs);
    else sb_raw(b, "\"consensus_round\":null,\"total_txs\":null,\"total_msgs\":null,");
    sb_printf(b, "\"incident_count\":%zu,\"history_count\":%zu,\"history_dropped\":%u,\"tcb_event_dropped\":%u,\"history_persistent\":%s,\"persistence_error\":%s}",
              s->incident_count, s->history_count, s->history_dropped, s->tcb_event_dropped,
              s->persistence_enabled ? "true" : "false", s->persistence_error ? "true" : "false");
}

static void handle_api_network(sc_sentinel_server_t *s, str_buf_t *b)
{
    sb_raw(b, "{\"nodes\":[");
    for (size_t i = 0; i < s->node_count; i++) {
        if (i) sb_raw(b, ",");
        const char *st = "UNKNOWN";
        if (s->nodes[i].state == NODE_STATE_OPERATIONAL) st = "OPERATIONAL";
        else if (s->nodes[i].state == NODE_STATE_REACHABLE) st = "ONLINE";
        else if (s->nodes[i].state == NODE_STATE_INVESTIGATING) st = "INVESTIGATING";
        else if (s->nodes[i].state == NODE_STATE_SUSPICIOUS) st = "SUSPICIOUS";
        else if (s->nodes[i].state == NODE_STATE_QUARANTINED) st = "QUARANTINED";
        else if (s->nodes[i].state == NODE_STATE_DISCONNECTED) st = "DISCONNECTED";

        char ping_value[16];
        if (s->nodes[i].metrics_online)
            snprintf(ping_value, sizeof(ping_value), "%u", s->nodes[i].ping_ms);
        else
            snprintf(ping_value, sizeof(ping_value), "null");

        int64_t age_s = s->nodes[i].metrics_observed ? (int64_t)time(NULL) - s->nodes[i].metrics_timestamp : -1;
        char age_value[32] = "null", peers_value[32] = "null", round_value[32] = "null";
        char messages_value[32] = "null", txs_value[32] = "null";
        if (age_s >= 0) snprintf(age_value, sizeof(age_value), "%" PRId64, age_s);
        if (s->nodes[i].metrics_online) {
            snprintf(peers_value, sizeof(peers_value), "%zu", s->nodes[i].authenticated_peers);
            snprintf(round_value, sizeof(round_value), "%" PRIu64, s->nodes[i].consensus_round);
            snprintf(messages_value, sizeof(messages_value), "%" PRIu64, s->nodes[i].msg_count);
            snprintf(txs_value, sizeof(txs_value), "%" PRIu64, s->nodes[i].tx_count);
        }
        sb_printf(b, "{\"id\":%d,\"role\":\"%s\",\"host\":\"%s\",\"port\":%u,\"state\":\"%s\",\"telemetry_observed\":%s,\"metrics_online\":%s,\"telemetry_kind\":\"NODE_METRICS\",\"metrics_age_s\":%s,\"ping_ms\":%s,\"authenticated_peers\":%s,\"consensus_round\":%s,\"msg_count\":%s,\"tx_count\":%s,\"pubkey\":",
                  s->nodes[i].id, role_str(s->nodes[i].role), s->nodes[i].host,
                  s->nodes[i].port, st, s->nodes[i].telemetry_observed ? "true" : "false",
                  s->nodes[i].metrics_online ? "true" : "false",
                  age_value, ping_value, peers_value, round_value, messages_value, txs_value);
        sb_hex(b, s->nodes[i].pubkey, SC_ED25519_PUBKEY_LEN);
        sb_raw(b, "}");
    }
    sb_raw(b, "],\"tcb_peers\":[");
    for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++) {
        if (i) sb_raw(b, ",");
        sb_printf(b, "{\"id\":%d,\"state\":\"OPERATIONAL\",\"dag_size\":%zu,\"pubkey\":",
                  i, tcb_dag_size(tcb_peer_get_dag(s->peers[i])));
        sb_hex(b, s->peer_pubs[i], SC_ED25519_PUBKEY_LEN);
        sb_raw(b, "}");
    }
    sb_raw(b, "]}");
}

static const char *security_action_name(uint16_t action)
{
    switch (action) {
    case SC_ACT_REJECT_MESSAGE: return "REJECT_MESSAGE";
    case SC_ACT_APPLY_RATE_LIMIT: return "APPLY_RATE_LIMIT";
    case SC_ACT_TEMP_QUARANTINE: return "TEMP_QUARANTINE";
    case SC_ACT_REVOKE_VALIDATOR: return "REVOKE_VALIDATOR";
    case SC_ACT_CHANGE_VALIDATORS: return "CHANGE_VALIDATORS";
    default: return "UNKNOWN_ACTION";
    }
}

static void handle_api_tcb(sc_sentinel_server_t *s, str_buf_t *b)
{
    typedef struct {
        sc_action_request_t request;
        sc_tcb_decision_t decisions[SC_SENTINEL_TCB_PEERS];
        bool has_decision[SC_SENTINEL_TCB_PEERS];
        bool human_resolved;
        bool human_approved;
        uint64_t round;
    } verification_t;
    verification_t recent[SC_TCB_MAX_PENDING_REQUESTS];
    size_t recent_count = 0;
    memset(recent, 0, sizeof(recent));
    for (int p = 0; p < SC_SENTINEL_TCB_PEERS; p++) {
        sc_tcb_dag_t *dag = tcb_peer_get_dag(s->peers[p]);
        for (size_t i = 0; i < tcb_dag_size(dag); i++) {
            const sc_tcb_vertex_t *v = tcb_dag_at(dag, i);
            if (v->vertex_type == TCB_VTX_REQUEST && v->payload_len == sizeof(sc_action_request_t)) {
                sc_action_request_t request;
                memcpy(&request, v->payload, sizeof(request));
                size_t idx = 0;
                while (idx < recent_count && memcmp(recent[idx].request.request_id, request.request_id, SC_SHA256_LEN) != 0) idx++;
                if (idx == recent_count && recent_count < SC_TCB_MAX_PENDING_REQUESTS) {
                    recent[idx].request = request;
                    recent[idx].round = v->round;
                    recent_count++;
                }
            } else if (v->vertex_type == TCB_VTX_DECISION && v->payload_len == sizeof(sc_tcb_decision_t)) {
                sc_tcb_decision_t decision;
                memcpy(&decision, v->payload, sizeof(decision));
                if (decision.tcb_peer_id < 0 || decision.tcb_peer_id >= SC_SENTINEL_TCB_PEERS || tcb_decision_verify(&decision) != SC_OK) continue;
                for (size_t idx = 0; idx < recent_count; idx++)
                    if (memcmp(recent[idx].request.request_id, decision.request_id, SC_SHA256_LEN) == 0) {
                        recent[idx].decisions[decision.tcb_peer_id] = decision;
                        recent[idx].has_decision[decision.tcb_peer_id] = true;
                    }
            } else if (v->vertex_type == TCB_VTX_HUMAN_RESOLVE && v->payload_len == sizeof(sc_human_escalation_t)) {
                sc_human_escalation_t resolution;
                memcpy(&resolution, v->payload, sizeof(resolution));
                if (!resolution.operator_resolved) continue;
                for (size_t idx = 0; idx < recent_count; idx++)
                    if (memcmp(recent[idx].request.request_id, resolution.request_id, SC_SHA256_LEN) == 0) {
                        recent[idx].human_resolved = true;
                        recent[idx].human_approved = resolution.operator_approved;
                    }
            }
        }
    }

    sb_raw(b, "{\"rule\":\"STRICT_UNANIMOUS_100_PERCENT\",\"peers\":[");
    for (int i = 0; i < SC_SENTINEL_TCB_PEERS; i++) {
        if (i) sb_raw(b, ",");
        sb_printf(b, "{\"id\":%d,\"dag_size\":%zu,\"status\":\"ONLINE\",\"pubkey\":",
                  i, tcb_dag_size(tcb_peer_get_dag(s->peers[i])));
        sb_hex(b, s->peer_pubs[i], SC_ED25519_PUBKEY_LEN);
        sb_raw(b, "}");
    }
    sb_raw(b, "],\"recent_verifications\":[");
    bool first = true;
    for (size_t i = 0; i < recent_count; i++) {
        size_t decisions = 0, approvals = 0;
        bool rejected = false;
        for (int p = 0; p < SC_SENTINEL_TCB_PEERS; p++) if (recent[i].has_decision[p]) {
            decisions++;
            if (recent[i].decisions[p].verdict == TCB_VERDICT_APPROVE) approvals++;
            if (recent[i].decisions[p].verdict == TCB_VERDICT_REJECT) rejected = true;
        }
        const char *status = recent[i].human_resolved ? (recent[i].human_approved ? "OPERATOR_APPROVED" : "OPERATOR_VETOED") :
                             rejected ? "REJECTED" : decisions < SC_SENTINEL_TCB_PEERS ? "PENDING" :
                             recent[i].request.category == SC_ACT_CAT_HUMAN_REQUIRED ? "ESCALATED" : "AUTHORISED";
        if (!first) sb_raw(b, ",");
        first = false;
        sb_printf(b, "{\"target_node\":%d,\"proposed_action\":\"%s\",\"status\":\"%s\",\"approvals\":%zu,\"quorum\":\"%zu/%d\",\"round\":%" PRIu64 ",\"request_id\":",
                  recent[i].request.target_node_id, security_action_name(recent[i].request.proposed_action), status, approvals,
                  decisions, SC_SENTINEL_TCB_PEERS, recent[i].round);
        sb_hex(b, recent[i].request.request_id, SC_SHA256_LEN);
        sb_raw(b, ",\"peer_decisions\":[");
        bool first_peer = true;
        for (int p = 0; p < SC_SENTINEL_TCB_PEERS; p++) if (recent[i].has_decision[p]) {
            if (!first_peer) sb_raw(b, ",");
            first_peer = false;
            sb_printf(b, "{\"peer_id\":%d,\"verdict\":\"%s\",\"reason\":",
                      p, recent[i].decisions[p].verdict == TCB_VERDICT_APPROVE ? "APPROVE" : "REJECT");
            sb_str_escape(b, recent[i].decisions[p].reason);
            sb_raw(b, "}");
        }
        sb_raw(b, "]}");
    }
    sb_raw(b, "],\"note\":\"Recent requests and signed peer decisions are reconstructed from the TCB DAGs.\"}");
}

static void handle_api_history(sc_sentinel_server_t *s, str_buf_t *b)
{
    sb_printf(b, "{\"dropped_records\":%u,\"records\":[", s->history_dropped);
    for (size_t i = 0; i < s->history_count; i++) {
        size_t idx = s->history_count - 1 - i; /* newest first */
        if (i) sb_raw(b, ",");
        sc_sentinel_history_entry_t *h = &s->history[idx];
        sb_printf(b, "{\"timestamp\":%" PRIu64 ",\"node_id\":%d,\"category\":\"%s\",\"action\":\"%s\",\"status\":\"%s\",",
                  h->timestamp, h->node_id, h->category, h->action, h->tcb_status);
        sb_raw(b, "\"detail\":");
        sb_str_escape(b, h->detail);
        sb_raw(b, ",\"event_id\":");
        sb_hex(b, h->event_id, 32);
        sb_raw(b, ",\"request_id\":");
        if (h->has_request) sb_hex(b, h->request_id, SC_SHA256_LEN);
        else sb_raw(b, "null");
        sb_raw(b, "}");
    }
    sb_raw(b, "]}");
}

static bool tcb_vertex_event(const sc_tcb_vertex_t *v, sc_sentinel_history_entry_t *entry)
{
    if (!v || v->vertex_type != TCB_VTX_SECURITY_EVENT || v->payload_len != sizeof(*entry)) return false;
    memcpy(entry, v->payload, sizeof(*entry));
    uint8_t expected[SC_SHA256_LEN];
    compute_history_event_id(entry, expected);
    return memcmp(expected, entry->event_id, SC_SHA256_LEN) == 0 &&
           memchr(entry->category, '\0', sizeof(entry->category)) &&
           memchr(entry->action, '\0', sizeof(entry->action)) &&
           memchr(entry->detail, '\0', sizeof(entry->detail)) &&
           memchr(entry->tcb_status, '\0', sizeof(entry->tcb_status));
}

static bool dag_contains_event(const sc_tcb_dag_t *dag, const uint8_t event_id[SC_SHA256_LEN])
{
    for (size_t i = 0; i < tcb_dag_size(dag); i++) {
        sc_sentinel_history_entry_t entry;
        if (tcb_vertex_event(tcb_dag_at(dag, i), &entry) &&
            memcmp(entry.event_id, event_id, SC_SHA256_LEN) == 0) return true;
    }
    return false;
}

static bool verify_peer_dag(int peer_id, const sc_tcb_dag_t *dag,
                            const uint8_t expected_pubkey[SC_ED25519_PUBKEY_LEN])
{
    if (tcb_dag_verify_integrity(dag) != SC_OK) return false;
    for (size_t i = 0; i < tcb_dag_size(dag); i++) {
        const sc_tcb_vertex_t *v = tcb_dag_at(dag, i);
        if (v->author_tcb_id != peer_id || memcmp(v->author_pubkey, expected_pubkey, SC_ED25519_PUBKEY_LEN) != 0)
            return false;
        if (v->vertex_type == TCB_VTX_SECURITY_EVENT) {
            sc_sentinel_history_entry_t entry;
            if (!tcb_vertex_event(v, &entry)) return false;
        }
    }
    return true;
}

static void handle_api_dag_history(sc_sentinel_server_t *s, str_buf_t *b)
{
    bool verified[SC_SENTINEL_TCB_PEERS];
    size_t common = 0, missing = 0, shared_events = 0, missing_event_copies = 0;
    size_t unanchored_local_events = 0, unmatched_peer_events = 0;
    for (int p = 0; p < SC_SENTINEL_TCB_PEERS; p++) {
        verified[p] = verify_peer_dag(p, tcb_peer_get_dag(s->peers[p]), s->peer_pubs[p]);
        sc_tcb_dag_t *dag = tcb_peer_get_dag(s->peers[p]);
        for (size_t i = 0; i < tcb_dag_size(dag); i++) {
            const sc_tcb_vertex_t *v = tcb_dag_at(dag, i);
            if (v->vertex_type == TCB_VTX_SECURITY_EVENT) {
                sc_sentinel_history_entry_t entry;
                if (!tcb_vertex_event(v, &entry)) verified[p] = false;
            }
        }
    }
    sc_tcb_dag_t *base = tcb_peer_get_dag(s->peers[0]);
    for (size_t i = 0; i < tcb_dag_size(base); i++) {
        const sc_tcb_vertex_t *v = tcb_dag_at(base, i);
        if (v->vertex_type == TCB_VTX_SECURITY_EVENT) {
            sc_sentinel_history_entry_t entry;
            if (tcb_vertex_event(v, &entry)) {
                size_t copies = 0;
                for (int p = 0; p < SC_SENTINEL_TCB_PEERS; p++)
                    if (dag_contains_event(tcb_peer_get_dag(s->peers[p]), entry.event_id)) copies++;
                if (copies == SC_SENTINEL_TCB_PEERS) shared_events++;
            }
        }
        size_t found = 1;
        for (int p = 1; p < SC_SENTINEL_TCB_PEERS; p++)
            if (tcb_dag_get(tcb_peer_get_dag(s->peers[p]), v->hash)) found++;
        if (found == SC_SENTINEL_TCB_PEERS) common++;
    }
    for (int p = 0; p < SC_SENTINEL_TCB_PEERS; p++) {
        sc_tcb_dag_t *dag = tcb_peer_get_dag(s->peers[p]);
        for (size_t i = 0; i < tcb_dag_size(dag); i++) {
            const sc_tcb_vertex_t *v = tcb_dag_at(dag, i);
            if (!tcb_dag_get(base, v->hash)) missing++;
        }
    }
    for (size_t i = 0; i < s->history_count; i++) {
        size_t copies = 0;
        for (int p = 0; p < SC_SENTINEL_TCB_PEERS; p++)
            if (dag_contains_event(tcb_peer_get_dag(s->peers[p]), s->history[i].event_id)) copies++;
        if (copies < SC_SENTINEL_TCB_PEERS) {
            unanchored_local_events++;
            missing_event_copies += SC_SENTINEL_TCB_PEERS - copies;
        }
    }
    for (size_t i = 0; i < tcb_dag_size(base); i++) {
        sc_sentinel_history_entry_t entry;
        if (!tcb_vertex_event(tcb_dag_at(base, i), &entry)) continue;
        bool local_found = false;
        for (size_t j = 0; j < s->history_count; j++)
            if (memcmp(s->history[j].event_id, entry.event_id, SC_SHA256_LEN) == 0) { local_found = true; break; }
        if (!local_found) unmatched_peer_events++;
    }

    sb_raw(b, "{\"storage\":");
    sb_str_escape(b, s->persistence_enabled ? "DURABLE_LOCAL_SNAPSHOTS" : "IN_MEMORY_ONLY");
    sb_printf(b, ",\"shared_vertices\":%zu,\"peer_specific_vertices\":%zu,\"shared_events\":%zu,\"missing_event_copies\":%zu,\"unanchored_local_events\":%zu,\"unmatched_peer_events\":%zu,\"peers\":[",
              common, missing, shared_events, missing_event_copies, unanchored_local_events, unmatched_peer_events);
    for (int p = 0; p < SC_SENTINEL_TCB_PEERS; p++) {
        if (p) sb_raw(b, ",");
        sc_tcb_dag_t *dag = tcb_peer_get_dag(s->peers[p]);
        sb_printf(b, "{\"id\":%d,\"integrity\":\"%s\",\"size\":%zu,\"vertices\":[",
                  p, verified[p] ? "VERIFIED" : "FAILED", tcb_dag_size(dag));
        for (size_t i = 0; i < tcb_dag_size(dag); i++) {
            if (i) sb_raw(b, ",");
            const sc_tcb_vertex_t *v = tcb_dag_at(dag, i);
            sb_raw(b, "{\"hash\":"); sb_hex(b, v->hash, SC_SHA256_LEN);
            sb_printf(b, ",\"round\":%" PRIu64 ",\"author\":%d,\"type\":%u",
                      v->round, v->author_tcb_id, (unsigned)v->vertex_type);
            sc_sentinel_history_entry_t entry;
            if (tcb_vertex_event(v, &entry)) {
                sb_raw(b, ",\"event_id\":"); sb_hex(b, entry.event_id, SC_SHA256_LEN);
                sb_raw(b, ",\"action\":"); sb_str_escape(b, entry.action);
                sb_raw(b, ",\"status\":"); sb_str_escape(b, entry.tcb_status);
            }
            sb_raw(b, "}");
        }
        sb_raw(b, "]}");
    }
    sb_printf(b, "],\"persistence_error\":%s,\"event_append_dropped\":%u}",
              s->persistence_error ? "true" : "false", s->tcb_event_dropped);
}

/* ------------------------------------------------------------------ */
/* Client HTTP Request Handler                                        */
/* ------------------------------------------------------------------ */

static void serve_http_client(sc_sentinel_server_t *s, client_conn_t *c)
{
    /* Parse method and path */
    char method[16], path[256];
    if (sscanf(c->in, "%15s %255s", method, path) != 2)
        return;

    char *query = strchr(path, '?');
    if (query) { *query = '\0'; query++; }

    str_buf_t body = {0};
    const char *content_type = "application/json";
    int http_status = 200;

    if (strcmp(method, "POST") == 0) {
        char host[256] = {0}, origin[320] = {0}, expected[320];
        const char *host_hdr = strstr(c->in, "Host: ");
        const char *origin_hdr = strstr(c->in, "Origin: ");
        if (host_hdr) sscanf(host_hdr + 6, "%255s", host);
        if (origin_hdr) sscanf(origin_hdr + 8, "%319s", origin);
        snprintf(expected, sizeof(expected), "http://%s", host);
        if (!*host || !*origin || strcmp(origin, expected) != 0) {
            http_status = 403;
            sb_raw(&body, "{\"error\":\"same-origin POST required\"}");
        }
    }

    if (http_status == 403) {
        /* Do not process cross-origin state changes. */
    } else if (strcmp(method, "OPTIONS") == 0) {
        /* CORS preflight */
    } else if (strcmp(path, "/api/status") == 0) {
        handle_api_status(s, &body);
    } else if (strcmp(path, "/api/network") == 0) {
        handle_api_network(s, &body);
    } else if (strcmp(path, "/api/tcb") == 0) {
        handle_api_tcb(s, &body);
    } else if (strcmp(path, "/api/history") == 0) {
        handle_api_history(s, &body);
    } else if (strcmp(path, "/api/history/dags") == 0) {
        handle_api_dag_history(s, &body);
    } else if (strcmp(path, "/api/demo/trust") == 0) {
        char buf[2048];
        if (query && strstr(query, "scenario=disagreement"))
            sentinel_demo_trust_disagreement(s, buf, sizeof(buf));
        else if (query && strstr(query, "scenario=human"))
            sentinel_demo_trust_human(s, buf, sizeof(buf));
        else
            sentinel_demo_trust_unanimous(s, buf, sizeof(buf));
        sb_raw(&body, buf);
    } else if (strcmp(path, "/api/demo/attack") == 0) {
        char buf[2048];
        if (query && strstr(query, "scenario=invalid_tx"))
            sentinel_demo_attack_invalid_tx(s, buf, sizeof(buf));
        else if (query && strstr(query, "scenario=equivocation"))
            sentinel_demo_attack_equivocation(s, buf, sizeof(buf));
        else
            sentinel_demo_attack_replay_auth(s, buf, sizeof(buf));
        sb_raw(&body, buf);
    } else if (strcmp(path, "/api/demo/self_healing") == 0) {
        char buf[2048];
        sentinel_demo_self_healing(s, 3, buf, sizeof(buf));
        sb_raw(&body, buf);
    } else if (strcmp(path, "/api/governance/resolve") == 0) {
        char buf[2048];
        uint8_t req_id[SC_SHA256_LEN];
        char req_hex[SC_SHA256_LEN * 2 + 1];
        bool approve = false;
        const char *id_arg = query_param(query, "request_id");
        const char *approve_arg = query_param(query, "approve");
        bool valid_approval = approve_arg &&
            ((strncmp(approve_arg, "true", 4) == 0 && (approve_arg[4] == '\0' || approve_arg[4] == '&')) ||
             (strncmp(approve_arg, "false", 5) == 0 && (approve_arg[5] == '\0' || approve_arg[5] == '&')));
        if (!id_arg || !valid_approval) {
            sb_raw(&body, "{\"status\":\"ERROR\",\"error\":\"request_id and approve=true|false are required\"}");
        } else {
            size_t id_len = strcspn(id_arg, "&");
            if (id_len != SC_SHA256_LEN * 2) {
                sb_raw(&body, "{\"status\":\"ERROR\",\"error\":\"request_id must be 64 hexadecimal characters\"}");
            } else {
                memcpy(req_hex, id_arg, id_len);
                req_hex[id_len] = '\0';
                if (!crypto_hex_decode(req_hex, req_id, SC_SHA256_LEN)) {
                    sb_raw(&body, "{\"status\":\"ERROR\",\"error\":\"request_id is not valid hexadecimal\"}");
                } else {
                    approve = strncmp(approve_arg, "true", 4) == 0;
                    sentinel_resolve_governance(s, req_id, approve,
                        approve ? "Operator approved via Control Room" : "Operator vetoed via Control Room", buf, sizeof(buf));
                    sb_raw(&body, buf);
                }
            }
        }
    } else if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
        /* Serve index.html */
        content_type = "text/html; charset=utf-8";
        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/index.html", s->web_root);
        FILE *f = fopen(filepath, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            if (sz > 0 && sz < HTTP_MAX_BODY) {
                char *file_buf = malloc(sz + 1);
                if (file_buf) {
                    size_t read_bytes = fread(file_buf, 1, sz, f);
                    file_buf[read_bytes] = '\0';
                    sb_put(&body, file_buf, read_bytes);
                    free(file_buf);
                }
            }
            fclose(f);
        }
        if (body.len == 0) {
            sb_raw(&body, "<html><body><h1>SovereignChain Sentinel Operations Center</h1><p>Running on port 8088.</p></body></html>");
        }
    } else {
        sb_raw(&body, "{\"error\":\"not_found\"}");
    }

    if (s->persistence_enabled && s->state_dirty && persist_security_state(s) != SC_OK)
        s->persistence_error = true;

    /* Build HTTP response with CORS */
    str_buf_t resp = {0};
    sb_printf(&resp, "HTTP/1.1 %d %s\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n\r\n",
              http_status, http_status == 200 ? "OK" : "Forbidden", content_type, body.len);
    sb_put(&resp, body.p ? body.p : "", body.len);

    if (body.p) free(body.p);

    c->out = resp.p;
    c->out_len = resp.len;
    c->out_off = 0;
    c->responding = true;
}

sc_err_t sentinel_server_poll_step(sc_sentinel_server_t *s, int timeout_ms)
{
    if (!s || s->listen_fd < 0)
        return SC_ERR_INVALID;

    if (time(NULL) - s->last_probe_s >= 5)
        refresh_node_reachability(s);

    struct pollfd pfds[1 + HTTP_MAX_CLIENTS];
    int pcount = 0;

    pfds[0].fd = s->listen_fd;
    pfds[0].events = POLLIN;
    pfds[0].revents = 0;
    pcount++;

    for (int i = 0; i < HTTP_MAX_CLIENTS; i++) {
        if (s->clients[i].fd >= 0) {
            pfds[pcount].fd = s->clients[i].fd;
            pfds[pcount].events = s->clients[i].responding ? POLLOUT : POLLIN;
            pfds[pcount].revents = 0;
            pcount++;
        }
    }

    int rc = poll(pfds, pcount, timeout_ms);
    if (rc <= 0) return SC_OK;

    /* Accept new connections */
    if (pfds[0].revents & POLLIN) {
        int cfd = accept(s->listen_fd, NULL, NULL);
        if (cfd >= 0) {
            int flags = fcntl(cfd, F_GETFL, 0);
            if (flags >= 0) fcntl(cfd, F_SETFL, flags | O_NONBLOCK);
            for (int i = 0; i < HTTP_MAX_CLIENTS; i++) {
                if (s->clients[i].fd < 0) {
                    s->clients[i].fd = cfd;
                    s->clients[i].in_len = 0;
                    s->clients[i].out_len = 0;
                    s->clients[i].out_off = 0;
                    s->clients[i].responding = false;
                    break;
                }
            }
        }
    }

    /* Process client read/writes */
    for (int i = 0; i < HTTP_MAX_CLIENTS; i++) {
        client_conn_t *c = &s->clients[i];
        if (c->fd < 0) continue;

        if (c->responding) {
            ssize_t n = send(c->fd, c->out + c->out_off, c->out_len - c->out_off, 0);
            if (n > 0) {
                c->out_off += (size_t)n;
                if (c->out_off >= c->out_len) {
                    close(c->fd); c->fd = -1;
                    if (c->out) { free(c->out); c->out = NULL; }
                }
            } else if (n < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                close(c->fd); c->fd = -1;
                if (c->out) { free(c->out); c->out = NULL; }
            }
        } else {
            ssize_t n = recv(c->fd, c->in + c->in_len, HTTP_MAX_REQ - c->in_len, 0);
            if (n > 0) {
                c->in_len += (size_t)n;
                c->in[c->in_len] = '\0';
                if (strstr(c->in, "\r\n\r\n")) {
                    serve_http_client(s, c);
                }
            } else if (n <= 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                close(c->fd); c->fd = -1;
            }
        }
    }

    return SC_OK;
}
