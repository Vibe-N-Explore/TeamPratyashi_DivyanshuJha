#!/usr/bin/env bash
# phase_sentinel.sh - Integration test for SovereignChain Project Sentinel
#
# Validates:
#   Feature 1: Sovereign Security Control Room (REST API & Frontend serving)
#   Feature 2: Unanimous Trust Demonstration (Disagreement, Unanimous, Human Escalation)
#   Feature 3: Controlled Attack Replay Simulator (Replay Auth, Invalid Tx, Equivocation)
#   Feature 4: Autonomous Self-Healing Network (Failure detection, bounded recovery)
#   Feature 5: Permanent Security Memory (Audit log query & filtering)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "=== Phase Sentinel Integration Test ==="

BIN_SENTINEL="${ROOT_DIR}/bin/sentinel_server"

if [[ ! -x "${BIN_SENTINEL}" ]]; then
    echo "ERROR: Executable ${BIN_SENTINEL} not found. Run make all first."
    exit 1
fi

PORT=8999
TMP_LOG=$(mktemp /tmp/sc_sentinel_test.XXXXXX.log)

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill -TERM "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    rm -f "${TMP_LOG}"
}
trap cleanup EXIT

echo "[1/6] Launching Sentinel Operations Center on port ${PORT}..."
"${BIN_SENTINEL}" --port "${PORT}" --web-root "${ROOT_DIR}" > "${TMP_LOG}" 2>&1 &
SERVER_PID=$!

# Wait for server to bind and be ready
READY=0
for i in {1..25}; do
    if curl -s "http://127.0.0.1:${PORT}/api/status" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.2
done

if [[ "${READY}" -ne 1 ]]; then
    echo "ERROR: Sentinel server failed to respond within 5 seconds. Logs:"
    cat "${TMP_LOG}"
    exit 1
fi

echo "[2/6] Verifying Feature 1: Sovereign Security Control Room HTTP API..."
HTML_RESP=$(curl -s "http://127.0.0.1:${PORT}/")
echo "${HTML_RESP}" | grep -q "Project Sentinel"
echo "${HTML_RESP}" | grep -q "SovereignChain"

STATUS_JSON=$(curl -s "http://127.0.0.1:${PORT}/api/status")
echo "${STATUS_JSON}" | grep -q '"status":"HEALTHY"'
echo "${STATUS_JSON}" | grep -q '"active_nodes":6'
echo "${STATUS_JSON}" | grep -q '"tcb_peers":3'

NET_JSON=$(curl -s "http://127.0.0.1:${PORT}/api/network")
echo "${NET_JSON}" | grep -q '"nodes":'
echo "${NET_JSON}" | grep -q '"tcb_peers":'

TCB_JSON=$(curl -s "http://127.0.0.1:${PORT}/api/tcb")
echo "${TCB_JSON}" | grep -q '"rule":"STRICT_UNANIMOUS_100_PERCENT"'

echo "  PASS: Feature 1 Control Room and Telemetry API operational."

echo "[3/6] Verifying Feature 2: Unanimous Trust Demonstration..."
DISAGREE_JSON=$(curl -s -X POST "http://127.0.0.1:${PORT}/api/demo/trust?scenario=disagreement")
echo "${DISAGREE_JSON}" | grep -q "AUTHORISATION DENIED — UNANIMOUS APPROVAL NOT ACHIEVED"
echo "${DISAGREE_JSON}" | grep -q '"dissenting_peer":1'
echo "${DISAGREE_JSON}" | grep -q '"status":"REJECTED"'

UNAN_JSON=$(curl -s -X POST "http://127.0.0.1:${PORT}/api/demo/trust?scenario=unanimous")
echo "${UNAN_JSON}" | grep -q "UNANIMOUS AUTHORISATION ACHIEVED"
echo "${UNAN_JSON}" | grep -q '"status":"AUTHORISED"'

HUMAN_JSON=$(curl -s -X POST "http://127.0.0.1:${PORT}/api/demo/trust?scenario=human")
echo "${HUMAN_JSON}" | grep -q "MANDATORY OPERATOR SIGN-OFF REQUIRED"
echo "${HUMAN_JSON}" | grep -q '"status":"ESCALATED"'

RESOLVE_JSON=$(curl -s -X POST "http://127.0.0.1:${PORT}/api/governance/resolve")
echo "${RESOLVE_JSON}" | grep -q '"operator_decision":"APPROVED"'

echo "  PASS: Feature 2 Strict Unanimity, Disagreement Veto, and Human Escalation verified."

echo "[4/6] Verifying Feature 3: Controlled Attack Replay Simulator..."
REPLAY_JSON=$(curl -s -X POST "http://127.0.0.1:${PORT}/api/demo/attack?scenario=replay_auth")
echo "${REPLAY_JSON}" | grep -q '"attack":"REPLAY_AUTH"'
echo "${REPLAY_JSON}" | grep -q '"outcome":"DEFENDED"'

TX_JSON=$(curl -s -X POST "http://127.0.0.1:${PORT}/api/demo/attack?scenario=invalid_tx")
echo "${TX_JSON}" | grep -q '"attack":"TAMPERED_TX_SIGNATURE"'
echo "${TX_JSON}" | grep -q '"outcome":"DEFENDED"'

EQUIV_JSON=$(curl -s -X POST "http://127.0.0.1:${PORT}/api/demo/attack?scenario=equivocation")
echo "${EQUIV_JSON}" | grep -q '"attack":"VALIDATOR_EQUIVOCATION"'
echo "${EQUIV_JSON}" | grep -q '"outcome":"DETECTED"'

echo "  PASS: Feature 3 Attack Replay Simulator vectors defended fail-closed."

echo "[5/6] Verifying Feature 4: Autonomous Self-Healing Network..."
HEAL_JSON=$(curl -s -X POST "http://127.0.0.1:${PORT}/api/demo/self_healing")
echo "${HEAL_JSON}" | grep -q '"feature":"SELF_HEALING"'
echo "${HEAL_JSON}" | grep -q '"status":"OPERATIONAL"'
echo "${HEAL_JSON}" | grep -q '"recovered_node":3'

echo "  PASS: Feature 4 Node failure detected and autonomous healing completed."

echo "[6/6] Verifying Feature 5: Permanent Security Memory & TCB DAG Auditing..."
HIST_JSON=$(curl -s "http://127.0.0.1:${PORT}/api/history")
echo "${HIST_JSON}" | grep -q '"records":'
echo "${HIST_JSON}" | grep -q "AUTHORISATION_DENIED"
echo "${HIST_JSON}" | grep -q "UNANIMOUS_AUTHORISATION_ACHIEVED"
echo "${HIST_JSON}" | grep -q "BOUNDED_RECOVERY_COMPLETE"

echo "  PASS: Feature 5 Immutable security events recorded and queryable."

echo "=== ALL SENTINEL INTEGRATION TESTS PASSED (6/6 stages, 12 checks) ==="
exit 0
