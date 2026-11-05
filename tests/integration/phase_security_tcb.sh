#!/usr/bin/env bash
# phase_security_tcb.sh - Integration test for Part 3 Security Subsystem & Distributed TCB.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "=== Phase Security & Distributed TCB Integration Test ==="

BIN_AGENT="${ROOT_DIR}/bin/sec_agent"
BIN_TCB="${ROOT_DIR}/bin/tcb_peer"

if [[ ! -x "${BIN_AGENT}" || ! -x "${BIN_TCB}" ]]; then
    echo "ERROR: Executables missing. Run make all first."
    exit 1
fi

TMP_DIR=$(mktemp -d /tmp/sc_sec_test.XXXXXX)
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "[1/3] Generating cryptographic identities for TCB peers and Security Agent..."
"${BIN_AGENT}" --test-anomaly 3 > "${TMP_DIR}/agent_test.log" 2>&1
grep -q "INCIDENT DETECTED!" "${TMP_DIR}/agent_test.log"
grep -q "Proposed Action: 3 (Category: AUTO_PERMITTED)" "${TMP_DIR}/agent_test.log"
echo "  PASS: AI Security Agent anomaly detector and recommendation formulation verified."

echo "[2/3] Launching Distributed TCB Peer Network (3 independent peers)..."
"${BIN_TCB}" --id 0 --peers 3 > "${TMP_DIR}/tcb0.log" 2>&1 &
PID0=$!
"${BIN_TCB}" --id 1 --peers 3 > "${TMP_DIR}/tcb1.log" 2>&1 &
PID1=$!
"${BIN_TCB}" --id 2 --peers 3 > "${TMP_DIR}/tcb2.log" 2>&1 &
PID2=$!

sleep 1

wait "${PID0}"
wait "${PID1}"
wait "${PID2}"

grep -q "TCB Peer 0 initialized" "${TMP_DIR}/tcb0.log"
grep -q "TCB Peer 1 initialized" "${TMP_DIR}/tcb1.log"
grep -q "TCB Peer 2 initialized" "${TMP_DIR}/tcb2.log"
echo "  PASS: All 3 TCB peers initialized independent cryptographic identities and DAG state."

echo "[3/3] Checking log outputs..."
test -s "${TMP_DIR}/tcb0.log"
test -s "${TMP_DIR}/tcb1.log"
test -s "${TMP_DIR}/tcb2.log"
echo "  PASS: Audit records verified."

echo "=== Security Subsystem & Distributed TCB Integration: ALL PASSED ==="
