#!/bin/bash
set -euo pipefail

ROOT="/d/Team Pratyashi/TeamPratyashi_DivyanshuJha-main3/TeamPratyashi_DivyanshuJha-main"
TMPDIR="/tmp/sc_mp_e2e_test"
rm -rf "$TMPDIR" && mkdir -p "$TMPDIR"

echo "=== 1. Starting Sentinel with Marketplace Engine ==="
"$ROOT/bin/sentinel_server.exe" --port 8980 --network "$ROOT/config/network.conf" --web-root "$ROOT" --state-dir "$TMPDIR" > "$TMPDIR/srv.log" 2>&1 &
SRV_PID=$!
sleep 2

cleanup() {
    kill -TERM "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== 2. Testing Marketplace Overview ==="
OVERVIEW=$(curl -s http://127.0.0.1:8980/api/marketplace/overview)
echo "$OVERVIEW" | grep -q '"status":"OPERATIONAL"'
echo "$OVERVIEW" | grep -q '"providers_count":3'
echo "  PASS: Overview endpoint operational with 3 canonical providers."

echo "=== 3. Testing Provider Registration ==="
REG_RESP=$(curl -s -X POST "http://127.0.0.1:8980/api/marketplace/providers/register?name=HyperCluster-GPU-Delta&cpu=128&gpu=NVIDIA%20H100&gcount=4&ram=262144&storage=4096&price=320")
echo "$REG_RESP" | grep -q '"status":"SUCCESS"'
echo "$REG_RESP" | grep -q '"provider_id":3'
echo "  PASS: Provider registered successfully."

echo "=== 4. Testing Task Creation (AI Inference Workload) ==="
CREATE_RESP=$(curl -s -X POST "http://127.0.0.1:8980/api/marketplace/tasks/create?title=DeepSeek-7B-Financial-Inference&customer=AcmeCorp&workload=4&cpu=16&gpu=1&ram=32768&budget=300")
echo "$CREATE_RESP" | grep -q '"status":"SUCCESS"'
TASK_ID=$(echo "$CREATE_RESP" | grep -o '"task_id":"[a-f0-9]*"' | cut -d'"' -f4)
echo "Created Task ID: $TASK_ID"

echo "=== 5. Testing Provider Matching & Ranking ==="
MATCH_RESP=$(curl -s "http://127.0.0.1:8980/api/marketplace/tasks/match?task_id=${TASK_ID}")
echo "$MATCH_RESP" | grep -q '"task_id":'
echo "$MATCH_RESP" | grep -q '"matches":'
echo "  PASS: Provider discovery and match scoring completed."

echo "=== 6. Testing Task Assignment & Escrow Lock ==="
ASSIGN_RESP=$(curl -s -X POST "http://127.0.0.1:8980/api/marketplace/tasks/assign?task_id=${TASK_ID}&provider_id=1")
echo "$ASSIGN_RESP" | grep -q '"escrow_status":"LOCKED"'
echo "  PASS: Task assigned to Provider 1 and escrow locked."

echo "=== 7. Testing Off-Chain Workload Execution ==="
EXEC_RESP=$(curl -s -X POST "http://127.0.0.1:8980/api/marketplace/tasks/execute?task_id=${TASK_ID}&fraud=false")
echo "$EXEC_RESP" | grep -q '"status":"SUCCESS"'
echo "  PASS: AI inference workload computed off-chain."

echo "=== 8. Testing Deterministic Result Verification (Legitimate) ==="
VERIFY_RESP=$(curl -s -X POST "http://127.0.0.1:8980/api/marketplace/tasks/verify?task_id=${TASK_ID}")
echo "$VERIFY_RESP" | grep -q '"passed":true'
echo "  PASS: Result verified against deterministic reference ground truth."

echo "=== 9. Testing Settlement Release ==="
SETTLE_RESP=$(curl -s -X POST "http://127.0.0.1:8980/api/marketplace/tasks/settle?task_id=${TASK_ID}")
echo "$SETTLE_RESP" | grep -q '"status":"SUCCESS"'
echo "$SETTLE_RESP" | grep -q '"settlement_tx":'
echo "  PASS: Escrow released, settlement transaction signed on-chain."

echo "=== 10. Testing Fraudulent Task Detection & Reputation Slashing ==="
TASK2_RESP=$(curl -s -X POST "http://127.0.0.1:8980/api/marketplace/tasks/create?title=Image-Edge-Detection-Fraud-Test&workload=3&cpu=4&ram=4096&budget=150")
TASK2_ID=$(echo "$TASK2_RESP" | grep -o '"task_id":"[a-f0-9]*"' | cut -d'"' -f4)
curl -s -X POST "http://127.0.0.1:8980/api/marketplace/tasks/assign?task_id=${TASK2_ID}&provider_id=2" >/dev/null
# Execute with fraud=true
curl -s -X POST "http://127.0.0.1:8980/api/marketplace/tasks/execute?task_id=${TASK2_ID}&fraud=true" >/dev/null
FRAUD_VERIFY=$(curl -s -X POST "http://127.0.0.1:8980/api/marketplace/tasks/verify?task_id=${TASK2_ID}")
echo "$FRAUD_VERIFY" | grep -q '"passed":false'
echo "  PASS: Fraudulent computation result caught and rejected fail-closed."

echo "=== 11. Checking Security History for Marketplace Audit Trail ==="
HIST=$(curl -s http://127.0.0.1:8980/api/history)
echo "$HIST" | grep -q "PROVIDER_REGISTERED"
echo "$HIST" | grep -q "TASK_SUBMITTED"
echo "$HIST" | grep -q "ESCROW_RESERVED"
echo "$HIST" | grep -q "RESULT_VERIFIED_PASS"
echo "$HIST" | grep -q "MARKETPLACE_FRAUD_DETECTED"
echo "  PASS: Complete marketplace economic & security lifecycle recorded in Permanent Security Memory."

echo "=== ALL MARKETPLACE BACKEND & SECURITY TESTS PASSED ==="
