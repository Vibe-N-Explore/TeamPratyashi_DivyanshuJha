#!/usr/bin/env bash
# test_pqc_integration.sh — Integration test script for SovereignChain Post-Quantum Cryptography Upgrade.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "=== SOVEREIGNCHAIN POST-QUANTUM CRYPTOGRAPHY UPGRADE VERIFICATION ==="
cd "${ROOT_DIR}"

# 1. Build and Run Unit Tests
echo "[+] Step 1: Compiling and executing PQC unit test suite..."
make build/test_pqc
./build/test_pqc
echo "[+] PQC Unit Tests passed cleanly!"

# 2. Build and Run Dedicated Hackathon Demonstration Binary
echo "[+] Step 2: Compiling and executing 9-Point PQC Demonstration..."
make bin/pqc_demo
./bin/pqc_demo
echo "[+] 9-Point Demonstration passed cleanly!"

# 3. Sentinel Server PQC HTTP Endpoint Verification
echo "[+] Step 3: Verifying Sentinel Server PQC REST APIs..."
make bin/sentinel_server

# Start Sentinel Server on temporary port 8099
PORT=8099
./bin/sentinel_server --port ${PORT} --webroot "${ROOT_DIR}" &
SERVER_PID=$!
trap "kill -9 ${SERVER_PID} 2>/dev/null || true" EXIT

sleep 2

# Probe /api/pqc/status
echo "  [>] Querying /api/pqc/status..."
STATUS_RESP=$(curl -s "http://127.0.0.1:${PORT}/api/pqc/status")
echo "  Response: ${STATUS_RESP}"
echo "${STATUS_RESP}" | grep -q "HYBRID" || (echo "[-] Failed: active_crypto_mode is not HYBRID" && exit 1)
echo "${STATUS_RESP}" | grep -q "ML-DSA-65" || (echo "[-] Failed: signature_algorithm is missing ML-DSA-65" && exit 1)
echo "${STATUS_RESP}" | grep -q "ML-KEM-768" || (echo "[-] Failed: kem_algorithm is missing ML-KEM-768" && exit 1)

# Probe /api/pqc/bench
echo "  [>] Querying /api/pqc/bench..."
BENCH_RESP=$(curl -s "http://127.0.0.1:${PORT}/api/pqc/bench")
echo "${BENCH_RESP}" | grep -q "ml_dsa_65" || (echo "[-] Failed: benchmark response missing ml_dsa_65" && exit 1)
echo "${BENCH_RESP}" | grep -q "ml_kem_768" || (echo "[-] Failed: benchmark response missing ml_kem_768" && exit 1)
echo "  Benchmark data verified!"

# Probe /api/pqc/demo
echo "  [>] Querying /api/pqc/demo..."
DEMO_RESP=$(curl -s "http://127.0.0.1:${PORT}/api/pqc/demo")
echo "${DEMO_RESP}" | grep -q '"all_passed":true' || (echo "[-] Failed: demo did not pass all 9 points" && exit 1)
echo "  Live 9-point execution over HTTP verified!"

kill -9 ${SERVER_PID} 2>/dev/null || true
trap - EXIT

echo ""
echo "========================================================================"
echo "  ALL POST-QUANTUM CRYPTOGRAPHY UPGRADE INTEGRATION CHECKS SUCCEEDED!   "
echo "========================================================================"
