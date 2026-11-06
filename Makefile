# SovereignChain - Phase 3 Makefile
CC      ?= cc
CFLAGS  := -std=c17 -Wall -Wextra -Werror -O2 -g -Isrc
# Auto-detect AddressSanitizer support (e.g. Linux/WSL vs MSYS2)
HAVE_ASAN := $(shell echo 'int main(void){return 0;}' | $(CC) -fsanitize=address,undefined -x c -o /dev/null - 2>/dev/null && echo yes)
ifeq ($(HAVE_ASAN),yes)
  SANFLAGS ?= -fsanitize=address,undefined -fno-omit-frame-pointer
else
  SANFLAGS ?=
endif

# OpenSSL: pkg-config is the right way to find include/lib paths.
# If pkg-config is missing, fall back to bare -lssl -lcrypto.
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs   openssl 2>/dev/null || echo "-lssl -lcrypto")

# liboqs: Open Quantum Safe for ML-DSA-65 and ML-KEM-768
OQS_CFLAGS ?= $(shell pkg-config --cflags liboqs 2>/dev/null)
OQS_LIBS   ?= $(shell pkg-config --libs   liboqs 2>/dev/null || echo "-loqs")

# PQC Module sources
PQC_SRC := src/pqc/pqc_crypto.c src/pqc/pqc_tx.c src/pqc/pqc_session.c \
           src/pqc/pqc_tcb.c src/pqc/pqc_marketplace.c src/pqc/pqc_demo.c

# All phases: config, log, crypto, net, tx, ledger, storage, mempool, dag, consensus, security & TCB, PQC.
LIB_SRC := src/config.c src/log.c src/crypto.c src/net.c src/tx.c src/ledger.c src/storage.c src/mempool.c src/dag.c src/consensus.c \
           src/security/incident.c src/security/sec_agent.c src/security/node_guard.c \
           src/tcb/decision.c src/tcb/tcb_policy.c src/tcb/tcb_dag.c src/tcb/tcb_peer.c \
           src/sentinel_server.c src/marketplace.c $(PQC_SRC)
HEADERS := $(wildcard src/*.h) $(wildcard src/security/*.h) $(wildcard src/tcb/*.h) $(wildcard src/pqc/*.h)

UNIT_SRC  := $(wildcard tests/unit/test_*.c)
UNIT_BINS := $(patsubst tests/unit/%.c,build/%,$(UNIT_SRC))

.PHONY: all test test-unit test-pqc test-integration clean

all: bin/node bin/injector bin/sec_agent bin/tcb_peer bin/sentinel_server bin/pqc_demo

bin/node: src/main.c $(LIB_SRC) $(HEADERS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $(OQS_CFLAGS) -o $@ src/main.c $(LIB_SRC) $(OPENSSL_LIBS) $(OQS_LIBS)

bin/injector: src/injector.c $(LIB_SRC) $(HEADERS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $(OQS_CFLAGS) -o $@ src/injector.c $(LIB_SRC) $(OPENSSL_LIBS) $(OQS_LIBS)

bin/sec_agent: src/sec_agent_main.c $(LIB_SRC) $(HEADERS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $(OQS_CFLAGS) -o $@ src/sec_agent_main.c $(LIB_SRC) $(OPENSSL_LIBS) $(OQS_LIBS)

bin/tcb_peer: src/tcb_main.c $(LIB_SRC) $(HEADERS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $(OQS_CFLAGS) -o $@ src/tcb_main.c $(LIB_SRC) $(OPENSSL_LIBS) $(OQS_LIBS)

bin/sentinel_server: src/sentinel_main.c $(LIB_SRC) $(HEADERS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $(OQS_CFLAGS) -o $@ src/sentinel_main.c $(LIB_SRC) $(OPENSSL_LIBS) $(OQS_LIBS)

bin/pqc_demo: src/pqc_demo_main.c $(LIB_SRC) $(HEADERS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $(OQS_CFLAGS) -o $@ src/pqc_demo_main.c $(LIB_SRC) $(OPENSSL_LIBS) $(OQS_LIBS)

# Unit tests: built with AddressSanitizer + UBSan.
build/test_%: tests/unit/test_%.c tests/unit/testutil.h $(LIB_SRC) $(HEADERS)
	@mkdir -p build
	$(CC) $(CFLAGS) $(SANFLAGS) $(OPENSSL_CFLAGS) $(OQS_CFLAGS) -Itests/unit \
	    -o $@ $< $(LIB_SRC) $(OPENSSL_LIBS) $(OQS_LIBS)

test-unit: $(UNIT_BINS)
	@set -e; for t in $(UNIT_BINS); do echo "== $$t"; ./$$t; done

test-pqc: build/test_pqc bin/pqc_demo
	@echo "== Running PQC Unit Tests =="
	./build/test_pqc
	@echo "== Running Dedicated PQC Demonstration =="
	./bin/pqc_demo

test-integration: bin/node bin/injector bin/sec_agent bin/tcb_peer bin/pqc_demo
	bash tests/integration/phase1.sh
	bash tests/integration/phase3.sh
	bash tests/integration/phase4.sh
	bash tests/integration/phase5.sh
	bash tests/integration/phase6.sh
	bash tests/integration/phase7.sh
	bash tests/integration/phase8.sh
	bash tests/integration/phase9.sh
	bash tests/integration/phase_security_tcb.sh
	bash tests/integration/phase_sentinel.sh
	bash tests/integration/test_pqc_integration.sh

test: test-unit test-integration

clean:
	rm -rf bin build logs
