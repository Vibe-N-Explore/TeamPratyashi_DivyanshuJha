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

# All phases: config, log, crypto, net, tx, ledger, storage, mempool, dag, consensus, security & TCB.
LIB_SRC := src/config.c src/log.c src/crypto.c src/net.c src/tx.c src/ledger.c src/storage.c src/mempool.c src/dag.c src/consensus.c \
           src/security/incident.c src/security/sec_agent.c src/security/node_guard.c \
           src/tcb/decision.c src/tcb/tcb_policy.c src/tcb/tcb_dag.c src/tcb/tcb_peer.c \
           src/sentinel_server.c
HEADERS := $(wildcard src/*.h) $(wildcard src/security/*.h) $(wildcard src/tcb/*.h)

UNIT_SRC  := $(wildcard tests/unit/test_*.c)
UNIT_BINS := $(patsubst tests/unit/%.c,build/%,$(UNIT_SRC))

.PHONY: all test test-unit test-integration clean

all: bin/node bin/injector bin/sec_agent bin/tcb_peer bin/sentinel_server

bin/node: src/main.c $(LIB_SRC) $(HEADERS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ src/main.c $(LIB_SRC) $(OPENSSL_LIBS)

bin/injector: src/injector.c $(LIB_SRC) $(HEADERS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ src/injector.c $(LIB_SRC) $(OPENSSL_LIBS)

bin/sec_agent: src/sec_agent_main.c $(LIB_SRC) $(HEADERS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ src/sec_agent_main.c $(LIB_SRC) $(OPENSSL_LIBS)

bin/tcb_peer: src/tcb_main.c $(LIB_SRC) $(HEADERS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ src/tcb_main.c $(LIB_SRC) $(OPENSSL_LIBS)

bin/sentinel_server: src/sentinel_main.c $(LIB_SRC) $(HEADERS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ src/sentinel_main.c $(LIB_SRC) $(OPENSSL_LIBS)

# Unit tests: built with AddressSanitizer + UBSan.
# test_crypto links OpenSSL; other tests don't (the rule is general).
build/test_%: tests/unit/test_%.c tests/unit/testutil.h $(LIB_SRC) $(HEADERS)
	@mkdir -p build
	$(CC) $(CFLAGS) $(SANFLAGS) $(OPENSSL_CFLAGS) -Itests/unit \
	    -o $@ $< $(LIB_SRC) $(OPENSSL_LIBS)

test-unit: $(UNIT_BINS)
	@set -e; for t in $(UNIT_BINS); do echo "== $$t"; ./$$t; done

test-integration: bin/node bin/injector bin/sec_agent bin/tcb_peer
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

test: test-unit test-integration

clean:
	rm -rf bin build logs
