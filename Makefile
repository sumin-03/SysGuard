# SysGuard Makefile.
#
# Targets:
#   make            -> build everything: the BPF object, the libbpf skeleton, and
#                      the full build/sysguard engine (the README "Build" contract).
#   make sysguard   -> the full build/sysguard binary (same result as the default).
#   make poc        -> build the standalone collector PoC binary (build/sysguard_poc)
#   make run        -> build and run the full engine live (needs sudo for BPF load)
#   make run-poc    -> build and run the PoC (needs sudo for BPF load/attach)
#   make vmlinux    -> (re)generate bpf/vmlinux.h from the running kernel BTF
#   make clean      -> remove build/

CC := clang
CFLAGS := -Wall -Wextra -O2 -g
BPF_CLANG := clang
BPF_CFLAGS := -g -O2 -target bpf

BIN := build/sysguard
POC_BIN := build/sysguard_poc

BPF_SRC := bpf/sysguard.bpf.c
BPF_OBJ := build/sysguard.bpf.o
BPF_SKEL := build/sysguard.skel.h
VMLINUX := bpf/vmlinux.h

# Full user-space sources (shared across A/B).
USER_SRC := \
	src/main.c \
	src/rules.c \
	src/fake_collector.c \
	src/jsonl_writer.c \
	src/bpf_collector.c \
	src/target_filter.c

# Standalone Week-1 collector PoC sources (owner A only).
POC_SRC := \
	src/bpf_collector.c \
	src/poc_main.c \
	src/target_filter.c

LIBS := -lbpf -lelf -lz

.PHONY: all poc vmlinux run-poc sysguard run test-c clean

# Default: build the BPF object, the skeleton, and the full engine. $(BIN)
# already depends on $(BPF_SKEL) -> $(BPF_OBJ), so this produces all three
# README "Build" artifacts through the existing dependency chain.
all: $(BIN)

# Generate vmlinux.h from the running kernel BTF (required for CO-RE).
$(VMLINUX):
	mkdir -p bpf
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

vmlinux: $(VMLINUX)

# Compile eBPF program into a BPF object.
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX) src/event.h
	mkdir -p build
	$(BPF_CLANG) $(BPF_CFLAGS) -I bpf -I src -c $(BPF_SRC) -o $(BPF_OBJ)

# Generate the libbpf skeleton header from the BPF object.
$(BPF_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $(BPF_OBJ) > $(BPF_SKEL)

# Week-1 standalone collector PoC (no dependency on B's modules).
poc: $(POC_BIN)

$(POC_BIN): $(BPF_SKEL) $(POC_SRC) src/collector.h src/event.h src/target_filter.h
	mkdir -p build
	$(CC) $(CFLAGS) -I build -I src -o $(POC_BIN) $(POC_SRC) $(LIBS)

run-poc: $(POC_BIN)
	sudo ./$(POC_BIN)

# Full SysGuard binary: A's eBPF collector wired into B's rules/JSONL/fake
# modules. -DHAS_BPF_COLLECTOR enables the real eBPF path (main.c + the glue in
# bpf_collector.c); without it main.c would fall back to the "eBPF unavailable"
# error branch.
sysguard: $(BIN)

$(BIN): $(BPF_SKEL) $(USER_SRC) src/collector.h src/event.h src/target_filter.h
	mkdir -p build
	$(CC) $(CFLAGS) -DHAS_BPF_COLLECTOR -I build -I src -o $(BIN) $(USER_SRC) $(LIBS)

# Build and run the full binary in live eBPF mode (needs sudo for BPF load).
run: $(BIN)
	sudo ./$(BIN) --output sysguard.jsonl

# Non-sudo C unit tests for the rule engine (no BPF/skeleton/root needed).
TEST_C_BIN := build/test_rules

$(TEST_C_BIN): tests/test_rules.c src/rules.c src/rules.h src/event.h src/alert.h
	mkdir -p build
	$(CC) $(CFLAGS) -I src -o $(TEST_C_BIN) tests/test_rules.c src/rules.c

test-c: $(TEST_C_BIN)
	./$(TEST_C_BIN)

clean:
	rm -rf build
