# SysGuard Makefile.
#
# Week 1 (owner A) targets:
#   make            -> compile eBPF program + generate libbpf skeleton (skeleton build experiment)
#   make poc        -> build the standalone collector PoC binary (build/sysguard_poc)
#   make run-poc    -> build and run the PoC (needs sudo for BPF load/attach)
#   make vmlinux    -> (re)generate bpf/vmlinux.h from the running kernel BTF
#
# The full `build/sysguard` binary target is wired but only links once B's
# modules (main.c, rules.c, fake_collector.c, jsonl_writer.c) exist.

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

# Full user-space sources (shared across A/B); used once all modules exist.
USER_SRC := \
	src/main.c \
	src/rules.c \
	src/fake_collector.c \
	src/jsonl_writer.c \
	src/bpf_collector.c

# Standalone Week-1 collector PoC sources (owner A only).
POC_SRC := \
	src/bpf_collector.c \
	src/poc_main.c

LIBS := -lbpf -lelf -lz

.PHONY: all poc vmlinux run-poc clean

# Week 1 default: prove the eBPF program compiles and a skeleton is generated.
all: $(BPF_SKEL)

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

$(POC_BIN): $(BPF_SKEL) $(POC_SRC) src/collector.h src/event.h
	mkdir -p build
	$(CC) $(CFLAGS) -I build -I src -o $(POC_BIN) $(POC_SRC) $(LIBS)

run-poc: $(POC_BIN)
	sudo ./$(POC_BIN)

# Full binary (enabled once src/main.c, rules.c, fake_collector.c, jsonl_writer.c land).
$(BIN): $(BPF_SKEL) $(USER_SRC)
	mkdir -p build
	$(CC) $(CFLAGS) -I build -I src -o $(BIN) $(USER_SRC) $(LIBS)

clean:
	rm -rf build
