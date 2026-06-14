# pugi — eBPF-based HTTP traffic observer
#
# Prerequisites (Linux 4.18+, e.g. RHEL 8):
#   - Go 1.22+
#   - clang 10+ (for compiling eBPF to BPF bytecode)
#   - libbpf / kernel-headers (for bpf_helper_verifier and BPF development)
#   - Kernel 4.18+ with CONFIG_BPF_SYSCALL=y, CONFIG_BPF_EVENTS=y
#
# Build:
#   make          — compile eBPF + Go, produce ./pugi
#   make clean    — remove build artifacts
#   make generate — only regenerate eBPF bindings (go generate)
#
# Note: eBPF compilation requires a Linux build host with clang and BPF
# target support. Development on macOS is limited to code review; actual
# builds must happen on Linux.

BINARY   := pugi
BPF_SRC  := bpf/pugi.c
GO_SRC   := main.go
CLANG    := clang
CC_FLAGS := -O2 -g -Wall -Werror -target bpf -idirafter /usr/include
GO_FLAGS := -ldflags="-s -w"

.PHONY: all clean generate build help

all: generate build

help:
	@echo "Targets:"
	@echo "  all       — generate + build (default)"
	@echo "  generate  — go generate (compile eBPF → Go bindings)"
	@echo "  build     — go build (after generate)"
	@echo "  clean     — remove binary + generated files"
	@echo ""
	@echo "Requires: Linux 4.18+, clang 10+, libbpf-dev, Go 1.22+"

# Step 1: compile eBPF C → BPF bytecode, produce Go bindings
generate:
	@echo "==> Checking prerequisites..."
	@command -v $(CLANG) >/dev/null 2>&1 || { echo "ERROR: clang not found. Install: dnf install clang"; exit 1; }
	@$(CLANG) -target bpf -O2 -c -x c /dev/null -o /dev/null 2>/dev/null || \
		{ echo "ERROR: clang does not support BPF target. Install LLVM/clang 10+."; exit 1; }
	@echo "==> Generating eBPF Go bindings (bpf2go)..."
	go generate -v

# Step 2: build the Go binary
build: generate
	@echo "==> Building $(BINARY)..."
	CGO_ENABLED=0 go build $(GO_FLAGS) -o $(BINARY) .

# Clean up
clean:
	@rm -f $(BINARY)
	@rm -f pugi_bpfel.go pugi_bpfeb.go pugi_bpfel.o pugi_bpfeb.o
	@echo "Clean."
