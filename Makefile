# eBPF Process Hider - Makefile
# Requires: clang, llvm, libbpf-dev, go >= 1.21, bpftool (for vmlinux.h)

BINARY   := ebpf-hide-proc
BPF_SRC  := bpf/hide_proc.c
VMLINUX  := bpf/vmlinux.h

.PHONY: all clean generate build vmlinux

all: vmlinux generate build

# Generate vmlinux.h from the running kernel's BTF
vmlinux: $(VMLINUX)

$(VMLINUX):
	@echo ">>> Generating vmlinux.h from kernel BTF..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
	@echo ">>> vmlinux.h generated ($(shell wc -l < $(VMLINUX)) lines)"

# Run bpf2go to compile BPF C -> Go bindings
generate: $(VMLINUX)
	@echo ">>> Running bpf2go code generation..."
	go generate ./...
	@echo ">>> Generated Go bindings for eBPF program"

# Build the final binary
build:
	@echo ">>> Building $(BINARY)..."
	CGO_ENABLED=0 go build -o $(BINARY) .
	@echo ">>> Built: $(BINARY) ($(shell ls -lh $(BINARY) | awk '{print $$5}'))"

# Quick run (must be root)
run: all
	sudo ./$(BINARY)

clean:
	rm -f $(BINARY)
	rm -f hideproc_bpfel.go hideproc_bpfel.o
	rm -f hideproc_bpfeb.go hideproc_bpfeb.o
	rm -f $(VMLINUX)
	@echo ">>> Cleaned"

# Install dependencies on Debian 11
deps:
	@echo ">>> Installing build dependencies..."
	sudo apt-get update
	sudo apt-get install -y \
		clang llvm \
		libbpf-dev \
		linux-headers-$$(uname -r) \
		bpftool \
		make gcc \
		pkg-config
	@echo ">>> Dependencies installed"

help:
	@echo "Targets:"
	@echo "  all      - Generate vmlinux.h, compile BPF, build binary (default)"
	@echo "  vmlinux  - Generate vmlinux.h from kernel BTF"
	@echo "  generate - Run bpf2go to compile eBPF C and generate Go bindings"
	@echo "  build    - Build the Go binary"
	@echo "  run      - Build and run (requires root)"
	@echo "  clean    - Remove generated files"
	@echo "  deps     - Install build dependencies (Debian 11)"
