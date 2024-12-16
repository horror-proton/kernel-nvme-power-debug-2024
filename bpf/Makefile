OUTPUT := ./build
CC := clang
CFLAGS := -O2 -g -Wall
LDFLAGS := -lbpf

$(OUTPUT)/vmlinux.h:
	mkdir -p $(OUTPUT)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(OUTPUT)/%.bpf.o: %.bpf.c common.h $(OUTPUT)/vmlinux.h
	$(CC) $(CFLAGS) -I$(OUTPUT) -target bpf -D__TARGET_ARCH_x86 -c $< -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o
	bpftool gen skeleton $< > $@

$(OUTPUT)/main: main.c common.h $(OUTPUT)/main.skel.h
	$(CC) $(CFLAGS) -I$(OUTPUT) $(LDFLAGS) $< -o $@

.DEFAULT_GOAL := $(OUTPUT)/main
