# Makefile for tlscap - eBPF HTTPS plaintext capture tool

CLANG   ?= clang
GCC     ?= gcc
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# BPF compilation flags
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -D__BPF_PROGRAM__ -I include

# User-space compilation flags
CFLAGS  := -g -O2 -Wall -Wextra -I include -I src
LDFLAGS := -lbpf -lelf -lz

# Source files
USER_SRCS := src/main.c src/ssl_detect.c src/output.c src/event_reader.c src/pcap_writer.c
USER_OBJS := $(USER_SRCS:.c=.o)

# Targets
TARGET   := tlscap
BPF_OBJ  := src/bpf/tlscap.bpf.o
BPF_SKEL := src/tlscap.skel.h

.PHONY: all clean test

all: $(TARGET)

# Step 1: Compile BPF program
$(BPF_OBJ): src/bpf/tlscap.bpf.c include/tlscap.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Step 2: Generate skeleton header
$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Step 3: Compile user-space objects
src/main.o: src/main.c $(BPF_SKEL) src/ssl_detect.h src/event_reader.h src/output.h src/pcap_writer.h
	$(GCC) $(CFLAGS) -c $< -o $@

src/ssl_detect.o: src/ssl_detect.c src/ssl_detect.h
	$(GCC) $(CFLAGS) -c $< -o $@

src/output.o: src/output.c src/output.h include/tlscap.h src/pcap_writer.h
	$(GCC) $(CFLAGS) -c $< -o $@

src/pcap_writer.o: src/pcap_writer.c src/pcap_writer.h include/tlscap.h
	$(GCC) $(CFLAGS) -c $< -o $@

src/event_reader.o: src/event_reader.c src/event_reader.h src/output.h include/tlscap.h
	$(GCC) $(CFLAGS) -c $< -o $@

# Step 4: Link final binary
$(TARGET): $(USER_OBJS)
	$(GCC) $^ -o $@ $(LDFLAGS)

# Tests
tests/test_ssl_detect: tests/test_ssl_detect.c src/ssl_detect.c src/ssl_detect.h
	$(GCC) $(CFLAGS) tests/test_ssl_detect.c src/ssl_detect.c -o $@

tests/test_output: tests/test_output.c src/output.c src/output.h include/tlscap.h
	$(GCC) $(CFLAGS) tests/test_output.c src/output.c -o $@

test: tests/test_ssl_detect tests/test_output
	./tests/test_ssl_detect
	./tests/test_output

clean:
	rm -f $(USER_OBJS) $(BPF_OBJ) $(BPF_SKEL) $(TARGET)
	rm -f tests/test_ssl_detect tests/test_output
