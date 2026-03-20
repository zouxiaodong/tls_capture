# tlscap

eBPF-based HTTPS plaintext capture tool for openEuler 22.03+.

Hooks `SSL_read`/`SSL_write` in OpenSSL via uprobes to intercept TLS plaintext data in real time. Zero modification to nginx or any target process.

## Prerequisites

- openEuler 22.03+ (kernel 5.10+, BTF enabled)
- Root privileges

```bash
sudo dnf install clang libbpf-devel bpftool elfutils-libelf-devel
```

## Build

```bash
make
```

## Usage

```bash
# Capture all OpenSSL traffic
sudo ./tlscap

# Capture from specific nginx PID
sudo ./tlscap -p $(pgrep -x nginx | head -1)

# Specify libssl.so path manually
sudo ./tlscap -l /usr/lib64/libssl.so.1.1

# Adjust ring buffer size (MB)
sudo ./tlscap -b 8
```

## Testing

```bash
# Unit tests (no root required)
make test

# Integration test (requires root + nginx)
sudo tests/integration_test.sh
```
