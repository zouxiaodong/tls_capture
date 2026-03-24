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
# Adjust ring buffer size (MB)
sudo ./tlscap -b 8
```

## Important Notes

### Statically Linked Executables

tlscap supports **both** dynamically linked and **statically linked** OpenSSL binaries:

- **Dynamic linking** (e.g., `ldd nginx | grep ssl`): Uses system libssl.so
- **Static linking** (no libssl.so dependency): Specify the executable path directly

```bash
# For statically linked nginx (no libssl.so dependency)
sudo ./tlscap -l /path/to/nginx

# Verify nginx has static SSL symbols
nm /path/to/nginx | grep SSL_
```

### Troubleshooting

**No output despite traffic?**
- Use `-v` flag to see verbose output and verify probes attached correctly
- Check that nginx is actually using SSL/TLS (`ldd nginx` shows no ssl = static linking)
- Make sure you're specifying the correct nginx binary path with `-l`

**eBPF probe attachment failed?**
- Verify kernel version >= 5.10: `uname -r`
- Check BTF support: `bpftool btf dump id 1 > /dev/null && echo "BTF OK"`

## Testing

```bash
# Unit tests (no root required)
make test

# Integration test (requires root + nginx)
sudo tests/integration_test.sh
```
