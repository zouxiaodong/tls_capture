# tlscap - eBPF HTTPS 明文抓包工具设计文档

## 概述

tlscap 是一个基于 eBPF uprobe 的 HTTPS 明文抓包工具，通过挂钩 OpenSSL 的 `SSL_read`/`SSL_write` 函数，实时捕获 nginx（或其他 OpenSSL 进程）的 TLS 加密前/解密后的 HTTP 明文数据。

## 目标

- **使用场景**: 开发调试环境，抓取客户端发往 nginx 的入口 HTTPS 明文（请求+响应）
- **目标平台**: openEuler 22.03+（内核 5.10+，支持 CO-RE/BTF）
- **技术方案**: eBPF uprobe 挂钩 OpenSSL `SSL_read`/`SSL_write`
- **开发语言**: C + libbpf
- **输出方式**: 终端实时输出

## 架构

```
┌─────────────────────────────────────────────┐
│              用户态 (tlscap)                  │
│                                             │
│  main.c ─── 参数解析、BPF加载、信号处理      │
│     │                                        │
│     ├── event_reader.c ─── 从 ring buffer     │
│     │      读取内核态事件                      │
│     │                                        │
│     ├── output.c ─── 格式化输出 HTTP 明文     │
│     │                                        │
│     └── ssl_detect.c ─── 检测 libssl 路径     │
│                                             │
├─────────────── ring buffer ──────────────────┤
│                                             │
│              内核态 (BPF 程序)                │
│                                             │
│  tlscap.bpf.c                               │
│     ├── uprobe/SSL_write ─── 捕获发送数据     │
│     ├── uretprobe/SSL_write                  │
│     ├── uprobe/SSL_read  ─── 捕获接收数据     │
│     └── uretprobe/SSL_read                   │
└─────────────────────────────────────────────┘
```

### 核心工作流

每个 uprobe/uretprobe 处理函数的第一步是检查 `target_pid` map。若设置了目标 PID 且当前进程不匹配，则直接返回。

**pid_tid key 编码**: 使用 `bpf_get_current_pid_tgid()` 的返回值，高 32 位为 tgid（用户空间 PID），低 32 位为 pid（用户空间 TID）：`u64 key = bpf_get_current_pid_tgid();`

1. **SSL_write uprobe entry**: 记录 `buf` 指针到 per-CPU hashmap，key 为 pid_tgid
2. **SSL_write uretprobe return**: 若返回值 > 0，`data_len = return_value`；从 map 取出 buf 指针，通过 `bpf_ringbuf_reserve` 分配事件空间，用 `bpf_probe_read_user` 读取 `data_len` 字节明文数据，提交到 ring buffer（nginx 发出的响应）
3. **SSL_read uprobe entry**: 记录 `buf` 指针到 map
4. **SSL_read uretprobe return**: 若返回值 > 0，`data_len = return_value`；从 buf 读取数据，同样通过 ring buffer 发送到用户态（客户端发来的请求）

**关键**: 对于 SSL_read 和 SSL_write，实际数据长度始终取自 uretprobe 的返回值（而非 entry 时的 `num` 参数），因为返回值才是实际读写的字节数。

## 数据结构

### 事件类型

```c
enum event_type {
    EVENT_SSL_READ,   // 客户端请求 (入站)
    EVENT_SSL_WRITE,  // 服务端响应 (出站)
};
```

### TLS 事件

```c
#define MAX_DATA_SIZE 16384

struct tls_event {
    u32 pid;
    u32 tid;
    u64 timestamp_ns;      // bpf_ktime_get_ns() 单调时钟
    enum event_type type;
    u32 data_len;           // 实际数据长度
    u8 truncated;           // 数据是否被截断
    u64 ssl_ptr;            // SSL* 指针，用作连接标识符
    char comm[16];          // 进程名
    char data[MAX_DATA_SIZE]; // 明文数据 (最大 16KB)
};
```

**时间戳**: 使用 `bpf_ktime_get_ns()` 获取单调时钟纳秒值。用户态通过 `clock_gettime(CLOCK_MONOTONIC)` 与 `gettimeofday()` 的差值将其转换为墙钟时间用于显示。

**连接关联**: `ssl_ptr` 字段存储 `SSL_read`/`SSL_write` 的第一个参数（SSL* 指针），可用于关联同一 TLS 连接上的请求和响应。

### uprobe entry 临时存储

```c
struct ssl_args {
    void *buf;       // SSL_read/SSL_write 的 buf 参数
    u64 ssl_ptr;     // SSL* 指针
};
```

## BPF Map 设计

| Map | 类型 | 用途 |
|-----|------|------|
| `ssl_read_args` | HASH (key: u64 pid_tgid, max_entries: 1024) | SSL_read entry 保存 buf 指针和 SSL* |
| `ssl_write_args` | HASH (key: u64 pid_tgid, max_entries: 1024) | SSL_write entry 保存 buf 指针和 SSL* |
| `events` | RING_BUFFER (默认 4MB，可通过 -b 配置) | 向用户态传递事件 |
| `target_pid` | ARRAY (1 entry) | 可选：过滤指定 PID |

### BPF 内存分配策略

`tls_event` 结构体约 16KB+，远超 eBPF 512 字节栈限制。使用 `bpf_ringbuf_reserve()` 直接在 ring buffer 中分配事件空间，避免栈分配和额外拷贝：

```c
// uretprobe 中的分配模式
struct tls_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
if (!evt)
    return 0;  // ring buffer 满，静默丢弃

// 填充事件字段...

// 读取明文数据，data_len 需做显式边界检查以通过 verifier
u32 len = ret_val;
evt->data_len = len;
if (len >= MAX_DATA_SIZE) {
    len = MAX_DATA_SIZE - 1;
    evt->truncated = 1;
}
// ret_val <= 0 表示错误或关闭，不产生有效事件
if (ret_val <= 0) {
    bpf_ringbuf_discard(evt, 0);
    return 0;
}

// 位掩码向 verifier 证明 len < MAX_DATA_SIZE，此处 len 已在 [0, MAX_DATA_SIZE-1]
bpf_probe_read_user(evt->data, len & (MAX_DATA_SIZE - 1), buf);
evt->data[len & (MAX_DATA_SIZE - 1)] = '\0';  // 确保 null 终止

bpf_ringbuf_submit(evt, 0);
```

**verifier 兼容**: `len & (MAX_DATA_SIZE - 1)` 的位掩码操作向 verifier 证明读取长度不超过 `MAX_DATA_SIZE`（要求 `MAX_DATA_SIZE` 为 2 的幂），确保通过验证。

## 用户态程序

### 命令行接口

```
用法: tlscap [选项]
  -p PID       只捕获指定 PID 的进程
  -l PATH      libssl.so 的路径 (默认自动检测)
  -b SIZE      ring buffer 大小，单位 MB (默认 4)
  -v           详细输出 (包含时间戳、PID/TID)
  -h           帮助信息
```

### 启动流程

1. 解析命令行参数
2. 自动检测 `libssl.so` 路径（通过 `/proc/<pid>/maps` 或 `ldconfig -p`）
3. 使用 skeleton API 加载 BPF 程序（open → load → attach），附加 uprobe/uretprobe 到 SSL_read/SSL_write
4. 若指定了 `-p PID`，写入 `target_pid` map
5. 进入事件循环，`ring_buffer__poll()` 读取事件
6. 收到 SIGINT/SIGTERM 时执行清理：detach 探针 → 销毁 ring buffer → 销毁 BPF 对象 → 退出

### 输出格式

终端实时输出，参考 `tcpdump -A` 风格：

```
──── READ (请求) ──── PID:12345 TID:12346 ──── 2026-03-19 10:30:15.123 ────
GET /api/users HTTP/1.1
Host: example.com
User-Agent: curl/7.81.0
Accept: */*

──── WRITE (响应) ──── PID:12345 TID:12346 ──── 2026-03-19 10:30:15.128 ────
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 42

{"id": 1, "name": "test"}
```

- 分隔线区分不同的请求/响应
- 标注方向（READ=客户端请求, WRITE=服务端响应）
- 显示 PID/TID 和时间戳
- 数据被截断时在分隔线末尾标注 `[TRUNCATED]`
- 二进制数据用十六进制 dump

## 错误处理

### BPF 内核态

- `bpf_ringbuf_reserve` 返回 NULL：静默丢弃该事件（ring buffer 满）
- `bpf_probe_read_user` 返回非零：将 `data_len` 设为 0，仍提交事件（用户态可据此判断读取失败）
- map 查找失败：直接返回，不产生事件

### 用户态

- **libssl 路径无效**: 打印错误信息并退出，提示使用 `-l` 手动指定路径
- **符号未找到（SSL_read/SSL_write）**: 打印错误信息，提示可能是静态链接的 OpenSSL 或符号被 strip
- **BPF 加载失败**: 打印 libbpf 错误信息，提示检查内核版本和 BTF 支持
- **ring buffer 事件丢弃**: 用户态通过 ring buffer 回调的 flags 检测丢弃，打印警告 `[WARNING: N events dropped]`
- **权限不足**: 检查 `geteuid() != 0` 时提前退出，提示需要 root 权限

## 项目文件结构

```
tlscap/
├── src/
│   ├── bpf/
│   │   └── tlscap.bpf.c      # eBPF 内核态程序
│   ├── main.c                 # 入口、参数解析、BPF 加载、信号处理
│   ├── event_reader.c         # ring buffer 事件读取与回调
│   ├── event_reader.h
│   ├── output.c               # 格式化输出
│   ├── output.h
│   ├── ssl_detect.c           # 自动检测 libssl 路径
│   └── ssl_detect.h
├── include/
│   └── tlscap.h               # 共享数据结构 (tls_event 等)
├── Makefile                   # 构建脚本
└── README.md
```

## 构建依赖

- `libbpf-devel` (libbpf + headers)
- `clang` (编译 BPF C 为字节码)
- `bpftool` (生成 skeleton header)
- `elfutils-libelf-devel`
- 内核需启用 BTF (`CONFIG_DEBUG_INFO_BTF=y`，openEuler 22.03+ 默认开启)

## 构建流程

```makefile
1. clang -target bpf → tlscap.bpf.o      # 编译 BPF 程序
2. bpftool gen skeleton → tlscap.skel.h    # 生成 skeleton
3. gcc → tlscap                            # 编译用户态程序，链接 libbpf/libelf
```

## 大数据处理

`tls_event.data` 最大 16KB（`MAX_DATA_SIZE = 16384`，2 的幂）。超过此长度的数据会被截断，`truncated` 标志置为 1。用户态输出时标注 `[TRUNCATED]`。对开发调试场景，16KB 足以覆盖绝大多数 HTTP 请求头和常见请求体。

## OpenSSL 兼容性

- 挂钩 `SSL_read` 和 `SSL_write` 函数，兼容 OpenSSL 1.1.x 和 3.x
- OpenSSL 3.x 中 `SSL_read_ex`/`SSL_write_ex` 内部调用 `SSL_read`/`SSL_write`，因此无需额外挂钩
- 仅支持动态链接的 `libssl.so`。若 nginx 静态链接了 OpenSSL，启动时检测并给出明确错误提示

## 约束与限制

- 需要 root 权限运行（eBPF 要求 CAP_BPF 或 root）
- 仅支持 OpenSSL 库（不支持 GnuTLS、BoringSSL 等）
- 单次数据捕获上限 16KB，超出部分截断
- 需要目标进程使用动态链接的 libssl.so

## 测试策略

- **集成测试**: 在本地启动 nginx + 自签名证书，用 `curl -k https://localhost` 发送请求，验证 tlscap 正确捕获请求和响应明文
- **用户态单元测试**: 测试 output.c 的格式化逻辑、ssl_detect.c 的路径检测逻辑
- **边界测试**: 测试大于 16KB 的请求体截断行为、并发请求下的事件正确性
