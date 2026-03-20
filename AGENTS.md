# AGENTS.md - 项目上下文指南

## 项目概述

**tlscap** 是一个基于 eBPF 的 HTTPS 明文捕获工具，专为 openEuler 22.03+ 设计。

### 核心特性
- 通过 uprobe 钩子拦截 OpenSSL 的 `SSL_read`/`SSL_write` 函数
- 实时捕获 TLS 明文数据
- 零侵入式设计 - 无需修改目标进程（如 nginx）
- 支持按 PID 过滤
- 可配置 ring buffer 大小

### 技术栈
- **eBPF**: 使用 libbpf 框架
- **语言**: C (BPF 程序 + 用户空间)
- **内核要求**: Linux 5.10+ (BTF enabled)
- **目标平台**: openEuler 22.03+

## 项目结构

```
tlscap/
├── include/
│   └── tlscap.h          # BPF 和用户空间共享的数据结构
├── src/
│   ├── bpf/
│   │   └── tlscap.bpf.c  # BPF 程序 (uprobe/uretprobe)
│   ├── main.c            # 主入口，CLI 解析，BPF 加载
│   ├── ssl_detect.c/h    # libssl.so 路径自动检测
│   ├── event_reader.c/h  # Ring buffer 事件读取
│   └── output.c/h        # 事件格式化输出
├── tests/
│   ├── integration_test.sh  # 端到端集成测试
│   ├── test_ssl_detect.c    # ssl_detect 单元测试
│   └── test_output.c        # output 单元测试
└── Makefile
```

## 构建与运行

### 依赖安装
```bash
sudo dnf install clang libbpf-devel bpftool elfutils-libelf-devel
```

### 构建
```bash
make
```

构建产物：
- `tlscap` - 主程序
- `src/bpf/tlscap.bpf.o` - 编译后的 BPF 对象
- `src/tlscap.skel.h` - BPF skeleton 头文件

### 运行
```bash
# 捕获所有 OpenSSL 流量
sudo ./tlscap

# 捕获特定 PID
sudo ./tlscap -p $(pgrep -x nginx | head -1)

# 手动指定 libssl.so 路径
sudo ./tlscap -l /usr/lib64/libssl.so.1.1

# 调整 ring buffer 大小 (MB，必须是 2 的幂)
sudo ./tlscap -b 8
```

### 测试
```bash
# 单元测试 (无需 root)
make test

# 集成测试 (需要 root + nginx)
sudo tests/integration_test.sh
```

## 架构说明

### 数据流
```
目标进程 (nginx/curl 等)
    │
    ├── SSL_write() ──► uprobe (ssl_write_entry) ──► 保存 buf 指针
    │                                            │
    │   ← SSL_write 返回 ── uretprobe (ssl_write_return)
    │                                            │
    │                                      读取明文数据
    │                                            │
    │                                      ──► Ring Buffer
    │                                            │
    └── SSL_read() ──► uprobe (ssl_read_entry) ──► 保存 buf 指针
                                                 │
        ← SSL_read 返回 ── uretprobe (ssl_read_return)
                                                 │
                                           读取明文数据
                                                 │
                                           ──► Ring Buffer
                                                 │
                                                 ▼
                                          event_reader_poll()
                                                 │
                                                 ▼
                                          output_event()
                                                 │
                                                 ▼
                                            stdout
```

### 核心数据结构

**tls_event** (include/tlscap.h):
```c
struct tls_event {
    __u32 pid;            // 进程 ID
    __u32 tid;            // 线程 ID
    __u64 timestamp_ns;   // 单调时钟时间戳
    __u32 type;           // EVENT_SSL_READ 或 EVENT_SSL_WRITE
    __u32 data_len;       // 数据长度
    __u8  truncated;      // 是否被截断
    __u64 ssl_ptr;        // SSL 对象指针
    char  comm[16];       // 进程名
    char  data[16384];    // 明文数据
};
```

### BPF Maps
- `ssl_read_args` / `ssl_write_args`: HASH map，保存函数入口时的参数
- `events`: RINGBUF map，向用户空间传递事件
- `target_pid`: ARRAY map，PID 过滤器

### libssl.so 检测优先级
1. 用户通过 `-l` 参数指定的路径
2. `/proc/pid/maps` 中查找
3. `ldconfig -p` 输出中查找

## 开发约定

### 代码风格
- 使用 GCC/Clang 默认的 C 风格
- 4 空格缩进
- 函数和变量使用 snake_case 命名
- 常量和宏使用 UPPER_CASE

### BPF 程序注意事项
- 必须包含 `vmlinux.h` 和 `bpf_helpers.h`
- 使用 `SEC()` 宏定义 section
- 验证器友好代码：避免无限循环，限制 map 访问

### 测试约定
- 单元测试放在 `tests/` 目录
- 测试文件命名：`test_<模块名>.c`
- 集成测试使用 bash 脚本

### Makefile 规则
- `make` / `make all`: 构建主程序
- `make test`: 构建并运行单元测试
- `make clean`: 清理构建产物

## 常见问题

### 构建失败
- 确保安装了所有依赖：`clang libbpf-devel bpftool elfutils-libelf-devel`
- 检查内核版本：`uname -r` 应 >= 5.10
- 检查 BTF 支持：`bpftool btf dump id 1 > /dev/null && echo "BTF OK"`

### 运行失败
- 需要 root 权限
- 如果找不到 libssl.so，使用 `-l` 参数手动指定
- 如果 uprobe 附加失败，可能是 OpenSSL 静态链接或符号被 strip

### 无数据输出
- 确认目标进程确实在使用 OpenSSL
- 检查 ring buffer 是否溢出（日志中会有 warning）
- 使用 `-v` 参数查看详细日志

## 相关文件

| 文件 | 用途 |
|------|------|
| `include/tlscap.h` | 共享数据结构定义 |
| `src/bpf/tlscap.bpf.c` | BPF 程序实现 |
| `src/main.c` | 主程序入口 |
| `src/ssl_detect.c` | libssl.so 路径检测 |
| `src/event_reader.c` | Ring buffer 事件读取 |
| `src/output.c` | 输出格式化 |
| `tests/integration_test.sh` | 集成测试脚本 |
