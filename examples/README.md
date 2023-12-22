# Examples

This folder contains examples showcasing the features supported in the `wbpf` packages.

- `kprobe`: This example demonstrates attaching a kprobe to the `execve` syscall using `kprobe` and `ringbuf`.

- `profiler`: An example for profiling applications that use the `BPF_MAP_TYPE_STACK_TRACE` table to store stack frames and `ringbuf` to submit stack traces to user-space. This example is also used to test the `syms` package, which handles symbol resolution tasks.

- `uprobe`: This example helps trace HTTP requests in a Golang application. It uses `uprobe` to attach to the `main.handler` function and `perfbuf` to submit extracted information to user-space. Additionally, it utilizes a `BPF_MAP_TYPE_PERCPU_ARRAY` as a buffer for the `event_t` struct. This is necessary because BPF programs are limited to a 512-byte stack.

- `xdp`: A small example demonstrating how to count packets on a specific interface based on source IPs. This example utilizes `xdp` and `BPF_MAP_TYPE_LRU_HASH` as a cache. It also provides guidance on extracting the source IP from the `xdp_md` struct.

## Usage

```console
# Build an example .i.e xdp
$ make CC=clang BUILD_BPF=1 build-xdp

# Run it
$ ./xdp/xdp
```
