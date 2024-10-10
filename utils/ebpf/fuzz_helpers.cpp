// Source: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
// "skb_", not taken care of since there are at least 23 functions

#include "helper_summaries.h"
#include <cstdlib>
#include <string>
#include <stdint.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef long long s64;
typedef int s32;
typedef u32 __wsum;
typedef uint32_t __be32;

extern "C" {

extern int64_t nd_int();
extern long nd_long();
extern uint64_t nd_u64();
extern uint32_t nd_u32();
extern int64_t memhavoc(void *, int);
extern bool sea_is_deref(void *, int);


struct bpf_map;

/// @brief Perform a lookup in map for an entry associated to key.
/// @param map
/// @param key
/// @return Map value associated to key, or NULL if no entry was found.
void *bpf_map_lookup_elem(struct bpf_map *map, const void *key) {
  int64_t flag = nd_int();
  if (flag) {
    return nullptr;
  }
  void *mem = malloc(8);
  return mem;
}

/// @brief Delete entry with key from map
/// @param map
/// @param key
/// @return 0 on success, or a negative error in case of failure.
long bpf_map_delete_elem(struct bpf_map *map, const void *key) {
  return nd_long();
}

/// @brief Redirect the packet to the endpoint referenced by map at index key.
/// @param map
/// @param key
/// @param flags
/// @return XDP_REDIRECT on success, or the value of the two lower bits of the
/// flags argument on error.
long bpf_redirect_map(struct bpf_map *map, u64 key, u64 flags) {
  return nd_long();
}

/// @brief Add or update the value of the entry associated to key in map with
/// value.
/// @param map
/// @param key
/// @param value
/// @param flags
/// @return  0 on success, or a negative error in case of failure.
long bpf_map_update_elem(struct bpf_map *map, const void *key,
                         const void *value, u64 flags) {
  return nd_long();
}

/// @brief  Copy a NUL terminated string from an unsafe kernel
/// address unsafe_ptr to dst.
/// instructions
/// @param dst
/// @param size
/// @param unsafe_ptr
/// @return Return On success, the strictly positive length of the string,
/// including the trailing NUL character. On error, a negative value.
/// *has security implications*
long bpf_probe_read(void *dst, int size, const void *unsafe_ptr) {
  // if possible, assert that `unsafe_ptr` is a kernel pointer
  // assert things about size
  sassert(size > 0);
  // assert destination is ok
  sassert(sea_is_deref(dst, size));
  // havoc. this assumes arbitrary value of size, a better model is possible for
  // smaller values of size
  void *mem = malloc(size);
  memhavoc(mem, size);
  memcpy(dst, mem, size);
  // return error code
  return nd_long();
}

/// @brief Walk a user or a kernel stack and return its id. To achieve this, the
/// helper needs ctx, which is a pointer to the context on which the tracing
/// program is executed, and a pointer to a map of type
/// BPF_MAP_TYPE_STACK_TRACE.
/// @param ctx
/// @param map
/// @param flags
/// @return The positive or null stack id on success, or a negative error in
/// case of failure.
long bpf_get_stackid(void *ctx, struct bpf_map *map, u64 flags) {
  return nd_long();
}

/// @brief Get the current pid and tgid.
/// @return A 64-bit integer containing the current tgid and pid, and created as
/// such: current_task->tgid << 32 | current_task->pid.
u64 bpf_get_current_pid_tgid(void) { return nd_u64(); }

/// @brief Get the current uid and gid.
/// @return A 64-bit integer containing the current GID and UID, and created as
/// such: current_gid << 32 | current_uid.
u64 bpf_get_current_uid_gid() { return nd_u64(); }

/// @brief Used for error injection, this helper uses kprobes to override the
/// return value of the probed function, and to set it to rc.
/// @param regs the context regs on which the kprobe works.
/// @param rc
/// @return 0
/// *has security implications*
long bpf_override_return(struct pt_regs *regs, u64 rc) { return 0; }

/// @brief Get a pseudo-random number.
/// @return A random 32-bit unsigned value.
u32 bpf_get_prandom_u32() { return nd_u32(); }

/// @brief Attempt in a safe way to write len bytes from the buffer src to dst
/// in memory. It only works for threads that are in user context
/// @param dst must be a valid user space address.
/// @param src
/// @param len
/// @return 0 on success, or a negative error in case of failure.
/// *has security implications*
long bpf_probe_write_user(void *dst, const void *src, u32 len) {
  return nd_long();
}

/// @brief retrieve the value of the event counter associated to ctx and store
/// it in the structure pointed by buf and of size buf_size.
/// @param ctx
/// @param buf
/// @param buf_size
/// @return 0 on success, or a negative error in case of failure.
/// *has security implications*
long bpf_perf_prog_read_value(struct bpf_perf_event_data *ctx,
                              struct bpf_perf_event_value *buf, u32 buf_size) {
  sassert(buf_size > 0);
  // assert destination is ok
  /*sassert(sea_is_deref(dst, size));*/
  sassert(sea_is_deref(buf, buf_size));
  return nd_long();
}

/// @brief Check whether the probe is being run is the context of a given subset
/// of the cgroup2 hierarchy. The cgroup2 to test is held by map of type
/// BPF_MAP_TYPE_CGROUP_ARRAY, at index.
/// @param map
/// @param index
/// @return Return  (current task belongs to the cgroup2) ? 1 : 0, negative
/// error code if an error occured *has security implications*
long bpf_current_task_under_cgroup(struct bpf_map *map, u32 index) {
  return nd_long();
}

/// @brief Emulate a call to setsockopt() on the socket associated to bpf_socket
/// @param bpf_socket must be a full socket, one of:
///     struct bpf_sock_ops for BPF_PROG_TYPE_SOCK_OPS.
///     struct bpf_sock_addr for BPF_CGROUP_INET4_CONNECT,
///     BPF_CGROUP_INET6_CONNECT and BPF_CGROUP_UNIX_CONNECT.
/// @param level
/// @param optname
/// @param optval
/// @param optlen
/// @return 0 on success, or a negative error in case of failure.
/// *has security implications*
long bpf_setsockopt(void *bpf_socket, int level, int optname, void *optval,
                    int optlen) {
  return nd_long();
}

/// @brief Emulate a call to getsockopt() on the socket associated to bpf_socket
/// @param bpf_socket must be a full socket, one of:
///     struct bpf_sock_ops for BPF_PROG_TYPE_SOCK_OPS.
///     struct bpf_sock_addr for BPF_CGROUP_INET4_CONNECT,
///     BPF_CGROUP_INET6_CONNECT and BPF_CGROUP_UNIX_CONNECT.
/// @param level
/// @param optname
/// @param optval
/// @param optlen
/// @return 0 on success, or a negative error in case of failure.
/// *has security implications*
long bpf_getsockopt(void *bpf_socket, int level, int optname, void *optval,
                    int optlen) {
  return nd_long();
}

/// @brief Read the value of a perf event counter. This helper relies on a map
/// of type BPF_MAP_TYPE_PERF_EVENT_ARRAY.
/// @param map
/// @param flags
/// @return The value of the perf event counter read from the map, or a negative
/// error code in case of failure *has security implications*
u64 bpf_perf_event_read(struct bpf_map *map, u64 flags) { return nd_u64(); }

/// @brief Write raw data blob into a special BPF perf event held by map of type
/// BPF_MAP_TYPE_PERF_EVENT_ARRAY.
/// @param ctx
/// @param map
/// @param flags
/// @param data
/// @param size
/// @return 0 on success, or a negative error in case of failure.
/// *has security implications*
long bpf_perf_event_output(void *ctx, struct bpf_map *map, u64 flags,
                           void *data, u64 size) {
  return nd_long();
}

/// @brief print like function that writes fmt_size bytes to fmt
/// @param fmt
/// @param fmt_size
/// @param
/// @return The number of bytes written to the buffer, or a negative error in
/// case of failure. *has security implications*
long bpf_trace_printk(const char *fmt, u32 fmt_size, ...) { return nd_long(); }

/// @brief Get the SMP (symmetric multiprocessing) processor id.
/// @return The SMP id of the processor running the program.
u32 bpf_get_smp_processor_id() { return nd_u32(); }

/// @brief Copy size bytes from data into a ring buffer ringbuf.
/// @param ringbuf
/// @param data
/// @param size
/// @param flags
/// @return 0 on success, or a negative error in case of failure.
/// *has security implications*
long bpf_ringbuf_output(void *ringbuf, void *data, u64 size, u64 flags) {
  return nd_long();
}

/// @brief Copy the comm attribute of the current task into buf of size_of_buf.
/// @param buf
/// @param size_of_buf
/// @return 0 on success, or a negative error in case of failure.
/// *has security implications*
long bpf_get_current_comm(void *buf, u32 size_of_buf) {
  // if possible, assert that `unsafe_ptr` is a kernel pointer
  // assert things about size
  sassert(size_of_buf > 0);
  // assert destination is ok
  sassert(sea_is_deref(buf, size_of_buf));
  // havoc
  void *mem = malloc(size_of_buf);
  memhavoc(mem, size_of_buf);
  memcpy(buf, mem, size_of_buf);
  // return error code
  return nd_long();
}

/// @brief Add an entry to, or update a map referencing sockets.
/// @param skops
/// @param map
/// @param key
/// @param flags
/// @return 0 on success, or a negative error in case of failure.
/// *has security implications*
long bpf_sock_map_update(struct bpf_sock_ops *skops, struct bpf_map *map,
                         void *key, u64 flags) {
  return nd_long();
}

/// @brief Adjust the address pointed by xdp_md->data_meta by delta (which can
/// be positive or negative).
/// @param xdp_md
/// @param delta
/// @return 0 on success, or a negative error in case of failure.
/// *has security implications*
long bpf_xdp_adjust_meta(struct xdp_buff *xdp_md, int delta) {
  return nd_long();
}

/// @brief Adjust (move) xdp_md->data by delta bytes. Note that it is possible
/// to use a negative value for delta.
/// @param xdp_md
/// @param delta
/// @return 0 on success, or a negative error in case of failure.
/// *has security implications*
long bpf_xdp_adjust_head(struct xdp_buff *xdp_md, int delta) {
  return nd_long();
}

/// @brief Adjust (move) xdp_md->data_end by delta bytes. Note that it is
/// possible to both shrink and grow the packet tail.
/// @param xdp_md
/// @param delta
/// @return 0 on success, or a negative error in case of failure.
/// *has security implications*
long bpf_xdp_adjust_tail(struct xdp_buff *xdp_md, int delta) {
  return nd_long();
}

/// @brief Return the time elapsed since system boot in nanoseconds
/// @return current ktime
u64 bpf_ktime_get_ns() { return nd_u64(); }

/// @brief Do FIB lookup in kernel tables using parameters in params.
/// @param ctx either struct xdp_md for XDP programs or struct sk_buff tc
/// cls_act programs.
/// @param params
/// @param plen
/// @param flags
/// *has security implications*
/// @return 0 on success, negative if any argument is invalid, positive
/// otherwise

long bpf_fib_lookup(void *ctx, struct bpf_fib_lookup *params, int plen,
                    u32 flags) {
  return nd_long();
}

/// @brief Invalidate the current skb->hash.
/// @param skb
/// *has security implications*
void bpf_set_hash_invalid(struct sk_buff *skb) {}

/// @brief Retrieve the hash of the packet, skb->hash
/// @param skb
/// @return the 32-bit hash
/// *has security implications*
u32 bpf_get_hash_recalc(struct sk_buff *skb) { return nd_u32(); }

/// @brief Recompute the layer 3 (e.g. IP) checksum for the packet associated to
/// skb.
/// @param skb
/// @param offset
/// @param from
/// @param to
/// @param size
/// @return 0 on success, or a negative error in case of failure.
/// *has security implications*
long bpf_l3_csum_replace(struct sk_buff *skb, u32 offset, u64 from, u64 to,
                         u64 size) {
  return nd_long();
}

/// @brief Recompute the layer 4 (e.g. TCP, UDP or ICMP) checksum for the packet
/// associated to skb.
/// @param skb
/// @param offset
/// @param from
/// @param to
/// @param flags
/// @return 0 on success, or a negative error in case of failure.
/// *has security implications*
long bpf_l4_csum_replace(struct sk_buff *skb, u32 offset, u64 from, u64 to,
                         u64 flags) {
  return nd_long();
}

/// @brief Compute a checksum difference, from the raw buffer pointed by from,
/// of length from_size (that must be a multiple of 4), towards the raw buffer
/// pointed by to, of size to_size (same remark).
/// @param from
/// @param from_size
/// @param to
/// @param to_size
/// @param seed
/// @return The checksum result, or a negative error code in case of failure.
/// *has security implications*
s64 bpf_csum_diff(__be32 *from, u32 from_size, __be32 *to, u32 to_size,
                  __wsum seed) {
  return nd_int();
}

/// @brief Redirect the packet to another net device of index ifindex.
/// @param ifindex
/// @param flags
/// @return (XDP) ? ((success) ? XDP_REDIRECT : XDP_ABORTED) : ((success) ?
/// TC_ACT_REDIRECT : TC_ACT_SHOT)
long bpf_redirect(u32 ifindex, u64 flags) { return nd_long(); }

/// @brief Obtain the 64-bit jiffies
/// @return the 64-bit jiffies
u64 bpf_jiffies64() { return nd_u64(); }

/// @brief used to trigger a tail call to another program
/// @param ctx
/// @param prog_array_map
/// @param index
/// @return 0 on success, or a negative error in case of failure.
/// *has security implications*
long bpf_tail_call(void *ctx, struct bpf_map *prog_array_map, u32 index) {
  return nd_long();
}
}
