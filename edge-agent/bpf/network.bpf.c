// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Q-EDR Network Telemetry eBPF Probes
 *
 * Observes network activity via:
 *   - tracepoint/sock/inet_sock_set_state → TCP state transitions (connect, accept, close)
 *   - tracepoint/syscalls/sys_enter_bind  → socket bind
 *   - tracepoint/syscalls/sys_exit_bind   → bind result
 *
 * Events are sent to user-space via a BPF ring buffer.
 */

#include "common.h"

/* Ring buffer for network events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MB */
} network_events SEC(".maps");

/* Temporary storage for bind enter→exit correlation */
struct bind_args {
	__u16 family;
	__u16 port;
	__u32 addr[4];
	__s32 fd;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);   /* pid_tgid */
	__type(value, struct bind_args);
} bind_args_map SEC(".maps");

/* Helper to populate common header */
static __always_inline void fill_net_header(struct event_header *hdr, __u32 event_type) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	hdr->event_type = event_type;
	hdr->pid = pid_tgid >> 32;
	hdr->tid = (__u32)pid_tgid;
	hdr->uid = (__u32)uid_gid;
	hdr->gid = uid_gid >> 32;
	hdr->timestamp_ns = bpf_ktime_get_boot_ns();
	hdr->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(hdr->comm, sizeof(hdr->comm));
	hdr->ppid = 0;
}

/*
 * Tracepoint: sock/inet_sock_set_state
 *
 * Fires on TCP state transitions. This is the preferred mechanism for
 * observing TCP connections because it's a stable tracepoint (kernel ≥4.16).
 *
 * Key transitions we observe:
 *   TCP_SYN_SENT → TCP_ESTABLISHED  (outbound connect succeeded)
 *   TCP_CLOSE    → TCP_SYN_SENT     (outbound connect initiated)
 *   TCP_NEW_SYN_RECV → TCP_ESTABLISHED (inbound accept)
 *   TCP_ESTABLISHED → TCP_CLOSE_WAIT (remote close)
 *   * → TCP_CLOSE                   (connection closed)
 *
 * Format:
 *   field: const void * skaddr;   offset:8;  size:8;
 *   field: int oldstate;          offset:16; size:4;
 *   field: int newstate;          offset:20; size:4;
 *   field: __u16 sport;           offset:24; size:2;
 *   field: __u16 dport;           offset:26; size:2;
 *   field: __u16 family;          offset:28; size:2;
 *   field: __u16 protocol;        offset:30; size:2;
 *   field: __u8 saddr[4];         offset:32; size:4;
 *   field: __u8 daddr[4];         offset:36; size:4;
 *   field: __u8 saddr_v6[16];     offset:40; size:16;
 *   field: __u8 daddr_v6[16];     offset:56; size:16;
 */
struct inet_sock_set_state_args {
	struct trace_entry ent;
	const void *skaddr;
	__s32 oldstate;
	__s32 newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8  saddr[4];
	__u8  daddr[4];
	__u8  saddr_v6[16];
	__u8  daddr_v6[16];
};

SEC("tracepoint/sock/inet_sock_set_state")
int tracepoint__sock__inet_sock_set_state(struct inet_sock_set_state_args *ctx) {
	struct network_event *evt;
	__u32 event_type;

	/* Determine event type based on state transition */
	if (ctx->newstate == TCP_ESTABLISHED && ctx->oldstate == TCP_SYN_SENT) {
		event_type = EVENT_NET_CONNECT; /* Outbound connect succeeded */
	} else if (ctx->newstate == TCP_ESTABLISHED && ctx->oldstate == TCP_NEW_SYN_RECV) {
		event_type = EVENT_NET_ACCEPT;  /* Inbound connection accepted */
	} else if (ctx->newstate == TCP_CLOSE || ctx->newstate == TCP_CLOSE_WAIT ||
		   ctx->newstate == TCP_FIN_WAIT1) {
		event_type = EVENT_NET_CLOSE;   /* Connection closing */
	} else {
		return 0; /* Skip other transitions */
	}

	evt = bpf_ringbuf_reserve(&network_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_net_header(&evt->hdr, event_type);

	evt->family = ctx->family;
	evt->protocol = ctx->protocol;
	evt->sport = ctx->sport;
	evt->dport = ctx->dport;
	evt->old_state = ctx->oldstate;
	evt->new_state = ctx->newstate;
	evt->ret_code = 0;
	evt->socket_fd = -1;
	evt->backlog = 0;

	/* Copy addresses based on family */
	if (ctx->family == AF_INET) {
		bpf_probe_read_kernel(&evt->saddr[0], 4, ctx->saddr);
		bpf_probe_read_kernel(&evt->daddr[0], 4, ctx->daddr);
	} else if (ctx->family == AF_INET6) {
		bpf_probe_read_kernel(evt->saddr, 16, ctx->saddr_v6);
		bpf_probe_read_kernel(evt->daddr, 16, ctx->daddr_v6);
	}

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/*
 * Tracepoint: syscalls/sys_enter_bind
 * Captures bind() arguments for correlation with sys_exit_bind.
 */
struct sys_enter_bind_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__u32 pad;
	__s32 fd;
	const void *umyaddr;
	__s32 addrlen;
};

SEC("tracepoint/syscalls/sys_enter_bind")
int tracepoint__syscalls__sys_enter_bind(struct sys_enter_bind_args *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct bind_args args = {};

	args.fd = ctx->fd;

	/* Read the sockaddr_in family and port from user memory */
	__u16 sa_family = 0;
	bpf_probe_read_user(&sa_family, sizeof(sa_family), ctx->umyaddr);
	args.family = sa_family;

	if (sa_family == AF_INET) {
		/* struct sockaddr_in: family(2) + port(2) + addr(4) */
		bpf_probe_read_user(&args.port, 2, ctx->umyaddr + 2);
		bpf_probe_read_user(&args.addr[0], 4, ctx->umyaddr + 4);
	} else if (sa_family == AF_INET6) {
		bpf_probe_read_user(&args.port, 2, ctx->umyaddr + 2);
		bpf_probe_read_user(args.addr, 16, ctx->umyaddr + 8);
	}

	/* Swap port from network byte order */
	args.port = __builtin_bswap16(args.port);

	bpf_map_update_elem(&bind_args_map, &pid_tgid, &args, BPF_ANY);
	return 0;
}

/*
 * Tracepoint: syscalls/sys_exit_bind
 * Correlates with enter to emit bind event with return code.
 */
struct sys_exit_bind_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__s64 ret;
};

SEC("tracepoint/syscalls/sys_exit_bind")
int tracepoint__syscalls__sys_exit_bind(struct sys_exit_bind_args *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct bind_args *args;

	args = bpf_map_lookup_elem(&bind_args_map, &pid_tgid);
	if (!args)
		return 0;

	struct network_event *evt;
	evt = bpf_ringbuf_reserve(&network_events, sizeof(*evt), 0);
	if (!evt)
		goto cleanup;

	fill_net_header(&evt->hdr, EVENT_NET_BIND);

	evt->family = args->family;
	evt->sport = args->port;
	evt->dport = 0;
	evt->protocol = 0; /* Not easily available at bind time */
	bpf_memcpy(evt->saddr, args->addr, sizeof(evt->saddr));
	bpf_memset(evt->daddr, 0, sizeof(evt->daddr));
	evt->ret_code = (__s32)ctx->ret;
	evt->socket_fd = args->fd;
	evt->old_state = 0;
	evt->new_state = 0;
	evt->backlog = 0;

	bpf_ringbuf_submit(evt, 0);

cleanup:
	bpf_map_delete_elem(&bind_args_map, &pid_tgid);
	return 0;
}

LICENSE("Dual BSD/GPL");
