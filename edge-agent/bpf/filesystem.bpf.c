// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Q-EDR Filesystem Telemetry eBPF Probes
 *
 * Observes filesystem activity via syscall tracepoints:
 *   - syscalls/sys_enter_openat + sys_exit_openat  → file open/create
 *   - syscalls/sys_enter_write  + sys_exit_write   → file write (metadata only)
 *   - syscalls/sys_enter_renameat2                  → file rename
 *   - syscalls/sys_enter_unlinkat                   → file/dir delete
 *   - syscalls/sys_enter_mkdirat                    → directory creation
 *   - syscalls/sys_enter_fchmodat                   → permission change
 *   - syscalls/sys_enter_fchownat                   → ownership change
 *
 * WARNING: Filesystem events, especially open and write, can be extremely
 * high volume. User-space filtering and rate limiting are essential.
 */

#include "common.h"

/* Ring buffer for filesystem events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MB */
} fs_events SEC(".maps");

/* Temp storage for openat enter→exit correlation */
struct openat_args {
	__s32 dir_fd;
	__s32 flags;
	__u32 mode;
	char  path[MAX_PATH_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct openat_args);
} openat_args_map SEC(".maps");

/* Temp storage for write enter→exit correlation */
struct write_args {
	__s32 fd;
	__u64 count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct write_args);
} write_args_map SEC(".maps");

static __always_inline void fill_fs_header(struct event_header *hdr, __u32 event_type) {
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

/* ========== Openat Events ========== */

struct sys_enter_openat_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__u32 pad;
	__s32 dfd;
	const char *filename;
	__s32 flags;
	__u32 mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct sys_enter_openat_args *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct openat_args args = {};

	args.dir_fd = ctx->dfd;
	args.flags = ctx->flags;
	args.mode = ctx->mode;
	bpf_probe_read_user_str(args.path, sizeof(args.path), ctx->filename);

	bpf_map_update_elem(&openat_args_map, &pid_tgid, &args, BPF_ANY);
	return 0;
}

struct sys_exit_openat_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__s64 ret;
};

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct sys_exit_openat_args *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct openat_args *args;

	args = bpf_map_lookup_elem(&openat_args_map, &pid_tgid);
	if (!args)
		return 0;

	struct fs_event *evt;
	evt = bpf_ringbuf_reserve(&fs_events, sizeof(*evt), 0);
	if (!evt)
		goto cleanup;

	fill_fs_header(&evt->hdr, EVENT_FS_OPEN);
	bpf_memcpy(evt->path, args->path, sizeof(evt->path));
	bpf_memset(evt->path2, 0, sizeof(evt->path2));
	evt->dir_fd = args->dir_fd;
	evt->dir_fd2 = 0;
	evt->flags = args->flags;
	evt->mode = args->mode;
	evt->fd = (__s32)ctx->ret;
	evt->ret_code = ctx->ret < 0 ? (__s32)ctx->ret : 0;
	evt->count = 0;
	evt->written = 0;
	evt->owner_id = 0;
	evt->group_id = 0;

	bpf_ringbuf_submit(evt, 0);

cleanup:
	bpf_map_delete_elem(&openat_args_map, &pid_tgid);
	return 0;
}

/* ========== Write Events (metadata only) ========== */

struct sys_enter_write_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__u32 pad;
	__u32 fd;
	const void *buf;
	__u64 count;
};

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct sys_enter_write_args *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct write_args args = {
		.fd = (__s32)ctx->fd,
		.count = ctx->count,
	};
	bpf_map_update_elem(&write_args_map, &pid_tgid, &args, BPF_ANY);
	return 0;
}

struct sys_exit_write_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__s64 ret;
};

SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint__syscalls__sys_exit_write(struct sys_exit_write_args *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct write_args *args;

	args = bpf_map_lookup_elem(&write_args_map, &pid_tgid);
	if (!args)
		return 0;

	struct fs_event *evt;
	evt = bpf_ringbuf_reserve(&fs_events, sizeof(*evt), 0);
	if (!evt)
		goto cleanup;

	fill_fs_header(&evt->hdr, EVENT_FS_WRITE);
	bpf_memset(evt->path, 0, sizeof(evt->path));
	bpf_memset(evt->path2, 0, sizeof(evt->path2));
	evt->dir_fd = 0;
	evt->dir_fd2 = 0;
	evt->flags = 0;
	evt->mode = 0;
	evt->fd = args->fd;
	evt->ret_code = ctx->ret < 0 ? (__s32)ctx->ret : 0;
	evt->count = args->count;
	evt->written = ctx->ret;
	evt->owner_id = 0;
	evt->group_id = 0;

	bpf_ringbuf_submit(evt, 0);

cleanup:
	bpf_map_delete_elem(&write_args_map, &pid_tgid);
	return 0;
}

/* ========== Rename Events ========== */

struct sys_enter_renameat2_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__u32 pad;
	__s32 olddfd;
	const char *oldname;
	__s32 newdfd;
	const char *newname;
	__u32 flags;
};

SEC("tracepoint/syscalls/sys_enter_renameat2")
int tracepoint__syscalls__sys_enter_renameat2(struct sys_enter_renameat2_args *ctx) {
	struct fs_event *evt;
	evt = bpf_ringbuf_reserve(&fs_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_fs_header(&evt->hdr, EVENT_FS_RENAME);
	bpf_probe_read_user_str(evt->path, sizeof(evt->path), ctx->oldname);
	bpf_probe_read_user_str(evt->path2, sizeof(evt->path2), ctx->newname);
	evt->dir_fd = ctx->olddfd;
	evt->dir_fd2 = ctx->newdfd;
	evt->flags = (__s32)ctx->flags;
	evt->mode = 0;
	evt->fd = -1;
	evt->ret_code = 0;
	evt->count = 0;
	evt->written = 0;
	evt->owner_id = 0;
	evt->group_id = 0;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/* ========== Unlink Events ========== */

struct sys_enter_unlinkat_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__u32 pad;
	__s32 dfd;
	const char *pathname;
	__s32 flag;
};

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct sys_enter_unlinkat_args *ctx) {
	struct fs_event *evt;
	evt = bpf_ringbuf_reserve(&fs_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_fs_header(&evt->hdr, EVENT_FS_UNLINK);
	bpf_probe_read_user_str(evt->path, sizeof(evt->path), ctx->pathname);
	bpf_memset(evt->path2, 0, sizeof(evt->path2));
	evt->dir_fd = ctx->dfd;
	evt->dir_fd2 = 0;
	evt->flags = ctx->flag;
	evt->mode = 0;
	evt->fd = -1;
	evt->ret_code = 0;
	evt->count = 0;
	evt->written = 0;
	evt->owner_id = 0;
	evt->group_id = 0;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/* ========== Mkdir Events ========== */

struct sys_enter_mkdirat_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__u32 pad;
	__s32 dfd;
	const char *pathname;
	__u32 mode;
};

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int tracepoint__syscalls__sys_enter_mkdirat(struct sys_enter_mkdirat_args *ctx) {
	struct fs_event *evt;
	evt = bpf_ringbuf_reserve(&fs_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_fs_header(&evt->hdr, EVENT_FS_MKDIR);
	bpf_probe_read_user_str(evt->path, sizeof(evt->path), ctx->pathname);
	bpf_memset(evt->path2, 0, sizeof(evt->path2));
	evt->dir_fd = ctx->dfd;
	evt->dir_fd2 = 0;
	evt->flags = 0;
	evt->mode = ctx->mode;
	evt->fd = -1;
	evt->ret_code = 0;
	evt->count = 0;
	evt->written = 0;
	evt->owner_id = 0;
	evt->group_id = 0;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/* ========== Chmod Events ========== */

struct sys_enter_fchmodat_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__u32 pad;
	__s32 dfd;
	const char *filename;
	__u32 mode;
};

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int tracepoint__syscalls__sys_enter_fchmodat(struct sys_enter_fchmodat_args *ctx) {
	struct fs_event *evt;
	evt = bpf_ringbuf_reserve(&fs_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_fs_header(&evt->hdr, EVENT_FS_CHMOD);
	bpf_probe_read_user_str(evt->path, sizeof(evt->path), ctx->filename);
	bpf_memset(evt->path2, 0, sizeof(evt->path2));
	evt->dir_fd = ctx->dfd;
	evt->dir_fd2 = 0;
	evt->flags = 0;
	evt->mode = ctx->mode;
	evt->fd = -1;
	evt->ret_code = 0;
	evt->count = 0;
	evt->written = 0;
	evt->owner_id = 0;
	evt->group_id = 0;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/* ========== Chown Events ========== */

struct sys_enter_fchownat_args {
	struct trace_entry ent;
	__s32 __syscall_nr;
	__u32 pad;
	__s32 dfd;
	const char *filename;
	__s32 user;
	__s32 group;
	__s32 flag;
};

SEC("tracepoint/syscalls/sys_enter_fchownat")
int tracepoint__syscalls__sys_enter_fchownat(struct sys_enter_fchownat_args *ctx) {
	struct fs_event *evt;
	evt = bpf_ringbuf_reserve(&fs_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_fs_header(&evt->hdr, EVENT_FS_CHOWN);
	bpf_probe_read_user_str(evt->path, sizeof(evt->path), ctx->filename);
	bpf_memset(evt->path2, 0, sizeof(evt->path2));
	evt->dir_fd = ctx->dfd;
	evt->dir_fd2 = 0;
	evt->flags = ctx->flag;
	evt->mode = 0;
	evt->fd = -1;
	evt->ret_code = 0;
	evt->count = 0;
	evt->written = 0;
	evt->owner_id = ctx->user;
	evt->group_id = ctx->group;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

LICENSE("Dual BSD/GPL");
