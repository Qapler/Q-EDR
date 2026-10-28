// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Q-EDR Filesystem Telemetry eBPF Probes
 *
 * Observes filesystem syscalls via raw_tracepoint/sys_enter and sys_exit,
 * dispatching on the x86_64 syscall number:
 *   - open, creat, openat, openat2 (enter + exit)  → file open/create
 *   - write (enter + exit)                         → file write (metadata only)
 *   - rename, renameat, renameat2                  → file rename
 *   - unlink, rmdir, unlinkat                      → file/dir delete
 *   - mkdir, mkdirat                               → directory creation
 *   - chmod, fchmodat, fchmodat2                   → permission change
 *   - chown, lchown, fchownat                      → ownership change
 *
 * Raw tracepoints are used instead of tracepoint/syscalls/sys_enter_*: on
 * Linux 7.0 the per-syscall enter tracepoints that capture user-space strings
 * (__filename_val etc.) ran the attached program for only ~9% of calls
 * system-wide, while raw_tracepoint/sys_enter saw every call. Legacy x86_64
 * syscalls are included because glibc's rename(), unlink(), mkdir(), chmod()
 * and chown() use them rather than the *at variants.
 *
 * WARNING: Filesystem events, especially open and write, can be extremely
 * high volume. User-space filtering and rate limiting are essential.
 */

#include "common.h"

/* x86_64 syscall numbers (arch/x86/entry/syscalls/syscall_64.tbl). */
#define NR_write      1
#define NR_open       2
#define NR_rename     82
#define NR_mkdir      83
#define NR_rmdir      84
#define NR_creat      85
#define NR_unlink     87
#define NR_chmod      90
#define NR_chown      92
#define NR_lchown     94
#define NR_openat     257
#define NR_mkdirat    258
#define NR_fchownat   260
#define NR_unlinkat   263
#define NR_renameat   264
#define NR_fchmodat   268
#define NR_renameat2  316
#define NR_openat2    437
#define NR_fchmodat2  452

#define AT_SYMLINK_NOFOLLOW 0x100

/* Force emitting event structs into BTF so bpf2go -type can generate Go types. */
const struct fs_event *unused_fs_event __attribute__((unused));

/* Ring buffer for filesystem events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MB */
} fs_events SEC(".maps");

/* Temp storage for open* enter→exit correlation */
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

/* ========== Enter-side helpers ========== */

static __always_inline int save_open(__s32 dfd, const char *path, __s32 flags, __u32 mode) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct openat_args args = {};

	args.dir_fd = dfd;
	args.flags = flags;
	args.mode = mode;
	bpf_probe_read_user_str(args.path, sizeof(args.path), path);

	bpf_map_update_elem(&openat_args_map, &pid_tgid, &args, BPF_ANY);
	return 0;
}

/* Emit a single-shot path event (rename/unlink/mkdir/chmod/chown). Syscall
 * results are not correlated, so ret_code is always 0. */
static __always_inline int emit_path_event(__u32 type, __s32 dfd, const char *path,
					   __s32 dfd2, const char *path2, __s32 flags,
					   __u32 mode, __s32 owner, __s32 group) {
	struct fs_event *evt;
	evt = bpf_ringbuf_reserve(&fs_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_header(&evt->hdr, type);
	bpf_probe_read_user_str(evt->path, sizeof(evt->path), path);
	if (path2)
		bpf_probe_read_user_str(evt->path2, sizeof(evt->path2), path2);
	else
		bpf_memset(evt->path2, 0, sizeof(evt->path2));
	evt->dir_fd = dfd;
	evt->dir_fd2 = path2 ? dfd2 : 0;
	evt->flags = flags;
	evt->mode = mode;
	evt->fd = -1;
	evt->ret_code = 0;
	evt->count = 0;
	evt->written = 0;
	evt->owner_id = owner;
	evt->group_id = group;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	long id = ctx->args[1];

	switch (id) {
	case NR_write: case NR_open: case NR_creat: case NR_openat: case NR_openat2:
	case NR_rename: case NR_renameat: case NR_renameat2:
	case NR_unlink: case NR_rmdir: case NR_unlinkat:
	case NR_mkdir: case NR_mkdirat:
	case NR_chmod: case NR_fchmodat: case NR_fchmodat2:
	case NR_chown: case NR_lchown: case NR_fchownat:
		break;
	default:
		return 0;
	}

	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
	__u64 a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0;
	READ_KERN(a0, &regs->di);
	READ_KERN(a1, &regs->si);
	READ_KERN(a2, &regs->dx);
	READ_KERN(a3, &regs->r10);
	READ_KERN(a4, &regs->r8);

	switch (id) {
	case NR_write: {
		__u64 pid_tgid = bpf_get_current_pid_tgid();
		struct write_args args = {
			.fd = (__s32)a0,
			.count = a2,
		};
		bpf_map_update_elem(&write_args_map, &pid_tgid, &args, BPF_ANY);
		return 0;
	}
	case NR_open:
		return save_open(AT_FDCWD, (const char *)a0, (__s32)a1, (__u32)a2);
	case NR_creat:
		return save_open(AT_FDCWD, (const char *)a0, O_CREAT | O_WRONLY | O_TRUNC, (__u32)a1);
	case NR_openat:
		return save_open((__s32)a0, (const char *)a1, (__s32)a2, (__u32)a3);
	case NR_openat2: {
		/* struct open_how { __u64 flags; __u64 mode; __u64 resolve; } */
		__u64 how[2] = {};
		bpf_probe_read_user(how, sizeof(how), (const void *)a2);
		return save_open((__s32)a0, (const char *)a1, (__s32)how[0], (__u32)how[1]);
	}
	case NR_rename:
		return emit_path_event(EVENT_FS_RENAME, AT_FDCWD, (const char *)a0,
				       AT_FDCWD, (const char *)a1, 0, 0, 0, 0);
	case NR_renameat:
		return emit_path_event(EVENT_FS_RENAME, (__s32)a0, (const char *)a1,
				       (__s32)a2, (const char *)a3, 0, 0, 0, 0);
	case NR_renameat2:
		return emit_path_event(EVENT_FS_RENAME, (__s32)a0, (const char *)a1,
				       (__s32)a2, (const char *)a3, (__s32)a4, 0, 0, 0);
	case NR_unlink:
		return emit_path_event(EVENT_FS_UNLINK, AT_FDCWD, (const char *)a0,
				       0, NULL, 0, 0, 0, 0);
	case NR_rmdir:
		return emit_path_event(EVENT_FS_UNLINK, AT_FDCWD, (const char *)a0,
				       0, NULL, AT_REMOVEDIR, 0, 0, 0);
	case NR_unlinkat:
		return emit_path_event(EVENT_FS_UNLINK, (__s32)a0, (const char *)a1,
				       0, NULL, (__s32)a2, 0, 0, 0);
	case NR_mkdir:
		return emit_path_event(EVENT_FS_MKDIR, AT_FDCWD, (const char *)a0,
				       0, NULL, 0, (__u32)a1, 0, 0);
	case NR_mkdirat:
		return emit_path_event(EVENT_FS_MKDIR, (__s32)a0, (const char *)a1,
				       0, NULL, 0, (__u32)a2, 0, 0);
	case NR_chmod:
		return emit_path_event(EVENT_FS_CHMOD, AT_FDCWD, (const char *)a0,
				       0, NULL, 0, (__u32)a1, 0, 0);
	case NR_fchmodat:
		return emit_path_event(EVENT_FS_CHMOD, (__s32)a0, (const char *)a1,
				       0, NULL, 0, (__u32)a2, 0, 0);
	case NR_fchmodat2:
		return emit_path_event(EVENT_FS_CHMOD, (__s32)a0, (const char *)a1,
				       0, NULL, (__s32)a3, (__u32)a2, 0, 0);
	case NR_chown:
		return emit_path_event(EVENT_FS_CHOWN, AT_FDCWD, (const char *)a0,
				       0, NULL, 0, 0, (__s32)a1, (__s32)a2);
	case NR_lchown:
		return emit_path_event(EVENT_FS_CHOWN, AT_FDCWD, (const char *)a0,
				       0, NULL, AT_SYMLINK_NOFOLLOW, 0, (__s32)a1, (__s32)a2);
	case NR_fchownat:
		return emit_path_event(EVENT_FS_CHOWN, (__s32)a0, (const char *)a1,
				       0, NULL, (__s32)a4, 0, (__s32)a2, (__s32)a3);
	}
	return 0;
}

/* ========== Exit side: open* and write ========== */

static __always_inline int emit_open(__s64 ret) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct openat_args *args;

	args = bpf_map_lookup_elem(&openat_args_map, &pid_tgid);
	if (!args)
		return 0;

	struct fs_event *evt;
	evt = bpf_ringbuf_reserve(&fs_events, sizeof(*evt), 0);
	if (!evt)
		goto cleanup;

	fill_header(&evt->hdr, EVENT_FS_OPEN);
	bpf_memcpy(evt->path, args->path, sizeof(evt->path));
	bpf_memset(evt->path2, 0, sizeof(evt->path2));
	evt->dir_fd = args->dir_fd;
	evt->dir_fd2 = 0;
	evt->flags = args->flags;
	evt->mode = args->mode;
	evt->fd = (__s32)ret;
	evt->ret_code = ret < 0 ? (__s32)ret : 0;
	evt->count = 0;
	evt->written = 0;
	evt->owner_id = 0;
	evt->group_id = 0;

	bpf_ringbuf_submit(evt, 0);

cleanup:
	bpf_map_delete_elem(&openat_args_map, &pid_tgid);
	return 0;
}

static __always_inline int emit_write(__s64 ret) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct write_args *args;

	args = bpf_map_lookup_elem(&write_args_map, &pid_tgid);
	if (!args)
		return 0;

	struct fs_event *evt;
	evt = bpf_ringbuf_reserve(&fs_events, sizeof(*evt), 0);
	if (!evt)
		goto cleanup;

	fill_header(&evt->hdr, EVENT_FS_WRITE);
	bpf_memset(evt->path, 0, sizeof(evt->path));
	bpf_memset(evt->path2, 0, sizeof(evt->path2));
	evt->dir_fd = 0;
	evt->dir_fd2 = 0;
	evt->flags = 0;
	evt->mode = 0;
	evt->fd = args->fd;
	evt->ret_code = ret < 0 ? (__s32)ret : 0;
	evt->count = args->count;
	evt->written = ret;
	evt->owner_id = 0;
	evt->group_id = 0;

	bpf_ringbuf_submit(evt, 0);

cleanup:
	bpf_map_delete_elem(&write_args_map, &pid_tgid);
	return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tracepoint__sys_exit(struct bpf_raw_tracepoint_args *ctx) {
	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
	__s64 ret = (__s64)ctx->args[1];
	long id = 0;

	READ_KERN(id, &regs->orig_ax);
	switch (id) {
	case NR_open: case NR_creat: case NR_openat: case NR_openat2:
		return emit_open(ret);
	case NR_write:
		return emit_write(ret);
	}
	return 0;
}

LICENSE("Dual BSD/GPL");
