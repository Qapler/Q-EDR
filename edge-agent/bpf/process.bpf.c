// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Q-EDR Process Telemetry eBPF Probes
 *
 * Attaches to stable kernel tracepoints to observe:
 *   - sched/sched_process_exec  → process execution
 *   - sched/sched_process_fork  → process creation
 *   - sched/sched_process_exit  → process termination
 *
 * Events are sent to user-space via a BPF ring buffer.
 */

#include "common.h"

/* Force emitting event structs into BTF so bpf2go -type can generate Go types. */
const struct process_exec_event *unused_process_exec_event __attribute__((unused));
const struct process_fork_event *unused_process_fork_event __attribute__((unused));
const struct process_exit_event *unused_process_exit_event __attribute__((unused));

/* Ring buffer for sending events to user-space */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MB */
} process_events SEC(".maps");

/*
 * Tracepoint: sched/sched_process_exec
 *
 * Fires when a process calls execve() successfully.
 * Tracepoint format (from /sys/kernel/debug/tracing/events/sched/sched_process_exec/format):
 *   field: char filename[];  offset:8;  size:4;  signed:0;
 *   field: pid_t pid;        offset:12; size:4;  signed:1;
 *   field: pid_t old_pid;    offset:16; size:4;  signed:1;
 */
struct sched_process_exec_args {
	struct trace_entry ent;
	__u32 __data_loc_filename;
	__s32 pid;
	__s32 old_pid;
};

SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__process_exec(struct sched_process_exec_args *ctx) {
	struct process_exec_event *evt;

	evt = bpf_ringbuf_reserve(&process_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_header(&evt->hdr, EVENT_PROCESS_EXEC);

	/* Read filename from tracepoint data location.
	 * The __data_loc format stores offset in low 16 bits, length in high 16 bits. */
	unsigned short off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(evt->filename, sizeof(evt->filename),
			   (void *)ctx + off);

	evt->argv_len = 0;
	evt->ret_code = 0; /* exec tracepoint fires on success */

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/*
 * Raw tracepoint: sched_process_fork
 *
 * TP_PROTO(struct task_struct *parent, struct task_struct *child).
 * A raw tracepoint is used instead of tracepoint/sched/sched_process_fork
 * because that tracepoint's record layout changed across kernels (char[16]
 * comm fields became __data_loc), while the task_struct fields are read with
 * CO-RE and stay portable. Thread creation (CLONE_THREAD) is skipped so that
 * process.fork means a new process, matching the leader-only exit events.
 */
SEC("raw_tracepoint/sched_process_fork")
int raw_tracepoint__sched_process_fork(struct bpf_raw_tracepoint_args *ctx) {
	struct task_struct *parent = (struct task_struct *)ctx->args[0];
	struct task_struct *child = (struct task_struct *)ctx->args[1];
	struct process_fork_event *evt;
	int parent_tgid = 0, child_pid = 0, child_tgid = 0;

	READ_KERN(parent_tgid, &parent->tgid);
	READ_KERN(child_pid, &child->pid);
	READ_KERN(child_tgid, &child->tgid);
	if (child_tgid == parent_tgid)
		return 0;

	evt = bpf_ringbuf_reserve(&process_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_header(&evt->hdr, EVENT_PROCESS_FORK);

	evt->child_pid = child_tgid;
	evt->child_tid = child_pid;
	evt->clone_flags = 0; /* Not available from this tracepoint */
	bpf_probe_read_kernel_str(evt->child_comm, sizeof(evt->child_comm),
				  __builtin_preserve_access_index(&child->comm));
	evt->child_start_time_ns = 0;
	READ_KERN(evt->child_start_time_ns, &child->start_boottime);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/*
 * Tracepoint: sched/sched_process_exit
 *
 * Fires when a process (or thread) exits. do_exit() stores the wait status
 * in task->exit_code before this tracepoint fires, so it is read via CO-RE.
 */
SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__process_exit(void *ctx) {
	struct process_exit_event *evt;

	/* Only report thread-group leaders (PID == TID) to avoid
	 * duplicate exit events for multi-threaded processes. */
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	if (pid != tid)
		return 0;

	evt = bpf_ringbuf_reserve(&process_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	fill_header(&evt->hdr, EVENT_PROCESS_EXIT);

	/* exit_code is a wait(2) status: exit status in bits 8-15, signal in 0-6. */
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	int code = 0;
	READ_KERN(code, &task->exit_code);
	evt->exit_code = (code >> 8) & 0xff;
	evt->signal = code & 0x7f;
	evt->start_time_ns = evt->hdr.start_time_ns;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

LICENSE("Dual BSD/GPL");
