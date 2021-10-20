// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, tid_t);
	__type(value, u64);
} read_buffer SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, tid_t);
	__type(value, u64);
} files SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;


SEC("tracepoint/syscalls/sys_enter_openat")
int handle_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	tid_t tid;
	pid_t pid;

	struct task_struct *task;
	struct event *e;

	tid = bpf_get_current_pid_tgid();
	pid = bpf_get_current_pid_tgid() >> 32;

	char filename[MAX_FILENAME_LEN];
	bpf_probe_read_user_str(&filename, sizeof(filename), (char *)ctx->args[1]);

    //bpf_printk("** sys_enter_openat: %s.\n", &filename);

    char* target = "/tmp/test";   ///BUG, BUG, BUG (sizeof is not what i think it is)
	if (sizeof(target) > sizeof(filename)) return 0;
    for (int i=0; i < sizeof(target); i++)
	{
		if (target[i] != filename[i])
		{
			return 0;
		}
	}

    //bpf_printk("** sys_enter_openat: Compare succeeded.\n");
 
	unsigned long *val = 0;
	bpf_map_update_elem(&files, &tid, &val, BPF_ANY);

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;


	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = false;
    //e->syscall = "sys_enter_openat";
	e->pid = tid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (char *)ctx->args[1]);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
    // bpf_ringbuf_discard(e,0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_exit_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task;
	struct event *e;
	tid_t tid;

	tid = bpf_get_current_pid_tgid();

    // check if we are supposed to handle this call
    void* res = bpf_map_lookup_elem(&files, &tid);
	if (res == NULL)
	{
       return 0;
	}

    bpf_map_delete_elem(&files, &tid);

    // see if openat worked and if we have a file new descriptor
    unsigned long fd = (unsigned long)ctx->args[0];
    if ( fd == -1 )
	{
       return 0;
    }

    // store the file descriptor, so that we know 
    // what to look for in sys_enter_read

	bpf_map_update_elem(&files, &tid, &fd, BPF_ANY);


	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = true;
    //e->syscall = "sys_exit_openat";
	e->pid = tid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* send data to user-space for post-processing */
	//bpf_ringbuf_submit(e, 0);
    bpf_ringbuf_discard(e,0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	tid_t tid;
	pid_t pid;

	struct task_struct *task;
	struct event *e;

	tid = bpf_get_current_pid_tgid();
	pid = bpf_get_current_pid_tgid() >> 32;

    // check if we should process this call
	unsigned int * target_fd = (unsigned int *)bpf_map_lookup_elem(&files, &tid);
	if (target_fd == NULL)
	{
       return 0;
	}

    // check if it's the right file descriptor
    unsigned long fd = (unsigned long)ctx->args[0];
    if ( *target_fd != fd )
    {
       bpf_printk("** sys_enter_read: File descriptor %u vs %u not matching.\n", 
            *target_fd,
            fd);
       return 0;
    }

     bpf_printk("** sys_enter_read: MATCH. File descriptor %u vs %u.\n", 
            *target_fd,
            fd);

	// store pointer to buffer
    unsigned long buf = ctx->args[1];
	bpf_map_update_elem(&read_buffer, &tid, &buf, BPF_ANY);

    //bpf_printk("** sys_enter_read: Buffer stored.");


	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = false;
    //e->syscall = "sys_enter_read";
	e->pid = tid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	 return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_exit_read(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task;
	struct event *e;
	tid_t tid;

	tid = bpf_get_current_pid_tgid();

    // check if we are supposed to handle this call
    // and get buffer pointer (if present)
	unsigned long * buf = bpf_map_lookup_elem(&read_buffer, &tid);
    if (buf == NULL)
	{
       return 0;
	}

    bpf_printk("** sys_exit_read: Buffer found:  %s", *buf);
	bpf_map_delete_elem(&read_buffer, &tid);

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = true;
	e->pid = tid;
    //e->syscall = "sys_exit_read";
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    long len = bpf_probe_read_user_str(&e->content, sizeof(e->content), (const void *)*buf);
    bpf_printk("** sys_exit_read: Buffer read: %s (len=%u).", e->content, len);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (len > 0) {

        char replace[256];
        for(int i=0; i < 256; i++)
        {
           replace[i] =  ' ';
        }
        
        replace[0] = 'O';
        replace[1] = 'h';
        replace[2] = 'B';
        replace[3] = 'P';
        replace[4] = 'F';
        replace[5] = '!';
        replace[6] = '\n';

        bpf_probe_write_user((void*)*buf, (void *)replace, 256);  //API doesn't seem to write beyond src buffer
    }

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
