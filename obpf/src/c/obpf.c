// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
/* Modified by @wunderwuzzi23 (copied from bootstrap.c) */

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "obpf.h"
#include "obpf.skel.h"

static struct env {
	bool   verbose;
	char*  pattern;
} env;

const char *argp_program_version = "obpf 0.1";
const char *argp_program_bug_address = "https://github.com/wunderwuzzi23/offensive-bpf>";
const char argp_program_doc[] = "Offensive BPF\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "pattern", 'p', "", 0, "The target pattern of files to look for" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		env.pattern = arg;
		//printf("Parsed Target Pattern: %s\n", env.pattern);
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	// const struct event *e = data;
	// struct tm *tm;
	// char ts[32];
	// time_t t;

	// time(&t);
	// tm = localtime(&t);
	// strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	// if (e->exit_event) {
	// 	printf("%-8s %-12s %-16s %-7d %-7d Content: %s",
	// 	       ts, "sys_exit_getdents64", e->comm, e->pid, e->ppid, e->content);
	// 	printf("\n");
	// } else {
	// 	printf("%-8s %-12s %-16s %-7d %-7d Filename: %s\n",
	// 	       ts, "sys_enter_getdents64", e->comm, e->pid, e->ppid, e->filename );
	// }

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct obpf_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = obpf_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with the target pattern  */
	skel->bss->PATTERN = env.pattern;

	/* Load & verify BPF programs */
	err = obpf_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = obpf_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	// Not sending any events from BPF program to user space
	printf("Offensive BPF - Running...\n");
	// printf("%-8s %-5s %-16s %-7s %-7s %s\n",
	//        "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT CODE");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	obpf_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
