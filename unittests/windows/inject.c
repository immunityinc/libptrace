/*
 * Copyright (C) 2019, Cyxtera Cybersecurity, Inc.  All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 2.1 as
 * published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * version 2.1 for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 2.1 along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301,
 * USA.
 *
 * THE CODE AND SCRIPTS POSTED ON THIS WEBSITE ARE PROVIDED ON AN "AS IS" BASIS
 * AND YOUR USE OF SUCH CODE AND/OR SCRIPTS IS AT YOUR OWN RISK.  CYXTERA
 * DISCLAIMS ALL EXPRESS AND IMPLIED WARRANTIES, EITHER IN FACT OR BY OPERATION
 * OF LAW, STATUTORY OR OTHERWISE, INCLUDING, BUT NOT LIMITED TO, ALL
 * WARRANTIES OF MERCHANTABILITY, TITLE, FITNESS FOR A PARTICULAR PURPOSE,
 * NON-INFRINGEMENT, ACCURACY, COMPLETENESS, COMPATABILITY OF SOFTWARE OR
 * EQUIPMENT OR ANY RESULTS TO BE ACHIEVED THEREFROM.  CYXTERA DOES NOT WARRANT
 * THAT SUCH CODE AND/OR SCRIPTS ARE OR WILL BE ERROR-FREE.  IN NO EVENT SHALL
 * CYXTERA BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, RELIANCE,
 * EXEMPLARY, PUNITIVE OR CONSEQUENTIAL DAMAGES, OR ANY LOSS OF GOODWILL, LOSS
 * OF ANTICIPATED SAVINGS, COST OF PURCHASING REPLACEMENT SERVICES, LOSS OF
 * PROFITS, REVENUE, DATA OR DATA USE, ARISING IN ANY WAY OUT OF THE USE AND/OR
 * REDISTRIBUTION OF SUCH CODE AND/OR SCRIPTS, REGARDLESS OF THE LEGAL THEORY
 * UNDER WHICH SUCH LIABILITY IS ASSERTED AND REGARDLESS OF WHETHER CYXTERA HAS
 * BEEN ADVISED OF THE POSSIBILITY OF SUCH LIABILITY.
 *
 * inject.c
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <libptrace/log.h>
#include <libptrace/core.h>
#include <libptrace/event.h>
#include <libptrace/error.h>
#include <libptrace/inject.h>

/* XXX: FIXME */
#include "../../src/process.h"
#include "../../src/thread.h"

void logger(void *cookie, const char *format, va_list ap)
{
	vfprintf(stderr, format, ap);
}

int inject_handler_pre(struct pt_process *p, void *cookie)
{
	printf("Preparing to run code in process %d\n", p->pid);
	return PT_EVENT_DROP;
}

int inject_handler_post(struct pt_process *p, void *cookie)
{
	printf("Ran code in process %d\n", p->pid);
	return PT_EVENT_DROP;
}

int attached(struct pt_event_attached *event)
{
	struct pt_inject inject;

	printf("Process with PID %d created\n", event->process->pid);

	inject.data          = "\x31\xc0\xc3";	/* xor eax, eax ; ret */
	inject.data_size     = 3;
	inject.argument      = NULL;
	inject.argument_size = 0;
	inject.handler_pre   = inject_handler_pre;
	inject.cookie_pre    = NULL;
	inject.handler_post  = inject_handler_post;
	inject.cookie_post   = NULL;

	printf("Inject: %d\n", pt_inject(&inject, event->process));

	return PT_EVENT_DROP;
}

int thread_create(struct pt_event_thread_create *event)
{
	printf("Thread with TID %d created\n", event->thread->tid);
	return PT_EVENT_DROP;
}

int thread_exit(struct pt_event_thread_exit *event)
{
	printf("Thread with TID %d exited\n", event->thread->tid);
	return PT_EVENT_DROP;
}

void usage(const char *p)
{
	fprintf(stderr, "Use as: %s <pid>\n", p ? p : "niques les flics");
}

int main(int argc, char **argv)
{
	struct pt_log_hook log_hook = PT_LOG_HOOK_INIT;
	struct pt_event_handlers handlers;
	pt_handle_t handle;
	int pid;

	if (argc != 2) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	pid = atoi(argv[1]);

	/* Set up the logger. */
	log_hook.handler = logger;
	pt_log_hook_register(&log_hook);

	pt_event_handlers_init(&handlers);
	handlers.attached.handler      = attached;
	handlers.thread_create.handler = thread_create;
	handlers.thread_exit.handler   = thread_exit;

	handle = pt_process_attach(pid, &handlers, 0);
	if (!pt_handle_valid(handle)) {
		pt_error_perror("pt_process_attach() failed");
		exit(EXIT_FAILURE);
	}

	if (pt_main() == -1) {
		pt_error_perror("pt_main() failed");
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
