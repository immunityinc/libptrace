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
 * pt_core.c
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <libptrace/core.h>
#include <libptrace/error.h>
#include <libptrace/event.h>
#include <libptrace/factory.h>
#include <libptrace/log.h>
#include <libptrace/util.h>

void logger(void *cookie, const char *format, va_list ap)
{
	fprintf(stderr, "T%d) ", pt_util_tid_get());
	vfprintf(stderr, format, ap);
}

void *core_thread(void *cookie)
{
	struct pt_core *core = (struct pt_core *)cookie;
	printf("Calling pt_core_main...\n");
	pt_core_main(core);
	return NULL;
}

int attached_handler(struct pt_event_attached *event)
{
	printf("Attached to PID %d\n", pt_process_pid_get(event->process));
	return PT_EVENT_DROP;
}

int main(int argc, char **argv)
{
	struct pt_log_hook log_hook = PT_LOG_HOOK_INIT;
	struct pt_event_handlers handlers;
	struct pt_core *core;
	pt_handle_t h1, h2;
	pthread_t thread;
	pt_pid_t pid;

	if (argc != 2) {
		fprintf(stderr, "Use as: %s <pid>\n", argv[0] ?: "");
		exit(EXIT_FAILURE);
	}

	pid = atoi(argv[1]);

        log_hook.handler = logger;
        pt_log_hook_register(&log_hook);

	core = pt_factory_core_new(PT_FACTORY_CORE_WINDOWS);
	if (core == NULL) {
		pt_error_perror("pt_factory_core_new()");
		exit(EXIT_FAILURE);
	}

	pt_event_handlers_init(&handlers);
	handlers.attached.handler = attached_handler;

	printf("Calling pthread_create...\n");
	pthread_create(&thread, NULL, core_thread, core);

	sleep(2);

	printf("Calling pt_core_process_attach_remote...\n");
	h1 = pt_core_process_attach_remote(core, pid, &handlers, 0);
	if (!pt_handle_valid(h1)) {
		pt_error_perror("pt_core_attach_remote()");
		exit(EXIT_FAILURE);
	}

	printf("Calling pt_core_execv_remote...\n");
	h2 = pt_core_execv_remote(core, "c:\\windows\\notepad.exe", NULL, &handlers, 0);
	if (!pt_handle_valid(h2)) {
		pt_error_perror("pt_core_attach_remote()");
		exit(EXIT_FAILURE);
	}

	sleep(5);
}
