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
 * heaptrace.c
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <stdio.h>
#include <inttypes.h>
#include <libptrace/libptrace.h>
#include <libptrace/breakpoint.h>

void logger(void *cookie, const char *format, va_list ap)
{
	vfprintf(stderr, format, ap);
}

void alloc_handler(struct pt_thread *thread, void *cookie)
{
	struct pt_breakpoint *breakpoint = (struct pt_breakpoint *)cookie;
	pt_register_t argv[3];

	if (pt_cconv_function_argv_get(thread, 3, argv) == -1) {
		fprintf(stderr, "wtf, error\n");
		return;
	}

	printf("RtlAllocateHeap(0x%"PRIx64", 0x%"PRIx32", 0x%"PRIx64")\n", argv[0], argv[1], argv[2]);
}

void usage(const char *p)
{
	fprintf(stderr, "Use as: %s <pid>\n", p ? p : "niques les flics");
}

int main(int argc, char **argv)
{
	struct pt_log_hook log_hook = PT_LOG_HOOK_INIT;
	struct pt_breakpoint alloc_hook;
	struct pt_process process;
	int pid, ret;

	if (argc != 2) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	pid = atoi(argv[1]);

	log_hook.handler = logger;
	pt_log_hook_register(&log_hook);
	pt_process_init(&process);

	/* Initialize breakpoint hook. */
	pt_breakpoint_sw_init(&alloc_hook);
	alloc_hook.symbol = "ntdll!RtlAllocateHeap";
	alloc_hook.handler = alloc_handler;
	alloc_hook.cookie = &alloc_hook;

	if (pt_process_attach(&process, pid) == -1) {
		fprintf(stderr, "pt_process_exec() failed: %u\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	pt_process_breakpoint_set(&process, &alloc_hook);

	if (pt_main() == -1) {
		fprintf(stderr, "pt_main() failed: %u\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
