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
 * cconv.c
 *
 * libptrace windows calling convention implementation.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <libptrace/error.h>
#include "process.h"
#include "thread.h"
#include "thread_x86_32.h"
#include "thread_x86_64.h"

int
pt_x86_32_cconv_function_argv_get(struct pt_thread *thread, int argc, pt_register_t *argv)
{
	uint32_t esp;
	int i;

	pt_error_save(), pt_error_clear();

	esp = pt_windows_thread_x86_32_get_esp(thread);

	if (esp == -1 && pt_error_is_set())
		return -1;

	pt_error_restore();

	for (i = 0; i < argc; i++) {
		uint32_t dummy;

		esp += 4;
		if (pt_process_read(thread->process, &dummy, esp, 4) == -1)
			return -1;

		argv[i] = dummy;
	}

	return 0;
}

uint32_t pt_x86_32_cconv_function_retval_get(struct pt_thread *thread)
{
	return pt_windows_thread_x86_32_get_eax(thread);
}

uint32_t pt_x86_32_cconv_function_retaddr_get(struct pt_thread *thread)
{
	uint32_t esp, retaddr;

	pt_error_save(), pt_error_clear();

	esp = pt_windows_thread_x86_32_get_esp(thread);

	if (esp == -1 && pt_error_is_set())
		return -1;

	pt_error_restore();

	if (pt_process_read(thread->process, &retaddr, esp, 4) == -1)
		return -1;

	return retaddr;
}

#ifdef __i386__
int pt_cconv_function_argv_get(struct pt_thread *thread, int argc, pt_register_t *argv)
{
	return pt_x86_32_cconv_function_argv_get(thread, argc, argv);
}

pt_register_t pt_cconv_function_retaddr_get(struct pt_thread *thread)
{
	assert(thread != NULL);
	assert(thread->process != NULL);

	return pt_x86_32_cconv_function_retaddr_get(thread);
}

pt_register_t pt_cconv_function_retval_get(struct pt_thread *thread)
{
	assert(thread != NULL);
	assert(thread->process != NULL);

	return pt_x86_32_cconv_function_retval_get(thread);
}
#endif

#ifdef __x86_64__
int
pt_x86_64_cconv_function_argv_get(struct pt_thread *thread, int argc, pt_register_t *argv)
{
	uint64_t rsp;
	int i;

	pt_error_save(), pt_error_clear();

	switch (argc) {
	default:
		rsp = pt_windows_thread_x86_64_get_rsp(thread);

		/* Skip saved rip and 32-bytes of shadow space. */
		rsp += 40;

		for (i = 4; i < argc; i++, rsp += 8) {
			struct pt_process *p = thread->process;

			if (pt_process_read(p, &argv[i], rsp, 8) == -1)
				return -1;
		}
	case 4:
		argv[3] = pt_windows_thread_x86_64_get_r9(thread);
	case 3:
		argv[2] = pt_windows_thread_x86_64_get_r8(thread);
	case 2:
		argv[1] = pt_windows_thread_x86_64_get_rdx(thread);
	case 1:
		argv[0] = pt_windows_thread_x86_64_get_rcx(thread);
	case 0:
		break;
	}

	if (pt_error_is_set())
		return -1;

	pt_error_restore();
	return 0;
}

uint64_t pt_x86_64_cconv_function_retval_get(struct pt_thread *thread)
{
	return pt_windows_thread_x86_64_get_rax(thread);
}

uint64_t pt_x86_64_cconv_function_retaddr_get(struct pt_thread *thread)
{
	uint64_t rsp, retaddr;

	pt_error_save(), pt_error_clear();

	rsp = pt_windows_thread_x86_64_get_rsp(thread);

	if (rsp == -1 && pt_error_is_set())
		return -1;

	pt_error_restore();

	if (pt_process_read(thread->process, &retaddr, rsp, 8) == -1)
		return -1;

	return retaddr;
}

pt_register_t pt_cconv_function_retaddr_get(struct pt_thread *thread)
{
	assert(thread != NULL);
	assert(thread->process != NULL);

	if (pt_windows_process_wow64_get(thread->process) == 0)
		return pt_x86_64_cconv_function_retaddr_get(thread);
	else
		return pt_x86_32_cconv_function_retaddr_get(thread);
}

pt_register_t pt_cconv_function_retval_get(struct pt_thread *thread)
{
	assert(thread != NULL);
	assert(thread->process != NULL);

	if (pt_windows_process_wow64_get(thread->process) == 0)
		return pt_x86_64_cconv_function_retval_get(thread);
	else
		return pt_x86_32_cconv_function_retval_get(thread);
}

int pt_cconv_function_argv_get(struct pt_thread *thread, int argc, pt_register_t *argv)
{
	assert(thread != NULL);
	assert(thread->process != NULL);

	if (pt_windows_process_wow64_get(thread->process) == 0)
		return pt_x86_64_cconv_function_argv_get(thread, argc, argv);
	else
		return pt_x86_32_cconv_function_argv_get(thread, argc, argv);
}

#endif
