/* libptrace, a process tracing and manipulation library.
 *
 * Copyright (C) 2006-2019, Ronald Huizer <rhuizer@hexpedition.com>
 * Copyright (C) 2019, Cyxtera Cybersecurity, Inc.  All rights reserved.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
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
 * thread.c
 *
 * libptrace windows thread management.
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <windows.h>
#include <winbase.h>
#include <winnt.h>
#include <ntdef.h>
#include <libptrace/windows/error.h>
#include "common.h"
#include "thread.h"
#include "wrappers/kernel32.h"

extern struct pt_arch_data pt_windows_thread_arch_data;

int pt_windows_thread_init(struct pt_thread *thread)
{
	struct pt_windows_thread_data *thread_data;

	/* Initialize Windows specific data for this thread. */
	thread_data = malloc(sizeof(struct pt_windows_thread_data));
	if (thread_data == NULL) {
		pt_error_errno_set(errno);
		return -1;
	}
	thread_data->h       = INVALID_HANDLE_VALUE;

	pt_thread_init(thread);

	/* Windows architecture data.  Compilation dependent. */
	thread->arch_data    = &pt_windows_thread_arch_data;
	thread->private_data = thread_data;
	thread->t_op         = &pt_windows_thread_operations;

	return 0;
}

int pt_windows_thread_destroy(struct pt_thread *thread)
{
	HANDLE h;

	assert(thread != NULL);
	assert(thread->private_data != NULL);

	h = pt_windows_thread_handle_get(thread);
	if (HANDLE_VALID(h) && CloseHandle(h) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	free(thread->private_data);

	return 0;
}

struct pt_thread *pt_windows_thread_new(void)
{
	struct pt_thread *thread;

	if ( (thread = malloc(sizeof *thread)) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	if (pt_windows_thread_init(thread) == -1) {
		free(thread);
		return NULL;
	}

	return thread;
}

int pt_windows_thread_suspend(struct pt_thread *thread)
{
	HANDLE h = pt_windows_thread_handle_get(thread);
	return pt_windows_api_suspend_thread(h);
}

int pt_windows_thread_resume(struct pt_thread *thread)
{
	HANDLE h = pt_windows_thread_handle_get(thread);

	if (ResumeThread(h) == (DWORD)-1) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

void *pt_thread_get_tls(struct pt_thread *thread)
{
	return thread->tls_data;
}

void *pt_thread_get_start(struct pt_thread *thread)
{
	return thread->start;
}
