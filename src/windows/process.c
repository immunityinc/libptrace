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
 * process.c
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <windows.h>
#include <libptrace/log.h>
#include <libptrace/windows/error.h>
#include "../breakpoint.h"
#include "../module.h"
#include "adapter.h"
#include "core.h"
#include "common.h"
#include "process.h"
#include "symbol.h"
#include "wrappers/ntdll.h"
#include "wrappers/kernel32.h"

int pt_windows_process_init(struct pt_process *process)
{
	struct pt_windows_process_data *process_data;

	/* Initialize Windows private process data. */
	process_data = malloc(sizeof *process_data);
	if (process_data == NULL) {
		pt_error_errno_set(errno);
		return -1;
	}
	process_data->h         = INVALID_HANDLE_VALUE;
	process_data->wow64     = 0;
	process_data->active    = 0;

	/* Initialize the process structure itself. */
	if (pt_process_init(process) == -1) {
		free(process_data);
		return -1;
	}
	process->private_data   = process_data;
	process->p_op           = &pt_windows_process_operations;

	return 0;
}

int pt_windows_process_destroy(struct pt_process *process)
{
	HANDLE h;

	assert(process != NULL);
	assert(process->private_data != NULL);

	pt_symbol_manager_release(process);

	h = pt_windows_process_handle_get(process);
	if (HANDLE_VALID(h) && CloseHandle(h) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	free(process->private_data);
	process->private_data = NULL;

	return 0;
}

struct pt_process *pt_windows_process_new(void)
{
	struct pt_process *process;

	if ( (process = malloc(sizeof *process)) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	if (pt_windows_process_init(process) == -1) {
		free(process);
		return NULL;
	}

	return process;
}

int pt_windows_process_brk(struct pt_process *process)
{
	BOOL ret;

	/* The process is not in attached state. */
	if (process->state != PT_PROCESS_STATE_ATTACHED) {
		pt_error_internal_set(PT_ERROR_NOT_ATTACHED);
		return -1;
	}

#if 0	/* XXX: FIXME */
	/* We can't differentiate breakpoints... This is problematic. */
	if (process->remote_break_addr == PT_ADDRESS_NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}
#endif

	ret = DebugBreakProcess(pt_windows_process_handle_get(process));
	if (ret != 0)
		process->remote_break_count++;
	else
		pt_windows_error_winapi_set();

	return ret != 0 ? 0 : -1;
}

/* Open a process given its PID.
 *
 * We ensure that the process is in a consistent state, meaning all of its
 * threads suspended.  A small debug event loop is used for this during
 * attaching, which means that during the initial attach we may miss
 * some events.
 */
void pt_process_detach_bottom_(struct pt_process *process)
{
	struct pt_breakpoint_internal *bp;
	struct pt_thread *thread;

	if (process->state != PT_PROCESS_STATE_DETACH_BOTTOM)
		return;

	/* Remove all breakpoints. */
	pt_process_for_each_breakpoint_internal (process, bp)
		bp->breakpoint->b_op->process_remove(process, bp);

	/* Remove all internal single step flags. */
	pt_process_for_each_thread (process, thread)
		pt_thread_single_step_internal_remove(thread);

	process->state = PT_PROCESS_STATE_DETACH_TOP;
}

int pt_process_detach_top_(struct pt_core *core, struct pt_process *process)
{
	HANDLE debug_object_handle;
	HANDLE process_handle;

	if (process->state != PT_PROCESS_STATE_DETACH_TOP)
		return -1;

	/* Don't keep trying to detach if this function fails.  We unset
	 * the detach request here, then see if we really can detach the
	 * process or not.
	 */
	process->state = PT_PROCESS_STATE_DETACHED;

	/* In case Windows does not have DebugActiveProcessStop() or the
	 * function errors, we cannot detach the debugger.
	 */
	debug_object_handle = pt_windows_core_debug_object_handle_get(core);
	process_handle = pt_windows_process_handle_get(process);
	if (pt_windows_api_nt_remove_process_debug(process_handle, debug_object_handle) == -1)
		return -1;

	/* And delete the process. */
	pt_process_delete(process);

	return 0;
}

static int pt_process_resume_per_thread_(struct pt_process *process)
{
	struct pt_thread *thread;
	int ret = 0;

	pt_process_for_each_thread(process, thread)
		ret |= pt_thread_resume(thread);

	return ret;
}

/* XXX: racy if we call this when there is a running thread in the process
 * creating new threads.
 */
static int pt_process_suspend_per_thread_(struct pt_process *process)
{
	struct pt_thread *thread;
	int ret = 0;

	/* XXX: consider rollback when not all threads succeeded. */
	pt_process_for_each_thread(process, thread)
		ret |= pt_thread_suspend(thread);

	return ret;
}

int pt_windows_process_suspend(struct pt_process *process)
{
	HANDLE h;

	if (process->state != PT_PROCESS_STATE_ATTACHED) {
		pt_error_internal_set(PT_ERROR_NOT_ATTACHED);
		return -1;
	}

	h = pt_windows_process_handle_get(process);
	if (pt_windows_api_nt_suspend_process(h) == -1)
		return pt_process_suspend_per_thread_(process);

	return 0;
}

int pt_windows_process_resume(struct pt_process *process)
{
	HANDLE h;

	if (process->state != PT_PROCESS_STATE_ATTACHED) {
		pt_error_internal_set(PT_ERROR_NOT_ATTACHED);
		return -1;
	}

	h = pt_windows_process_handle_get(process);
	if (pt_windows_api_nt_resume_process(h) == -1)
		return pt_process_resume_per_thread_(process);

	return 0;
}

/* Write 'len' bytes from 'src' to the location 'dest' in the process
 * described in the ptrace_context 'p'.
 */
int
pt_windows_process_write(struct pt_process *process,
                         void *dest, const void *src, size_t len)
{
	HANDLE h;

	if (process->state != PT_PROCESS_STATE_ATTACHED) {
		pt_error_internal_set(PT_ERROR_NOT_ATTACHED);
		return -1;
	}

	h = pt_windows_process_handle_get(process);
	if (WriteProcessMemory(h, dest, src, len, NULL) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

/* Read 'len' bytes from 'src' in the process
 * described in the ptrace_context 'p' to the location 'dest'.
 */
ssize_t
pt_windows_process_read(struct pt_process *process,
                        void *dest, const void *src, size_t len)
{
	SIZE_T n;

	if (process->state != PT_PROCESS_STATE_ATTACHED) {
		pt_error_internal_set(PT_ERROR_NOT_ATTACHED);
		return -1;
	}

	if (len > SSIZE_MAX) {
		pt_error_internal_set(PT_ERROR_INVALID_ARG);
		return -1;
	}

	HANDLE h = pt_windows_process_handle_get(process);
	if (ReadProcessMemory(h, src, dest, len, &n) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	assert(n <= len);
	return n;
}

pt_address_t pt_process_export_find(struct pt_process *process, const char *symbol)
{
	pt_address_t ret = PT_ADDRESS_NULL;
	struct pt_module *module;
	const char *symbol_name;
	char *module_name, *p;

	if (process->state != PT_PROCESS_STATE_ATTACHED) {
		pt_error_internal_set(PT_ERROR_NOT_ATTACHED);
		return PT_ADDRESS_NULL;
	}

	if ( (p = strchr(symbol, '!')) != NULL) {
		symbol_name = strdup(p + 1);
		if (symbol_name == NULL) {
			pt_error_errno_set(errno);
			return PT_ADDRESS_NULL;
		}

		module_name = malloc(p - symbol + 1);
		if (module_name == NULL) {
			pt_error_errno_set(errno);
			free((void *)symbol_name);
			return PT_ADDRESS_NULL;
		}

		memcpy(module_name, symbol, p - symbol);
		module_name[p - symbol] = 0;
	} else {
		symbol_name = symbol;
		module_name = NULL;
	}

	pt_process_for_each_module (process, module) {
		/* Could happen, depending on whether we could get the proper
		 * security token.  If so, there's sadly nothing we can do but
		 * skip name based resolution for this module.  Anything else
		 * could lead to resolution of this particular symbol in a
		 * different module.
		 */
		if (module_name && module->name == NULL)
			continue;

		if (module_name && strcmp(module->name, module_name))
			continue;

		ret = pt_module_export_find(process, module, symbol_name);
		if (ret != PT_ADDRESS_NULL)
			break;
	}

	if (symbol_name != NULL && module_name != NULL) {
		free((void *)symbol_name);
		free(module_name);
	}

	if (ret == PT_ADDRESS_NULL)
		pt_error_internal_set(PT_ERROR_SYMBOL_UNKNOWN);

	return ret;
}

static int create_remote_thread_(struct pt_process *process,
                                 const void *handler, const void *cookie)
{
	HANDLE handle = pt_windows_process_handle_get(process);
	HANDLE th;
	DWORD id;

	/* Create the remote thread. */
	th = CreateRemoteThread(handle, NULL, 0, handler, (LPVOID)cookie, 0, &id);
	if (th == NULL) {
		pt_windows_error_winapi_set();
		return -1;
	}

	CloseHandle(th);
	return (int)id;
}

NTSTATUS WINAPI NtCreateThreadEx(
	PHANDLE hThread, ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes, HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	ULONG StackZeroBits,
	ULONG SizeOfStackCommit,
	ULONG SizeOfStackReserve,
	LPVOID lpBytesBuffer
);

struct create_thread_ex_struct_
{
	ULONG_PTR	size;
	ULONG_PTR	unknown1;
	ULONG_PTR	unknown2;
	ULONG_PTR	unknown3;
	ULONG_PTR	unknown4;
	ULONG_PTR	unknown5;
	ULONG_PTR	unknown6;
	ULONG_PTR	unknown7;
	ULONG_PTR	unknown8;
};

static int nt_create_thread_ex_(struct pt_process *process,
                                const void *handler, const void *cookie)
{
	HANDLE handle = pt_windows_process_handle_get(process);
	struct create_thread_ex_struct_ ctx;
	DWORD temp1 = 0, temp2 = 0;
	NTSTATUS ret;
	HANDLE th;
	DWORD id;

	/* If either of these functions are missing, this function is
	 * unsupported.  We pre-test to not create any unnecessary handles.
	 */
	if (pt_windows_api_have_nt_create_thread_ex() == 0 ||
	    pt_windows_api_have_get_thread_id() == 0) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	/* Set the thread creation context.  Most of this is magic. */
	ctx.size	= sizeof(ctx);
	ctx.unknown1	= 0x10003;
	ctx.unknown2	= sizeof(ULONG_PTR) * 2;
	ctx.unknown3	= (ULONG_PTR)&temp1;
	ctx.unknown4	= 0;
	ctx.unknown5	= 0x10004;
	ctx.unknown6	= sizeof(ULONG_PTR);
	ctx.unknown7	= (ULONG_PTR)&temp2;
	ctx.unknown8	= 0;

	/* Create the remote thread. */
	ret = pt_windows_api_nt_create_thread_ex(
		&th, 0x1FFFFF, 0, handle, (LPVOID)handler, (LPVOID)cookie,
		TRUE, 0, 0, 0, &ctx);
	if (ret == -1)
		return -1;

	/* If we can't get the thread id, terminate the thread.
	 * This is ugly, but there's nothing better we can do, and for
	 * portability reasons we do want this function to return a TID
	 * instead of a HANDLE.
	 */
	if ( (id = pt_windows_api_get_thread_id(th)) == 0) {
		TerminateThread(th, 0);
		CloseHandle(th);
		return -1;
	}

	/* We created a suspended thread. Resume it. */
	if (ResumeThread(th) == -1) {
		pt_windows_error_winapi_set();
		TerminateThread(th, 0);
		CloseHandle(th);
		return -1;
	}

	CloseHandle(th);
	return (int)id;
}

static inline int use_nt_create_thread_ex_(OSVERSIONINFOEX *version)
{
	if (version->dwMajorVersion != 6)
		return 0;

	if (version->dwMinorVersion == 0)
		return 1;

	if (version->dwMinorVersion == 1)
		return 1;

	return 0;
}

int pt_windows_process_thread_create(struct pt_process *process,
                                     const void *handler, const void *cookie)
{
	OSVERSIONINFOEX version;

	/* We determine the Windows version to determine the strategy we'll
	 * use for remote thread creation.  This is to ensure we can create
	 * threads in remote processes in a different terminal session.
	 */
	version.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if (GetVersionEx((LPOSVERSIONINFOA)&version) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	if (use_nt_create_thread_ex_(&version)) {
		pt_log("%s(): using NtCreateThreadEx()\n", __FUNCTION__);
		return nt_create_thread_ex_(process, handler, cookie);
	} else {
		pt_log("%s(): using CreateRemoteThread()\n", __FUNCTION__);
		return create_remote_thread_(process, handler, cookie);
	}
}

/* Allocate 'len' bytes somewhere in the process described in the
 * pt_process 'p'.
 */
void *pt_windows_process_malloc(struct pt_process *process, size_t len)
{
	HANDLE handle = pt_windows_process_handle_get(process);

	void *ret = VirtualAllocEx(
		handle,
		NULL,
		len,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (ret == NULL) {
		pt_windows_error_winapi_set();
		pt_log("%s(): VirtualAllocEx failed: %d\n", __FUNCTION__,
		       GetLastError());
		return NULL;
	}

	return ret;
}

int pt_windows_process_free(struct pt_process *process, const void *p)
{
	HANDLE handle = pt_windows_process_handle_get(process);

	if (VirtualFreeEx(handle, (void *)p, 0, MEM_RELEASE) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}
