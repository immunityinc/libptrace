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
 * core.c
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <windows.h>
#include <ntstatus.h>
#include <libptrace/pe.h>
#include <libptrace/log.h>
#include <libptrace/windows/error.h>
#include "core.h"
#include "module.h"
#include "process.h"
#include "pathname.h"
#include "shortcut.h"
#include "symbol.h"
#include "thread.h"
#include "token.h"
#include "wrappers/ntdbg.h"
#include "wrappers/ntdll.h"
#include "wrappers/psapi.h"
#include "wrappers/kernel32.h"
#include "../breakpoint.h"
#include "../compat.h"
#include "../factory.h"
#include "../message.h"
#include "../handle.h"

/* XXX: FACTOR OUT */
#include "win32util.h"
#if defined(__x86_64__)
  #include "process_x86_64.h"
  #include "thread_x86_64.h"
#elif defined(__i386__)
  #include "process_x86_32.h"
  #include "thread_x86_32.h"
#else
  #error "Unsupported architecture."
#endif

#define DBGUI_PID_CAST(x) ((DWORD)(uintptr_t)(x))
#define DBGUI_TID_CAST(x) ((DWORD)(uintptr_t)(x))
#define DBGUI_PID(x)      (DBGUI_PID_CAST((x)->AppClientId.UniqueProcess))
#define DBGUI_TID(x)      (DBGUI_TID_CAST((x)->AppClientId.UniqueThread))
#define HANDLE_VALID(h)   ((h) != NULL && (h) != INVALID_HANDLE_VALUE)

extern struct pt_core pt_core_main_;

struct pt_core_operations pt_windows_core_operations = {
        .destroy	= pt_windows_core_destroy,
	.attach		= pt_windows_core_process_attach,
	.detach		= pt_windows_core_process_detach,
	.exec		= pt_windows_core_exec,
	.execv		= pt_windows_core_execv,
	.event_wait	= pt_windows_core_event_wait
};

static int
pt_core_event_handle(struct pt_process *, PDBGUI_WAIT_STATE_CHANGE, int *);

static int
process_handlers_init_(struct pt_process *, struct pt_event_handlers *);

int pt_windows_core_init(struct pt_core *core)
{
	struct pt_windows_core_data *core_data;
	HANDLE debug_handle, event_handle;
	OBJECT_ATTRIBUTES oa;

	/* Initialize Windows specific data for this core. */
	core_data = malloc(sizeof(struct pt_windows_core_data));
	if (core_data == NULL) {
		pt_error_errno_set(errno);
		goto err;
	}
	core_data->debug_object_handle         = INVALID_HANDLE_VALUE;
	core_data->msg_queue_post_event_handle = INVALID_HANDLE_VALUE;

	/* Allocate an event handle. */
	event_handle = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (event_handle == NULL) {
		pt_windows_error_winapi_set();
		goto err_data;
	}

	/* Allocate a debug object handle. */
	InitializeObjectAttributes(&oa, 0, 0, 0, 0);
	debug_handle = pt_windows_api_nt_create_debug_object(DEBUG_ALL_ACCESS, &oa, 0);
	if (debug_handle == INVALID_HANDLE_VALUE)
		goto err_event;

	if (pt_core_init(core) == -1)
		goto err_debug;

	/* Windows core data. */
	core->private_data = core_data;
	core->c_op         = &pt_windows_core_operations;
	pt_windows_core_debug_object_handle_set(core, debug_handle);
	pt_windows_core_msg_queue_post_event_handle_set(core, event_handle);

	return 0;

err_debug:
	CloseHandle(debug_handle);
err_event:
	CloseHandle(event_handle);
err_data:
	free(core_data);
err:
	return -1;
}

int pt_windows_core_destroy(struct pt_core *core)
{
	HANDLE h;

	assert(core != NULL);
	assert(core->private_data != NULL);

	/* Close the debug object handle. */
	h = pt_windows_core_debug_object_handle_get(core);
	if (HANDLE_VALID(h) && CloseHandle(h) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	/* Close the message queue event handle. */
	h = pt_windows_core_msg_queue_post_event_handle_get(core);
	if (HANDLE_VALID(h) && CloseHandle(h) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	free(core->private_data);

	return 0;
}

struct pt_core *pt_windows_core_new(void)
{
	struct pt_core *core;

	if ( (core = malloc(sizeof *core)) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	if (pt_windows_core_init(core) == -1) {
		free(core);
		return NULL;
	}

	return core;
}

static int
pt_windows_core_event_handle_debug_(struct pt_core *core, HANDLE h)
{
	LARGE_INTEGER delay = { .QuadPart = 0 };
	DBGUI_WAIT_STATE_CHANGE event;
	struct pt_process *process;
	int status;

	/* Get a debug event without blocking. */
	pt_log("%s(): waiting for debug event\n", __FUNCTION__);

	if (pt_windows_api_nt_wait_for_debug_event(h, TRUE, &delay, &event) == -1)
		return -1;

	pt_log("%s(): received an event: %d\n", __FUNCTION__, event.NewState);

	/* We've drained all events. */
	if (event.NewState == DbgIdle)
		return 0;

	/* This should not be exposed to us.  Make sure on debug builds. */
	assert(event.NewState != DbgReplyPending);

	/* Find the pt_process by PID. */
	process = pt_core_process_find(core, DBGUI_PID(&event));
	if (process == NULL) {
		pt_log("%s(): unknown process id: %d\n", __FUNCTION__, DBGUI_PID(&event));
		return -1;
	}

	/* Handle the event for this process. */
	pt_core_event_handle(process, &event, &status);

	/* If we're quitting, mark the process to be detached. */
	if (core->quit == 1)
		pt_windows_core_process_detach(core, process);

	pt_process_detach_bottom_(process);

	pt_log("%s(): continue status is 0x%.8x\n", __FUNCTION__, status);
	pt_log("%s(): process state: %d\n", __FUNCTION__, process->state);

	/* XXX: error handling. */
	pt_windows_api_nt_debug_continue(h, &event.AppClientId, status);

	/* See if we can detach.  On success, the process is gone,
	 * so we break the loop.
	 */
	if (pt_process_detach_top_(core, process) == 0)
		return 0;

	if (process->state == PT_PROCESS_STATE_EXITED ||
	    process->state == PT_PROCESS_STATE_DETACHED)
		pt_process_delete(process);

	return 0;
}

static int
pt_windows_core_event_handle_queue_(struct pt_core *core)
{
	struct pt_message_status response;
	struct pt_message_storage msg;
        struct pt_process *process;

	while (pt_queue_recv(&core->msg_queue, &msg, sizeof msg) == 0) {
		switch (msg.msg.type) {
		case PT_MESSAGE_TYPE_ATTACH:
			response.handle = pt_core_process_attach(
				core,
				msg.msg_attach.pid,
				msg.msg_attach.handlers,
				msg.msg_attach.options
			);
			break;
		case PT_MESSAGE_TYPE_EXECV:
			response.handle = pt_core_execv(
				core,
				msg.msg_execv.filename,
				msg.msg_execv.argv,
				msg.msg_execv.handlers,
				msg.msg_execv.options
			);
			break;

		case PT_MESSAGE_TYPE_DETACH:
			process = pt_handle_process_find(core, msg.msg_detach.handle);
			if (process == NULL) {
				pt_error_internal_set(PT_ERROR_HANDLE);
				response.status = -1;
				break;
			}

			response.status = pt_core_process_detach(core, process);
			break;

		case PT_MESSAGE_TYPE_BREAK:
			process = pt_handle_process_find(core, msg.msg_detach.handle);
			if (process == NULL) {
				pt_error_internal_set(PT_ERROR_HANDLE);
				response.status = -1;
				break;
			}

			response.status = pt_core_process_break(core, process);
			break;
		}

		pt_queue_send(msg.msg.response, &response, sizeof response);
	}

	return 0;
}

int pt_windows_core_event_wait(struct pt_core *core)
{
	HANDLE handles[2];
	DWORD wait_ret;

	/* Get the debug object and event queue handles. */
	handles[0] = pt_windows_core_debug_object_handle_get(core);
	handles[1] = pt_windows_core_msg_queue_post_event_handle_get(core);

	/* Wait for either a message post event or a debug event. */
	wait_ret = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
	switch (wait_ret) {
	case WAIT_FAILED:
		pt_windows_error_winapi_set();
		return -1;

	case WAIT_TIMEOUT:
		/* XXX: Shouldn't happen.  Implement timers later. */
		assert(0);

	case WAIT_OBJECT_0:
		pt_windows_core_event_handle_debug_(core, handles[0]);
		break;

	case WAIT_OBJECT_0 + 1:
		pt_windows_core_event_handle_queue_(core);
		break;

	default:
		assert(0);
	}

	return 0;
}

struct pt_process *pt_windows_core_execv(
	struct pt_core *core,
	const utf8_t *pathname,
	utf8_t *const argv[],
	struct pt_event_handlers *handlers,
	int options)
{
	utf8_t command_line[32768] = "";
	int i = 0;

	/* Join the arguments together to form command_line. */
	if (argv && argv[i] != NULL) {
		sstrncat(command_line, argv[i], sizeof(command_line));

		while (argv[++i] != NULL) {
			sstrncat(command_line, " ", sizeof(command_line));
			sstrncat(command_line, argv[i], sizeof(command_line));
		}
	}

	return pt_windows_core_exec(core, pathname, command_line, handlers, options);
}

struct pt_process *pt_windows_core_exec(
	struct pt_core *core,
	const utf8_t *pathname,
	const utf8_t *arguments_,
	struct pt_event_handlers *handlers,
	int options)
{
	WCHAR *pathnamew_p = NULL, *argumentsw_p = NULL, *dirnamew_p = NULL;
	struct pt_file_native file = PT_FILE_NATIVE_INIT;
	uint16_t characteristics, machine;
	struct pt_process *process = NULL;
	int ret = -1, i, consolemode = 0;
	utf8_t *arguments, *dirname, *p;
	PROCESS_INFORMATION procinfo;
	struct shortcut shortcut;
	struct pe_context pex;
	STARTUPINFOW si;

	/* zero out memory here is mandatory */
	ZeroMemory(&si, sizeof(STARTUPINFOW));
	ZeroMemory(&procinfo, sizeof(PROCESS_INFORMATION));

	/* First check if we are dealing with a shortcut file by checking for
	 * .lnk extensions.
	 */
	shortcut_init(&shortcut);
	if (pathname_is_shortcut(pathname)) {
		if (shortcut_resolve(&shortcut, pathname) == -1) {
			pt_log("%s(): failed to resolve shortcut.\n",
			       __FUNCTION__);
			goto out;
		}

		pathname = shortcut.pathname;
	}

	file.filename = pathname;
	if (pe_open(&pex, (struct pt_file *)&file, PT_FILE_RDONLY) == -1) {
		pt_error_pe_set(pex.error);
		pt_log("%s(): pt_open() failed.\n", __FUNCTION__);
		goto out;
	}

	/* For now only work with i386 and x86-64. */
	machine = pe_image_header_get_machine(&pex);
	if (machine != PE_IMAGE_FILE_MACHINE_I386 &&
	    machine != PE_IMAGE_FILE_MACHINE_AMD64) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		pt_log("%s(): Unknown machine type.\n", __FUNCTION__);
		pe_close(&pex);
		goto out;
	}

	/* Check if the file is indeed executable. */
	characteristics = pe_image_header_get_characteristics(&pex);
	if ( (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		pt_log("%s(): Unknown characteristics.\n", __FUNCTION__);
		pe_close(&pex);
		goto out;
	}

	/* If we use the console subsystem, explicitly create a new console
	 * window in CreateProcess.
	 */
	if (pe_opt_hdr_subsystem_get(&pex) == IMAGE_SUBSYSTEM_WINDOWS_CUI)
		consolemode = CREATE_NEW_CONSOLE;

	pe_close(&pex);

	/* Initialize STARTUPINFOW. */
	si.cb = sizeof(STARTUPINFOW);
	si.lpReserved = NULL;
	si.lpDesktop = NULL;
	si.lpTitle = NULL;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_FORCEOFFFEEDBACK;
	si.wShowWindow = SW_SHOWDEFAULT;
	si.cbReserved2 = 0;
	si.lpReserved2 = NULL;

	if ( (p = strrchr(pathname, '\\')) != NULL) {
		/* We will try to derive the directory name from the pathname.
		 */
		if ( (dirname = strdup(pathname)) == NULL) {
			pt_error_errno_set(errno);
			goto out;
		}

		dirname[(intptr_t)(p - pathname)] = 0;
	} else {
		dirname = NULL;
	}

	/* According to MSDN arguments can be modified by CreateProcess.  As
	 * this function can have the arguments string constant, we copy it.
	 */
	arguments = (utf8_t *)arguments_;
	if (arguments && (arguments = strdup(arguments)) == NULL) {
		pt_error_errno_set(errno);
		goto out_free_dirname;
	}

	/* convert the all the arguments to call the W-flavor CreateProcessW() API */
	if (pathname != NULL) {
		ret = MultiByteToWideCharDyn(CP_UTF8, MB_ERR_INVALID_CHARS, pathname, -1, &pathnamew_p);
		if (!ret)
			goto out_free_arguments;
	}

	if (arguments != NULL) {
		ret = MultiByteToWideCharDyn(CP_UTF8, MB_ERR_INVALID_CHARS, arguments, -1, &argumentsw_p);
		if (!ret)
			goto out_free_pathnamew;
	}

	if (dirname != NULL) {
		ret = MultiByteToWideCharDyn(CP_UTF8, MB_ERR_INVALID_CHARS, dirname, -1, &dirnamew_p);
		if (!ret)
			goto out_free_argumentsw;
	}

	i = CreateProcessW(pathnamew_p, argumentsw_p, NULL, NULL, FALSE,
		CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED |
		NORMAL_PRIORITY_CLASS | consolemode,
		NULL, dirnamew_p, &si, &procinfo);

	if (i == FALSE) {
		pt_log("%s(): CreateProcess() failed: %d.\n",
		       __FUNCTION__, GetLastError());

		pt_windows_error_winapi_set();
		goto out_free_dirnamew;
	}

	/* Attach to it.  We do not use DEBUG_PROCESS because it will not let
	 * us use a custom debug port.
	 */
	pt_log("%s(): Process created with PID %d; attaching...\n",
	       __FUNCTION__, procinfo.dwProcessId);
	process = pt_windows_core_process_attach(core, procinfo.dwProcessId, handlers, options);
	if (process == NULL) {
		pt_log("%s(): Failed to attach.\n", __FUNCTION__);
		TerminateProcess(procinfo.hProcess, 0);
	}

	ResumeThread(procinfo.hThread);
	CloseHandle(procinfo.hThread);
	CloseHandle(procinfo.hProcess);

out_free_dirnamew:
	if (dirnamew_p != NULL)
		free(dirnamew_p);

out_free_argumentsw:
	if (argumentsw_p != NULL)
		free(argumentsw_p);

out_free_pathnamew:
	if (pathnamew_p != NULL)
		free(pathnamew_p);

out_free_arguments:
	if (arguments != NULL)
		free(arguments);

out_free_dirname:
	if (dirname != NULL)
		free(dirname);

out:
	if (shortcut.pathname != NULL)
		shortcut_destroy(&shortcut);

	return process;
}

int pt_windows_core_process_kill_on_exit_set(struct pt_core *core, int value)
{
	HANDLE h = pt_windows_core_debug_object_handle_get(core);
	ULONG state = !!value;
	int ret;

	ret = pt_windows_api_nt_set_information_debug_object(
		h,
		DebugObjectKillProcessOnExitInformation,
		&state,
		sizeof(state),
		NULL
	);

	return ret;
}

static int
process_handlers_init_(struct pt_process *process, struct pt_event_handlers *handlers)
{
	struct pt_event_handler *module_unload = NULL;
	struct pt_event_handler *thread_create = NULL;
	struct pt_event_handler *process_exit = NULL;
	struct pt_event_handler *thread_exit = NULL;
	struct pt_event_handler *module_load = NULL;
	struct pt_event_handler *attached = NULL;

	if (handlers->attached.handler != NULL) {
		attached = pt_event_handler_stack_push(
			&process->handlers.attached,
			(pt_event_handler_t)handlers->attached.handler,
			handlers->attached.cookie
		);
	        if (attached == NULL)
			goto err;
	}

	if (handlers->process_exit.handler != NULL) {
		process_exit = pt_event_handler_stack_push(
			&process->handlers.process_exit,
			(pt_event_handler_t)handlers->process_exit.handler,
			handlers->process_exit.cookie
		);
		if (process_exit == NULL)
			goto err_attached;
	}

	if (handlers->thread_create.handler != NULL) {
		thread_create = pt_event_handler_stack_push(
			&process->handlers.thread_create,
			(pt_event_handler_t)handlers->thread_create.handler,
			handlers->thread_create.cookie
		);
		if (thread_create == NULL)
			goto err_process_exit;
	}

	if (handlers->thread_exit.handler != NULL) {
		thread_exit = pt_event_handler_stack_push(
			&process->handlers.thread_exit,
			(pt_event_handler_t)handlers->thread_exit.handler,
			handlers->thread_exit.cookie
		);
		if (thread_exit == NULL)
			goto err_thread_create;
	}

	if (handlers->module_load.handler != NULL) {
		module_load = pt_event_handler_stack_push(
			&process->handlers.module_load,
			(pt_event_handler_t)handlers->module_load.handler,
			handlers->module_load.cookie
		);
		if (module_load == NULL)
			goto err_thread_exit;
	}

	if (handlers->module_unload.handler != NULL) {
		module_unload = pt_event_handler_stack_push(
			&process->handlers.module_unload,
			(pt_event_handler_t)handlers->module_unload.handler,
			handlers->module_unload.cookie
		);
		if (module_unload == NULL)
			goto err_module_load;
	}

	process->handlers.breakpoint          = handlers->breakpoint;
	process->handlers.remote_break        = handlers->remote_break;
	process->handlers.single_step         = handlers->single_step;
	process->handlers.segfault            = handlers->segfault;
	process->handlers.illegal_instruction = handlers->illegal_instruction;
	process->handlers.divide_by_zero      = handlers->divide_by_zero;
	process->handlers.priv_instruction    = handlers->priv_instruction;
	process->handlers.unknown_exception   = handlers->unknown_exception;
	process->handlers.x86_dr              = handlers->x86_dr;

	return 0;

err_module_load:
	if (module_load != NULL)
		pt_event_handler_destroy(module_load);
err_thread_exit:
	if (thread_exit != NULL)
		pt_event_handler_destroy(thread_exit);
err_thread_create:
	if (thread_create != NULL)
		pt_event_handler_destroy(thread_create);
err_process_exit:
	if (process_exit != NULL)
		pt_event_handler_destroy(process_exit);
err_attached:
	if (attached != NULL)
		pt_event_handler_destroy(attached);
err:
	return -1;
}

struct pt_process *
pt_windows_core_process_attach(
	struct pt_core *core,
	pt_pid_t pid,
	struct pt_event_handlers *handlers,
	int options)
{
	DWORD access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                       PROCESS_VM_WRITE | PROCESS_VM_READ |
                       PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION;
	HANDLE h = pt_windows_core_debug_object_handle_get(core);
	struct pt_process *process;
	FILETIME ct, et, kt, ut;
	HANDLE process_handle;
	BOOL wow64 = FALSE;
	BOOL ret;

	/* Set debug privileges.  In case of failure, we try to continue
	 * anyway, and leave permission access tests to the other functions.
	 */
	token_add_privilege(SE_DEBUG_NAME);

	if ( (process_handle = OpenProcess(access, FALSE, pid)) == NULL) {
		pt_log("%s(): OpenProcess failed.\n", __FUNCTION__);
		pt_windows_error_winapi_set();
		goto err;
	}

#if __x86_64__
	/* See if we're dealing with a WoW64 process. */
	if (pt_windows_api_is_wow64_process(process_handle, &wow64) == -1)
		goto err_handle;
#endif

	pt_log("%s() WoW64 process: %s\n", __FUNCTION__,
		wow64 == TRUE ? "true" : "false");

	/* Create the new process structure. */
	if (wow64 == TRUE)
		process = pt_factory_process_new(PT_FACTORY_PROCESS_WINDOWS_WOW64);
	else
		process = pt_factory_process_new(PT_FACTORY_PROCESS_WINDOWS);

	if (process == NULL)
		goto err_handle;

	/* Initialize the handlers and options. */
	if (process_handlers_init_(process, handlers) == -1)
		goto err_process;

	process->options = options;

	/* Enable a debugger to attach to the process and debug it. */
	if (pt_windows_api_nt_debug_active_process(process_handle, h) == -1) {
		pt_log("%s(): failed to debug active process.\n", __FUNCTION__);
		goto err_process;
	}

	/* Break in remotely. */
	if (DebugBreakProcess(process_handle) == 0) {
		pt_windows_error_winapi_set();
		goto err_detach;
	}

	/* Partially initialize the process structure. */
	process->core = core;
	process->pid  = pid;
	pt_windows_process_active_set(process, 1);	/* Active attach */

	/* Initialize the process creation time used for handles. */
	ret = pt_windows_api_get_process_times(process_handle, &ct, &et, &kt, &ut);
	if (ret == -1)
		goto err_detach;

	process->creation_time = ct.dwHighDateTime;
	process->creation_time <<= 32;
	process->creation_time |= ct.dwLowDateTime;

	/* Insert the process into the tree.  If the insert fails, the process
	 * already exists in the tree.  This shouldn't happen under normal
	 * circumstances, as the tree is sorted by PID, and exiting processes
	 * are automatically removed.
	 */
	if (avl_tree_insert(&core->process_tree, &process->avl_node) != 0) {
		pt_error_internal_set(PT_ERROR_EXISTS);
		goto err_detach;
	}

	/* We're done with the handle.  We'll get a new one through the
	 * debug events, and will use that from here on. */
	CloseHandle(process_handle);

	pt_log("%s(): attached to PID %d\n", __FUNCTION__, process->pid);

	return process;

err_detach:
	pt_windows_api_nt_remove_process_debug(process_handle, h);
err_process:
	pt_process_delete(process);
err_handle:
	CloseHandle(process_handle);
err:
	return NULL;
}

int pt_windows_core_process_detach(struct pt_core *core, struct pt_process *process)
{
	if (process->state != PT_PROCESS_STATE_ATTACHED) {
		pt_error_internal_set(PT_ERROR_NOT_ATTACHED);
		return -1;
	}

	process->state = PT_PROCESS_STATE_DETACH_BOTTOM;

	return 0;
}

static inline utf8_t *
get_dll_nt_name_by_map_(struct pt_process *process, struct pt_module *module)
{
	HANDLE handle = pt_windows_process_handle_get(process);
	return pt_windows_api_get_mapped_filename(handle, (void *)module->base);
}

static inline utf8_t *
get_dll_name_by_handle_(struct pt_process *process, struct pt_module *module)
{
	HANDLE handle = pt_windows_module_handle_get(module);
	return pt_windows_api_nt_query_object_name(handle);
}

static utf8_t *
get_dll_name_(struct pt_process *process, struct pt_module *module)
{
	utf8_t *name_nt, *name_dos;

	name_nt = get_dll_nt_name_by_map_(process, module);
	if (name_nt == NULL) {
		pt_log("%s(): get_dll_nt_name_by_map_() failed: %s.\n",
			__FUNCTION__, pt_error_strerror());

		name_nt = get_dll_name_by_handle_(process, module);
		if (name_nt == NULL) {
			pt_log("%s(): get_dll_name_by_handle_() failed: %s.\n",
				__FUNCTION__, pt_error_strerror());
			return NULL;
		}
	}

	pt_log("%s(): NT name: %s\n", __FUNCTION__, name_nt);

	name_dos = pathname_nt_to_dos(name_nt);
	if (name_dos == NULL) {
		pt_log("%s(): failed to convert NT pathname %s to MS-DOS.\n",
		       __FUNCTION__, name_nt);
	}

	free(name_nt);

	return name_dos;
}

static struct pt_thread *thread_new_(struct pt_process *process)
{
#ifdef __x86_64__
	if (pt_windows_process_wow64_get(process))
		return pt_windows_wow64_thread_new();
#endif

	return pt_windows_thread_new();
}

static inline void symbol_manager_install_(struct pt_process *process)
{
	if ( !(process->options & PT_CORE_OPTION_SYMBOL_MANAGER))
		return;

	if (pt_symbol_manager_install(process, &windows_symbol_op) < 0)
		pt_log("%s(): Unable to initialize symbol manager\n", __FUNCTION__);
}

static int handle_create_process_(
	struct pt_process *process,
	PDBGUI_WAIT_STATE_CHANGE event)
{
	HANDLE process_handle, thread_handle, module_handle;
	void *module_base, *thread_start;
	DWORD process_id, thread_id;
	struct pt_module *module;
	struct pt_thread *thread;

	process->state = PT_PROCESS_STATE_CREATED;

	/* Get the information we need in shorthand. */
	process_id     = DBGUI_PID(event);
	process_handle = event->StateInfo.CreateProcessInfo.HandleToProcess;
	thread_id      = DBGUI_TID(event);
	thread_handle  = event->StateInfo.CreateProcessInfo.HandleToThread;
	thread_start   = event->StateInfo.CreateProcessInfo.NewProcess.InitialThread.StartAddress;
	module_handle  = event->StateInfo.CreateProcessInfo.NewProcess.FileHandle;
	module_base    = event->StateInfo.CreateProcessInfo.NewProcess.BaseOfImage;

	/* NOTE:  Windows does not dispatch a CREATE_THREAD_DEBUG_EVENT
	 * for the initial thread in a process.  We add it to the thread
	 * list of the process right here.
	 */
	if ( (thread = thread_new_(process)) == NULL)
		goto err_handle;

	/* Initialize the thread structure for this process. */
	pt_windows_thread_handle_set(thread, thread_handle);
	thread->tid            = thread_id;
	thread->process        = process;
	thread->start          = thread_start;
	thread->state          = THREAD_SUSPENDED;
	thread->flags          = THREAD_FLAG_MAIN;

	/* Module structure for main module. */
	if ( (module = pt_windows_module_new()) == NULL)
		goto err_thread;

	/* Initialize the module structure for this process. */
	pt_windows_module_handle_set(module, module_handle);
	module->base         = (pt_address_t)module_base;
	module->pathname     = get_dll_name_(process, module);
	module->process      = process;

	/* Now we have the pathname, isolate the module name. */
	if (module->pathname != NULL)
		module->name = pathname_filename_base_get(module->pathname);

	/* Initialize the process structure itself. */
	avl_tree_insert(&process->threads, &thread->avl_node);
	list_add(&module->process_entry, &process->modules);

	process->pid = process_id;
	pt_windows_process_handle_set(process, process_handle);

	/* initialize symbol manager */
	symbol_manager_install_(process);

	/* setup module symbol env */
	if (module->pathname != NULL && process->smgr && process->smgr->sop &&
	    process->smgr->sop->module_attach) {
		int err;

		pt_log("%s(): adding new symbol for module module: %s\n", __FUNCTION__, module->pathname);
		err = process->smgr->sop->module_attach(module);
		if (err < 0) {
			/* just log symbol loading failure */
			pt_log("%s(): adding new symbol for module module: %s FAILED! error: %s\n",
			       __FUNCTION__, module->pathname, pt_error_strerror());
		}
	}

	/* Track the main thread + module separately for efficiency. */
	process->main_thread = thread;
	process->main_module = module;

	/* Bugfix:  Windows XP SP1 attach will have DR6 set to 0xA005
	 * instead of 0.  This messes up breakpoint single-stepping
	 * later on, so we zero it out.
	 */
	/* XXX HACK XXX THIS NEEDS TO BE ARCH INDEPENDENT LATER. */
#if defined(__x86_64__)
	if (pt_windows_thread_x86_64_set_dr6(thread, 0) == -1) {
		pt_log("%s(): pt_windows_thread_x86_set_dr6() failed.\n", __FUNCTION__);

		goto err_module;
	}
#elif defined(__i386__)
	if (pt_windows_thread_x86_32_set_dr6(thread, 0) == -1) {
		pt_log("%s(): pt_windows_thread_x86_set_dr6() failed.\n", __FUNCTION__);
		goto err_module;
	}
#else
  #error "Unsupported architecture."
#endif

	pt_log("Created pt_process for PID %u with main TID %u\n",
	       process->pid, thread->tid);

	return 0;

err_module:
	pt_module_delete(module);
err_thread:
	pt_thread_delete(thread);
err_handle:
	if (module_handle != NULL)
		CloseHandle(module_handle);

	return -1;
}

static void handle_create_thread_(
	struct pt_process *process,
	PDBGUI_WAIT_STATE_CHANGE event)
{
	struct pt_event_thread_create ev = { NULL, 1, NULL };
	struct pt_thread *thread;
	HANDLE thread_handle;

	thread_handle = event->StateInfo.CreateThread.HandleToThread;
	if (!HANDLE_VALID(thread_handle)) {
		pt_windows_error_winapi_set_value(ERROR_INVALID_HANDLE);
		goto out;
	}

	/* Allocate space for the pt_thread descriptor. */
	if ( (thread = thread_new_(process)) == NULL)
		goto out;

	/* Initialize and link in the thread. */
	pt_windows_thread_handle_set(thread, thread_handle);
	thread->tid            = DBGUI_TID(event);
	thread->process        = process;
	thread->state          = THREAD_SUSPENDED;
	thread->flags          = THREAD_FLAG_NONE;
	avl_tree_insert(&process->threads, &thread->avl_node);

	ev.error  = 0;
	ev.thread = thread;
out:
	pt_event_handler_stack_call(&process->handlers.thread_create,
	                            (struct pt_event *)&ev);
}

static void handle_exit_process_(
	struct pt_process *process,
	PDBGUI_WAIT_STATE_CHANGE event)
{
	struct pt_event_process_exit ev;

	process->state = PT_PROCESS_STATE_EXITED;

	/* Invoke callback handlers. */
	ev.process  = process;
	ev.exitcode = event->StateInfo.ExitProcess.ExitStatus;
	pt_event_handler_stack_call(&process->handlers.process_exit,
	                            (struct pt_event *)&ev);
}

static void handle_exit_thread_(
	struct pt_process *process,
	PDBGUI_WAIT_STATE_CHANGE event)
{
	struct pt_event_thread_exit ev = { NULL, 0, NULL, 0 };
	DWORD tid = DBGUI_TID(event);
	struct pt_thread *thread;

	/* Find the thread in the process list and reap it. */
	thread = pt_process_thread_find(process, tid);
	if (thread == NULL) {
		pt_log("%s: thread %d does not belong to process %d.\n",
		       __FUNCTION__, tid, process->pid);
		ev.error = 1;
		pt_error_internal_set(PT_ERROR_NOT_FOUND);
	} else {
		ev.thread   = thread;
		ev.exitcode = event->StateInfo.ExitThread.ExitStatus;
	}

	pt_event_handler_stack_call(&process->handlers.thread_exit,
	                            (struct pt_event *)&ev);

	if (thread != NULL)
		pt_thread_delete(thread);
}

static void handle_load_dll_(
	struct pt_process *process,
	PDBGUI_WAIT_STATE_CHANGE event)
{
	struct pt_event_module_load ev = { NULL, 0, NULL };
	HANDLE h = event->StateInfo.LoadDll.FileHandle;
	struct pt_module *module;

	/* Allocate a new module descriptor. */
	if ( (module = pt_windows_module_new()) == NULL) {
		if (h != NULL)
			CloseHandle(h);
		ev.error = 1;
		goto out;
	}

	/* Link in the module */
	pt_windows_module_handle_set(module, h);
	module->base     = (pt_address_t)event->StateInfo.LoadDll.BaseOfDll;
	module->pathname = get_dll_name_(process, module);

	/* Now we have the pathname, isolate the module name. */
	if (module->pathname != NULL) {
		module->name = pathname_filename_base_get(module->pathname);
		if (module->name == NULL) {
			pt_module_delete(module);
			ev.error = 1;
			goto out;
		}
	}

	module->process = process;
	list_add(&module->process_entry, &process->modules);

	/* setup module symbol env -> before event handling ! */
	if (process->smgr && process->smgr->sop &&
	    process->smgr->sop->module_attach) {
		int err;
		pt_log("%s(): adding new symbol for module module: %s\n", __FUNCTION__, module->pathname);
		err = process->smgr->sop->module_attach(module);
		if (err < 0) {
			/* just log symbol loading failure */
			pt_log("%s(): adding new symbol for module module: %s FAILED! error: %s\n",
			       __FUNCTION__, module->pathname, pt_error_strerror());
		}
	}

	pt_log("%s(): Loaded module %s\n", __FUNCTION__, module->pathname);

	/* Invoke the callback handlers. */
	ev.module = module;
out:
	pt_event_handler_stack_call(
		&process->handlers.module_load,
		(struct pt_event *)&ev
	);
}

static struct pt_module *
find_module_(struct pt_process *process, void *base)
{
        struct pt_module *module;

        /* XXX: pt_address_t */
        pt_process_for_each_module (process, module) {
                if (module->base == (pt_address_t)base)
                        return module;
        }

        return NULL;
}

static void handle_unload_dll_(
	struct pt_process *process,
	PDBGUI_WAIT_STATE_CHANGE event)
{
	struct pt_event_module_unload ev = { NULL, 0, NULL };
	struct pt_module *module;

	/* See if the module exists in our module list. */
	module = find_module_(process, event->StateInfo.UnloadDll.BaseAddress);
	if (module == NULL) {
		ev.error = 1;
		pt_error_internal_set(PT_ERROR_NOT_FOUND);
	} else {
		ev.module = module;
		pt_log("%s(): Unloaded module %s\n", __FUNCTION__,
		       module->pathname);
	}

	pt_event_handler_stack_call(
		&process->handlers.module_unload,
		(struct pt_event *)&ev
	);

	if (module != NULL)
		pt_module_delete(module);
}

static const char *exception_code_to_string_(DWORD code)
{
	switch(code) {
	case EXCEPTION_ACCESS_VIOLATION:
		return "EXCEPTION_ACCESS_VIOLATION";
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
	case EXCEPTION_BREAKPOINT:
		return "EXCEPTION_BREAKPOINT";
	case EXCEPTION_DATATYPE_MISALIGNMENT:
		return "EXCEPTION_DATATYPE_MISALIGNMENT";
	case EXCEPTION_FLT_DENORMAL_OPERAND:
		return "EXCEPTION_FLT_DENORMAL_OPERAND";
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
	case EXCEPTION_FLT_INEXACT_RESULT:
		return "EXCEPTION_FLT_INEXACT_RESULT";
	case EXCEPTION_FLT_INVALID_OPERATION:
		return "EXCEPTION_FLT_INVALID_OPERATION";
	case EXCEPTION_FLT_OVERFLOW:
		return "EXCEPTION_FLT_OVERFLOW";
	case EXCEPTION_FLT_STACK_CHECK:
		return "EXCEPTION_FLT_STACK_CHECK";
	case EXCEPTION_FLT_UNDERFLOW:
		return "EXCEPTION_FLT_UNDERFLOW";
	case EXCEPTION_ILLEGAL_INSTRUCTION:
		return "EXCEPTION_ILLEGAL_INSTRUCTION";
	case EXCEPTION_IN_PAGE_ERROR:
		return "EXCEPTION_IN_PAGE_ERROR";
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		return "EXCEPTION_INT_DIVIDE_BY_ZERO";
	case EXCEPTION_INT_OVERFLOW:
		return "EXCEPTION_INT_OVERFLOW";
	case EXCEPTION_INVALID_DISPOSITION:
		return "EXCEPTION_INVALID_DISPOSITION";
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:
		return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
	case EXCEPTION_PRIV_INSTRUCTION:
		return "EXCEPTION_PRIV_INSTRUCTION";
	case EXCEPTION_SINGLE_STEP:
		return "EXCEPTION_SINGLE_STEP";
	case EXCEPTION_STACK_OVERFLOW:
		return "EXCEPTION_STACK_OVERFLOW";
	case EXCEPTION_INVALID_HANDLE:
		return "EXCEPTION_INVALID_HANDLE";
	case STATUS_WX86_BREAKPOINT:
		return "EXCEPTION_WX86_BREAKPOINT";
	case STATUS_WX86_SINGLE_STEP:
		return "EXCEPTION_WX86_SINGLE_STEP";
	case 0xC000001E:
		return "EXCEPTION_INVALID_LOCK_SEQUENCE";
	case 0x406d1388:
		return "EXCEPTION_SET_THREAD_NAME";
	case DBG_PRINTEXCEPTION_C:
		return "DBG_PRINTEXCEPTION_C";
	}

	return "Unknown exception";
}

static inline void
trace_exception_(struct pt_process *process, LPEXCEPTION_RECORD exception)
{
	pt_log("%s(): EXCEPTION_DEBUG_EVENT: %s (%#08x) %#08x\n",
	           __FUNCTION__,
	           exception_code_to_string_(exception->ExceptionCode),
	           exception->ExceptionCode, exception->ExceptionAddress);

	switch (exception->ExceptionCode) {
	case EXCEPTION_ACCESS_VIOLATION:
		pt_log("    RWFlag : %d\n"
		       "    Address: %#08x\n",
		       exception->ExceptionInformation[0],
		       exception->ExceptionInformation[1]
		);
		break;
	}
}

static inline void
trace_output_debug_string_ansi_(struct pt_process *process,
                                LPEXCEPTION_RECORD exception)
{
	uint16_t data_length = exception->ExceptionInformation[0];
	char data[data_length];
	ssize_t ret;

	ret = pt_process_read(
		process,
		data,
		(pt_address_t)exception->ExceptionInformation[1],
		data_length
	);

	/* XXX: no codepage support here; see if we can determine the
	 * ANSI codepage of the remote process/thread such as
	 * CP_THREAD_ACP somehow later.
	 */

	if (ret == data_length)
		pt_log("%s(): OUTPUT_DEBUG_STRING_EVENT: %s\n", __FUNCTION__, data);
	else
		pt_log("%s(): OUTPUT_DEBUG_STRING_EVENT (%p)\n", __FUNCTION__,
		       exception->ExceptionInformation[1]);
}

static inline int
exception_filter_(struct pt_process *process, int code, int first_chance)
{
	/* First chance exceptions are let through. */
	if (first_chance != 0)
		return 0;

	/* Invalid handles always need 2nd chance handling. */
	if (code == EXCEPTION_INVALID_HANDLE)
		return 0;

	/* Debug string exceptions always need 2nd chance handling. */
	if (code == DBG_PRINTEXCEPTION_C)
		return 0;

	/* Second chance handling was requested for the process. */
	if (process->options & PT_CORE_OPTION_EVENT_SECOND_CHANCE)
		return 0;

	return 1;
}

/* The default behaviour of the debugger is to forward all exceptions to
 * the debuggee if there are no handlers present.
 *
 * If there is a handler present, the handler will return an integer
 * either equal to PT_EVENT_FORWARD in order to delegate the
 * exception to the debuggee, or PT_EVENT_DROP, which does not
 * delegate the exception.
 */
static int
handle_exception_(struct pt_process *process, PDBGUI_WAIT_STATE_CHANGE event)
{
	LPEXCEPTION_RECORD exception = &event->StateInfo.Exception.ExceptionRecord;
	ULONG first_chance = event->StateInfo.Exception.FirstChance;
	int status = PT_EVENT_FORWARD;
	struct pt_thread *thread;

	trace_exception_(process, exception);

	/* See if we have the thread that caused the exception in our list.
	 * If not, something weird is going on, and we just forward the
	 * exception.
	 */
	thread = pt_process_thread_find(process, DBGUI_TID(event));
	if (thread == NULL)
		return DBG_EXCEPTION_NOT_HANDLED;

	/* See if support for second chance exceptions has been requested. */
	if (exception_filter_(process, exception->ExceptionCode, first_chance))
		return DBG_EXCEPTION_NOT_HANDLED;

	switch (exception->ExceptionCode) {
	case STATUS_WX86_BREAKPOINT:
	case EXCEPTION_BREAKPOINT: {
		struct pt_event_breakpoint ev;

		/* If we have not yet seen the breakpoint exception triggered
		 * by attaching the debugger, deal with it now.  We will not
		 * call the bottom handler in this case, but rather call the
		 * 'attached' event handler.
		 */
		if ( !(process->state & PT_PROCESS_STATE_ATTACHED)) {
			struct pt_event_attached ev;

			/* For WoW64 processes we hit the system breakpoint
			 * twice.  Once in 64-bit mode, and once in 32-bit
			 * mode.  We handle this here by ignoring the 64-bit one.
			 */
			if (pt_windows_process_wow64_get(process) &&
			    pt_windows_process_active_get(process) == 0 &&
			    exception->ExceptionCode == EXCEPTION_BREAKPOINT) {
				status = PT_EVENT_DROP;
				break;
			}

#if 0			/* XXX FIXME */
			/* Look up DbgBreakPoint now. */
			process->remote_break_addr =
				pt_process_export_find(process, "ntdll!DbgBreakPoint");
#endif

			process->state = PT_PROCESS_STATE_ATTACHED;

			status = PT_EVENT_DROP;

			pt_log("%s(): ntdll!DbgBreakPoint at 0x%.8x\n", __FUNCTION__,
				process->remote_break_addr);

			/* Setup the attached event structure. */
			ev.cookie  = NULL;
			ev.error   = 0;
			ev.process = process;

			/* Call the event handlers for the attached event. */
			pt_event_handler_stack_call(
				&process->handlers.attached,
				(struct pt_event *)&ev
			);
		} else {
			/* Invoke the bottom handler. */
			ev.address = (pt_address_t)exception->ExceptionAddress;
			ev.thread  = thread;
			ev.chance  = !first_chance;

			/* If we have a remote_break_address breakpoint, this
			 * is a breakin requested by a remote thread.  We call
			 * a separate handler for this.
			 */
//			if (ev.address == process->remote_break_addr) {
				if (process->remote_break_count != 0) {
					process->remote_break_count--;

					if (process->handlers.remote_break != NULL)
						status = process->handlers.remote_break(&ev);
					else
						status = PT_EVENT_FORWARD;
					break;
				}
//			}

			status = pt_breakpoint_handler(thread, &ev);
		}
		break;
	}
	/* XXX: handle second chance. */
	case STATUS_WX86_SINGLE_STEP:
	case EXCEPTION_SINGLE_STEP:
#if defined(__x86_64__)
		status = windows_x86_64_handle_exception_single_step_(process, thread, exception);
#elif defined(__i386__)
		status = windows_x86_32_handle_exception_single_step_(process, thread, exception);
#else
  #error "Unsupport architecture."
#endif
		break;
	case EXCEPTION_ACCESS_VIOLATION:
		if (process->handlers.segfault != NULL) {
			struct pt_event_segfault ev;

			ev.address       = exception->ExceptionAddress;
			ev.fault_address = (void *)
			                   exception->ExceptionInformation[1];
			ev.thread        = thread;
			ev.chance        = !first_chance;

			status = process->handlers.segfault(&ev);
		}
		break;

	/* SetThreadName() exception. */
	case 0x406d1388:
		/* XXX: support saving thread names later. */
		break;

	case EXCEPTION_ILLEGAL_INSTRUCTION:
	case 0xC000001E:	/* STATUS_INVALID_LOCK_SEQUENCE */
		if (process->handlers.illegal_instruction != NULL) {
			struct pt_event_illegal_instruction ev;

			ev.address = exception->ExceptionAddress;
			ev.thread  = thread;
			ev.chance  = !first_chance;

			status = process->handlers.illegal_instruction(&ev);
		}
		break;

	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		if (process->handlers.divide_by_zero != NULL) {
			struct pt_event_divide_by_zero ev;

			ev.address = exception->ExceptionAddress;
			ev.thread  = thread;
			ev.chance  = !first_chance;

			status = process->handlers.divide_by_zero(&ev);
		}
		break;

	case EXCEPTION_PRIV_INSTRUCTION:
		if (process->handlers.priv_instruction != NULL) {
			struct pt_event_priv_instruction ev;

			ev.address = exception->ExceptionAddress;
			ev.thread  = thread;
			ev.chance  = !first_chance;

			status = process->handlers.priv_instruction(&ev);
		}
		break;

	/* Invalid handles used in CloseHandle() can trigger exceptions that
	 * otherwise would not occur.  When there is a registered interest in
	 * these exceptions we will let the interest decide what happens.
	 * Absent an interest, we forward on first chance, and drop on second.
	 *
	 * XXX: for now interests cannot be registered for this exception.
	 */
	case EXCEPTION_INVALID_HANDLE:
		if (first_chance != 0)
			status = PT_EVENT_FORWARD;
		else
			status = PT_EVENT_DROP;
		break;

	case DBG_PRINTEXCEPTION_C:
		trace_output_debug_string_ansi_(process, exception);
		if (first_chance != 0)
			status = PT_EVENT_FORWARD;
		else
			status = PT_EVENT_DROP;
		break;
	default:
		if (process->handlers.unknown_exception != NULL) {
			pt_log("%s(): handling unknown exception\n", __FUNCTION__);
			struct pt_event_unknown_exception ev;

			ev.number  = exception->ExceptionCode;
			ev.address = exception->ExceptionAddress;
			ev.thread  = thread;
			ev.chance  = !first_chance;

			status = process->handlers.unknown_exception(&ev);
		}
		break;
	}

	if (status == PT_EVENT_FORWARD)
		status = DBG_EXCEPTION_NOT_HANDLED;
	else if (status == PT_EVENT_DROP)
		status = DBG_CONTINUE;
	else
		abort();

	return status;
}

static int pt_core_event_handle(
	struct pt_process *process,
	PDBGUI_WAIT_STATE_CHANGE event,
	int *status)
{
	struct pt_thread *thread;
	int ret = 0;

        *status = DBG_EXCEPTION_NOT_HANDLED;

	if (process->state != PT_PROCESS_STATE_INIT) {
		DWORD thread_id = DBGUI_TID(event);

		thread = pt_process_thread_find(process, thread_id);
		if (event->NewState != DbgCreateThreadStateChange) {
			if (thread == NULL) {
				pt_log("%s: unknown thread id: %d\n", __FUNCTION__, thread_id);
				return -1;
			}
		}
	}

	switch (event->NewState) {
	case DbgCreateThreadStateChange:
		pt_log("%s: DbgCreateThreadStateChange\n", __FUNCTION__);
		handle_create_thread_(process, event);
		break;
	case DbgCreateProcessStateChange:
		pt_log("%s: DbgCreateProcessStateChange\n", __FUNCTION__);
		handle_create_process_(process, event);
		break;
	case DbgExitThreadStateChange:
		pt_log("%s: DbgExitThreadStateChange\n", __FUNCTION__);
		handle_exit_thread_(process, event);
		break;
	case DbgExitProcessStateChange:
		pt_log("%s: DbgExitProcessStateChange\n", __FUNCTION__);
		handle_exit_process_(process, event);
		break;
	case DbgExceptionStateChange:
		pt_log("%s: DbgExceptionStateChange\n", __FUNCTION__);
		if (0)
	case DbgBreakpointStateChange:
		pt_log("%s: DbgBreakpointStateChange\n", __FUNCTION__);
		if (0)
	case DbgSingleStepStateChange:
		pt_log("%s: DbgSingleStepStateChange\n", __FUNCTION__);
		*status = handle_exception_(process, event);
		break;
	case DbgLoadDllStateChange:
		pt_log("%s: DbgLoadDllStateChange\n", __FUNCTION__);
		handle_load_dll_(process, event);
		break;
	case DbgUnloadDllStateChange:
		pt_log("%s: DbgUnloadDllStateChange\n", __FUNCTION__);
		handle_unload_dll_(process, event);
		break;
        default:
		pt_log("%s: Unknown debug event: %d\n", __FUNCTION__, event->NewState);
                ret = -1;
                break;
	}

	/* We are close to resuming the debuggee through ContinueDebugEvent()
	 * At this point, we want to reestablish the list of persistent
	 * breakpoints.  The way we do this is by single stepping over the
	 * replaced breakpoint and then patching back the soft break.
	 */
	pt_process_for_each_thread (process, thread) {
		if (thread->breakpoint_restore != NULL) {
			pt_log("%s(): breakpoint_restore set.  Single stepping\n", __FUNCTION__);

			if (pt_thread_single_step_internal_set(thread) == -1)
				pt_log("Failed to set single-step flag: %s\n",
				       pt_error_strerror());
		}
	}

	return ret;
}

int
handle_debug_single_step_(struct pt_process *process,
                          struct pt_thread *thread,
                          LPEXCEPTION_RECORD exception)
{
	int status = PT_EVENT_FORWARD;

	pt_log("%s()\n", __FUNCTION__);

	/* We may be single stepping over a breakpoint in order to make it
	 * persist.  If so we will restore the breakpoint here and then
	 * carry on.  We will invoke the single step handler as well if there
	 * was an external single step request.
	 */
	if (thread->flags & THREAD_FLAG_SINGLE_STEP_INTERNAL) {
		struct pt_breakpoint_internal *bp = thread->breakpoint_restore;

		/* Mask out the flag again. */
		thread->flags &= ~THREAD_FLAG_SINGLE_STEP_INTERNAL;

		if (bp && bp->breakpoint->b_op->restore != NULL)
			bp->breakpoint->b_op->restore(thread, bp);
		thread->breakpoint_restore = NULL;

		/* Only pass the event to our handler if it was not
		 * internal, or was both internal and external.
		 */
		if ( !(thread->flags & THREAD_FLAG_SINGLE_STEP))
			return PT_EVENT_DROP;
	}

	if (process->handlers.single_step != NULL) {
		struct pt_event_single_step ev;

		ev.address = exception->ExceptionAddress;
		ev.thread = thread;

		status = process->handlers.single_step(&ev);
	}

	/* If we requested the single-step ourselves, we can now remove the
	 * flag again (it is currently set so the callback handler can test
	 * whether the event was requested by us or not).
	 */
	thread->flags &= ~THREAD_FLAG_SINGLE_STEP;

	return status;
}


