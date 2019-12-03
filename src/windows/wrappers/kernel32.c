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
 * kernel32.c
 *
 * libptrace windows kernel32 wrapper.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#define _WIN32_WINNT 0x600

#include <windows.h>
#include <libptrace/charset.h>
#include <libptrace/windows/error.h>
#include "common.h"
#include "kernel32.h"
#include "../../stringlist.h"

#define FILENAME_DEF_SIZE	256

static HMODULE kernel32;
static BOOL   WINAPI (*__IsWow64Process)(HANDLE, PBOOL);
static SIZE_T WINAPI (*__VirtualQueryEx)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
static BOOL   WINAPI (*__DebugSetProcessKillOnExit)(BOOL);
static HANDLE WINAPI (*__OpenThread)(DWORD, BOOL, DWORD);
static DWORD  WINAPI (*__GetThreadId)(HANDLE);
static BOOL   WINAPI (*__GetProcessTimes)(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME);
static DWORD  WINAPI (*__SuspendThread)(HANDLE);
static DWORD  WINAPI (*__Wow64SuspendThread)(HANDLE);
static BOOL   WINAPI (*__Wow64GetThreadContext)(HANDLE, PWOW64_CONTEXT);
static BOOL   WINAPI (*__Wow64SetThreadContext)(HANDLE, const WOW64_CONTEXT *);
static UINT   WINAPI (*__GetDriveTypeW)(LPCWSTR);

static void __attribute__((constructor)) __kernel32_initialize(void)
{
	if ( (kernel32 = LoadLibraryW(L"kernel32.dll")) == NULL)
		return;

	__VirtualQueryEx         = IMPORT(kernel32, VirtualQueryEx);
	__IsWow64Process         = IMPORT(kernel32, IsWow64Process);
	__DebugSetProcessKillOnExit = IMPORT(kernel32, DebugSetProcessKillOnExit);
	__OpenThread             = IMPORT(kernel32, OpenThread);
	__GetThreadId            = IMPORT(kernel32, GetThreadId);
	__GetProcessTimes        = IMPORT(kernel32, GetProcessTimes);
	__SuspendThread          = IMPORT(kernel32, SuspendThread);
	__Wow64SuspendThread     = IMPORT(kernel32, Wow64SuspendThread);
	__Wow64GetThreadContext  = IMPORT(kernel32, Wow64GetThreadContext);
	__Wow64SetThreadContext  = IMPORT(kernel32, Wow64SetThreadContext);
	__GetDriveTypeW          = IMPORT(kernel32, GetDriveTypeW);
}

static void __attribute((destructor)) __kernel32_destroy(void)
{
	__VirtualQueryEx         = NULL;
	__IsWow64Process         = NULL;
	__DebugSetProcessKillOnExit = NULL;
	__OpenThread             = NULL;
	__GetThreadId            = NULL;
	__GetProcessTimes        = NULL;
	__SuspendThread          = NULL;
	__Wow64SuspendThread     = NULL;
	__Wow64GetThreadContext  = NULL;
	__Wow64SetThreadContext  = NULL;
	__GetDriveTypeW          = NULL;

	if (kernel32 != NULL)
		FreeLibrary(kernel32);
}

int pt_windows_api_get_drive_type(const utf8_t *pathname)
{
	utf16_t *wpathname;
	UINT ret;

	if (__GetDriveTypeW == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if ( (wpathname = pt_utf8_to_utf16(pathname)) == NULL)
		return -1;

	/* GetDriveType() does not set any error. */
	ret = __GetDriveTypeW(wpathname);

	free(wpathname);

	return ret;
}

int pt_windows_api_wow64_set_thread_context(HANDLE h, const WOW64_CONTEXT *ctx)
{
	if (__Wow64SetThreadContext == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (__Wow64SetThreadContext(h, ctx) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_wow64_get_thread_context(HANDLE h, PWOW64_CONTEXT ctx)
{
	if (__Wow64GetThreadContext == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (__Wow64GetThreadContext(h, ctx) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_suspend_thread(HANDLE h)
{
	if (__SuspendThread == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (__SuspendThread(h) == (DWORD)-1) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_wow64_suspend_thread(HANDLE h)
{
	if (__Wow64SuspendThread == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (__Wow64SuspendThread(h) == (DWORD)-1) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_get_process_times(
	HANDLE     hProcess,
	LPFILETIME lpCreationTime,
	LPFILETIME lpExitTime,
	LPFILETIME lpKernelTime,
	LPFILETIME lpUserTime)
{
	BOOL ret;

	if (__GetProcessTimes == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = __GetProcessTimes(hProcess, lpCreationTime, lpExitTime,
	                        lpKernelTime, lpUserTime);
	if (ret == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_have_get_process_times(void)
{
	return __GetProcessTimes != NULL;
}

DWORD pt_windows_api_get_thread_id(HANDLE hThread)
{
	DWORD ret;

	if (__GetThreadId == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return 0;
	}

	if ( (ret = __GetThreadId(hThread)) == 0)
		pt_windows_error_winapi_set();

	return ret;
}

int pt_windows_api_have_get_thread_id(void)
{
	return __GetThreadId != NULL;
}

HANDLE pt_windows_api_open_thread(DWORD dwDesiredAccess, BOOL bInheritHandle,
                                  DWORD dwThreadId)
{
	HANDLE ret;

	if (__OpenThread == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return NULL;
	}

	ret = __OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
	if (ret == NULL) {
		pt_windows_error_winapi_set();
		return NULL;
	}

	return ret;
}

int pt_windows_api_have_open_thread(void)
{
	return __OpenThread != NULL;
}

int pt_windows_api_debug_set_process_kill_on_exit(BOOL KillOnExit)
{
	if (__DebugSetProcessKillOnExit == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (__DebugSetProcessKillOnExit(KillOnExit) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_have_debug_set_process_kill_on_exit(void)
{
	return __DebugSetProcessKillOnExit != NULL;
}

int pt_windows_api_is_wow64_process(HANDLE hProcess, PBOOL Wow64Process)
{
	if (__IsWow64Process == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (__IsWow64Process(hProcess, Wow64Process) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_have_is_wow64_process(void)
{
	return __IsWow64Process != NULL;
}

SIZE_T pt_windows_api_virtual_query_ex(HANDLE hProcess, LPCVOID lpAddress,
                                       PMEMORY_BASIC_INFORMATION lpBuffer,
                                       SIZE_T dwLength)
{
	SIZE_T ret;

	if (__VirtualQueryEx == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return 0;
	}

	ret = __VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
	if (ret == 0)
		pt_windows_error_winapi_set();

	return ret;
}

int pt_windows_api_have_virtual_query_ex(void)
{
	return __VirtualQueryEx != NULL;
}

HMODULE pt_windows_load_library(const utf8_t *name)
{
	utf16_t *wname;
	HMODULE ret;

	if ( (wname = pt_utf8_to_utf16(name)) == NULL)
		return NULL;

	if ( (ret = LoadLibraryW(wname)) == NULL)
		pt_windows_error_winapi_set();

	free(wname);

	return ret;
}

HMODULE pt_windows_get_module_handle(const utf8_t *name)
{
	utf16_t *wname;
	HMODULE ret;

	if ( (wname = pt_utf8_to_utf16(name)) == NULL)
		return NULL;

	if ( (ret = GetModuleHandleW(wname)) == NULL)
		pt_windows_error_winapi_set();

	free(wname);

	return ret;
}

FARPROC pt_windows_get_proc_address(HMODULE h, const char *procname)
{
	FARPROC ret;

	if ( (ret = GetProcAddress(h, procname)) == NULL)
		pt_windows_error_winapi_set();

	return ret;
}

int pt_windows_api_get_logical_drive_strings(struct pt_string_list *pathnames)
{
	LPWSTR lpDrivesNames, ptr;
	DWORD ret_csize, csize;
	size_t names, i;

	ret_csize = GetLogicalDriveStringsW(0, NULL);
	if (!ret_csize) {
		pt_windows_error_winapi_set();
		return -1;
	}

	/* Overestimate by terminating 0-char for safety purposes. */
	lpDrivesNames = (LPWSTR)malloc((ret_csize + 1) * sizeof(WCHAR));
	if (lpDrivesNames == NULL) {
		pt_error_errno_set(errno);
		return -1;
	}

	/* From GetLogicalDriveStringsW() API:
	 * The maximum size of the buffer pointed to by lpFileName, in WCHARs.
	 * This size does not include the terminating null character. If this
	 * parameter is zero, lpBuffer is not used.
	 */
	do {
		csize = ret_csize;
		ret_csize = GetLogicalDriveStringsW(ret_csize, lpDrivesNames);
		if (ret_csize == 0) {
			pt_windows_error_winapi_set();
			free(lpDrivesNames);
			return -1;
		}
	} while (ret_csize > csize);

	/* Pathnames are separated by 0-characters and terminated by an entry
	 * of two zero characters.  Count the number of names we get.
	 */
	names = 0;
	for (i = 0; lpDrivesNames[i] != 0 || lpDrivesNames[i + 1] != 0; i++) {
		if (lpDrivesNames[i + 1] == 0)
			names++;
	}

	/* Allocate the pointer array for all pathnames. */
	if (pt_string_list_init(pathnames, names) == -1) {
		free(lpDrivesNames);
		return -1;
	}

	/* Add all drive names to the string list. */
	ptr = lpDrivesNames;
	for (i = 0; i < names; i++) {
		pathnames->strings[i] = pt_utf16_to_utf8(ptr);
		if (pathnames->strings[i] == NULL) {
			while (i-- != 0)
				free(pathnames->strings[i]);
			pt_string_list_destroy(pathnames);
			free(lpDrivesNames);
			return -1;
		}

		ptr += wcslen(ptr) + 1;
	}

	free(lpDrivesNames);

	return 0;
}

utf8_t *pt_windows_api_query_dos_device(const utf8_t *devicename)
{
	DWORD csize = FILENAME_DEF_SIZE;
	LPWSTR lpTargetPath = NULL;
	LPWSTR lpDeviceName;
	DWORD ret_csize;
	utf8_t *ret;

	if ( (lpDeviceName = pt_utf8_to_utf16(devicename)) == NULL)
		return NULL;

	do {
		LPWSTR newstr;

		/* Overcommit by 1 character for safety reasons. */
		newstr = (LPWSTR)realloc(lpTargetPath, (csize + 1) * sizeof(WCHAR));
		if (newstr == NULL) {
			pt_error_errno_set(errno);
			if (lpTargetPath != NULL)
				free(lpTargetPath);
			free(lpDeviceName);
			return NULL;
		}
		lpTargetPath = newstr;

		ret_csize = QueryDosDeviceW(lpDeviceName, lpTargetPath, csize);
		if (ret_csize == 0 && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			pt_windows_error_winapi_set();
			free(lpTargetPath);
			free(lpDeviceName);
			return NULL;
		}

		csize = csize * 2;
	} while (ret_csize == 0);

	ret = pt_utf16_to_utf8(lpTargetPath);
	free(lpTargetPath);
	free(lpDeviceName);

	return ret;
}
