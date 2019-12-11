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
static BOOL   WINAPI (*IsWow64Process_)(HANDLE, PBOOL);
static SIZE_T WINAPI (*VirtualQueryEx_)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
static BOOL   WINAPI (*DebugSetProcessKillOnExit_)(BOOL);
static HANDLE WINAPI (*OpenThread_)(DWORD, BOOL, DWORD);
static DWORD  WINAPI (*GetThreadId_)(HANDLE);
static BOOL   WINAPI (*GetProcessTimes_)(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME);
static DWORD  WINAPI (*SuspendThread_)(HANDLE);
static DWORD  WINAPI (*Wow64SuspendThread_)(HANDLE);
static BOOL   WINAPI (*Wow64GetThreadContext_)(HANDLE, PWOW64_CONTEXT);
static BOOL   WINAPI (*Wow64SetThreadContext_)(HANDLE, const WOW64_CONTEXT *);
static UINT   WINAPI (*GetDriveTypeW_)(LPCWSTR);

static void __attribute__((constructor)) kernel32_initialize_(void)
{
	if ( (kernel32 = LoadLibraryW(L"kernel32.dll")) == NULL)
		return;

	VirtualQueryEx_         = IMPORT(kernel32, VirtualQueryEx);
	IsWow64Process_         = IMPORT(kernel32, IsWow64Process);
	DebugSetProcessKillOnExit_ = IMPORT(kernel32, DebugSetProcessKillOnExit);
	OpenThread_             = IMPORT(kernel32, OpenThread);
	GetThreadId_            = IMPORT(kernel32, GetThreadId);
	GetProcessTimes_        = IMPORT(kernel32, GetProcessTimes);
	SuspendThread_          = IMPORT(kernel32, SuspendThread);
	Wow64SuspendThread_     = IMPORT(kernel32, Wow64SuspendThread);
	Wow64GetThreadContext_  = IMPORT(kernel32, Wow64GetThreadContext);
	Wow64SetThreadContext_  = IMPORT(kernel32, Wow64SetThreadContext);
	GetDriveTypeW_          = IMPORT(kernel32, GetDriveTypeW);
}

static void __attribute__((destructor)) __kernel32_destroy(void)
{
	VirtualQueryEx_         = NULL;
	IsWow64Process_         = NULL;
	DebugSetProcessKillOnExit_ = NULL;
	OpenThread_             = NULL;
	GetThreadId_            = NULL;
	GetProcessTimes_        = NULL;
	SuspendThread_          = NULL;
	Wow64SuspendThread_     = NULL;
	Wow64GetThreadContext_  = NULL;
	Wow64SetThreadContext_  = NULL;
	GetDriveTypeW_          = NULL;

	if (kernel32 != NULL)
		FreeLibrary(kernel32);
}

int pt_windows_api_get_drive_type(const utf8_t *pathname)
{
	utf16_t *wpathname;
	UINT ret;

	if (GetDriveTypeW_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if ( (wpathname = pt_utf8_to_utf16(pathname)) == NULL)
		return -1;

	/* GetDriveType() does not set any error. */
	ret = GetDriveTypeW_(wpathname);

	free(wpathname);

	return ret;
}

int pt_windows_api_wow64_set_thread_context(HANDLE h, const WOW64_CONTEXT *ctx)
{
	if (Wow64SetThreadContext_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (Wow64SetThreadContext_(h, ctx) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_wow64_get_thread_context(HANDLE h, PWOW64_CONTEXT ctx)
{
	if (Wow64GetThreadContext_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (Wow64GetThreadContext_(h, ctx) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_suspend_thread(HANDLE h)
{
	if (SuspendThread_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (SuspendThread_(h) == (DWORD)-1) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_wow64_suspend_thread(HANDLE h)
{
	if (Wow64SuspendThread_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (Wow64SuspendThread_(h) == (DWORD)-1) {
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

	if (GetProcessTimes_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = GetProcessTimes_(hProcess, lpCreationTime, lpExitTime,
	                       lpKernelTime, lpUserTime);
	if (ret == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_have_get_process_times(void)
{
	return GetProcessTimes_ != NULL;
}

DWORD pt_windows_api_get_thread_id(HANDLE hThread)
{
	DWORD ret;

	if (GetThreadId_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return 0;
	}

	if ( (ret = GetThreadId_(hThread)) == 0)
		pt_windows_error_winapi_set();

	return ret;
}

int pt_windows_api_have_get_thread_id(void)
{
	return GetThreadId_ != NULL;
}

HANDLE pt_windows_api_open_thread(DWORD dwDesiredAccess, BOOL bInheritHandle,
                                  DWORD dwThreadId)
{
	HANDLE ret;

	if (OpenThread_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return NULL;
	}

	ret = OpenThread_(dwDesiredAccess, bInheritHandle, dwThreadId);
	if (ret == NULL) {
		pt_windows_error_winapi_set();
		return NULL;
	}

	return ret;
}

int pt_windows_api_have_open_thread(void)
{
	return OpenThread_ != NULL;
}

int pt_windows_api_debug_set_process_kill_on_exit(BOOL KillOnExit)
{
	if (DebugSetProcessKillOnExit_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (DebugSetProcessKillOnExit_(KillOnExit) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_have_debug_set_process_kill_on_exit(void)
{
	return DebugSetProcessKillOnExit_ != NULL;
}

int pt_windows_api_is_wow64_process(HANDLE hProcess, PBOOL Wow64Process)
{
	if (IsWow64Process_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (IsWow64Process_(hProcess, Wow64Process) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_have_is_wow64_process(void)
{
	return IsWow64Process_ != NULL;
}

SIZE_T pt_windows_api_virtual_query_ex(HANDLE hProcess, LPCVOID lpAddress,
                                       PMEMORY_BASIC_INFORMATION lpBuffer,
                                       SIZE_T dwLength)
{
	SIZE_T ret;

	if (VirtualQueryEx_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return 0;
	}

	ret = VirtualQueryEx_(hProcess, lpAddress, lpBuffer, dwLength);
	if (ret == 0)
		pt_windows_error_winapi_set();

	return ret;
}

int pt_windows_api_have_virtual_query_ex(void)
{
	return VirtualQueryEx_ != NULL;
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
