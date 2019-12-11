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
 * psapi.c
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#include <windows.h>
#include <psapi.h>
#include <libptrace/charset.h>
#include <libptrace/windows/error.h>
#include "common.h"
#include "psapi.h"

#define FILENAME_DEF_SIZE	256
#define PROCLIST_DEF_SIZE	256
#define MODLIST_DEF_SIZE	256

static HMODULE psapi;
static BOOL  WINAPI (*EnumProcesses_)(DWORD *, DWORD, DWORD *);
static BOOL  WINAPI (*EnumProcessModules_)(HANDLE, HMODULE *, DWORD, LPDWORD);
static DWORD WINAPI (*GetModuleFileNameExW_)(HANDLE, HMODULE, LPWSTR, DWORD);
static DWORD WINAPI (*GetMappedFileNameW_)(HANDLE, LPVOID, LPWSTR, DWORD);

static void __attribute__((constructor)) psapi_initialize_(void)
{
	if ( (psapi = LoadLibraryW(L"psapi.dll")) == NULL)
		return;

	EnumProcesses_        = IMPORT(psapi, EnumProcesses);
	EnumProcessModules_   = IMPORT(psapi, EnumProcessModules);
	GetModuleFileNameExW_ = IMPORT(psapi, GetModuleFileNameExW);
	GetMappedFileNameW_   = IMPORT(psapi, GetMappedFileNameW);
}

static void __attribute__((destructor)) psapi_destroy_(void)
{
	EnumProcesses_        = NULL;
	EnumProcessModules_   = NULL;
	GetModuleFileNameExW_ = NULL;
	GetMappedFileNameW_   = NULL;

	if (psapi != NULL)
		FreeLibrary(psapi);
}

/** Enumerate all processes
 *
 * Retrieves the process identifier for each process object in the system.
 *
 * \param ppProcessIds Pointer to a pointer which will hold a dynamically
 *        allocated array containing process ids.
 *        Memory should be released through free().
 * \param pBytesReturned Pointer to a DWORD holding the number of bytes
 *        used in the ProcessIds array.
 *
 * \return TRUE on success, FALSE on failure.
 */
BOOL
pt_windows_api_enum_processes(DWORD **ppProcessIds, DWORD *pBytesReturned)
{
	size_t size = PROCLIST_DEF_SIZE;
	DWORD *proclist = NULL;
	DWORD BytesReturned;
	DWORD *ret;
	BOOL b;

	if (EnumProcesses_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return FALSE;
	}

	do {
		DWORD *newptr;

		newptr = (DWORD *)realloc(proclist, size * sizeof(DWORD));
		if (newptr == NULL) {
			pt_error_errno_set(errno);
			if (proclist != NULL)
				free(proclist);
			return FALSE;
		}
		proclist = newptr;

		b = EnumProcesses_(
			proclist,
			size * sizeof(DWORD),
			&BytesReturned
		);
		if (!b) {
			free(proclist);
			pt_windows_error_winapi_set();
			return FALSE;
		}
		size *= 2;
	} while (BytesReturned == size * sizeof(DWORD) / 2);

	*pBytesReturned = BytesReturned;

	/* Give up the memory we do not need, if possible. */
	if ( (ret = realloc(proclist, BytesReturned)) == NULL)
		*ppProcessIds = proclist;
	else
		*ppProcessIds = ret;

	return TRUE;
}

/** Enumerate all modules for a process
 *
 * Retrieves a handle for each module in the specified process.
 *
 * \param hProcess The handle to the process whose modules we enumerate
 *
 * \param lpphModule Pointer to a pointer which will hold a dynamically
 *        allocated array containing module HANDLEs.
 *        Memory should be released through free().
 *
 * \param lpcbNeeded Pointer to a DWORD holding the number of bytes
 *        used in the module HANDLE array (note that the EnumProcessModules
 *        function returns the number of bytes that would be used if the
 *        array was large enough, but we rescale it dynamically to fit).
 *
 * \return TRUE on success, FALSE on failure.
 */
BOOL
pt_windows_api_enum_process_modules(HANDLE hProcess, HMODULE **lpphModule,
                                    LPDWORD lpcbNeeded)
{
	size_t size = MODLIST_DEF_SIZE;
	HMODULE *modlist = NULL, *ret;
	DWORD cbNeeded;
	BOOL b;

	if (EnumProcessModules_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return FALSE;
	}

	do {
		HMODULE *newptr;

		newptr = (HMODULE *)realloc(modlist, size * sizeof(HMODULE));
		if (newptr == NULL) {
			pt_error_errno_set(errno);
			if (modlist != NULL)
				free(modlist);
			return FALSE;
		}
		modlist = newptr;

		b = EnumProcessModules_(
			hProcess,
			modlist,
			size * sizeof(HMODULE),
			&cbNeeded
		);
		if (!b) {
			pt_windows_error_winapi_set();
			free(modlist);
			return FALSE;
		}
		size *= 2;
	} while (size * sizeof(HMODULE) / 2 < cbNeeded);

	*lpcbNeeded = cbNeeded;
	/* Give up the memory we do not need, if possible. */
	if ( (ret = realloc(modlist, cbNeeded)) == NULL)
		*lpphModule = modlist;
	else
		*lpphModule = ret;

	return TRUE;
}

utf8_t *pt_windows_api_get_module_filename_ex(HANDLE hProcess, HMODULE hModule)
{
	DWORD size = FILENAME_DEF_SIZE;
	LPWSTR lpImageFileName = NULL;
	LPWSTR newstr;
	DWORD retsize;
	utf8_t *ret;

	if (GetModuleFileNameExW_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return NULL;
	}

	do {
		newstr = (LPWSTR)realloc(lpImageFileName, size * 2);
		if (newstr == NULL) {
			pt_error_errno_set(errno);
			if (lpImageFileName != NULL)
				free(lpImageFileName);
			return NULL;
		}
		lpImageFileName = newstr;

		/* The return value of this function is rather inconsistent.
		 * When no truncation happens, the return value is the length
		 * of the string in lpImageFileName without a terminating
		 * 0-byte.
		 *
		 * If truncation happens, the return value is the length of
		 * the string in lpImageFileName including the 0-byte.
		 */
		retsize = GetModuleFileNameExW_(hProcess, hModule,
		                                lpImageFileName, size);
		if (!retsize) {
			pt_windows_error_winapi_set();
			free(lpImageFileName);
			return NULL;
		}
		size *= 2;
	} while (size / 2 == retsize);

	ret = pt_utf16_to_utf8(lpImageFileName);
	free(lpImageFileName);

	return ret;
}

utf8_t *pt_windows_api_get_mapped_filename(HANDLE hProcess, LPVOID lpv)
{
	DWORD size = FILENAME_DEF_SIZE;
	LPWSTR lpMappedFileName = NULL;
	LPWSTR newstr;
	DWORD retsize;
	utf8_t *ret;

	if (GetMappedFileNameW_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return NULL;
	}

	do {
		newstr = (LPWSTR)realloc(lpMappedFileName, size * 2);
		if (newstr == NULL) {
			pt_error_errno_set(errno);
			if (lpMappedFileName != NULL)
				free(lpMappedFileName);
			return NULL;
		}
		lpMappedFileName = newstr;

		/* The return value of this function is rather inconsistent.
		 * When no truncation happens, the return value is the length
		 * of the string in lpImageFileName without a terminating
		 * 0-byte.
		 *
		 * If truncation happens, the return value is the length of
		 * the string in lpMappedFileName including the 0-byte.
		 */
		retsize = GetMappedFileNameW_(hProcess, lpv,
		                              lpMappedFileName, size);
		if (!retsize) {
			pt_windows_error_winapi_set();
			free(lpMappedFileName);
			return NULL;
		}
		size *= 2;
	} while (size / 2 == retsize);

	ret = pt_utf16_to_utf8(lpMappedFileName);
	free(lpMappedFileName);

	return ret;
}
