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
 * advapi32.c
 *
 * libptrace windows advapi32 wrapper.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <windows.h>
#include <libptrace/charset.h>
#include <libptrace/windows/error.h>
#include "advapi32.h"
#include "common.h"

static HMODULE advapi32;
static BOOL WINAPI (*LookupPrivilegeValueW_)(LPCWSTR, LPCWSTR, PLUID);
static BOOL WINAPI (*OpenProcessToken_)(HANDLE, DWORD, PHANDLE);
static BOOL WINAPI (*AdjustTokenPrivileges_)(HANDLE, BOOL, PTOKEN_PRIVILEGES,
                                             DWORD, PTOKEN_PRIVILEGES, PDWORD);

static void __attribute__((constructor)) advapi32_initialize_(void)
{
	if ( (advapi32 = LoadLibraryW(L"advapi32.dll")) == NULL)
		return;

	LookupPrivilegeValueW_ = IMPORT(advapi32, LookupPrivilegeValueW);
	OpenProcessToken_      = IMPORT(advapi32, OpenProcessToken);
	AdjustTokenPrivileges_ = IMPORT(advapi32, AdjustTokenPrivileges);
}

static void __attribute__((destructor)) advapi32_destroy_(void)
{
	LookupPrivilegeValueW_ = NULL;
	OpenProcessToken_      = NULL;
	AdjustTokenPrivileges_ = NULL;

	if (advapi32 != NULL)
		FreeLibrary(advapi32);
}

int pt_windows_api_adjust_token_privileges(
	HANDLE            TokenHandle,
	BOOL              DisableAllPrivileges,
	PTOKEN_PRIVILEGES NewState,
	DWORD             BufferLength,
        PTOKEN_PRIVILEGES PreviousState,
	PDWORD            ReturnLength)
{
	BOOL ret;

	if (AdjustTokenPrivileges_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = AdjustTokenPrivileges_(
		TokenHandle,
		DisableAllPrivileges,
		NewState,
		BufferLength,
		PreviousState,
		ReturnLength
	);

	if (ret == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_open_process_token(HANDLE h, DWORD access, PHANDLE htok)
{
	if (OpenProcessToken_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (OpenProcessToken_(h, access, htok) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_lookup_privilege_value(const utf8_t *systemname,
                                          const utf8_t *name, PLUID uid)
{
	LPWSTR systemname_w = NULL;
	LPWSTR name_w;
	int ret = -1;

	if (LookupPrivilegeValueW_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		goto out;
        }

	if (systemname && (systemname_w = pt_utf8_to_utf16(systemname)) == NULL)
		goto out;

	if ( (name_w = pt_utf8_to_utf16(name)) == NULL)
		goto out_systemname;

	if (LookupPrivilegeValueW_(systemname_w, name_w, uid) == 0) {
		pt_windows_error_winapi_set();
		goto out_name;
	}

	ret = 0;

out_name:
	free(name_w);
out_systemname:
	if (systemname_w != NULL)
		free(systemname_w);
out:
	return ret;
}
