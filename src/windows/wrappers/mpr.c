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
 * mpr.c
 *
 * libptrace windows mpr wrapper.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <windows.h>
#include <libptrace/charset.h>
#include <libptrace/windows/error.h>
#include "common.h"
#include "mpr.h"

#define FILENAME_DEF_SIZE       256

static HMODULE mpr;
static DWORD WINAPI (*WNetGetConnectionW_)(LPCWSTR, LPWSTR, LPDWORD);

static void __attribute__((constructor)) mpr_initialize_(void)
{
	if ( (mpr = LoadLibraryW(L"mpr.dll")) == NULL)
		return;

	WNetGetConnectionW_ = IMPORT(mpr, WNetGetConnectionW);
}

static void __attribute__((destructor)) mpr_destroy_(void)
{
	WNetGetConnectionW_ = NULL;

	if (mpr != NULL)
		FreeLibrary(mpr);
}

utf8_t *pt_windows_api_wnet_get_connection(const utf8_t *localname)
{
	DWORD length = FILENAME_DEF_SIZE;
	utf16_t *wremotename = NULL;
	utf16_t *wlocalname;
	utf8_t *remotename;
	utf16_t *tmp;
	DWORD ret;

	if (WNetGetConnectionW_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return NULL;
	}

	if ( (wlocalname = pt_utf8_to_utf16(localname)) == NULL)
		return NULL;

	do {
		if ( (tmp = realloc(wremotename, (length + 1) * 2)) == NULL) {
			pt_error_errno_set(errno);
			if (wremotename != NULL) free(wremotename);
			free(wlocalname);
			return NULL;
		}

		wremotename = tmp;
		ret = WNetGetConnectionW_(wlocalname, wremotename, &length);
	} while (ret == ERROR_MORE_DATA);

	free(wlocalname);

	if (ret != NO_ERROR) {
		pt_windows_error_winapi_set_value(ret);
		free(wremotename);
		return NULL;
	}

	remotename = pt_utf16_to_utf8(wremotename);
	free(wremotename);

	return remotename;
}
