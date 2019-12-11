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
 * error.c
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 * Author: Massimiliano Oldani <max@immunityinc.com>
 *
 */
#include <windows.h>
#include <assert.h>
#include <libptrace/charset.h>
#include <libptrace/pe.h>
#include "error.h"

void pt_windows_error_save(void);
void pt_windows_error_restore(void);
const utf8_t *pt_windows_error_strerror(void);

/* current pt_windows_errno */
static __thread struct pt_windows_error pt_windows_errno = {
	.type = PT_WINDOWS_ERROR_TYPE_NONE
};

/* saved pt_windows_errno */
static __thread struct pt_windows_error pt_windows_errno_saved = {
	.type = PT_WINDOWS_ERROR_TYPE_NONE
};

static __thread utf8_t *pt_windows_errmsg = NULL;

struct pt_error_operations pt_error_windows_operations = {
	.save     = pt_windows_error_save,
	.restore  = pt_windows_error_restore,
	.strerror = pt_windows_error_strerror
};

static WCHAR *chompw(WCHAR *str)
{
	size_t len = wcslen(str);

	if (len > 0 && str[len - 1] == L'\n') {
		if (len > 1 && str[len - 2] == L'\r')
			str[len - 2] = L'\0';

		str[len - 1] = L'\0';
	}
	return str;
}

static utf8_t *format_winapi_error_msg(DWORD error)
{
	LPWSTR msg = NULL;
        utf8_t *utf8_msg;
	DWORD ret;

	ret = FormatMessageW(
			FORMAT_MESSAGE_ALLOCATE_BUFFER  |
			FORMAT_MESSAGE_FROM_SYSTEM      |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			error,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(WCHAR *)&msg,
			0x10,
			NULL
	);

	if (ret == 0 || msg == NULL)
		return NULL;

	utf8_msg = pt_utf16_to_utf8(chompw(msg));
        LocalFree(msg);

	return utf8_msg;
}

static utf8_t *format_hresult_error_msg(HRESULT error)
{
	DWORD format_flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
	                     FORMAT_MESSAGE_IGNORE_INSERTS;
	HINSTANCE hInst = NULL;
	LPWSTR msg = NULL;
	utf8_t *utf8_msg;
	DWORD ret;

	switch (HRESULT_FACILITY(error)) {
	case FACILITY_MSMQ:
		hInst = LoadLibraryW(L"mqutil.dll");
		if (hInst != NULL)
			format_flags |= FORMAT_MESSAGE_FROM_HMODULE;
		break;

		/* TODO: add here the other specific HMODULE dll holding the
		 * specific resource tables
		 */

	case FACILITY_NULL:
	case FACILITY_WIN32:
	case FACILITY_WINDOWS:
	default:
		format_flags |= FORMAT_MESSAGE_FROM_SYSTEM;
		break;
	}

	ret = FormatMessageW(format_flags,
	                     hInst,
                             error,
	                     MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
	                     (LPWSTR)&msg,
	                     0x10,
	                     NULL
	);

	if (hInst != NULL)
		FreeLibrary(hInst);

	if (ret == 0 || msg == NULL)
		return NULL;

	utf8_msg = pt_utf16_to_utf8(chompw(msg));
	LocalFree(msg);

	return utf8_msg;
}

#if 0
static const utf8_t *format_errno_error_(int error)
{
	LPWSTR msg = __wcserror(NULL);
	utf8_t *utf8_msg;

	if (!msg)
		return "errno Error Message Not Available";

	/* XXX: error handling. */
	if ( (utf8_msg = utf16_to_utf8(msg)) == NULL)
		goto out_free;

	strncpy(pt_last_error_msg_, utf8_msg, sizeof(pt_last_error_msg_));
	pt_last_error_msg_[sizeof(pt_last_error_msg_) - 1] = '\0';

out_free:
	if (utf8_msg)
		free(utf8_msg);

	return pt_last_error_msg_;
}
#endif

static inline utf8_t *update_errmsg_(utf8_t *msg)
{
	if (pt_windows_errmsg != NULL)
		free(pt_windows_errmsg);

	if (msg == NULL)
		msg = (utf8_t *)strdup("Error Message Not Available");

	pt_windows_errmsg = msg;
	return msg;
}

const utf8_t *pt_windows_error_strerror(void)
{
	struct pt_windows_error *winerr =
		(struct pt_windows_error *)pt_errno.private_data;
	utf8_t *errmsg;

	switch (winerr->type) {
	case PT_WINDOWS_ERROR_TYPE_WINAPI:
		errmsg = format_winapi_error_msg(winerr->winapi_error);
        	return update_errmsg_(errmsg);
	case PT_WINDOWS_ERROR_TYPE_OLE:
		errmsg = format_hresult_error_msg(winerr->ole_error);
        	return update_errmsg_(errmsg);
	default:
		abort();
	}
}

void pt_windows_error_winapi_set(void)
{
	/* CAVEAT: Referencing TLS data in MingW currently calls
	 * __emutls_get_address() which will update the Windows error
	 * retrieved by GetLastError() behind the scenes.
	 *
	 * We retrieve the error prior to referencing any TLS data.
	 */
	pt_windows_error_winapi_set_value(GetLastError());
}

void pt_windows_error_winapi_set_value(DWORD err)
{
	pt_windows_errno.type         = PT_WINDOWS_ERROR_TYPE_WINAPI;
	pt_windows_errno.winapi_error = err;

	pt_errno.type                 = PT_ERROR_TYPE_WINDOWS;
	pt_errno.p_op                 = &pt_error_windows_operations;
	pt_errno.private_data         = &pt_windows_errno;
}

int pt_windows_error_winapi_test(DWORD err)
{
	if (pt_errno.type != PT_ERROR_TYPE_WINDOWS)
		return 0;

	if (pt_errno.private_data != &pt_windows_errno)
		return 0;

	if (pt_windows_errno.type != PT_WINDOWS_ERROR_TYPE_WINAPI)
		return 0;

	if (pt_windows_errno.winapi_error != err)
		return 0;

	return 1;
}

void pt_windows_error_ole_set(HRESULT num)
{
	pt_windows_errno.type      = PT_WINDOWS_ERROR_TYPE_OLE;
	pt_windows_errno.ole_error = num;

	pt_errno.type              = PT_ERROR_TYPE_WINDOWS;
	pt_errno.p_op              = &pt_error_windows_operations;
	pt_errno.private_data      = &pt_windows_errno;
}

void pt_windows_error_save(void)
{
	pt_windows_errno_saved = pt_windows_errno;
	pt_errno_saved.private_data = &pt_windows_errno_saved;
}

void pt_windows_error_restore(void)
{
	pt_windows_errno = pt_windows_errno_saved;
	pt_errno.private_data = &pt_windows_errno;
}
