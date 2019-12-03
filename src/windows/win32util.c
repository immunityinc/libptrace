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
 * win32util.c
 *
 * libptrace windows utility functions.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 * Author: Massimiliano Oldani <max@immunityinc.com>
 *
 */
#include <windows.h>
#include <stdio.h>
#include <assert.h>
#include <libptrace/windows/error.h>


/* like MultiByteToWideChar() but returns the dynamic converted strings into malloc()'ed buffer */
int MultiByteToWideCharDyn(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteString, int cbMultiByte, LPWSTR *lppBuffer)
{
	LPWSTR buf = NULL;
	int ret;

	*lppBuffer = NULL;

	ret = MultiByteToWideChar(CodePage, dwFlags, lpMultiByteString, cbMultiByte, NULL, 0);
	/* The documentation does not talk about negative return values, since
	 * the number of chars should be always a positive explicitly the
	 * function checks for negative value and manages them as errors
	 */
	if (!ret || ret < 0) {
		pt_windows_error_winapi_set();
		return 0;
	}

	/* returned value holds the number of chars needed for the conversion included the NULL terminator */
	if ( (buf = malloc(ret * sizeof(WCHAR))) == NULL) {
		pt_error_errno_set(errno);
		return 0;
	}

	ret = MultiByteToWideChar(CodePage, dwFlags, lpMultiByteString, cbMultiByte, buf, ret);
	if (!ret) {
		pt_windows_error_winapi_set();
		free(buf);
		return 0;
	}

	*lppBuffer = buf;
	return ret;
}
