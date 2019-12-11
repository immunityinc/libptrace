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
 * shortcut.c
 *
 * libptrace windows shortcut management.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 * Author: Massimiliano Oldani <max@immunityinc.com>
 *
 */
#define COBJMACROS
#include <stdio.h>
#include <windows.h>
#include <initguid.h>
#include <shlguid.h>
#include <libptrace/windows/error.h>
#include "shortcut.h"
#include "win32util.h"

void shortcut_init(struct shortcut *shortcut)
{
	shortcut->pathname  = NULL;
	shortcut->arguments = NULL;
	shortcut->window_   = NULL;
}

void shortcut_set_resolve_window(struct shortcut *shortcut, HWND window)
{
	shortcut->window_ = window;
}

/* The function is now UTF-8 safe and all internal COM operations works now
 * with W-class e.g. IShellLinkW etc.. the other generic classes using OLE
 * strings are managed only for Win32 apps
 */
int shortcut_resolve(struct shortcut *shortcut, const utf8_t *pathname)
{
	WCHAR targetpathw[MAX_PATH], argumentsw[MAX_PATH];
	IPersistFile *persist_file;
	WCHAR *pathnamew_p = NULL;
	IShellLinkW *shell_linkw;
	HRESULT hresult;
	int ret = -1;

	hresult = CoInitialize(NULL);
	if (FAILED(hresult)) {
		pt_windows_error_ole_set(hresult);
		return -1;
	}

	/* Instantiate a shell link interface */
	hresult = CoCreateInstance(&CLSID_ShellLink, NULL,
	                           CLSCTX_INPROC_SERVER, &IID_IShellLinkW,
	                           (void **)&shell_linkw);
	if (FAILED(hresult)) {
		pt_windows_error_ole_set(hresult);
		goto out;
	}

	/* Get to the IPersistFile interface for the shell link. */
	hresult = IShellLinkW_QueryInterface(shell_linkw, &IID_IPersistFile,
	                                     (void **)&persist_file);
	if (FAILED(hresult)) {
		pt_windows_error_ole_set(hresult);
		goto out_release;
	}

	/* Load the link file.  This function expects filename to be a
	 * LPCOLESTR type (which is always a wchar_t on 32-bit windows).
	 * Unless we need any port to Win16 LPCOLESTR is OLE32bit
	 * Input string are always UTF8 strings, CP_UTF8 needs MB_ERR_INVALID_CHARS or 0
	 */
	ret = MultiByteToWideCharDyn(CP_UTF8, MB_ERR_INVALID_CHARS, pathname,
	                    -1, &pathnamew_p);
	if (!ret)
		goto out_release;

	hresult = IPersistFile_Load(persist_file, pathnamew_p, STGM_READ);
	if (FAILED(hresult)) {
		pt_windows_error_ole_set(hresult);
		goto out_release2;
	}

	/* Try to resolve the link, and let the OS interact when the
	 * shortcut is dangling.
	 */
	if (shortcut->window_ != NULL) {
		hresult = IShellLinkW_Resolve(shell_linkw,
		                              shortcut->window_, 0);
		if (FAILED(hresult)) {
			pt_windows_error_ole_set(hresult);
			goto out_release2;
		}
	}

	/* Resolve the target pathname of the shortcut. */
	hresult = IShellLinkW_GetPath(shell_linkw, targetpathw, MAX_PATH, NULL, 0);
	if (FAILED(hresult)) {
		pt_windows_error_ole_set(hresult);
		goto out_release2;
	}

	/* Resolve the arguments of the shortcut.
	 * XXX: the arguments can be silently truncated.  The Windows API is
	 * horrible in this area.
	 */
	hresult = IShellLinkW_GetArguments(shell_linkw, argumentsw, MAX_PATH);
	/* shortcut structures holds always UTF-8 strings */
	if (SUCCEEDED(hresult))
		shortcut->arguments = pt_utf16_to_utf8(argumentsw);

	/* Initialize the structure: with UTF-8 string */
	shortcut->pathname = pt_utf16_to_utf8(targetpathw);
	ret = 0;

out_release2:
	IPersistFile_Release(persist_file);
	free(pathnamew_p);
out_release:
	IShellLinkW_Release(shell_linkw);
out:
	CoUninitialize();
	return ret;
}

void shortcut_destroy(struct shortcut *shortcut)
{
	if (shortcut->pathname != NULL)
		free(shortcut->pathname);

	if (shortcut->arguments != NULL)
		free(shortcut->arguments);
}

#ifdef TEST
int main(int argc, char **argv)
{
	struct shortcut shortcut;

	shortcut_init(&shortcut);
	if (shortcut_resolve(&shortcut, argv[1]) == -1) {
		shortcut_destroy(&shortcut);
		fprintf(stderr, "shortcut_resolve() failed: %d\n",
		        GetLastError());
		exit(EXIT_FAILURE);
	}

	printf("Target: %s\n", shortcut.pathname);
	printf("Arguments: %s\n", shortcut.arguments);

	shortcut_destroy(&shortcut);
}

#endif	/* TEST */
