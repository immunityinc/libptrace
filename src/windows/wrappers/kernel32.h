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
 * kernel32.h
 *
 * libptrace windows kernel32 wrapper.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_WINDOWS_API_KERNEL32_H
#define PT_WINDOWS_API_KERNEL32_H

#include <windows.h>
#include <libptrace/charset.h>
#include "../../stringlist.h"

#ifdef __cplusplus
extern "C" {
#endif

int pt_windows_api_wow64_get_thread_context(HANDLE, PWOW64_CONTEXT);
int pt_windows_api_wow64_set_thread_context(HANDLE, const WOW64_CONTEXT *);
int pt_windows_api_suspend_thread(HANDLE);
int pt_windows_api_wow64_suspend_thread(HANDLE);
int pt_windows_api_get_process_times(HANDLE, LPFILETIME, LPFILETIME,
                                     LPFILETIME, LPFILETIME);
DWORD pt_windows_api_get_thread_id(HANDLE);
HANDLE pt_windows_api_open_thread(DWORD, BOOL, DWORD);
int pt_windows_api_debug_set_process_kill_on_exit(BOOL KillOnExit);
int pt_windows_api_is_wow64_process(HANDLE hProcess, PBOOL Wow64Process);
SIZE_T pt_windows_api_virtual_query_ex(HANDLE hProcess, LPCVOID lpAddress,
                                       PMEMORY_BASIC_INFORMATION lpBuffer,
                                       SIZE_T dwLength);
HMODULE pt_windows_load_library(const utf8_t *name);
HMODULE pt_windows_get_module_handle(const utf8_t *name);
FARPROC pt_windows_get_proc_address(HMODULE h, const char *procname);
int pt_windows_api_get_logical_drive_strings(struct pt_string_list *pathnames);
utf8_t *pt_windows_api_query_dos_device(const utf8_t *devicename);
int pt_windows_api_get_drive_type(const utf8_t *pathname);

int pt_windows_api_have_get_process_times(void);
int pt_windows_api_have_get_thread_id(void);
int pt_windows_api_have_open_thread(void);
int pt_windows_api_have_debug_set_process_kill_on_exit(void);
int pt_windows_api_have_is_wow64_process(void);
int pt_windows_api_have_virtual_query_ex(void);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_WINDOWS_API_KERNEL32_H */
