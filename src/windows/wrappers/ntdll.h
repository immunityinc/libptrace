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
 * ntdll.h
 *
 * libptrace windows ntdll wrapper.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_WINDOWS_API_NTDLL_H
#define PT_WINDOWS_API_NTDLL_H

#include <windows.h>
#include "ntdbg.h"

#ifdef __cplusplus
extern "C" {
#endif

int pt_windows_api_nt_remove_process_debug(
        HANDLE ProcessHandle,
        HANDLE DebugObjectHandle);
int pt_windows_api_nt_set_information_debug_object(
        HANDLE DebugObjectHandle,
        DEBUGOBJECTINFOCLASS InformationClass,
        PVOID Information,
        ULONG InformationLength,
        PULONG ReturnLength);
HANDLE pt_windows_api_nt_create_debug_object(
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG Flags);
int pt_windows_api_nt_wait_for_debug_event(
        HANDLE DebugObjectHandle,
        BOOLEAN Alertable,
        PLARGE_INTEGER Timeout,
        PDBGUI_WAIT_STATE_CHANGE WaitStateChange);
int pt_windows_api_nt_debug_continue(
	HANDLE DebugObjectHandle,
	PCLIENT_ID ClientId,
	NTSTATUS ContinueStatus);
int pt_windows_api_nt_debug_active_process(
	HANDLE ProcessHandle,
	HANDLE DebugObjectHandle);
int pt_windows_api_nt_suspend_process(HANDLE);
int pt_windows_api_nt_resume_process(HANDLE);
int pt_windows_api_nt_create_thread_ex(
	PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE,
	LPVOID, BOOL, ULONG, ULONG, ULONG, LPVOID);
int pt_windows_api_have_nt_create_thread_ex(void);
int pt_windows_api_have_nt_suspend_process(void);
int pt_windows_api_have_nt_resume_process(void);

utf8_t *pt_windows_api_nt_query_object_name(HANDLE);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_WINDOWS_API_NTDLL_H */
