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
 * ntdll.c
 *
 * libptrace windows ntdll wrapper.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <ntdef.h>
#include <libptrace/windows/error.h>
#include "common.h"
#include "ntdll.h"
#include "ntdbg.h"

/* Prototype these functions, as mingw lacks a header file for it */
NTSTATUS NTAPI NtSuspendProcess(HANDLE ProcessHandle);
NTSTATUS NTAPI NtResumeProcess(HANDLE ProcessHandle);
NTSTATUS NTAPI NtCreateThreadEx(
	PHANDLE hThread, ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes, HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	ULONG StackZeroBits,
	ULONG SizeOfStackCommit,
	ULONG SizeOfStackReserve,
	LPVOID lpBytesBuffer);
NTSTATUS NTAPI NtCreateDebugObject(
	PHANDLE DebugObjectHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG Flags);
NTSTATUS NTAPI NtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle);
NTSTATUS NTAPI NtRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugObjectHandle);
NTSTATUS NTAPI NtWaitForDebugEvent(
	HANDLE DebugObjectHandle,
	BOOLEAN Alertable,
	PLARGE_INTEGER Timeout,
	PDBGUI_WAIT_STATE_CHANGE WaitStateChange);
NTSTATUS NTAPI NtDebugContinue(
	HANDLE DebugObjectHandle,
	PCLIENT_ID ClientId,
	NTSTATUS ContinueStatus);
NTSTATUS NTAPI NtSetInformationDebugObject(
	HANDLE DebugObjectHandle,
	DEBUGOBJECTINFOCLASS InformationClass,
	PVOID Information,
	ULONG InformationLength,
	PULONG ReturnLength);

static HMODULE ntdll;
static NTSTATUS NTAPI (*NtSuspendProcess_)(HANDLE);
static NTSTATUS NTAPI (*NtResumeProcess_)(HANDLE);
static NTSTATUS NTAPI (*NtCreateThreadEx_)(PHANDLE, ACCESS_MASK, LPVOID,
	HANDLE, LPTHREAD_START_ROUTINE, LPVOID, BOOL, ULONG, ULONG, ULONG,
	LPVOID);
static NTSTATUS NTAPI (*NtQueryObject_)(HANDLE, OBJECT_INFORMATION_CLASS,
	PVOID, ULONG, PULONG);
static NTSTATUS NTAPI (*NtCreateDebugObject_)(PHANDLE, ACCESS_MASK,
	POBJECT_ATTRIBUTES, ULONG);
static NTSTATUS NTAPI (*NtDebugActiveProcess_)(HANDLE, HANDLE);
static NTSTATUS NTAPI (*NtRemoveProcessDebug_)(HANDLE, HANDLE);
static NTSTATUS NTAPI (*NtWaitForDebugEvent_)(HANDLE, BOOLEAN, PLARGE_INTEGER,
	PDBGUI_WAIT_STATE_CHANGE);
static NTSTATUS NTAPI (*NtDebugContinue_)(HANDLE, PCLIENT_ID, NTSTATUS);
static NTSTATUS NTAPI (*NtSetInformationDebugObject_)(HANDLE,
	DEBUGOBJECTINFOCLASS, PVOID, ULONG, PULONG);

static void __attribute__((constructor)) ntdll_initialize_(void)
{
	if ( (ntdll = LoadLibraryW(L"ntdll.dll")) == NULL)
		return;

	NtSuspendProcess_            = IMPORT(ntdll, NtSuspendProcess);
	NtResumeProcess_             = IMPORT(ntdll, NtResumeProcess);
	NtCreateThreadEx_            = IMPORT(ntdll, NtCreateThreadEx);
	NtQueryObject_               = IMPORT(ntdll, NtQueryObject);
	NtCreateDebugObject_         = IMPORT(ntdll, NtCreateDebugObject);
	NtDebugActiveProcess_        = IMPORT(ntdll, NtDebugActiveProcess);
	NtRemoveProcessDebug_        = IMPORT(ntdll, NtRemoveProcessDebug);
	NtWaitForDebugEvent_         = IMPORT(ntdll, NtWaitForDebugEvent);
	NtDebugContinue_             = IMPORT(ntdll, NtDebugContinue);
	NtSetInformationDebugObject_ = IMPORT(ntdll, NtSetInformationDebugObject);
}

static void __attribute__((destructor)) ntdll_destroy_(void)
{
	NtSuspendProcess_            = NULL;
	NtResumeProcess_             = NULL;
	NtCreateThreadEx_            = NULL;
	NtQueryObject_               = NULL;
	NtCreateDebugObject_         = NULL;
	NtDebugActiveProcess_        = NULL;
	NtRemoveProcessDebug_        = NULL;
	NtWaitForDebugEvent_         = NULL;
	NtDebugContinue_             = NULL;
	NtSetInformationDebugObject_ = NULL;

	if (ntdll != NULL)
		FreeLibrary(ntdll);
}

int pt_windows_api_nt_remove_process_debug(
	HANDLE ProcessHandle,
	HANDLE DebugObjectHandle)
{
	NTSTATUS ret;

	if (NtRemoveProcessDebug_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = NtRemoveProcessDebug_(ProcessHandle, DebugObjectHandle);
	if (!NT_SUCCESS(ret)) {
		pt_windows_error_winapi_set_value(RtlNtStatusToDosError(ret));
		return -1;
	}

	return 0;
}

int pt_windows_api_nt_set_information_debug_object(
	HANDLE DebugObjectHandle,
	DEBUGOBJECTINFOCLASS InformationClass,
	PVOID Information,
	ULONG InformationLength,
	PULONG ReturnLength)
{
	NTSTATUS ret;

	if (NtSetInformationDebugObject_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = NtSetInformationDebugObject_(
		DebugObjectHandle,
		InformationClass,
		Information,
		InformationLength,
		ReturnLength
	);

	if (!NT_SUCCESS(ret)) {
		pt_windows_error_winapi_set_value(RtlNtStatusToDosError(ret));
		return -1;
	}

	return 0;
}

int pt_windows_api_nt_wait_for_debug_event(
	HANDLE DebugObjectHandle,
	BOOLEAN Alertable,
	PLARGE_INTEGER Timeout,
	PDBGUI_WAIT_STATE_CHANGE WaitStateChange)
{
	NTSTATUS ret;

	if (NtWaitForDebugEvent_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = NtWaitForDebugEvent_(
		DebugObjectHandle,
		Alertable,
		Timeout,
		WaitStateChange
	);
	if (!NT_SUCCESS(ret)) {
		pt_windows_error_winapi_set_value(RtlNtStatusToDosError(ret));
		return -1;
	}

	return 0;
}

int pt_windows_api_nt_debug_active_process(
	HANDLE ProcessHandle,
	HANDLE DebugObjectHandle)
{
	NTSTATUS ret;

	if (NtDebugActiveProcess_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = NtDebugActiveProcess_(ProcessHandle, DebugObjectHandle);
	if (!NT_SUCCESS(ret)) {
		pt_windows_error_winapi_set_value(RtlNtStatusToDosError(ret));
		return -1;
	}

	return 0;
}

int pt_windows_api_nt_debug_continue(
	HANDLE DebugObjectHandle,
	PCLIENT_ID ClientId,
	NTSTATUS ContinueStatus)
{
	NTSTATUS ret;

	if (NtDebugContinue_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = NtDebugContinue_(
		DebugObjectHandle,
		ClientId,
		ContinueStatus
	);

	if (!NT_SUCCESS(ret)) {
		pt_windows_error_winapi_set_value(RtlNtStatusToDosError(ret));
		return -1;
	}

	return 0;
}

HANDLE pt_windows_api_nt_create_debug_object(
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG Flags)
{
	HANDLE DebugObjectHandle;
	NTSTATUS ret;

	if (NtCreateDebugObject_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return INVALID_HANDLE_VALUE;
	}

	ret = NtCreateDebugObject_(
		&DebugObjectHandle,
		DesiredAccess,
		ObjectAttributes,
		Flags
	);

	if (!NT_SUCCESS(ret)) {
		pt_windows_error_winapi_set_value(RtlNtStatusToDosError(ret));
		return INVALID_HANDLE_VALUE;
	}

	return DebugObjectHandle;
}

int pt_windows_api_nt_create_thread_ex(
	PHANDLE hThread, ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes, HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	ULONG StackZeroBits,
	ULONG SizeOfStackCommit,
	ULONG SizeOfStackReserve,
	LPVOID lpBytesBuffer)
{
	NTSTATUS ret;

	if (NtCreateThreadEx_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = NtCreateThreadEx_(
		hThread,
		DesiredAccess,
		ObjectAttributes,
		ProcessHandle,
		lpStartAddress,
		lpParameter,
		CreateSuspended,
		StackZeroBits,
		SizeOfStackCommit,
		SizeOfStackReserve,
		lpBytesBuffer
	);

	if (!NT_SUCCESS(ret)) {
		pt_windows_error_winapi_set_value(RtlNtStatusToDosError(ret));
		return -1;
	}

	return 0;
}

int pt_windows_api_have_nt_create_thread_ex(void)
{
	return NtCreateThreadEx_ != NULL;
}

int pt_windows_api_nt_suspend_process(HANDLE hProcess)
{
	NTSTATUS ret;

	if (NtSuspendProcess_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = NtSuspendProcess_(hProcess);
	if (!NT_SUCCESS(ret)) {
		pt_windows_error_winapi_set_value(RtlNtStatusToDosError(ret));
		return -1;
	}

	return 0;
}

int pt_windows_api_have_nt_suspend_process(void)
{
	return NtSuspendProcess_ != NULL;
}

int pt_windows_api_nt_resume_process(HANDLE hProcess)
{
	NTSTATUS ret;

	if (NtResumeProcess_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = NtResumeProcess_(hProcess);
	if (!NT_SUCCESS(ret)) {
		pt_windows_error_winapi_set_value(RtlNtStatusToDosError(ret));
		return -1;
	}

	return 0;
}

int pt_windows_api_have_nt_resume_process(void)
{
	return NtResumeProcess_ != NULL;
}

utf8_t *pt_windows_api_nt_query_object_name(HANDLE h)
{
	unsigned char *np, *p = NULL;
	unsigned char buf[256];
	utf8_t *result = NULL;
	PUNICODE_STRING pus;
	NTSTATUS ret;
	ULONG s = 0;

	if (NtQueryObject_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return NULL;
	}

	/* Try with the local buffer to see if things fit. */
	ret = NtQueryObject_(h, ObjectNameInformation, buf, sizeof buf, &s);
	if (NT_SUCCESS(ret))
		p = buf;

	/* If not reallocate while we have changing results.
	 *
	 * Result changes shouldn't happen, but this is to deal with cases
	 * where the underlying handle names would change while executing
	 * this code.
	 */
	while (!NT_SUCCESS(ret) && ret == STATUS_BUFFER_OVERFLOW) {
		if ( (np = realloc(p, s)) == NULL) {
			pt_error_errno_set(errno);
			goto out_free;
		}

		p = np;
		ret = NtQueryObject_(h, ObjectNameInformation, p, s, &s);
	}

	/* Handle all non-STATUS_BUFFER_OVERFLOW errors. */
	if (!NT_SUCCESS(ret)) {
		pt_windows_error_winapi_set_value(RtlNtStatusToDosError(ret));
		goto out_free;
	}

	pus = (PUNICODE_STRING)p;
	if (pus->Buffer == NULL || pus->Length == 0) {
		pt_error_internal_set(PT_ERROR_NOT_FOUND);
		goto out_free;
	}

	/* Convert the resulting name to utf-8. */
	result = pt_utf16_to_utf8(pus->Buffer);

out_free:
	/* If we have dynamically allocated 'p', clean it up. */
	if (p != buf)
		free(p);

	return result;
}

int pt_windows_api_nt_query_object(
	HANDLE Handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength)
{
	NTSTATUS ret;

	if (NtQueryObject_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = NtQueryObject_(
		Handle,
		ObjectInformationClass,
		ObjectInformation,
		ObjectInformationLength,
		ReturnLength
	);

	if (!NT_SUCCESS(ret)) {
		pt_windows_error_winapi_set_value(RtlNtStatusToDosError(ret));
		return -1;
	}

	return 0;
}
