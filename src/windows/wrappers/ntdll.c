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
static NTSTATUS NTAPI (*__NtSuspendProcess)(HANDLE);
static NTSTATUS NTAPI (*__NtResumeProcess)(HANDLE);
static NTSTATUS NTAPI (*__NtCreateThreadEx)(PHANDLE, ACCESS_MASK, LPVOID,
	HANDLE, LPTHREAD_START_ROUTINE, LPVOID, BOOL, ULONG, ULONG, ULONG,
	LPVOID);
static NTSTATUS NTAPI (*__NtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS,
	PVOID, ULONG, PULONG);
static NTSTATUS NTAPI (*__NtCreateDebugObject)(PHANDLE, ACCESS_MASK,
	POBJECT_ATTRIBUTES, ULONG);
static NTSTATUS NTAPI (*__NtDebugActiveProcess)(HANDLE, HANDLE);
static NTSTATUS NTAPI (*__NtRemoveProcessDebug)(HANDLE, HANDLE);
static NTSTATUS NTAPI (*__NtWaitForDebugEvent)(HANDLE, BOOLEAN, PLARGE_INTEGER,
	PDBGUI_WAIT_STATE_CHANGE);
static NTSTATUS NTAPI (*__NtDebugContinue)(HANDLE, PCLIENT_ID, NTSTATUS);
static NTSTATUS NTAPI (*__NtSetInformationDebugObject)(HANDLE,
	DEBUGOBJECTINFOCLASS, PVOID, ULONG, PULONG);

static void __attribute__((constructor)) __ntdll_initialize(void)
{
	if ( (ntdll = LoadLibraryW(L"ntdll.dll")) == NULL)
		return;

	__NtSuspendProcess            = IMPORT(ntdll, NtSuspendProcess);
	__NtResumeProcess             = IMPORT(ntdll, NtResumeProcess);
	__NtCreateThreadEx            = IMPORT(ntdll, NtCreateThreadEx);
	__NtQueryObject               = IMPORT(ntdll, NtQueryObject);
	__NtCreateDebugObject         = IMPORT(ntdll, NtCreateDebugObject);
	__NtDebugActiveProcess        = IMPORT(ntdll, NtDebugActiveProcess);
	__NtRemoveProcessDebug        = IMPORT(ntdll, NtRemoveProcessDebug);
	__NtWaitForDebugEvent         = IMPORT(ntdll, NtWaitForDebugEvent);
	__NtDebugContinue             = IMPORT(ntdll, NtDebugContinue);
	__NtSetInformationDebugObject = IMPORT(ntdll, NtSetInformationDebugObject);
}

static void __attribute((destructor)) __ntdll_destroy(void)
{
	__NtSuspendProcess            = NULL;
	__NtResumeProcess             = NULL;
	__NtCreateThreadEx            = NULL;
	__NtQueryObject               = NULL;
	__NtCreateDebugObject         = NULL;
	__NtDebugActiveProcess        = NULL;
	__NtRemoveProcessDebug        = NULL;
	__NtWaitForDebugEvent         = NULL;
	__NtDebugContinue             = NULL;
	__NtSetInformationDebugObject = NULL;

	if (ntdll != NULL)
		FreeLibrary(ntdll);
}

int pt_windows_api_nt_remove_process_debug(
	HANDLE ProcessHandle,
	HANDLE DebugObjectHandle)
{
	NTSTATUS ret;

	if (__NtRemoveProcessDebug == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = __NtRemoveProcessDebug(ProcessHandle, DebugObjectHandle);
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

	if (__NtSetInformationDebugObject == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = __NtSetInformationDebugObject(
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

	if (__NtWaitForDebugEvent == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = __NtWaitForDebugEvent(
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

	if (__NtDebugActiveProcess == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = __NtDebugActiveProcess(ProcessHandle, DebugObjectHandle);
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

	if (__NtDebugContinue == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = __NtDebugContinue(
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

	if (__NtCreateDebugObject == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return INVALID_HANDLE_VALUE;
	}

	ret = __NtCreateDebugObject(
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

	if (__NtCreateThreadEx == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = __NtCreateThreadEx(
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
	return __NtCreateThreadEx != NULL;
}

int pt_windows_api_nt_suspend_process(HANDLE hProcess)
{
	NTSTATUS ret;

	if (__NtSuspendProcess == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = __NtSuspendProcess(hProcess);
	if (!NT_SUCCESS(ret)) {
		pt_windows_error_winapi_set_value(RtlNtStatusToDosError(ret));
		return -1;
	}

	return 0;
}

int pt_windows_api_have_nt_suspend_process(void)
{
	return __NtSuspendProcess != NULL;
}

int pt_windows_api_nt_resume_process(HANDLE hProcess)
{
	NTSTATUS ret;

	if (__NtResumeProcess == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = __NtResumeProcess(hProcess);
	if (!NT_SUCCESS(ret)) {
		pt_windows_error_winapi_set_value(RtlNtStatusToDosError(ret));
		return -1;
	}

	return 0;
}

int pt_windows_api_have_nt_resume_process(void)
{
	return __NtResumeProcess != NULL;
}

utf8_t *pt_windows_api_nt_query_object_name(HANDLE h)
{
	unsigned char *np, *p = NULL;
	unsigned char buf[256];
	utf8_t *result;
	NTSTATUS ret;
	ULONG s = 0;

	if (__NtQueryObject == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return NULL;
	}

	/* Try with the local buffer to see if things fit. */
	ret = __NtQueryObject(h, ObjectNameInformation, buf, sizeof buf, &s);
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

			if (p != NULL)
				free(p);

			return NULL;
		}

		p = np;
		ret = __NtQueryObject(h, ObjectNameInformation, p, s, &s);
	}

	/* Handle all non-STATUS_BUFFER_OVERFLOW errors. */
	if (!NT_SUCCESS(ret)) {
		pt_windows_error_winapi_set_value(RtlNtStatusToDosError(ret));
		return NULL;
	}

	/* Convert the resulting name to utf-8. */
	result = pt_utf16_to_utf8(((PUNICODE_STRING)p)->Buffer);

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

	if (__NtQueryObject == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = __NtQueryObject(
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
