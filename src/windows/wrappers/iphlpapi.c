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
 * iphlpapi.c
 *
 * libptrace windows iphlpapi wrapper.
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
#include "iphlpapi.h"

/* Prototypes of deprecated functions.
 * These are used to support Windows XP SP1 and before.
 */
DWORD WINAPI
AllocateAndGetTcpExTableFromStack(PVOID *, BOOL, HANDLE, DWORD, DWORD);
DWORD WINAPI
AllocateAndGetUdpExTableFromStack(PVOID *, BOOL, HANDLE, DWORD, DWORD);

static HMODULE iphlpapi;
static DWORD WINAPI (*AllocateAndGetTcpExTableFromStack_)
	(PVOID *, BOOL, HANDLE, DWORD, DWORD);
static DWORD WINAPI (*AllocateAndGetUdpExTableFromStack_)
	(PVOID *, BOOL, HANDLE, DWORD, DWORD);

static void __attribute__((constructor)) iphlpapi_initialize_(void)
{
	if ( (iphlpapi = LoadLibraryW(L"iphlpapi.dll")) == NULL)
		return;

	AllocateAndGetTcpExTableFromStack_ =
		IMPORT(iphlpapi, AllocateAndGetTcpExTableFromStack);
	AllocateAndGetUdpExTableFromStack_ =
		IMPORT(iphlpapi, AllocateAndGetUdpExTableFromStack);
}

static void __attribute__((destructor)) iphlpapi_destroy_(void)
{
	AllocateAndGetTcpExTableFromStack_ = NULL;
	AllocateAndGetUdpExTableFromStack_ = NULL;

	if (iphlpapi != NULL)
		FreeLibrary(iphlpapi);
}

int pt_windows_api_allocate_and_get_tcp_ex_table_from_stack(
	PVOID *ppTcpTable,
	BOOL bOrder,
	HANDLE hHeap,
	DWORD dwFlags,
	DWORD dwFamily)
{
	DWORD ret;

	if (AllocateAndGetTcpExTableFromStack_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = AllocateAndGetTcpExTableFromStack_(
		ppTcpTable,
		bOrder,
		hHeap,
		dwFlags,
		dwFamily
	);

	if (ret != ERROR_SUCCESS) {
		pt_windows_error_winapi_set_value(ret);
		return -1;
	}

	return 0;
}

int pt_windows_api_allocate_and_get_udp_ex_table_from_stack(
	PVOID *ppUDPTable,
	BOOL bOrder,
	HANDLE hHeap,
	DWORD dwFlags,
	DWORD dwFamily)
{
	DWORD ret;

	if (AllocateAndGetUdpExTableFromStack_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = AllocateAndGetUdpExTableFromStack_(
		ppUDPTable,
		bOrder,
		hHeap,
		dwFlags,
		dwFamily
	);

	if (ret != ERROR_SUCCESS) {
		pt_windows_error_winapi_set_value(ret);
		return -1;
	}

	return 0;
}

