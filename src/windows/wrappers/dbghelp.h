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
 * dbghelp.h
 *
 * libptrace windows dbghelp wrapper.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_WINDOWS_API_DBGHELP_H
#define PT_WINDOWS_API_DBGHELP_H

#include <windows.h>
#include <dbghelp.h>
#include <libptrace/charset.h>

struct pt_windows_api_symbol_info
{
	ULONG	TypeIndex;
	ULONG64	Reserved[2];
	ULONG	Index;
	ULONG	Size;
	ULONG64	ModBase;
	ULONG	Flags;
	ULONG64	Value;
	ULONG64	Address;
	ULONG	Register;
	ULONG	Scope;
	ULONG	Tag;
	utf8_t	*Name;
};

struct pt_windows_api_imagehlp_module64
{
	DWORD64  BaseOfImage;
	DWORD    ImageSize;
	DWORD    TimeDateStamp;
	DWORD    CheckSum;
	DWORD    NumSyms;
	SYM_TYPE SymType;
	utf8_t	 *ModuleName;
	utf8_t   *ImageName;
	utf8_t   *LoadedImageName;
	utf8_t   *LoadedPdbName;
	DWORD    CVSig;
	utf8_t   *CVData;
	DWORD    PdbSig;
	GUID     PdbSig70;
	DWORD    PdbAge;
	BOOL     PdbUnmatched;
	BOOL     DbgUnmatched;
	BOOL     LineNumbers;
	BOOL     GlobalSymbols;
	BOOL     TypeInfo;
	BOOL     SourceIndexed;
	BOOL     Publics;
};

typedef BOOL (*pt_windows_api_sym_enum_symbols_callback_t)(
	struct pt_windows_api_symbol_info *pSymInfo,
	ULONG SymbolSize,
	PVOID UserContext
);

#ifdef __cplusplus
extern "C" {
#endif

int pt_windows_api_sym_enum_symbols(HANDLE, ULONG64, const utf8_t *,
	pt_windows_api_sym_enum_symbols_callback_t, const PVOID);
void pt_windows_api_imagehlp_module64_destroy(struct pt_windows_api_imagehlp_module64 *);
int pt_windows_api_sym_get_module_info64(HANDLE, DWORD64, struct pt_windows_api_imagehlp_module64 *);
int pt_windows_api_sym_unload_module64(HANDLE, DWORD64);
DWORD64 pt_windows_api_sym_load_module_ex(HANDLE, HANDLE, const utf8_t *,
        const utf8_t *, DWORD64, DWORD, PMODLOAD_DATA, DWORD);
int pt_windows_api_sym_initialize(HANDLE, const utf8_t *, BOOL);
int pt_windows_api_sym_set_options(DWORD options, DWORD *old);
utf8_t *pt_windows_api_undecorate_symbol_name(const utf8_t *name, DWORD flags);
int pt_windows_api_sym_cleanup(HANDLE h);
int pt_windows_api_sym_unload_module64(HANDLE h, DWORD64 base);
int pt_windows_api_sym_set_search_path(HANDLE h, const utf8_t *path);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_WINDOWS_API_DBGHELP_H */
