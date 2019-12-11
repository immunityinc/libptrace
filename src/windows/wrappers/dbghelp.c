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
 * dbghelp.c
 *
 * libptrace windows dbghelp wrapper.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <windows.h>
#include <dbghelp.h>
#include <libptrace/charset.h>
#include <libptrace/windows/error.h>
#include "common.h"
#include "dbghelp.h"

static HMODULE dbghelp;
static BOOL    WINAPI (*SymInitializeW_)(HANDLE, PCWSTR, BOOL);
static DWORD   WINAPI (*SymSetOptions_)(DWORD);
static BOOL    WINAPI (*SymSetSearchPathW_)(HANDLE, PCWSTR);
static BOOL    WINAPI (*SymUnloadModule64_)(HANDLE, DWORD64);
static BOOL    WINAPI (*SymCleanup_)(HANDLE);
static DWORD   WINAPI (*UnDecorateSymbolNameW_)(PCWSTR, PWSTR, DWORD, DWORD);
static DWORD64 WINAPI (*SymLoadModuleExW_)(HANDLE, HANDLE, PCWSTR, PCWSTR,
                                           DWORD64, DWORD, PMODLOAD_DATA,
                                           DWORD);
static BOOL    WINAPI (*SymUnloadModule64_)(HANDLE, DWORD64);
static BOOL    WINAPI (*SymGetModuleInfoW64_)(HANDLE, DWORD64, PIMAGEHLP_MODULEW64);
static BOOL    WINAPI (*SymEnumSymbolsW_)(HANDLE, ULONG64, PCWSTR,
                                          PSYM_ENUMERATESYMBOLS_CALLBACKW,
                                          const PVOID);

static void __attribute__((constructor)) dbghelp_initialize_(void)
{
	if ( (dbghelp = LoadLibraryW(L"dbghelp.dll")) == NULL)
		return;

	SymInitializeW_        = IMPORT(dbghelp, SymInitializeW);
	SymSetOptions_         = IMPORT(dbghelp, SymSetOptions);
	SymSetSearchPathW_     = IMPORT(dbghelp, SymSetSearchPathW);
	SymUnloadModule64_     = IMPORT(dbghelp, SymUnloadModule64);
	SymCleanup_            = IMPORT(dbghelp, SymCleanup);
	UnDecorateSymbolNameW_ = IMPORT(dbghelp, UnDecorateSymbolNameW);
	SymLoadModuleExW_      = IMPORT(dbghelp, SymLoadModuleExW);
	SymUnloadModule64_     = IMPORT(dbghelp, SymUnloadModule64);
	SymGetModuleInfoW64_   = IMPORT(dbghelp, SymGetModuleInfoW64);
	SymEnumSymbolsW_       = IMPORT(dbghelp, SymEnumSymbolsW);
}

static void __attribute__((destructor)) dbghelp_destroy_(void)
{
	SymInitializeW_        = NULL;
	SymSetOptions_         = NULL;
	SymSetSearchPathW_     = NULL;
	SymUnloadModule64_     = NULL;
	SymCleanup_            = NULL;
	UnDecorateSymbolNameW_ = NULL;
	SymLoadModuleExW_      = NULL;
	SymUnloadModule64_     = NULL;
	SymGetModuleInfoW64_   = NULL;
	SymEnumSymbolsW_       = NULL;

	if (dbghelp != NULL)
		FreeLibrary(dbghelp);
}

static BOOL CALLBACK sym_enum_symbols_adapter_(
	PSYMBOL_INFOW	pSymInfo,
	ULONG		SymbolSize,
	PVOID		UserContext)
{
	pt_windows_api_sym_enum_symbols_callback_t EnumSymbolsCallback =
		(pt_windows_api_sym_enum_symbols_callback_t)((PVOID **)UserContext)[0];
	PVOID OldContext = ((PVOID **)UserContext)[1];
	struct pt_windows_api_symbol_info syminfo;

	/* Adapt PSYMBOLINFO_W to pt_windows_api_symbol_info. */
	syminfo.TypeIndex   = pSymInfo->TypeIndex;
	syminfo.Reserved[0] = pSymInfo->Reserved[0];
	syminfo.Reserved[1] = pSymInfo->Reserved[1];
	syminfo.Index       = pSymInfo->info;	/* XXX: mingw calls this member info ??? */
	syminfo.Size        = pSymInfo->Size;
	syminfo.ModBase     = pSymInfo->ModBase;
	syminfo.Flags       = pSymInfo->Flags;
	syminfo.Value       = pSymInfo->Value;
	syminfo.Address     = pSymInfo->Address;
	syminfo.Register    = pSymInfo->Register;
	syminfo.Scope       = pSymInfo->Scope;
	syminfo.Tag         = pSymInfo->Tag;
	syminfo.Name        = pt_utf16_to_utf8(pSymInfo->Name);

	return EnumSymbolsCallback(&syminfo, SymbolSize, OldContext);
}

int pt_windows_api_sym_enum_symbols(
	HANDLE		hProcess,
	ULONG64		BaseOfDll,
	const utf8_t	*Mask,
	pt_windows_api_sym_enum_symbols_callback_t EnumSymbolsCallback,
	const PVOID	UserContext)
{
	PVOID NewContext[2] = { EnumSymbolsCallback, UserContext };
	LPWSTR MaskW = NULL;
	BOOL ret;

	if (SymEnumSymbolsW_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (Mask != NULL && (MaskW = pt_utf8_to_utf16(Mask)) == NULL)
		return -1;

	ret = SymEnumSymbolsW_(
		hProcess,
		BaseOfDll,
		MaskW,
		sym_enum_symbols_adapter_,
		NewContext
	);

	if (MaskW)
		free(MaskW);

	if (ret == FALSE) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

void pt_windows_api_imagehlp_module64_destroy(struct pt_windows_api_imagehlp_module64 *p)
{
	if (p->ModuleName)
		free(p->ModuleName);

	if (p->ImageName)
		free(p->ImageName);

	if (p->LoadedImageName)
		free(p->LoadedImageName);

	if (p->LoadedPdbName)
		free(p->LoadedPdbName);

	if (p->CVData)
		free(p->CVData);
}

int pt_windows_api_sym_get_module_info64(
	HANDLE hProcess,
	DWORD64 dwAddr,
	struct pt_windows_api_imagehlp_module64 *ModuleInfo)
{
	utf8_t *modulename, *imagename, *loadedimagename, *loadedpdbname;
	IMAGEHLP_MODULEW64 modinfo;
	utf8_t *cvdata;

	if (SymGetModuleInfoW64_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		goto err;
	}

	modinfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
	if (SymGetModuleInfoW64_(hProcess, dwAddr, &modinfo) == FALSE) {
		pt_windows_error_winapi_set();
		goto err;
	}

	if ( (modulename = pt_utf16_to_utf8(modinfo.ModuleName)) == NULL)
		goto err;

	if ( (imagename = pt_utf16_to_utf8(modinfo.ImageName)) == NULL)
		goto err_modulename;

	if ( (loadedimagename = pt_utf16_to_utf8(modinfo.LoadedImageName)) == NULL)
		goto err_imagename;

	if ( (loadedpdbname = pt_utf16_to_utf8(modinfo.LoadedPdbName)) == NULL)
		goto err_loadedimagename;

	if ( (cvdata = pt_utf16_to_utf8(modinfo.CVData)) == NULL)
		goto err_loadedpdbname;

	/* Adapt IMAGEHLP_MODULE64 to struct pt_imagehlp_module64. */
	ModuleInfo->BaseOfImage     = modinfo.BaseOfImage;
	ModuleInfo->ImageSize       = modinfo.ImageSize;
	ModuleInfo->TimeDateStamp   = modinfo.TimeDateStamp;
	ModuleInfo->CheckSum        = modinfo.CheckSum;
	ModuleInfo->NumSyms         = modinfo.NumSyms;
	ModuleInfo->SymType         = modinfo.SymType;
	ModuleInfo->ModuleName      = modulename;
	ModuleInfo->ImageName       = imagename;
	ModuleInfo->LoadedImageName = loadedimagename;
	ModuleInfo->LoadedPdbName   = loadedpdbname;
	ModuleInfo->CVSig           = modinfo.CVSig;
	ModuleInfo->CVData          = cvdata;
	ModuleInfo->PdbSig          = modinfo.PdbSig;
	ModuleInfo->PdbSig70        = modinfo.PdbSig70;
	ModuleInfo->PdbAge          = modinfo.PdbAge;
	ModuleInfo->PdbUnmatched    = modinfo.PdbUnmatched;
	ModuleInfo->DbgUnmatched    = modinfo.DbgUnmatched;
	ModuleInfo->LineNumbers     = modinfo.LineNumbers;
	ModuleInfo->GlobalSymbols   = modinfo.GlobalSymbols;
	ModuleInfo->TypeInfo        = modinfo.TypeInfo;
	ModuleInfo->SourceIndexed   = modinfo.SourceIndexed;
	ModuleInfo->Publics         = modinfo.Publics;

	return 0;

err_loadedpdbname:
	free(loadedpdbname);
err_loadedimagename:
	free(loadedimagename);
err_imagename:
	free(imagename);
err_modulename:
	free(modulename);
err:
	return -1;
}

int pt_windows_api_sym_uynload_module64(HANDLE hProcess, DWORD64 BaseOfDll)
{
	if (SymUnloadModule64_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (SymUnloadModule64_(hProcess, BaseOfDll) == FALSE) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

DWORD64 pt_windows_api_sym_load_module_ex(
	HANDLE hProcess,
	HANDLE hFile,
	const utf8_t *ImageName,
	const utf8_t *ModuleName,
	DWORD64 BaseOfDll,
	DWORD DllSize,
	PMODLOAD_DATA Data,
	DWORD Flags)
{
	LPWSTR ImageNameW, ModuleNameW;
	DWORD64 ret;

	if (SymLoadModuleExW_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return 0;
	}

	if ( (ImageNameW = pt_utf8_to_utf16(ImageName)) == NULL)
		return 0;

	if ( (ModuleNameW = pt_utf8_to_utf16(ModuleName)) == NULL) {
		free(ImageNameW);
		return 0;
	}

	ret = SymLoadModuleExW_(hProcess, hFile, ImageNameW, ModuleNameW,
	                         BaseOfDll, DllSize, Data, Flags);
	if (ret == 0)
		pt_windows_error_winapi_set();

	free(ImageNameW);
	free(ModuleNameW);

	return ret;
}

int
pt_windows_api_sym_initialize(HANDLE h, const utf8_t *search_path, BOOL invade)
{
	LPWSTR search_pathw = NULL;
	BOOL ret;

	if (SymInitializeW_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (search_path != NULL) {
		if ( (search_pathw = pt_utf8_to_utf16(search_path)) == NULL)
			return -1;
	}

	ret = SymInitializeW_(h, search_pathw, invade);

	if (search_pathw != NULL)
		free(search_pathw);

	if (ret == FALSE) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_sym_set_options(DWORD options, DWORD *old)
{
	DWORD ret;

	if (SymSetOptions_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	ret = SymSetOptions_(options);
	if (old != NULL)
		*old = ret;

	return 0;
}

utf8_t *pt_windows_api_undecorate_symbol_name(const utf8_t *name, DWORD flags)
{
	PWSTR wname, wuname;
	utf8_t *ret = NULL;
	DWORD count;
	size_t len;

	if (UnDecorateSymbolNameW_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		goto out;
	}

	if ( (wname = pt_utf8_to_utf16(name)) == NULL)
		goto out;

	/* Undecorating should only remove characters, so in the worst case
	 * we get a string of equal length.
	 * XXX: this is an unverified assumption.
	 */
	len = wcslen(wname) + 1;
	if ( (wuname = malloc(len * sizeof(WCHAR))) == NULL) {
		pt_error_errno_set(errno);
		goto out_wname;
	}

	count = UnDecorateSymbolNameW_(wname, wuname, len, flags);
	if (count == 0) {
		pt_windows_error_winapi_set();
		goto out_wuname;
	}

	ret = pt_utf16_to_utf8(wuname);

out_wuname:
	free(wuname);
out_wname:
	free(wname);
out:
	return ret;
}

int pt_windows_api_sym_cleanup(HANDLE h)
{
	if (SymCleanup_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (SymCleanup_(h) == FALSE) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_sym_unload_module64(HANDLE h, DWORD64 base)
{
	if (SymUnloadModule64_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (SymUnloadModule64_(h, base) == FALSE) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

int pt_windows_api_sym_set_search_path(HANDLE h, const utf8_t *path)
{
	PCWSTR wpath;

	if (SymSetSearchPathW_ == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if ( (wpath = pt_utf8_to_utf16(path)) == NULL)
                return -1;

	if (SymSetSearchPathW_(h, wpath) == FALSE) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}
