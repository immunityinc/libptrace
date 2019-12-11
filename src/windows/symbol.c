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
 * symbol.c
 *
 * libptrace windows symbol management.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Massimiliano Oldani <max@immunityinc.com>
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <windows.h>
#include <libptrace/log.h>
#include <libptrace/windows/error.h>
#include "../avl.h"
#include "process.h"
#include "symbol.h"
#include "module.h"
#include "wrappers/dbghelp.h"

static const utf8_t *symbols_search_path;

static int
pt_windows_symbol_mngr_init(struct pt_symbol_manager *sm)
{
	DWORD opt_flags = SYMOPT_LOAD_LINES |
	                  SYMOPT_FAIL_CRITICAL_ERRORS |
	                  SYMOPT_NO_PROMPTS;
	HANDLE h = pt_windows_process_handle_get(sm->process);

	if (pt_windows_api_sym_initialize(h, NULL, FALSE) == -1)
		return -1;

	/* since we're not scanning the process when attaching, let's call
	 * the SymSetOptions after the library initialization (function can't fail)
	 */
	pt_windows_api_sym_set_options(opt_flags, NULL);
	pt_log("%s(): initialized succesfully, now setting search path if present\n", __FUNCTION__);

	/* If we have no symbols search path, we're done. */
	if (symbols_search_path == NULL)
		return 0;

	pt_log("%s(): custom search path present: %s\n", __FUNCTION__, symbols_search_path);
	if (pt_windows_api_sym_set_search_path(h, symbols_search_path) == -1)
		pt_log("%s(): failed to set up search path: %S\n", __FUNCTION__, symbols_search_path);

	return 0;
}

static void pt_windows_symbol_mngr_release(struct pt_symbol_manager *smgr)
{
	pt_windows_api_sym_cleanup(smgr->process);
}

static int
pt_windows_symbol_mngr_module_load(struct pt_module *m)
{
	HANDLE hprocess = pt_windows_process_handle_get(m->process);
	HANDLE hfile = pt_windows_module_handle_get(m);
	struct pt_os_symbol_info_header_ *info;
	DWORD64 ret;
	BOOL err;

	/* module has been already loaded, BUG? */
	assert(m->s_cache->info == NULL);
	if (m->s_cache->info)
		return 0;

	ret = pt_windows_api_sym_load_module_ex(
		hprocess,
		hfile,
		m->pathname,
		m->name,
		(DWORD64)(uintptr_t)m->base,
		0,
		NULL,
		0
	);

	/* If module is already loaded, ret == 0 && ERROR_SUCCESS */
	if (ret == 0 && pt_windows_error_winapi_test(ERROR_SUCCESS) == 0) {
		pt_log("%s(): unable to load module: %s\n",
		       __FUNCTION__, pt_error_strerror());
		return -1;
	}

	/* set the correct info */
	if ( (info = malloc(sizeof(*info))) == NULL) {
		pt_error_errno_set(errno);
		return -1;
	}

	err = pt_windows_api_sym_get_module_info64(
		hprocess,
		(DWORD64)(uintptr_t)m->base,
		&info->imagehlp
	);
	if (err == -1) {
		free(info);
		return -1;
	}

	pt_log("%s(): succesfully loaded symbol for module: %s at base: %p info: PDB: %s\n",
		   __FUNCTION__, m->pathname, m->base, info->imagehlp.SymType == SymPdb ? "YES" : "NO");

	/* set the actual info field in the module cache manager */
	m->s_cache->info = info;

	return 0;
}

int
pt_windows_symbol_mngr_module_unload(struct pt_module *m)
{
	HANDLE h = pt_windows_process_handle_get(m->process);
	DWORD64 base = (DWORD64)(uintptr_t)m->base;

	pt_log("%s(): unloading symbol for module: %s at base: %p\n",
	       __FUNCTION__, m->pathname, m->base);

	return pt_windows_api_sym_unload_module64(h, base);
}

struct enum_symbol_ctx
{
	const utf8_t	*symname;
	struct pt_module *module;
	struct pt_symbol_entry *first;
	unsigned int resolved;

	/* when TRUE, return immediatly after the first symbol resolve */
	BOOL once;
};

inline static struct enum_symbol_ctx *
ctx_get(const utf8_t *symname, struct pt_module *module, BOOL once)
{
	struct enum_symbol_ctx *ctx;

	assert(module != NULL);

	if ( (ctx = malloc(sizeof(*ctx))) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	ctx->symname = symname;
	ctx->module  = module;
	ctx->first = NULL;
	ctx->resolved = 0;
	ctx->once = once;

	return ctx;
}

inline static void ctx_put(struct enum_symbol_ctx *ctx, BOOL free_sym)
{
	assert(ctx != NULL);

	if (free_sym)
		pt_symbol_free(&ctx->first);

	free(ctx);
}

static inline utf8_t *undecorate_(const utf8_t *symname)
{
	DWORD flags = UNDNAME_COMPLETE;
	return pt_windows_api_undecorate_symbol_name(symname, flags);
}

static struct pt_symbol_entry *
ctx_insert_sym(struct pt_windows_api_symbol_info *psym, struct enum_symbol_ctx *ctx)
{
	struct pt_symbol_entry *new_sym;

	assert(psym != NULL);
	assert(ctx != NULL);

	if ( (new_sym = malloc(sizeof(*new_sym))) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	/* new_sym will take ownership of psym->Name */
	new_sym->symname = psym->Name;

	/* is it a decorated symbol ? */
	if (new_sym->symname[0] == '?')
		new_sym->undecorated_symname = undecorate_(new_sym->symname);
	else
		new_sym->undecorated_symname = NULL;

	new_sym->module_addr      = (PVOID)(uintptr_t)psym->ModBase;
	new_sym->flags            = psym->Flags;
	new_sym->addr             = (PVOID)(uintptr_t)psym->Address;

	if (psym->Flags & SYMFLAG_VALUEPRESENT)
		new_sym->value  = psym->Value;

	new_sym->tag              = psym->Tag;
	new_sym->module           = ctx->module;
	new_sym->next             = NULL;

	/* insert the new symbol */
	struct pt_symbol_entry **next_sym = &(ctx->first);
	while(*next_sym)
		next_sym = &((*next_sym)->next);
	*next_sym = new_sym;

	return new_sym;
}

static BOOL
enum_symbols_(struct pt_windows_api_symbol_info *pSymInfo, ULONG SymbolSize, PVOID UserContext)
{
	struct enum_symbol_ctx *ctx = (struct enum_symbol_ctx *)UserContext;
	struct pt_symbol_entry *sym_entry = NULL;

	assert(pSymInfo != NULL);
	assert(UserContext != NULL);

	pt_log("%s(): callback symbol resolved: %s (sym size arg: %ld)\n",
		__FUNCTION__, pSymInfo->Name, SymbolSize);

	sym_entry = ctx_insert_sym(pSymInfo, ctx);

	if (sym_entry) {
		ctx->resolved++;
		/* stop the enumeration if requested */
		if (ctx->once == TRUE)
			return FALSE;
	} else if (pSymInfo->Name) {
		free(pSymInfo->Name);
	}

	return TRUE;
}

static struct pt_symbol_entry *
windows_symbol_enum(const utf8_t *symname, struct pt_module *module, BOOL once)
{
	HANDLE hprocess = pt_windows_process_handle_get(module->process);
	struct enum_symbol_ctx *ctx;
	int ret;

	if ( (ctx = ctx_get(symname, module, once)) == NULL)
		return NULL;

	ret = pt_windows_api_sym_enum_symbols(
		hprocess,
		(ULONG64)(uintptr_t)module->base,
		symname,
		enum_symbols_,
		ctx
	);

	if (ret == -1) {
		pt_log("%s(): SymEnumSymbols error: %s\n", __FUNCTION__,
		       pt_error_strerror());
		ctx_put(ctx, TRUE);
		return NULL;
	}

	struct pt_symbol_entry *sym_returned = ctx->first;
	ctx_put(ctx, FALSE);

	return sym_returned;
}

static struct pt_symbol_entry *resolve_symbol_(
	const utf8_t *symbol_name,
	struct pt_module  *module,
	int flags)
{
	struct pt_symbol_entry *sym;
	BOOL once = (flags & PT_SYMBOL_SEARCH_ONCE) ? TRUE : FALSE;
	sym = windows_symbol_enum(symbol_name, module, once);
	return sym;
}


static struct pt_symbol_entry *resolve_symbol_all_(
	const utf8_t *symbol_name,
	struct pt_process *process,
	int flags)
{
	struct pt_module *module;
	struct pt_symbol_entry *sym_entry = NULL, *new_entry = NULL;

	pt_process_for_each_module(process, module) {
		new_entry = resolve_symbol_(symbol_name, module, flags);
		if (new_entry) {
			pt_symbol_join(&sym_entry, new_entry);
			if (flags & PT_SYMBOL_SEARCH_ONCE)
				break;
		}
	}

	return sym_entry;
}

struct pt_symbol_entry *windows_symbol_resolve(
	const utf8_t *symbol,
	struct pt_process *process,
	struct pt_module *module,
	int flags)
{
	struct pt_symbol_entry *sym_entry = NULL;

	assert(symbol != NULL);
	assert(process != NULL);

	/* search only within this specific module */
	if (module)
		sym_entry = resolve_symbol_(symbol, module, flags);
	else
		sym_entry = resolve_symbol_all_(symbol, process, flags);

	if (sym_entry)
		pt_log("%s(): symbol %s resolved\n", symbol);

	return sym_entry;
}

/* this function should initialize custom info in the cache field of the module */
int  windows_symbol_module_attach(struct pt_module *module)
{

	if (pt_windows_symbol_mngr_module_load(module) < 0) {
		free(module->s_cache->info);
		module->s_cache->info = NULL;
		return -1;
	}

	return 0;
}

/* thgis function should be called when the module is released */
void windows_symbol_module_detach(struct pt_module *module)
{
	if (module->s_cache && module->s_cache->info) {
		free(module->s_cache->info);
		module->s_cache->info = NULL;
	}

	/* even if we get any error out of this function, we can't do much since
	 * module is already unloading..
	 */
	pt_windows_symbol_mngr_module_unload(module);
}

void pt_symbol_set_search_path(const utf8_t *path)
{
	symbols_search_path = path;
}

static int windows_symbol_mngr_init(struct pt_symbol_manager *smgr)
{
	return pt_windows_symbol_mngr_init(smgr);
}

static void windows_symbol_mngr_release(struct pt_symbol_manager *smgr)
{
	pt_windows_symbol_mngr_release(smgr);
}

struct pt_symbol_op windows_symbol_op = {
	.symbol_mgr_init	= windows_symbol_mngr_init,
	.symbol_mgr_release	= windows_symbol_mngr_release,
	.resolve_symbol		= windows_symbol_resolve,
	.module_attach		= windows_symbol_module_attach,
	.module_detach		= windows_symbol_module_detach,
};

utf8_t *pt_os_symbol_undecorate(const utf8_t *symname)
{
	return undecorate_(symname);
}
