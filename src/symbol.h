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
 * symbol.h
 *
 * libptrace symbol management.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Massimiliano Oldani <max@immunityinc.com>
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_SYMBOL_INTERNAL_H
#define PT_SYMBOL_INTERNAL_H

#include <stdlib.h>
#include <libptrace/charset.h>
//#include <libptrace/module.h>
#include <libptrace/list.h>
#include "process.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct pt_symbol_op;
struct pt_module;


struct pt_symbol_manager
{
	/* backpointer */
	struct pt_process	*process;

	/* symbol operation table */
	struct pt_symbol_op *sop;

	/* constructor arg */
	void *private_;
};


struct pt_symbol_op
{
	int (*symbol_mgr_init)(struct pt_symbol_manager *smgr);
	void (*symbol_mgr_release)(struct pt_symbol_manager* smgr);

	/* called to initialized/free per-module symbol resource
	 * module_attach() is called when a new module is loaded,
	 * module_detach() is called when a loaded module in unloaded
	 */
	int  (*module_attach)(struct pt_module *module);
	void (*module_detach)(struct pt_module *module);

	struct pt_symbol_entry *(*resolve_symbol)(const utf8_t *symbol,
						  struct pt_process *process,
						  struct pt_module *module,
						  int flags);
	/* here add the other functions realtive to lines/public syms, etc..
	 *
	 * ...
	 * ...
	 */
};

/* XXX: to be defined */
struct pt_symbol_cache_header
{
};

struct pt_os_symbol_info_header_;
struct pt_symbol_cache_info
{
	/* XXX: will be defined in the future, by now the cache just return no
	 * resolved symbols
	 */
	struct pt_symbol_cache_header *cache;

	/* defined at the os-level */
	struct pt_os_symbol_info_header_ *info;
};


struct pt_symbol_entry
{
	/* this is dup()'ed and must be free when releasing the struct */
	utf8_t *symname;

	/* if this is a C++ symbol (e.g. starting with '?' on Windows) this
	 * field will hold the undecorated symbol name, can be NULL
	 */
	utf8_t *undecorated_symname;

	/* tag (type) and flags content fields are both arch os-dependent
	 * usage and values are managed within os/symbol.h dir
	 */
	union {
		unsigned long tag;
		unsigned long type;
	};
	int flags;

	/* symbol address, could be absolute or relative, based on prev field */
	void *addr;

	/* symbol module base address */
	void *module_addr;

	/* if symbol relocation holds more info: e.g. a constant etc.. */
	unsigned long value;

	/* this field stores a pointer to the module holding the symbol,
	 * this pointer is valid ONLY when the pt_symbol_entry is returned and is not
	 * meant to be saved, since it could be invalid as soon as the stopped process
	 * is awakened. In the future we will add a refcounting to keep the reference
	 * valid managing pt_symbol_entry and pt_module life objected unrelated to
	 * the debugger events (module unloading etc..) */
	struct pt_module *module;

	/* last entry has NULL */
	struct pt_symbol_entry *next;
};


#define PT_SYMBOL_SEARCH_NOCACHE 0x00000001 /* do not look into the cache */
#define PT_SYMBOL_SEARCH_NOSAVE  0x00000002 /* do not save the entry into the cache after the resolution */
#define PT_SYMBOL_SEARCH_ONCE    0x00000004 /* return only the first symbol with the matching name */
extern struct pt_symbol_entry *pt_resolve_symbol(const utf8_t *symbol,
						 struct pt_process *process,
						 struct pt_module *module,
						 int flags);

extern utf8_t *pt_os_symbol_undecorate_(const utf8_t *symname);

inline static utf8_t *pt_symbol_undecorate(const utf8_t *symname)
{
	return pt_os_symbol_undecorate_(symname);
}

int  pt_symbol_manager_install(struct pt_process *, struct pt_symbol_op *);
void pt_symbol_manager_release(struct pt_process *);

inline static void pt_symbol_internal_free(struct pt_symbol_entry *sym_entry)
{
	if (sym_entry->symname)
		free(sym_entry->symname);

	if (sym_entry->undecorated_symname)
		free(sym_entry->undecorated_symname);
}

inline static void pt_symbol_free(struct pt_symbol_entry **sym_entry)
{
	struct pt_symbol_entry *entry = *sym_entry, *tmp;

	while (entry) {
		tmp = entry->next;
		pt_symbol_internal_free(entry);
		free(entry);
		entry = tmp;
	}

	/* debug only */
	*sym_entry = NULL;
}


/* join the 'latter' symbol chain into the 'former' one */
inline static void pt_symbol_join(struct pt_symbol_entry **former,
				  struct pt_symbol_entry *latter)
{
	/* first join, no entry in the *former ptr */
	struct pt_symbol_entry **next = former;
	while(*next)
		next = &((*next)->next);

	*next = latter;
}


#ifdef  __cplusplus
};
#endif

#endif	/* !PT_SYMBOL_INTERNAL_H */
