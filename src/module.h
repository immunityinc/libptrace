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
 * module.h
 *
 * libptrace module management.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_MODULE_INTERNAL_H
#define PT_MODULE_INTERNAL_H

#include <libptrace/charset.h>
#include <libptrace/list.h>
#include <libptrace/module.h>

struct pt_module;

struct pt_module_operations
{
	int (*destroy)(struct pt_module *);
};

struct pt_module
{
	utf8_t			*name;
	utf8_t			*pathname;
	pt_address_t		base;
	void			*private_data;

	/* backlink to process. */
	struct pt_process	*process;
	/* list entry to track it in the process list. */
	struct list_head        process_entry;

	/* super pointer. */
	void			*super_;

	/* symbol resolution cache */
	struct pt_symbol_cache_info *s_cache;

	struct pt_module_operations *m_op;
};

#ifdef __cplusplus
extern "C" {
#endif

int pt_module_init(struct pt_module *module);
int pt_module_destroy(struct pt_module *module);
int pt_module_delete(struct pt_module *module);

/* those should be defined at the OS layer to attach/detach symbol information from a module */
int  pt_module_attach_symbol_mngr(struct pt_module *module);
void pt_module_detach_symbol_mngr(struct pt_module *module);

void pt_module_exports_delete(struct pt_module_exports *exports);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_MODULE_INTERNAL_H */
