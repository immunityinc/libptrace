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
 * module.c
 *
 * libptrace module management.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <stdlib.h>
#include <libptrace/error.h>
#include "module.h"
#include "symbol.h"

int pt_module_init(struct pt_module *module)
{
	struct pt_symbol_cache_info *s_cache;

	assert(module != NULL);

	if ( (s_cache = malloc(sizeof(*s_cache))) == NULL) {
		pt_error_errno_set(errno);
		return -1;
	}

	module->name           = NULL;
	module->pathname       = NULL;
	module->base           = PT_ADDRESS_NULL;
	module->process        = NULL;
	module->private_data   = NULL;
	module->super_         = NULL;
        module->s_cache        = s_cache;
	module->s_cache->cache = NULL; /* cache: XXX not implemented yet */
	module->s_cache->info  = NULL; /* low level OS module info cache */
	module->m_op           = NULL;
	list_init(&module->process_entry);

	return 0;
}

int pt_module_destroy(struct pt_module *module)
{
	if (module->m_op->destroy && module->m_op->destroy(module) == -1)
		return -1;

	if (module->s_cache != NULL)
		free(module->s_cache);

	list_del(&module->process_entry);
	return 0;
}

int pt_module_delete(struct pt_module *module)
{
	assert(module != NULL);

	if (pt_module_destroy(module) == -1)
		return -1;

	free(module);
	return 0;
}

/* Accessor functions for virtualization. */
pt_address_t pt_module_get_base(struct pt_module *module)
{
	return module->base;
}
