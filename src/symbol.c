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
 * libptrace symbol management.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Massimiliano Oldani <max@immunityinc.com>
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <libptrace/error.h>
#include <libptrace/charset.h>
#include <libptrace/process.h>
#include <libptrace/log.h>
#include "symbol.h"

int
pt_symbol_manager_install(struct pt_process *process, struct pt_symbol_op *sop)
{
	struct pt_symbol_manager *smgr;
	int err;

	assert(process->smgr == NULL);

	if ( (smgr = malloc(sizeof *smgr)) == NULL) {
		pt_error_errno_set(errno);
		return -1;
	}

	smgr->process = process;
	smgr->sop = sop;

	/* this is managed by the OS layer */
	smgr->private_ = NULL;

	if (smgr->sop->symbol_mgr_init) {
		err = smgr->sop->symbol_mgr_init(smgr);
		if (err < 0) {
			free(smgr);
			return err;
		}
	}

	/* install the symbol mgr */
	process->smgr = smgr;
	return 0;
}

void pt_symbol_manager_release(struct pt_process *process)
{
	assert(process != NULL);

	if (process->smgr == NULL)
		return;

	if (process->smgr->sop->symbol_mgr_release)
		process->smgr->sop->symbol_mgr_release(process->smgr);

	free(process->smgr);
}

struct pt_symbol_entry *
pt_resolve_symbol(const utf8_t *symbol, struct pt_process *process,
                  struct pt_module *module, int flags)
{
	struct pt_symbol_entry *sym = NULL;

	/* process do not have yet symbol mngr support installed:
	 * called out of main pt_main() loop??
	 */
	if (!process->smgr)
		return NULL;

	/* look thought the cache before */
	if ((flags & PT_SYMBOL_SEARCH_NOCACHE) == 0) {
		/* try to look into the cache before, if found just return
	     * XXX: to be implemented
	     */
	}

	pt_log("%s(): symbol lookup cache miss for symbol: %s\n", __FUNCTION__, symbol);

	/* cache miss */
	/* do low-level lookup */
	if (process->smgr->sop->resolve_symbol)
		sym = process->smgr->sop->resolve_symbol(symbol, process, module, flags);

	if (sym && (flags & PT_SYMBOL_SEARCH_NOSAVE) == 0) {
		/* here the the code to add the symbol to the cache should be added
		 * XXX: to be implemented
		 */
	}

	return sym;
}

