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
 * breakpoint_hw.c
 *
 * libptrace hardware breakpoint support.
 *
 * Executable breakpoints are faults and they will retrigger.  We are supposed
 * to use the Resume Flag in EFLAGS to prevent this, but vmware seems too
 * retarded to deal with it properly.  Therefore, we handle executable
 * breakpoints by single stepping and then setting them again, similar to int 3
 * breakpoints.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <libptrace/error.h>
#include <libptrace/event.h>
#include <libptrace/list.h>
#include <libptrace/log.h>
#include "breakpoint.h"
#include "process.h"
#include "thread.h"

/* real implementation function implementd in the OS moduele: need to refactor
 * it together with the header before.. used now just to shutup the compiler
 */
extern void x86_debug_register_free(struct x86_debug_registers *, struct x86_debug_register *);

static struct pt_breakpoint_operations breakpoint_hw_operations;

void pt_breakpoint_hw_init(struct pt_breakpoint *bp)
{
	pt_breakpoint_init(bp);
	bp->b_op = &breakpoint_hw_operations;
}

static int translate_size_(size_t size)
{
	switch (size) {
	case 1:
		return X86_DR_SIZE_1;
	case 2:
		return X86_DR_SIZE_2;
	case 4:
		return X86_DR_SIZE_4;
	case 8:
		return X86_DR_SIZE_8;
	}

	return -1;
}

static int
pt_breakpoint_hw_thread_set(struct pt_thread *thread,
                            struct pt_breakpoint_internal *bpi)
{
	struct pt_breakpoint *bp = bpi->breakpoint;
	int ret, size;

	pt_log("%s(thread = %p, breakpoint = %p) @ %p\n", __FUNCTION__,
	           thread, bpi, bpi->address);

	/* See if we have a valid hardware breakpoint size. */
	if ( (size = translate_size_(bp->size)) == -1) {
		pt_error_internal_set(PT_ERROR_INVALID_ARG);
		pt_log("%s(): invalid breakpoint size %u\n",
		           __FUNCTION__, bp->size);
		return -1;
	}

	/* See if we have a debug register we can use available. */
	/* TODO: XXX: bp->handler has a differnt type, added the cast to
	 * x86_dr_andler_t to shutup the compiler since it seems that the
	 * handler is not used within the x86_debug_register_set() but this
	 * issue has to be clarified or FIXED
	 */
	ret = x86_debug_register_set(&thread->debug_registers,
	                             X86_DR_SCOPE_LOCAL, X86_DR_TYPE_EXEC,
	                             (uintptr_t)bpi->address, size,
	                             (x86_dr_handler_t)bp->handler, bp->cookie);
	if (ret == -1)
		return -1;

	/* XXX: implement proper register mirroring later. */
	return pt_thread_debug_registers_apply(thread);
}

/* XXX: error handling. */
static int
pt_breakpoint_hw_process_set(struct pt_process *process,
                             struct pt_breakpoint_internal *breakpoint)
{
	struct pt_thread *thread;

	pt_process_for_each_thread (process, thread)
		pt_breakpoint_hw_thread_set(thread, breakpoint);

	return 0;
}

static int
pt_breakpoint_hw_thread_remove(struct pt_thread *thread,
                               struct pt_breakpoint_internal *breakpoint)
{
	struct x86_debug_register *reg;

	reg = x86_debug_register_find(&thread->debug_registers,
	                              breakpoint->address,
	                              X86_DR_TYPE_EXEC);
	if (reg == NULL)
		return -1;

	x86_debug_register_free(&thread->debug_registers, reg);

	return 0;
}

static int
pt_breakpoint_hw_process_remove(struct pt_process *process,
                                struct pt_breakpoint_internal *breakpoint)
{
	struct pt_thread *thread;

	pt_process_for_each_thread (process, thread)
		pt_breakpoint_hw_thread_remove(thread, breakpoint);

	return 0;
}

static int
pt_breakpoint_hw_suppress(struct pt_thread *thread,
                          struct pt_breakpoint_internal *breakpoint)
{
	struct x86_debug_register *reg;

	pt_log("%s()\n", __FUNCTION__);

	reg = x86_debug_register_find(&thread->debug_registers,
	                              breakpoint->address,
	                              X86_DR_TYPE_EXEC);
	if (reg == NULL)
		return -1;

	pt_log("%s(): setting dbreg off\n", __FUNCTION__);
	reg->scope = X86_DR_SCOPE_NONE;
	return pt_thread_debug_registers_apply(thread);
}

static int
pt_breakpoint_hw_restore(struct pt_thread *thread,
                         struct pt_breakpoint_internal *breakpoint)
{
	struct x86_debug_register *reg;

	reg = x86_debug_register_find(&thread->debug_registers,
	                              breakpoint->address,
	                              X86_DR_TYPE_EXEC);
	if (reg == NULL)
		return -1;

	reg->scope = X86_DR_SCOPE_LOCAL;
	return pt_thread_debug_registers_apply(thread);
}

static struct pt_breakpoint_operations breakpoint_hw_operations = {
	.suppress	= pt_breakpoint_hw_suppress,
	.restore	= pt_breakpoint_hw_restore,
	.process_set	= pt_breakpoint_hw_process_set,
	.process_remove	= pt_breakpoint_hw_process_remove,
	.thread_set	= pt_breakpoint_hw_thread_set,
	.thread_remove	= pt_breakpoint_hw_thread_remove
};
