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
 * breakpoint.c
 *
 * High level management routines for breakpoints.
 * The low-level libptrace event framework is useful for hooking debug events
 * for breakpoints, but not managing breakpoints effectively.
 *
 * This module provides an event driven interface for managed breakpoints,
 * allowing persistent breakpoints, single shot breakpoints, disabling
 * breakpoints, conditional breakpoints, per thread breakpoints and so on.
 *
 * This implements some logic for dealing with static nanomites, where
 * breakpoint events for unregistered breakpoints are either forwarded directly
 * to the debuggee or to the low-level ptrace debug event handler.  In case of
 * a registered breakpoint on an address that already had an unregistered
 * breakpoint there, we will trigger both a breakpoint event, as well as a
 * low-level debug breakpoint event.
 *
 * Dealing with dynamic nanomites is infeasible for a non-instrumentation
 * framework, and for now not supported.  We can only make a best effort
 * attempt here dealing with nanomites.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <libptrace/event.h>
#include <libptrace/list.h>
#include <libptrace/log.h>
#include "breakpoint.h"
#include "process.h"
#include "thread.h"

void pt_breakpoint_init(struct pt_breakpoint *breakpoint)
{
	breakpoint->address = 0;
	breakpoint->symbol  = NULL;
	breakpoint->handler = NULL;
	breakpoint->cookie  = NULL;
	breakpoint->flag    = PT_BREAKPOINT_FLAG_NONE;
}

void pt_breakpoint_destroy(struct pt_breakpoint *breakpoint)
{
}

/* Breakpoint handler invocation management. */
int pt_breakpoint_handler(struct pt_thread *thread,
                          struct pt_event_breakpoint *ev)
{
	struct pt_process *process = thread->process;
	struct pt_breakpoint_internal *bpi;
	struct pt_breakpoint *bp;

	pt_log("%s(): address: 0x%x\n", __FUNCTION__, ev->address);

	/* Try to find a registered breakpoint handler for this event.
	 * If we do not have one, we proceed calling the ptrace breakpoint
	 * event hook directly.
	 */
	bpi = pt_thread_breakpoint_internal_find(thread, ev->address);
	if (bpi == NULL)
		bpi = pt_process_breakpoint_find_internal(process, ev->address);

	/* We do not have any high level handler for this breakpoint. */
	if (bpi == NULL) {
		pt_log("%s(): Unknown breakpoint, calling bottom handler.\n", __FUNCTION__);
		if (process->handlers.breakpoint != NULL)
			return process->handlers.breakpoint(ev);
		else
			return PT_EVENT_FORWARD;
	}

	pt_log("%s(): High level breakpoint at 0x%.8x\n", __FUNCTION__, ev->address);
	bp = bpi->breakpoint;

	/* If the breakpoint is disabled we're done.  We even do this for
	 * ONESHOT breakpoints, as these can be disabled before they are
	 * handled.
	 */
	if (bp->flag & PT_BREAKPOINT_FLAG_DISABLED)
		return PT_EVENT_DROP;

	/* If we have a suppress operation defined for this breakpoint,
	 * invoke it.
	 *
	 * XXX: handle suppression error.
	 */
	if (bp->b_op->suppress != NULL)
		bp->b_op->suppress(ev->thread, bpi);

	/* If this was a one shot breakpoint, remove it. */
	if (bp->flag & PT_BREAKPOINT_FLAG_ONESHOT) {
		bp->b_op->process_remove(process, bpi);
	} else {
		/* For persistent breakpoints, we need to reenable them
		 * at the right moment.  Which is on process resumption
		 * after single stepping the proper once.  There are
		 * some delicate races here, which I will detail later.
		 */
		ev->thread->breakpoint_restore = bpi;
	}

	/* We had a registered breakpoint, so we call its handler instead of
	 * the generic breakpoint handler as above.  We do this last, as the
	 * handler may well remove the breakpoint, which means we can't set
	 * breakpoint_restore again.
	 *
	 * XXX: warning, PT_BREAKPOINT_FLAG_ONESHOT breakpoints should never
	 * be removed in the breakpoint handler.
	 */
	bp->handler(thread, bp->cookie);

	/* Registered breakpoints are never relayed to the debuggee. */
	return PT_EVENT_DROP;
}

int breakpoint_avl_compare_(struct avl_node *a_, struct avl_node *b_)
{
        struct pt_breakpoint_internal *a =
		container_of(a_, struct pt_breakpoint_internal, avl_node);
        struct pt_breakpoint_internal *b =
		container_of(b_, struct pt_breakpoint_internal, avl_node);

        if (a->address < b->address)
                return -1;

        if (a->address > b->address)
                return 1;

        return 0;
}
