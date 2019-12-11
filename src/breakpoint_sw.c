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
 * breakpoint_sw.c
 *
 * High level management implementation for software breakpoints.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <libptrace/event.h>
#include <libptrace/list.h>
#include <libptrace/log.h>
#include "breakpoint.h"
#include "process.h"
#include "thread.h"

static struct pt_breakpoint_operations breakpoint_sw_operations;

void pt_breakpoint_sw_init(struct pt_breakpoint *bp)
{
	pt_breakpoint_init(bp);
	bp->b_op = &breakpoint_sw_operations;
}

static int
pt_breakpoint_sw_process_set(struct pt_process *process,
                             struct pt_breakpoint_internal *breakpoint)
{
	char buf[1];
	int ret;

	pt_log("%s(0x%p, 0x%p)\n", __FUNCTION__, process, breakpoint);

	/* Read memory, we store the original byte that was here.
	 *
	 * This is obviously not fool proof: to do this completely safe we
	 * would need to instrument the process in order to trace writes to
	 * addresses we put breakpoints on.
	 */
	ret = pt_process_read(process, buf, breakpoint->address, 1);
	if (ret == -1)
		return -1;

	/* Write the breakpoint out. */
	ret = pt_process_write(process, breakpoint->address, "\xCC", 1);
	if (ret == -1)
		return -1;

	/* Store the byte we replaced. */
	breakpoint->original = buf[0];

	pt_log("%s(): returning 0\n", __FUNCTION__);
	return 0;
}

static int
pt_breakpoint_sw_process_remove(struct pt_process *process,
                                struct pt_breakpoint_internal *bpi)
{
	struct pt_thread *thread;
	int ret;

	pt_log("%s(): patching back original byte 0x%.2x at 0x%p\n",
	       __FUNCTION__, bpi->original, bpi->address);
	/* Restore the original opcode we replaced. */
	ret = pt_process_write(process, bpi->address, &bpi->original, 1);
	if (ret == -1)
		return -1;

	/* Make sure to remove this breakpoint from all threads that happen
	 * to have it set as their breakpoint_restore.
	 */
	pt_process_for_each_thread (process, thread) {
		if (thread->breakpoint_restore == NULL)
			continue;

		if (thread->breakpoint_restore->breakpoint == bpi->breakpoint)
			thread->breakpoint_restore = NULL;
	}

	/* Clean up the breakpoint itself. */
	avl_tree_delete(&process->breakpoints, &bpi->avl_node);
	pt_breakpoint_destroy(bpi->breakpoint);
	free(bpi);

	return 0;
}

static int
pt_breakpoint_sw_suppress(struct pt_thread *thread,
                          struct pt_breakpoint_internal *breakpoint)
{
	pt_log("%s(): setting pc to: 0x%.8x\n", __FUNCTION__, breakpoint->address);

	if (pt_thread_register_pc_set(thread, breakpoint->address) == -1)
		return -1;

	pt_process_write(thread->process, breakpoint->address, &breakpoint->original, 1);

	return 0;
}

static int
pt_breakpoint_sw_restore(struct pt_thread *thread,
                         struct pt_breakpoint_internal *breakpoint)
{
	if (thread->process == NULL)
		return -1;

	pt_log("%s(): restoring 0xCC byte at 0x%.8x\n", __FUNCTION__, breakpoint->address);

	return pt_process_write(thread->process, breakpoint->address, "\xCC", 1);
}

static struct pt_breakpoint_operations breakpoint_sw_operations = {
	.suppress	= pt_breakpoint_sw_suppress,
	.restore	= pt_breakpoint_sw_restore,
	.process_set	= pt_breakpoint_sw_process_set,
	.process_remove	= pt_breakpoint_sw_process_remove,
	.thread_set	= NULL,
	.thread_remove	= NULL
};
