/* libptrace, a process tracing and manipulation library.
 *
 * Copyright (C) 2006-2019, Ronald Huizer <rhuizer@hexpedition.com>
 * Copyright (C) 2019, Cyxtera Cybersecurity, Inc.  All rights reserved.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
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
 * thread.c
 *
 * libptrace thread management.
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <libptrace/log.h>
#include <libptrace/breakpoint_x86.h>
#include <libptrace/error.h>
#include "breakpoint.h"
#include "registers.h"
#include "thread.h"
#include "process.h"

int thread_avl_compare_(struct avl_node *a_, struct avl_node *b_)
{
	struct pt_thread *a = container_of(a_, struct pt_thread, avl_node);
	struct pt_thread *b = container_of(b_, struct pt_thread, avl_node);

	if (a->tid < b->tid)
		return -1;

	if (a->tid > b->tid)
		return 1;

	return 0;
}

void pt_thread_init(struct pt_thread *thread)
{
	thread->tid                = -1;
	thread->process            = NULL;
	thread->private_data       = NULL;
	thread->flags              = THREAD_FLAG_NONE;
	thread->state              = 0;
	thread->tls_data           = NULL;
	thread->exit_code          = 0;
	thread->registers          = NULL;
	thread->breakpoint_restore = NULL;
	thread->db_restore         = NULL;
	thread->super_	           = NULL;
	thread->t_op               = NULL;

	INIT_AVL_NODE(&thread->avl_node);
	INIT_AVL_TREE(&thread->breakpoints, breakpoint_avl_compare_);
	x86_debug_registers_init(&thread->debug_registers);
}

int pt_thread_destroy(struct pt_thread *thread)
{
	if (thread->t_op->destroy && thread->t_op->destroy(thread) == -1)
		return -1;

	avl_tree_delete(&thread->process->threads, &thread->avl_node);
	return 0;
}

int pt_thread_delete(struct pt_thread *thread)
{
	if (pt_thread_destroy(thread) == -1)
		return -1;
	free(thread);
	return 0;
}

/* Memory interface for reading data through threads.
 *
 * This is implemented on the thread-level to support mixed mode threads in
 * processes: it is perfectly possible to have threads in 32-bit and 64-bit
 * mode coexisting within a single process.  All of these threads will have
 * different default pointer sizes and architecture data.
 */
int
pt_thread_sscanf(struct pt_thread *thread, const pt_address_t src, const char *fmt, ...)
{
	struct pt_process *process = thread->process;
	int items = 0;
	const char *p;
	va_list ap;

	va_start(ap, fmt);

	for (p = fmt; *p != '\0'; p++) {
		/* XXX: support literals that have to match later. */
		if (*p != '%')
			continue;

		/* Ensure we do not overindex. */
		if (*++p == '\0')
			break;

		switch (*p) {
		case 'i': {
			int *arg = va_arg(ap, int *);
			if (pt_process_read(process, arg, src, sizeof *arg) == -1)
				return EOF;
			items++;
			break;
		}
		case 'u': {
			unsigned int *arg = va_arg(ap, unsigned int *);
			if (pt_process_read(process, arg, src, sizeof *arg) == -1)
				return EOF;
			items++;
			break;
		}
		case 'p': {
			void **arg = va_arg(ap, void **);

			*arg = NULL;
			if (pt_process_read(process, arg, src, thread->arch_data->pointer_size) == -1)
				return EOF;
			items++;
			break;
		}
		default:
			break;
		}
	}

	va_end(ap);

	return items;
}


int pt_thread_suspend(struct pt_thread *thread)
{
	if (thread->t_op->suspend == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	return thread->t_op->suspend(thread);
}

int pt_thread_resume(struct pt_thread *thread)
{
	if (thread->t_op->resume == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	return thread->t_op->resume(thread);
}

int pt_thread_single_step_set(struct pt_thread *thread)
{
	if (thread->t_op->single_step_set == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (thread->t_op->single_step_set(thread) == -1)
		return -1;

	/* API user requested single step. */
	thread->flags |= THREAD_FLAG_SINGLE_STEP;
	return 0;
}

int pt_thread_single_step_remove(struct pt_thread *thread)
{
	pt_log("%s(tid %d)\n", __FUNCTION__, thread->tid);

	if (thread->t_op->single_step_remove == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if ( !(thread->flags & THREAD_FLAG_SINGLE_STEP))
		return 0;

	if (thread->t_op->single_step_remove(thread) == -1)
		return -1;

	/* API user requested single step removal. */
	thread->flags &= ~THREAD_FLAG_SINGLE_STEP;
	return 0;
}

int pt_thread_single_step_internal_set(struct pt_thread *thread)
{
	if (thread->t_op->single_step_set == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if (thread->t_op->single_step_set(thread) == -1)
		return -1;

	/* Internally used single step. */
        thread->flags |= THREAD_FLAG_SINGLE_STEP_INTERNAL;
	return 0;
}

int pt_thread_single_step_internal_remove(struct pt_thread *thread)
{
	pt_log("%s(tid %d)\n", __FUNCTION__, thread->tid);

	if (thread->t_op->single_step_remove == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	if ( !(thread->flags & THREAD_FLAG_SINGLE_STEP_INTERNAL)) {
		pt_log("%s(tid %d): THREAD_FLAG_SINGLE_STEP_INTERNAL not set.\n",
		       __FUNCTION__, thread->tid);
		return 0;
	}

	if (thread->t_op->single_step_remove(thread) == -1)
		return -1;

	/* Internally used single step removal. */
        thread->flags &= ~THREAD_FLAG_SINGLE_STEP_INTERNAL;
	return 0;
}

struct pt_registers *pt_thread_registers_get(struct pt_thread *thread)
{
	if (thread->t_op->registers_get == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return NULL;
	}

	return thread->t_op->registers_get(thread);
}

int pt_thread_registers_set(struct pt_thread *thread, struct pt_registers *regs)
{
	if (thread->t_op->registers_set == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	return thread->t_op->registers_set(thread, regs);
}

int pt_thread_debug_registers_apply(struct pt_thread *thread)
{
	if (thread->t_op->debug_registers_apply == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	return thread->t_op->debug_registers_apply(thread);
}

struct pt_breakpoint_internal *
pt_thread_breakpoint_internal_find(struct pt_thread *thread, pt_address_t address)
{
	struct avl_node *an;

	an = thread->breakpoints.root;
	while (an != NULL) {
		struct pt_breakpoint_internal *bp;

		bp = container_of(an, struct pt_breakpoint_internal, avl_node);
		if (bp->address == address)
			return bp;

		if (bp->address > address)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

struct pt_breakpoint *
pt_thread_breakpoint_find(struct pt_thread *thread, pt_address_t address)
{
	struct pt_breakpoint_internal *breakpoint;

	breakpoint = pt_thread_breakpoint_internal_find(thread, address);
	if (breakpoint == NULL)
		return NULL;

	return breakpoint->breakpoint;
}

int pt_thread_registers_print(struct pt_thread *thread)
{
	struct pt_registers *regs;
	int ret;

	if ( (regs = pt_thread_registers_get(thread)) == NULL)
		return -1;

	ret = pt_registers_print(regs);
	free(regs);

	return ret;
}

int thread_breakpoint_set(struct pt_thread *thread,
                          struct pt_breakpoint *bp)
{
	struct pt_breakpoint_internal *bpi;
	int ret;

	assert(thread != NULL);
	assert(bp != NULL);
	assert(bp->b_op != NULL);

	if ( (bpi = malloc(sizeof *bpi)) == NULL)
		return -1;

	bpi->address = bp->address;
	bpi->breakpoint = bp;

	if ( (ret = bp->b_op->thread_set(thread, bpi)) == 0)
		avl_tree_insert(&thread->breakpoints, &bpi->avl_node);
	else
		free(bpi);

	return ret;
}

/************************************************************************
 * Thread abstract register access functions.
 ***********************************************************************/
int pt_thread_register_pc_set(struct pt_thread *thread, pt_address_t pc)
{
	if (thread->t_op->register_pc_set == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	return thread->t_op->register_pc_set(thread, pc);
}
