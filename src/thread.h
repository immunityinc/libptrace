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
#ifndef PT_THREAD_INTERNAL_H
#define PT_THREAD_INTERNAL_H

#include <libptrace/breakpoint.h>
#include <libptrace/breakpoint_x86.h>
//#include <libptrace/error.h>
#include <libptrace/types.h>
#include "avl.h"

/* Thread states */
#define THREAD_EXITED				2
#define THREAD_SUSPENDED			3

/* Thread flags */
#define THREAD_FLAG_NONE			0
#define THREAD_FLAG_MAIN			1
#define THREAD_FLAG_TRACED			2
#define THREAD_FLAG_SINGLE_STEP			4
#define THREAD_FLAG_SINGLE_STEP_INTERNAL	8
#define THREAD_FLAG_HW_BREAKPOINT		16

#define pt_thread_for_each_breakpoint_internal(p, m)			\
	for (struct avl_node *an = avl_tree_min(&(p)->breakpoints),	\
	     *an2 = avl_tree_next_safe(an);				\
	     m = container_of(an, struct pt_breakpoint_internal,	\
	                      avl_node),				\
	     an != NULL;						\
	     an = an2, an2 = avl_tree_next_safe(an))

struct pt_thread_operations
{
        int          (*destroy)(struct pt_thread *);

        int          (*suspend)(struct pt_thread *);
        int          (*resume)(struct pt_thread *);

	int	     (*single_step_set)(struct pt_thread *);
	int	     (*single_step_remove)(struct pt_thread *);

	pt_address_t (*register_pc_get)(struct pt_thread *);
	int	     (*register_pc_set)(struct pt_thread *, pt_address_t);

	struct pt_registers *	(*registers_get)(struct pt_thread *);
	int			(*registers_set)(struct pt_thread *, struct pt_registers *);
	int 			(*debug_registers_apply)(struct pt_thread *);
};

struct pt_thread
{
	pt_tid_t			tid;
	struct pt_process		*process;
	struct pt_arch_data		*arch_data;
	void				*private_data;
	uint32_t			exit_code;
//	struct pt_error			error;
	uint16_t			state;
	uint16_t			flags;

	struct registers		*registers;

	/* XXX: architecture specific kludge. */
	struct x86_debug_registers	debug_registers;

	/* pointer to TLS address for this thread. */
	void				*tls_data;
	/* pointer to the start address for this thread. */
	void				*start;
	/* avl_node for the process list. */
	struct avl_node			avl_node;
	/* persistent breakpoint that may need to be restored. */
	struct pt_breakpoint_internal	*breakpoint_restore;
	/* persistent code hw breakpoint that may need to be restored. */
	struct x86_debug_register	*db_restore;

        /* breakpoint handlers for this thread */
        struct avl_tree			breakpoints;

	/* Upward indirection for python bindings. */
	void				*super_;

	/* operations for this thread */
	struct pt_thread_operations    *t_op;
};

#ifdef __cplusplus
extern "C" {
#endif

void pt_thread_init(struct pt_thread *);
int  pt_thread_destroy(struct pt_thread *);
int  pt_thread_delete(struct pt_thread *);
int  pt_thread_suspend(struct pt_thread *);
int  pt_thread_resume(struct pt_thread *);
int  pt_thread_single_step_set(struct pt_thread *);
int  pt_thread_single_step_remove(struct pt_thread *thread);
int  pt_thread_single_step_internal_set(struct pt_thread *thread);
int  pt_thread_single_step_internal_remove(struct pt_thread *thread);
int  pt_thread_sscanf(struct pt_thread *thread, const pt_address_t src, const char *fmt, ...);


struct pt_registers *pt_thread_registers_get(struct pt_thread *);
int pt_thread_registers_set(struct pt_thread *, struct pt_registers *);

int pt_thread_debug_registers_apply(struct pt_thread *thread);
int pt_thread_registers_print(struct pt_thread *);

int thread_breakpoint_set(struct pt_thread *, struct pt_breakpoint *);

struct pt_breakpoint_internal *
pt_thread_breakpoint_internal_find(struct pt_thread *thread, pt_address_t address);

struct pt_breakpoint *
pt_thread_breakpoint_find(struct pt_thread *thread, pt_address_t address);

/* Abstract register access. */
int          pt_thread_register_pc_set(struct pt_thread *, pt_address_t);
pt_address_t pt_thread_register_pc_get(struct pt_thread *);

#ifdef __cplusplus
};
#endif

#endif /* !PT_THREAD_INTERNAL_H */
