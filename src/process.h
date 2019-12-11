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
 * process.h
 *
 * libptrace process management.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_PROCESS_INTERNAL_H
#define PT_PROCESS_INTERNAL_H

#include <stdio.h>
#include <stdint.h>
#include <libptrace/event.h>
#include <libptrace/list.h>
#include <libptrace/types.h>
#include <libptrace/process.h>
#include "avl.h"
#include "arch.h"
#include "event.h"
#include "mutex.h"
#include "mmap.h"

#define pt_process_for_each_breakpoint_internal(p, m)			\
	for (struct avl_node *an = avl_tree_min(&(p)->breakpoints),	\
	     *an2 = avl_tree_next_safe(an);				\
	     m = container_of(an, struct pt_breakpoint_internal,	\
	                      avl_node),				\
	     an != NULL;						\
	     an = an2, an2 = avl_tree_next_safe(an))

struct pt_process_operations;
struct pt_symbol_manager;

struct pt_process
{
	struct pt_architecture		arch;
	pt_pid_t			pid;
	uint8_t				state;
	uint8_t				flags;
	int				remote_break_count;
	uint8_t				options;
	uint16_t			dummy;
	void				*private_data;
	uint64_t			creation_time;

	/* list of threads in the process. */
	struct avl_tree			threads;
	/* if there is a main thread, we use this. */
	struct pt_thread		*main_thread;

	/* the memory map of the process. */
	struct pt_mmap			mmap;

	/* list of modules in the process. */
	struct list_head		modules;
	/* module descriptor for the process image. */
	struct pt_module		*main_module;

	/* event handlers and argument cookies for this process */
	struct pt_event_handlers_internal handlers;

	/* breakpoint handlers for this process */
	struct avl_tree			breakpoints;

	/* avl tree that tracks all processes being debugged. */
	struct avl_node			avl_node;

	/* operations for this process */
	struct pt_process_operations	*p_op;

	/* symbol manager */
	struct pt_symbol_manager	*smgr;

	/* XXX: kludge.  Push to private_data. */
	pt_address_t			remote_break_addr;

	/* Upward indirection for python bindings. */
	void				*super_;

	/* core this process belongs to. */
	struct pt_core			*core;
};

struct pt_process_operations
{
	int          (*destroy)(struct pt_process *);
	int          (*brk)(struct pt_process *);
	int          (*suspend)(struct pt_process *);
	int          (*resume)(struct pt_process *);
	ssize_t      (*read)(struct pt_process *, void *, const pt_address_t, size_t);
	int          (*write)(struct pt_process *, pt_address_t, const void *, size_t);
	int          (*thread_create)(struct pt_process *, pt_address_t, pt_address_t);
	pt_address_t (*malloc)(struct pt_process *, size_t);
	int          (*free)(struct pt_process *, pt_address_t);
};

#ifdef __cplusplus
extern "C" {
#endif

int pt_process_init(struct pt_process *);
int pt_process_destroy(struct pt_process *);
int pt_process_delete(struct pt_process *);

int process_read_uint32(struct pt_process *process,
                        uint32_t *dest, const pt_address_t src);

struct pt_breakpoint_internal *
pt_process_breakpoint_find_internal(struct pt_process *process, pt_address_t address);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_PROCESS_INTERNAL_H */
