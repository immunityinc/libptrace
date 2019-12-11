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
 * breakpoint.h
 *
 * libptrace breakpoint related definitions.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_BREAKPOINT_INTERNAL_H
#define PT_BREAKPOINT_INTERNAL_H

#include <stdint.h>
#include <libptrace/charset.h>
#include <libptrace/event.h>
#include <libptrace/list.h>
#include <libptrace/process.h>
#include <libptrace/types.h>
#include "avl.h"

#define PT_BREAKPOINT_FLAG_NONE		0
#define PT_BREAKPOINT_FLAG_ONESHOT	1
#define PT_BREAKPOINT_FLAG_DISABLED	2
#define PT_BREAKPOINT_FLAG_CONDITIONAL	4

#define PT_BREAKPOINT_SCOPE_PROCESS	0
#define PT_BREAKPOINT_SCOPE_THREAD	1

#ifdef __cplusplus
extern "C" {
#endif

struct pt_breakpoint;
typedef void (*pt_breakpoint_handler_t)(struct pt_thread *, void *cookie);

/* Structure used to track process level breakpoints. */
struct pt_breakpoint_internal
{
	struct pt_breakpoint	*breakpoint;

	/* Symbolic breakpoints can have an address that differs per
	 * process.  Hence we store the resolved value in the breakpoint
	 * tracked in the process structures.
	 */
	pt_address_t		address;

	/* Correlates this breakpoint to a process. */
	struct avl_node		avl_node;
	/* The original byte we patched out. */
	uint8_t			original;
};

struct pt_breakpoint_operations
{
	int	(*thread_set)(struct pt_thread *, struct pt_breakpoint_internal *);
	int	(*thread_remove)(struct pt_thread *, struct pt_breakpoint_internal *);
	int	(*process_set)(struct pt_process *, struct pt_breakpoint_internal *);
	int	(*process_remove)(struct pt_process *, struct pt_breakpoint_internal *);
	int	(*suppress)(struct pt_thread *, struct pt_breakpoint_internal *);
	int	(*restore)(struct pt_thread *, struct pt_breakpoint_internal *);
};

struct pt_breakpoint
{
	uint8_t				flag;
	uint8_t				scope;
	pt_address_t			address;
	char				*symbol;
	size_t				size;
	pt_breakpoint_handler_t		handler;
	void				*cookie;

	struct pt_breakpoint_operations	*b_op;
};

void pt_breakpoint_init(struct pt_breakpoint *pt_breakpoint);
void pt_breakpoint_destroy(struct pt_breakpoint *pt_breakpoint);

int pt_breakpoint_handler(struct pt_thread *thread,
                          struct pt_event_breakpoint *ev);

int pt_breakpoint_set(struct pt_process *process,
                      struct pt_breakpoint *breakpoint);
int pt_breakpoint_remove(struct pt_process *process, struct pt_breakpoint *breakpoint);

int breakpoint_avl_compare_(struct avl_node *, struct avl_node *);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_BREAKPOINT_INTERNAL_H */
