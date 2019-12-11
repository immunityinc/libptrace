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
 * event.h
 *
 * Implementation of libptrace tracing/debugging events.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_EVENT_INTERNAL_H
#define PT_EVENT_INTERNAL_H

#include <libptrace/event.h>
#include <libptrace/list.h>
#include <libptrace/types.h>

typedef int (*pt_event_handler_t)(struct pt_event *);

struct pt_event_handler
{
	pt_event_handler_t	handler;
	void			*cookie;
	struct list_head	list;
};

struct pt_event_handler_stack
{
	struct list_head	list;
};

struct pt_event_handlers_internal
{
	struct pt_event_handler_stack attached;
	struct pt_event_handler_stack process_exit;
	struct pt_event_handler_stack thread_create;
	struct pt_event_handler_stack thread_exit;
	struct pt_event_handler_stack module_load;
	struct pt_event_handler_stack module_unload;

	int (*remote_break)(struct pt_event_breakpoint *);
	int (*breakpoint)(struct pt_event_breakpoint *);
	int (*single_step)(struct pt_event_single_step *);
	int (*segfault)(struct pt_event_segfault *);
	int (*illegal_instruction)(struct pt_event_illegal_instruction *);
	int (*divide_by_zero)(struct pt_event_divide_by_zero *);
	int (*priv_instruction)(struct pt_event_priv_instruction *);
	int (*unknown_exception)(struct pt_event_unknown_exception *);

	int (*x86_dr)(struct pt_event_x86_dr *);
};

#ifdef __cplusplus
extern "C" {
#endif

void pt_event_handler_stack_init(struct pt_event_handler_stack *stack);
void pt_event_handler_stack_destroy(struct pt_event_handler_stack *stack);
int  pt_event_handler_stack_call(struct pt_event_handler_stack *stack,
                                 struct pt_event *ev);

struct pt_event_handler *pt_event_handler_stack_push(struct pt_event_handler_stack *,
                                                     int (*)(struct pt_event *), void *);

void pt_event_handlers_internal_init(struct pt_event_handlers_internal *);
struct pt_event_handlers_internal *pt_event_handlers_internal_new(void);
void pt_event_handlers_internal_destroy(struct pt_event_handlers_internal *handlers);
void pt_event_handler_destroy(struct pt_event_handler *handler);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_EVENT_INTERNAL_H */
