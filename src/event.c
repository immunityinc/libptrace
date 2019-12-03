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
 * event.c
 *
 * Implementation of libptrace tracing/debugging events.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <libptrace/error.h>
#include <libptrace/list.h>
#include "event.h"

void pt_event_handler_destroy(struct pt_event_handler *handler)
{
	list_del(&handler->list);
	free(handler);
}

void pt_event_handlers_init(struct pt_event_handlers *handlers)
{
	assert(handlers != NULL);
	memset(handlers, 0, sizeof(*handlers));
}

void pt_event_handlers_internal_init(struct pt_event_handlers_internal *handlers)
{
	assert(handlers != NULL);

	memset(handlers, 0, sizeof *handlers);
	pt_event_handler_stack_init(&handlers->attached);
	pt_event_handler_stack_init(&handlers->process_exit);
	pt_event_handler_stack_init(&handlers->thread_create);
	pt_event_handler_stack_init(&handlers->thread_exit);
	pt_event_handler_stack_init(&handlers->module_load);
	pt_event_handler_stack_init(&handlers->module_unload);
}

struct pt_event_handlers_internal *pt_event_handlers_internal_new(void)
{
	struct pt_event_handlers_internal *handlers;

	handlers = (struct pt_event_handlers_internal *)malloc(sizeof *handlers);
	if (handlers == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	pt_event_handlers_internal_init(handlers);

	return handlers;
}

void pt_event_handlers_internal_destroy(struct pt_event_handlers_internal *handlers)
{
	assert(handlers != NULL);

	pt_event_handler_stack_destroy(&handlers->attached);
	pt_event_handler_stack_destroy(&handlers->process_exit);
	pt_event_handler_stack_destroy(&handlers->thread_create);
	pt_event_handler_stack_destroy(&handlers->thread_exit);
	pt_event_handler_stack_destroy(&handlers->module_load);
	pt_event_handler_stack_destroy(&handlers->module_unload);
}

void pt_event_handlers_internal_delete(struct pt_event_handlers_internal *handlers)
{
	assert(handlers != NULL);

	pt_event_handlers_internal_destroy(handlers);
	free(handlers);
}

void pt_event_handler_stack_init(struct pt_event_handler_stack *stack)
{
	assert(stack != NULL);
	list_init(&stack->list);
}

void pt_event_handler_stack_destroy(struct pt_event_handler_stack *stack)
{
	struct pt_event_handler *handler;
	struct list_head *lh, *lh2;

	assert(stack != NULL);

	list_for_each_safe (lh, lh2, &stack->list) {
		handler = list_entry(lh, struct pt_event_handler, list);
		list_del(&handler->list);
		free(handler);
	}
}

struct pt_event_handler *
pt_event_handler_stack_push(struct pt_event_handler_stack *stack,
                            int (*handler)(struct pt_event *), void *cookie)
{
	struct pt_event_handler *ev_handler;

	assert(stack != NULL);
	assert(handler != NULL);

	if ( (ev_handler = malloc(sizeof *ev_handler)) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	ev_handler->handler = handler;
	ev_handler->cookie  = cookie;
	list_add(&ev_handler->list, &stack->list);

	return ev_handler;
}

int pt_event_handler_stack_call(struct pt_event_handler_stack *stack,
                                struct pt_event *ev)
{
	struct pt_event_handler *handler;
	struct list_head *lh, *lh2;
	int ret = PT_EVENT_DROP;

	assert(stack != NULL);
	assert(ev != NULL);

	list_for_each_safe (lh, lh2, &stack->list) {
		handler = list_entry(lh, struct pt_event_handler, list);

		ev->cookie = handler->cookie;
		ret = handler->handler(ev);
		if (ret == PT_EVENT_DROP)
			break;
	}

	return ret;
}
