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
 * inject.c
 *
 * Implementation of libptrace code injection.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <libptrace/error.h>
#include <libptrace/process.h>
#include <libptrace/inject.h>
#include <libptrace/log.h>
#include "process.h"
#include "thread.h"

struct pt_inject_context_
{
	int tid;
	struct pt_process *process;

	/* Stacked event handlers. */
	struct pt_event_handler *thread_create;
	struct pt_event_handler *thread_exit;

	/* Pointer to allocated memory region in the remote. */
	pt_address_t data;

	/* Event handler and cookie for start of injected code. */
        int             (*handler_pre)(struct pt_process *, void *);
        void            *cookie_pre;

	/* Event handler and cookie for run completion of injected code. */
        int             (*handler_post)(struct pt_process *, void *);
        void            *cookie_post;
};

static int
pt_inject_thread_create_(struct pt_event *event)
{
	struct pt_event_thread_create *ev = (struct pt_event_thread_create *)event;
	struct pt_inject_context_ *ctx = (struct pt_inject_context_ *)ev->cookie;
	struct pt_process *p = ev->thread->process;
	int ret = PT_EVENT_FORWARD;
	int tid = ev->thread->tid;

	/* If we found the right thread, handle it. */
	if (p == ctx->process && tid == ctx->tid && ctx->handler_pre) {
		pt_log("%s(): injected code start in %d/%d.\n",
		       __FUNCTION__, tid, p->pid);

		if (ctx->handler_pre != NULL)
			ret = ctx->handler_pre(p, ctx->cookie_pre);

		return ret;
	}

	pt_log("%s(): forwarding event.\n", __FUNCTION__);
	return ret;
}

static int
pt_inject_thread_exit_(struct pt_event *event)
{
	struct pt_event_thread_exit *ev = (struct pt_event_thread_exit *)event;
	struct pt_inject_context_ *ctx = (struct pt_inject_context_ *)ev->cookie;
	struct pt_process *p = ev->thread->process;
	int ret = PT_EVENT_FORWARD;
	int tid = ev->thread->tid;

	/* If we found the right thread, handle it. */
	if (p == ctx->process && tid == ctx->tid && ctx->handler_post) {
		pt_log("%s(): injected code completed in %d/%d.\n",
		       __FUNCTION__, tid, p->pid);

		/* Call the inject post handler. */
		if (ctx->handler_post != NULL)
			ret = ctx->handler_post(p, ctx->cookie_post);

		/* We're done with the injection, so we clean up. */
		pt_event_handler_destroy(ctx->thread_create);
		pt_event_handler_destroy(ctx->thread_exit);
		pt_process_free(p, ctx->data); /* Ignore errors. */
		free(ctx);

		return ret;
	}

	/* Not the injection thread; forward the event. */
	pt_log("%s(): not the injection thread.  Forwarding event.\n",
	       __FUNCTION__);
	return PT_EVENT_FORWARD;
}

static inline int
inject_write_(struct pt_process *p, pt_address_t dst,
              const void *src, size_t size)
{
	if (src == NULL || size == 0)
		return 0;

	/* Write the code to be executed to the new region. */
	if (pt_process_write(p, dst, src, size) == -1)
		return -1;

	return 0;
}

int pt_inject(struct pt_inject *inject, struct pt_process *p)
{
	struct pt_inject_context_ *ctx;
	pt_address_t data, dest;
	int tid, ret;
	size_t size;

	/* Before we touch the remote, try to allocate the context. */
	if ( (ctx = malloc(sizeof *ctx)) == NULL) {
		pt_error_errno_set(errno);
		goto err;
	}

	/* Allocate a region to execute code from. */
	size = inject->data_size + inject->argument_size;
	if ( (data = pt_process_malloc(p, size)) == PT_ADDRESS_NULL)
		goto err_ctx;

	/* Write the code to be executed to the new region. */
	if (inject_write_(p, data, inject->data, inject->data_size) == -1)
		goto err_free;

	/* Write argument to the code in the new region. */
	dest = data + inject->argument_size;
	ret  = inject_write_(p, dest, inject->argument, inject->argument_size);
	if (ret == -1)
		goto err_free;


	/* Set the new event handlers.  This can error, so we do so prior
	 * to creating a new thread remotely.
	 */
	ctx->thread_create = pt_event_handler_stack_push(
		&p->handlers.thread_create,
	        pt_inject_thread_create_, ctx);
	if (ctx->thread_create == NULL)
		goto err_free;

	ctx->thread_exit   = pt_event_handler_stack_push(
		&p->handlers.thread_exit,
	        pt_inject_thread_exit_, ctx);
	if (ctx->thread_exit == NULL)
		goto err_thread_create_handler;

	/* Create a new thread to execute the code. */
	if ( (tid = pt_process_thread_create(p, data, dest)) == -1)
		goto err_thread_exit_handler;

	/* Initialize the rest of the context. */
	ctx->tid           = tid;
	ctx->process       = p;
	ctx->data          = data;
	ctx->handler_pre   = inject->handler_pre;
	ctx->cookie_pre    = inject->cookie_pre;
	ctx->handler_post  = inject->handler_post;
	ctx->cookie_post   = inject->cookie_post;

	pt_log("%s(): Created injection thread with TID %d.\n",
	       __FUNCTION__, tid);

	return 0;

err_thread_exit_handler:
	pt_event_handler_destroy(ctx->thread_exit);
err_thread_create_handler:
	pt_event_handler_destroy(ctx->thread_create);
err_free:
	pt_process_free(p, data);	/* Try once; ignore errors. */
err_ctx:
	free(ctx);
err:
	return -1;
}
