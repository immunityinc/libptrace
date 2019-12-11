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
 * core.c
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <stdio.h>
#include <signal.h>
#include <libptrace/error.h>
#include <libptrace/util.h>
#include "avl.h"
#include "core.h"
#include "compat.h"
#include "handle.h"
#include "message.h"
#include "process.h"

static int process_compare_(struct avl_node *a_, struct avl_node *b_);
struct pt_core pt_core_main_;

#ifdef WIN32
#include "windows/core.h"

/* XXX: rework later. */
static void __attribute__((constructor)) pt_core_main_initialize_(void)
{
	pt_windows_core_init(&pt_core_main_);
}
#endif

static int process_compare_(struct avl_node *a_, struct avl_node *b_)
{
	struct pt_process *a = container_of(a_, struct pt_process, avl_node);
	struct pt_process *b = container_of(b_, struct pt_process, avl_node);

	if (a->pid < b->pid)
		return -1;

	if (a->pid > b->pid)
		return 1;

	return 0;
}

int pt_core_init(struct pt_core *core)
{
	if (pt_queue_init(&core->msg_queue, 4096) == -1)
		return -1;

	core->msg_queue.flags = PT_QUEUE_FLAG_RECV_NONBLOCK;

	core->options      = PT_CORE_OPTION_AUTO_TERMINATE_MAIN;
	core->quit         = 0;
	core->private_data = NULL;
	INIT_AVL_TREE(&core->process_tree, process_compare_);

	return 0;
}

int pt_core_destroy(struct pt_core *core)
{
	if (core->c_op->destroy && core->c_op->destroy(core) == -1)
		return -1;

	if (pt_queue_destroy(&core->msg_queue) == -1)
		return -1;

	return 0;
}

void pt_core_delete(struct pt_core *core)
{
	pt_core_destroy(core);
	free(core);
}

int pt_core_options_get(struct pt_core *core)
{
	return core->options;
}

void pt_core_options_set(struct pt_core *core, int options)
{
	core->options = options;
}

int pt_core_event_wait(struct pt_core *core)
{
	if (core->c_op->event_wait == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	return core->c_op->event_wait(core);
}

struct pt_process *pt_core_process_find(struct pt_core *core, pt_pid_t pid)
{
	struct avl_node *an;

	an = core->process_tree.root;
	while (an != NULL) {
		struct pt_process *process;

		process = container_of(an, struct pt_process, avl_node);
		if (process->pid == pid)
			return process;

		if (process->pid > pid)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

struct pt_process *pt_process_find(pt_pid_t pid)
{
	return pt_core_process_find(&pt_core_main_, pid);
}

void pt_core_quit(struct pt_core *core)
{
	core->quit = 1;
}

void pt_quit(void)
{
	pt_core_quit(&pt_core_main_);
}

static inline int main_loop_done_(struct pt_core *core, int ret)
{
	int need_quit;

	/* On error, the main loop will return error. */
	if (ret != 0)
		return 1;

	/* If quit hasn't been flagged, we keep going. */
	need_quit = !(core->options & PT_CORE_OPTION_AUTO_TERMINATE_MAIN);
	if (need_quit && core->quit == 0)
		return 0;

	/* If quit was flagged and the process tree is empty, we're out. */
	if (avl_tree_empty(&core->process_tree))
		return 1;

	return 0;
}

int pt_core_main(struct pt_core *core)
{
	int ret;

	do {
		ret = pt_core_event_wait(core);
	} while (!main_loop_done_(core, ret));

	return ret;
}

int pt_main(void)
{
	return pt_core_main(&pt_core_main_);
}

pt_handle_t pt_process_attach(pt_pid_t pid, struct pt_event_handlers *handlers, int options)
{
	return pt_core_process_attach(&pt_core_main_, pid, handlers, options);
}

pt_handle_t pt_process_attach_remote(pt_pid_t pid, struct pt_event_handlers *handlers, int options)
{
	return pt_core_process_attach_remote(&pt_core_main_, pid, handlers, options);
}

int pt_core_process_detach_remote(struct pt_core *core, pt_handle_t handle)
{
	struct pt_message_status response;
	struct pt_message_detach request;
	struct pt_queue rx_queue;
	HANDLE h;

	/* XXX: FIXME layering violation. */
	h = pt_windows_core_msg_queue_post_event_handle_get(core);
	assert(h != NULL);
	assert(h != INVALID_HANDLE_VALUE);

	if (pt_queue_init(&rx_queue, 1) == -1)
		return -1;

	/* Post the message to the core message queue. */
	request.type     = PT_MESSAGE_TYPE_DETACH;
	request.handle   = handle;
	request.response = &rx_queue;

	if (pt_queue_send(&core->msg_queue, &request, sizeof request) == -1) {
		pt_queue_destroy(&rx_queue);
		return -1;
	}

	SetEvent(h);

	if (pt_queue_recv(&rx_queue, &response, sizeof response) == -1) {
		pt_queue_destroy(&rx_queue);
		return -1;
	}

	pt_queue_destroy(&rx_queue);

	/* XXX: copy errno status. */
	return response.status;
}

int pt_core_process_break(struct pt_core *core, struct pt_process *process)
{
	return pt_process_brk(process);
}

int pt_core_process_break_remote(struct pt_core *core, pt_handle_t handle)
{
	struct pt_message_status response;
	struct pt_message_break request;
	struct pt_queue rx_queue;
	HANDLE h;

	/* XXX: FIXME layering violation. */
	h = pt_windows_core_msg_queue_post_event_handle_get(core);
	assert(h != NULL);
	assert(h != INVALID_HANDLE_VALUE);

	if (pt_queue_init(&rx_queue, 1) == -1)
		return -1;

	/* Post the message to the core message queue. */
	request.type     = PT_MESSAGE_TYPE_BREAK;
	request.handle   = handle;
	request.response = &rx_queue;

	if (pt_queue_send(&core->msg_queue, &request, sizeof request) == -1) {
		pt_queue_destroy(&rx_queue);
		return -1;
	}

	SetEvent(h);

	if (pt_queue_recv(&rx_queue, &response, sizeof response) == -1) {
		pt_queue_destroy(&rx_queue);
		return -1;
	}

	pt_queue_destroy(&rx_queue);

	/* XXX: copy errno status. */
	return response.status;
}

int pt_core_process_detach(struct pt_core *core, struct pt_process *process)
{
	if (core->c_op->detach == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	/* The process doesn't belong to this core. */
	if (core != process->core) {
		pt_error_internal_set(PT_ERROR_INVALID_CORE);
		return -1;
	}

	return core->c_op->detach(core, process);
}

int pt_process_detach(struct pt_process *process)
{
	return pt_core_process_detach(&pt_core_main_, process);
}

pt_handle_t pt_core_execv_remote(
	struct pt_core *core,
	const utf8_t *filename,
	utf8_t *const argv[],
	struct pt_event_handlers *handlers,
	int options)
{
	struct pt_message_status response;
	struct pt_message_execv request;
	struct pt_queue rx_queue;
	HANDLE h;

	/* XXX: FIXME layering violation. */
	h = pt_windows_core_msg_queue_post_event_handle_get(core);
	assert(h != NULL);
	assert(h != INVALID_HANDLE_VALUE);

	if (pt_queue_init(&rx_queue, 1) == -1)
		return PT_HANDLE_NULL;

	/* Post the message to the core message queue. */
	request.type     = PT_MESSAGE_TYPE_EXECV;
	request.filename = filename;
	request.argv     = argv;
	request.handlers = handlers;
	request.options  = options;
	request.response = &rx_queue;

	if (pt_queue_send(&core->msg_queue, &request, sizeof request) == -1) {
		pt_queue_destroy(&rx_queue);
		return PT_HANDLE_NULL;
	}

	SetEvent(h);

	if (pt_queue_recv(&rx_queue, &response, sizeof response) == -1) {
		pt_queue_destroy(&rx_queue);
		return PT_HANDLE_NULL;
	}

	pt_queue_destroy(&rx_queue);

	/* XXX: copy errno status. */
	return response.handle;
}

pt_handle_t pt_core_execv(
	struct pt_core *core,
	const utf8_t *filename,
	utf8_t *const argv[],
	struct pt_event_handlers *handlers,
	int options)
{
	struct pt_process *process;
	pt_handle_process_t *ph;
	pt_handle_t handle;

	assert(core != NULL);
	assert(core->c_op != NULL);
	assert(filename != NULL);

	if (core->c_op->execv == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return PT_HANDLE_NULL;
	}

	process = core->c_op->execv(core, filename, argv, handlers, options);
	if (process == NULL)
		return PT_HANDLE_NULL;

	ph                = (pt_handle_process_t *)&handle;
	ph->pid           = process->pid;
	ph->creation_time = process->creation_time;

	return handle;
}

pt_handle_t pt_execv(
	const utf8_t *filename,
	utf8_t *const argv[],
	struct pt_event_handlers *handlers,
	int options)
{
	return pt_core_execv(&pt_core_main_, filename, argv, handlers, options);
}

pt_handle_t pt_core_process_attach_remote(
	struct pt_core *core,
	pt_pid_t pid,
	struct pt_event_handlers *handlers,
	int options)
{
	struct pt_message_status response;
	struct pt_message_attach request;
	struct pt_queue rx_queue;
	HANDLE h;

	/* XXX: FIXME layering violation. */
	h = pt_windows_core_msg_queue_post_event_handle_get(core);
	assert(h != NULL);
	assert(h != INVALID_HANDLE_VALUE);

	if (pt_queue_init(&rx_queue, 1) == -1)
		return PT_HANDLE_NULL;

	/* Post the message to the core message queue. */
	request.type     = PT_MESSAGE_TYPE_ATTACH;
	request.pid      = pid;
	request.handlers = handlers;
	request.options  = options;
	request.response = &rx_queue;

	if (pt_queue_send(&core->msg_queue, &request, sizeof request) == -1) {
		pt_queue_destroy(&rx_queue);
		return PT_HANDLE_NULL;
	}

	SetEvent(h);

	if (pt_queue_recv(&rx_queue, &response, sizeof response) == -1) {
		pt_queue_destroy(&rx_queue);
		return PT_HANDLE_NULL;
	}

	pt_queue_destroy(&rx_queue);

	/* XXX: copy errno status. */
	return response.handle;
}

pt_handle_t pt_core_process_attach(
	struct pt_core *core,
	pt_pid_t pid,
	struct pt_event_handlers *handlers,
	int options)
{
	struct pt_process *process;
	pt_handle_process_t *ph;
	pt_handle_t handle;

	assert(core != NULL);
	assert(core->c_op != NULL);

	if (core->c_op->attach == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return PT_HANDLE_NULL;
	}

	process = core->c_op->attach(core, pid, handlers, options);
	if (process == NULL)
		return PT_HANDLE_NULL;

	ph                = (pt_handle_process_t *)&handle;
	ph->pid           = process->pid;
	ph->creation_time = process->creation_time;

	return handle;
}
