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
 * core.h
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#ifndef PT_WINDOWS_CORE_INTERNAL_H
#define PT_WINDOWS_CORE_INTERNAL_H

#include <windows.h>
#include "../core.h"

struct pt_windows_core_data
{
	HANDLE		debug_object_handle;
	HANDLE		msg_queue_post_event_handle;
};

static inline HANDLE
pt_windows_core_debug_object_handle_get(struct pt_core *core)
{
	struct pt_windows_core_data *core_data =
		(struct pt_windows_core_data *)core->private_data;
	return core_data->debug_object_handle;
};

static inline HANDLE
pt_windows_core_msg_queue_post_event_handle_get(struct pt_core *core)
{
	struct pt_windows_core_data *core_data =
		(struct pt_windows_core_data *)core->private_data;
	return core_data->msg_queue_post_event_handle;
};

static inline void
pt_windows_core_debug_object_handle_set(struct pt_core *core, HANDLE h)
{
	struct pt_windows_core_data *core_data =
		(struct pt_windows_core_data *)core->private_data;
	core_data->debug_object_handle = h;
};

static inline void
pt_windows_core_msg_queue_post_event_handle_set(struct pt_core *core, HANDLE h)
{
	struct pt_windows_core_data *core_data =
		(struct pt_windows_core_data *)core->private_data;
	core_data->msg_queue_post_event_handle = h;
};

#ifdef __cplusplus
extern "C" {
#endif

int pt_windows_core_init(struct pt_core *core);
struct pt_core *pt_windows_core_new(void);
int pt_windows_core_destroy(struct pt_core *core);
int pt_windows_core_event_wait(struct pt_core *core);
struct pt_process *pt_windows_core_process_attach(struct pt_core *, pt_pid_t, struct pt_event_handlers *, int);
int pt_windows_core_process_detach(struct pt_core *, struct pt_process *);
struct pt_process *pt_windows_core_exec(struct pt_core *, const utf8_t *, const utf8_t *, struct pt_event_handlers *, int);
struct pt_process *pt_windows_core_execv(struct pt_core *, const utf8_t *, utf8_t *const [], struct pt_event_handlers *, int);

int  handle_debug_single_step_(struct pt_process *process,
                               struct pt_thread *thread,
                               LPEXCEPTION_RECORD exception);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_WINDOWS_CORE_INTERNAL_H */
