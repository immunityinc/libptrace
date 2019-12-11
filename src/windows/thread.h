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
 * thread.h
 *
 * libptrace windows thread management.
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#ifndef PT_WINDOWS_THREAD_INTERNAL_H
#define PT_WINDOWS_THREAD_INTERNAL_H

#include "../thread.h"

struct pt_windows_thread_data
{
	HANDLE	h;
};

static inline HANDLE pt_windows_thread_handle_get(struct pt_thread *thread)
{
	return ((struct pt_windows_thread_data *)thread->private_data)->h;
};

static inline void pt_windows_thread_handle_set(struct pt_thread *thread, HANDLE h)
{
	((struct pt_windows_thread_data *)thread->private_data)->h = h;
};

#ifdef __cplusplus
extern "C" {
#endif

extern struct pt_thread_operations pt_windows_thread_operations;

int pt_windows_thread_init(struct pt_thread *thread);
int pt_windows_thread_destroy(struct pt_thread *thread);
struct pt_thread *pt_windows_thread_new(void);

int pt_windows_thread_suspend(struct pt_thread *thread);
int pt_windows_thread_resume(struct pt_thread *thread);
int pt_windows_thread_single_step_set(struct pt_thread *);
int pt_windows_thread_single_step_remove(struct pt_thread *);

struct pt_registers *pt_windows_thread_registers_get(struct pt_thread *);

int pt_windows_thread_registers_set(struct pt_thread *, struct pt_registers *);
int pt_windows_thread_debug_registers_apply(struct pt_thread *thread);

void *pt_thread_get_tls(struct pt_thread *);
void *pt_thread_get_start(struct pt_thread *);

void *pt_windows_thread_register_pc_get(struct pt_thread *);
int   pt_windows_thread_register_pc_set(struct pt_thread *, void *);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_WINDOWS_THREAD_INTERNAL_H */
