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
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#ifndef PT_WINDOWS_PROCESS_INTERNAL_H
#define PT_WINDOWS_PROCESS_INTERNAL_H

#include <windows.h>
#include <libptrace/event.h>
#include <libptrace/module.h>
#include "../avl.h"
#include "../process.h"
#include "thread.h"

struct pt_windows_process_data
{
        HANDLE  h;
	int	wow64;
	int	active;		/* Did we use DebugActiveProcess()? */
};

static inline HANDLE pt_windows_process_handle_get(struct pt_process *process)
{
	return ((struct pt_windows_process_data *)process->private_data)->h;
};

static inline void pt_windows_process_handle_set(struct pt_process *process, HANDLE h)
{
	((struct pt_windows_process_data *)process->private_data)->h = h;
};

static inline int pt_windows_process_wow64_get(struct pt_process *process)
{
	return ((struct pt_windows_process_data *)process->private_data)->wow64;
};

static inline void pt_windows_process_wow64_set(struct pt_process *process, int wow64)
{
	((struct pt_windows_process_data *)process->private_data)->wow64 = !!wow64;
};

static inline int pt_windows_process_active_get(struct pt_process *process)
{
	return ((struct pt_windows_process_data *)process->private_data)->active;
};

static inline void pt_windows_process_active_set(struct pt_process *process, int active)
{
	((struct pt_windows_process_data *)process->private_data)->active = !!active;
};

#ifdef __cplusplus
extern "C" {
#endif

int                pt_windows_process_init(struct pt_process *);
int                pt_windows_process_destroy(struct pt_process *process);
struct pt_process *pt_windows_process_new(void);

ssize_t	pt_windows_process_read(struct pt_process *, void *, const void *, size_t);
int	pt_windows_process_write(struct pt_process *, void *, const void *, size_t);
int	pt_windows_process_thread_create(struct pt_process *, const void *, const void *);
void *	pt_windows_process_malloc(struct pt_process *, size_t);
int	pt_windows_process_free(struct pt_process *, const void *);

int	pt_windows_process_brk(struct pt_process *process);
int	pt_windows_process_resume(struct pt_process *process);
int	pt_windows_process_suspend(struct pt_process *process);

int breakpoint_handler(struct pt_thread *thread,
                       struct pt_event_breakpoint *ev);

/* XXX: private routines. */
void pt_process_detach_bottom_(struct pt_process *process);
int  pt_process_detach_top_(struct pt_core *core, struct pt_process *process);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_WINDOWS_PROCESS_INTERNAL_H */
