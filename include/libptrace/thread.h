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
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#ifndef PT_THREAD_H
#define PT_THREAD_H

#include <libptrace/breakpoint.h>
#include <libptrace/breakpoint_x86.h>
#include <libptrace/types.h>

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

#define pt_thread_for_each_dbreg(p, d)                                        \
	for (int i = 0; d = &((p)->debug_registers.regs[i]), i < 4; i++)

#define pt_thread_for_each_breakpoint(p, b)                                   \
        for (struct pt_iterator i = pt_iterator_breakpoint_begin_thread(p);   \
             (b) = pt_iterator_breakpoint_get(&i),                            \
             !pt_iterator_breakpoint_end(&i);                                 \
             pt_iterator_breakpoint_next(&i))

struct pt_thread;
typedef uint32_t pt_tid_t;

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

#endif /* !PT_THREAD_H */
