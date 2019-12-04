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
#ifndef PT_PROCESS_H
#define PT_PROCESS_H

#include <stdio.h>
#include <stdarg.h>
#include <libptrace/list.h>
#include <libptrace/types.h>
#include <libptrace/charset.h>
#include <libptrace/iterator.h>

#define PT_PROCESS_OPTION_NONE			0
#define PT_PROCESS_OPTION_EVENT_SECOND_CHANCE	1
#define PT_PROCESS_OPTION_SYMBOL_MANAGER	2

#define PT_PROCESS_STATE_INIT			0
#define PT_PROCESS_STATE_CREATED		1
#define PT_PROCESS_STATE_ATTACHED		2
#define PT_PROCESS_STATE_DETACH_BOTTOM		3
#define PT_PROCESS_STATE_DETACH_TOP		4
#define PT_PROCESS_STATE_DETACHED		5
#define PT_PROCESS_STATE_EXITED			6

#define pt_process_for_each_thread(p, t)                                      \
	for (struct pt_iterator i = pt_iterator_thread_begin(p);              \
	     (t) = pt_iterator_thread_get(&i),                                \
	     !pt_iterator_thread_end(&i);                                     \
	     pt_iterator_thread_next(&i))

#define pt_process_for_each_module(p, m)                                      \
	for (struct pt_iterator i = pt_iterator_module_begin(p);              \
	     (m) = pt_iterator_module_get(&i),                                \
	     !pt_iterator_module_end(&i);                                     \
	     pt_iterator_module_next(&i))

#define pt_process_for_each_breakpoint(p, b)                                  \
	for (struct pt_iterator i = pt_iterator_breakpoint_begin_process(p);  \
	     (b) = pt_iterator_breakpoint_get(&i),                            \
	     !pt_iterator_breakpoint_end(&i);                                 \
	     pt_iterator_breakpoint_next(&i))

struct pt_process;

#ifdef __cplusplus
extern "C" {
#endif

pt_pid_t          pt_process_pid_get(struct pt_process *);
struct pt_module *pt_process_main_module_get(struct pt_process *);
struct pt_thread *pt_process_main_thread_get(struct pt_process *);

int pt_process_option_set(struct pt_process *, int);
int pt_process_exited(struct pt_process *);

int pt_process_strlen(struct pt_process *, const pt_address_t, size_t *);
int pt_process_strlen16(struct pt_process *, const pt_address_t, size_t *);

int pt_process_exec(struct pt_process *, const utf8_t *, const utf8_t *);
int pt_process_execl(struct pt_process *, const utf8_t *, ...);
int pt_process_execv(struct pt_process *process, const utf8_t *, utf8_t *const []);


int          pt_process_write(struct pt_process *, pt_address_t, const void *, size_t);
ssize_t      pt_process_read(struct pt_process *, void *, const pt_address_t, size_t);
int          pt_process_thread_create(struct pt_process *, pt_address_t, pt_address_t);
pt_address_t pt_process_malloc(struct pt_process *, size_t);
int          pt_process_free(struct pt_process *, pt_address_t);

utf8_t *pt_process_read_string(struct pt_process *, const pt_address_t);
utf8_t *pt_process_read_string_utf16(struct pt_process *, const pt_address_t);

struct pt_breakpoint *
pt_process_breakpoint_find(struct pt_process *process, pt_address_t address);

int pt_process_breakpoint_set(struct pt_process *, struct pt_breakpoint *);
int pt_process_breakpoint_remove(struct pt_process *, struct pt_breakpoint *);

pt_address_t pt_process_export_find(struct pt_process *proc, const char *symbol);
struct pt_thread *pt_process_thread_find(struct pt_process *process, pt_pid_t tid);

int	pt_process_resume(struct pt_process *);
int	pt_process_suspend(struct pt_process *);
int	pt_process_brk(struct pt_process *);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_PROCESS_H */
