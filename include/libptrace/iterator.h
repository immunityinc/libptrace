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
 * iterator.h
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_ITERATOR_H
#define PT_ITERATOR_H

struct pt_core;
struct pt_process;
struct pt_module;
struct pt_thread;

struct pt_iterator
{
	void *private__[3];
};

#ifdef __cplusplus
extern "C" {
#endif

struct pt_iterator     pt_iterator_process_begin(struct pt_core *);
int                    pt_iterator_process_end(struct pt_iterator *);
struct pt_process *    pt_iterator_process_get(struct pt_iterator *);
void                   pt_iterator_process_next(struct pt_iterator *);

struct pt_iterator     pt_iterator_thread_begin(struct pt_process *);
int                    pt_iterator_thread_end(struct pt_iterator *);
void                   pt_iterator_thread_next(struct pt_iterator *);
struct pt_thread *     pt_iterator_thread_get(struct pt_iterator *);

struct pt_iterator     pt_iterator_module_begin(struct pt_process *);
int                    pt_iterator_module_end(struct pt_iterator *);
void                   pt_iterator_module_next(struct pt_iterator *);
struct pt_module *     pt_iterator_module_get(struct pt_iterator *);

struct pt_iterator     pt_iterator_breakpoint_begin_process(struct pt_process *);
struct pt_iterator     pt_iterator_breakpoint_begin_thread(struct pt_thread *);
int                    pt_iterator_breakpoint_end(struct pt_iterator *);
void                   pt_iterator_breakpoint_next(struct pt_iterator *);
struct pt_breakpoint * pt_iterator_breakpoint_get(struct pt_iterator *);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_ITERATOR_H */
