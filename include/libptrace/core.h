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
 * core.h
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_CORE_H
#define PT_CORE_H

#include <libptrace/charset.h>
#include <libptrace/event.h>
#include <libptrace/handle.h>
#include <libptrace/process.h>
#include <libptrace/types.h>

/* Behavioral options. */
#define PT_CORE_OPTION_NONE			0
#define PT_CORE_OPTION_EVENT_SECOND_CHANCE	1
#define PT_CORE_OPTION_SYMBOL_MANAGER		2
#define PT_CORE_OPTION_AUTO_TERMINATE_MAIN	4

#define pt_core_for_each_process(c, p)					\
	for (struct pt_iterator i = pt_iterator_process_begin(c);	\
	     (p) = pt_iterator_process_get(&i),				\
	     !pt_iterator_process_end(&i);				\
	     pt_iterator_process_next(&i))

struct pt_core;

#ifdef __cplusplus
extern "C" {
#endif

void			pt_core_delete(struct pt_core *);

int			pt_core_options_get(struct pt_core *);
void			pt_core_options_set(struct pt_core *, int);

pt_handle_t		pt_core_process_attach(struct pt_core *, pt_pid_t, struct pt_event_handlers *, int);
pt_handle_t		pt_core_process_attach_remote(struct pt_core *, pt_pid_t, struct pt_event_handlers *, int);
int			pt_core_process_detach(struct pt_core *, struct pt_process *);
int			pt_core_process_detach_remote(struct pt_core *, pt_handle_t);

int			pt_core_process_break(struct pt_core *, struct pt_process *);
int			pt_core_process_break_remote(struct pt_core *, pt_handle_t);

void			pt_core_quit(struct pt_core *);
int			pt_core_main(struct pt_core *);
int			pt_core_event_wait(struct pt_core *);
pt_handle_t		pt_core_execv(struct pt_core *, const utf8_t *, utf8_t *const [], struct pt_event_handlers *, int);
pt_handle_t		pt_core_execv_remote(struct pt_core *, const utf8_t *, utf8_t *const[], struct pt_event_handlers *, int);

pt_handle_t		pt_process_attach(pt_pid_t, struct pt_event_handlers *, int);
pt_handle_t		pt_process_attach_remote(pt_pid_t, struct pt_event_handlers *, int);
int			pt_process_detach(struct pt_process *);
int			pt_process_detach_remote(pt_handle_t);

void			pt_quit(void);
int			pt_main(void);
int			pt_event_wait(void);
pt_handle_t		pt_execv(const utf8_t *, utf8_t *const [], struct pt_event_handlers *, int);
pt_handle_t		pt_execv_remote(const utf8_t *, utf8_t *const [], struct pt_event_handlers *, int);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_CORE_H */
