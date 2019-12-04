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
 * event.h
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_EVENT_H
#define PT_EVENT_H

#include <libptrace/types.h>

#define PT_EVENT_DROP		0
#define PT_EVENT_FORWARD	1

#define PT_EVENT_COMMON							\
	void	*cookie;						\
	int	error;

struct pt_event
{
	PT_EVENT_COMMON;
};

struct pt_event_signal
{
	int	signo;
};

struct pt_event_syscall
{
	int	number;
	int	nargs;
};

struct pt_event_attached
{
	PT_EVENT_COMMON;
	struct pt_process	*process;
};

struct pt_event_process_exit
{
	PT_EVENT_COMMON;
	struct pt_process	*process;
	int			exitcode;
};

struct pt_event_thread_create
{
	PT_EVENT_COMMON;
	struct pt_thread	*thread;
};

struct pt_event_thread_exit
{
	PT_EVENT_COMMON;
	struct pt_thread	*thread;
	int			exitcode;
};

struct pt_event_module_load
{
	PT_EVENT_COMMON;
	struct pt_module	*module;
};

struct pt_event_module_unload
{
	PT_EVENT_COMMON;
	struct pt_module	*module;
};

struct pt_event_breakpoint
{
	pt_address_t		address;
	struct pt_thread	*thread;
	uint8_t			chance;
};

struct pt_event_single_step
{
	void			*address;
	struct pt_thread	*thread;
};

struct pt_event_windows
{
	struct pt_thread	*thread;
};

struct pt_event_segfault
{
	void			*address;
	void			*fault_address;
	struct pt_thread	*thread;
	uint8_t			chance;
};

struct pt_event_illegal_instruction
{
	void			*address;
	struct pt_thread	*thread;
	uint8_t			chance;
};

struct pt_event_divide_by_zero
{
	void			*address;
	struct pt_thread	*thread;
	uint8_t			chance;
};

struct pt_event_priv_instruction
{
	void			*address;
	struct pt_thread	*thread;
	uint8_t			chance;
};

struct pt_event_unknown_exception
{
	int			number;
	void			*address;
	struct pt_thread	*thread;
	uint8_t			chance;
};

/* XXX: architecture specific. */
struct pt_event_x86_dr
{
	void			*address;
	struct pt_thread	*thread;
};

typedef int (*pt_event_handler_t)(struct pt_event *);
typedef int (*pt_event_handler_attached_t)(struct pt_event_attached *);
typedef int (*pt_event_handler_process_exit_t)(struct pt_event_process_exit *);
typedef int (*pt_event_handler_thread_create_t)(struct pt_event_thread_create *);
typedef int (*pt_event_handler_thread_exit_t)(struct pt_event_thread_exit *);
typedef int (*pt_event_handler_module_load_t)(struct pt_event_module_load *);
typedef int (*pt_event_handler_module_unload_t)(struct pt_event_module_unload *);

struct pt_event_handler_attached
{
	pt_event_handler_attached_t	handler;
	void				*cookie;
};

struct pt_event_handler_process_exit
{
	pt_event_handler_process_exit_t	handler;
	void				*cookie;
};

struct pt_event_handler_thread_create
{
	pt_event_handler_thread_create_t	handler;
	void					*cookie;
};

struct pt_event_handler_thread_exit
{
	pt_event_handler_thread_exit_t handler;
	void 	*cookie;
};

struct pt_event_handler_module_load
{
	pt_event_handler_module_load_t handler;
	void	*cookie;
};

struct pt_event_handler_module_unload
{
	pt_event_handler_module_unload_t handler;
	void	*cookie;
};

struct pt_event_handlers
{
	struct pt_event_handler_attached	attached;
	struct pt_event_handler_process_exit	process_exit;
	struct pt_event_handler_thread_create	thread_create;
	struct pt_event_handler_thread_exit	thread_exit;
	struct pt_event_handler_module_load	module_load;
	struct pt_event_handler_module_unload	module_unload;

	int (*remote_break)(struct pt_event_breakpoint *);
	int (*breakpoint)(struct pt_event_breakpoint *);
	int (*single_step)(struct pt_event_single_step *);
	int (*segfault)(struct pt_event_segfault *);
	int (*illegal_instruction)(struct pt_event_illegal_instruction *);
	int (*divide_by_zero)(struct pt_event_divide_by_zero *);
	int (*priv_instruction)(struct pt_event_priv_instruction *);
	int (*unknown_exception)(struct pt_event_unknown_exception *);

	int (*x86_dr)(struct pt_event_x86_dr *);
};

#ifdef __cplusplus
extern "C" {
#endif

void pt_event_handlers_init(struct pt_event_handlers *);
void pt_event_handlers_destroy(struct pt_event_handlers *);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_EVENT_H */

