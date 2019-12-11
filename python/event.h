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
 * Python bindings for libptrace events.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PYPT_EVENT_INTERNAL_H
#define PYPT_EVENT_INTERNAL_H

struct pypt_event_handlers
{
	PyObject_HEAD;
	PyObject *dict;

	PyObject *attached;
	PyObject *process_exit;
	PyObject *thread_create;
	PyObject *thread_exit;
	PyObject *module_load;
	PyObject *module_unload;
	PyObject *remote_break;
	PyObject *breakpoint;
	PyObject *single_step;
	PyObject *segfault;
	PyObject *illegal_instruction;
	PyObject *divide_by_zero;
	PyObject *priv_instruction;
	PyObject *unknown_exception;
};

extern PyTypeObject pypt_event_handlers_type;

int pypt_handle_attached(struct pt_event_attached *event);
int pypt_handle_process_exit(struct pt_event_process_exit *event);
int pypt_handle_module_load(struct pt_event_module_load *event);
int pypt_handle_module_unload(struct pt_event_module_unload *event);
int pypt_handle_thread_create(struct pt_event_thread_create *event);
int pypt_handle_thread_exit(struct pt_event_thread_exit *event);
int pypt_handle_breakpoint(struct pt_event_breakpoint *ev);
int pypt_handle_remote_break(struct pt_event_breakpoint *ev);
int pypt_handle_single_step(struct pt_event_single_step *ev);
int pypt_handle_segfault(struct pt_event_segfault *ev);
int pypt_handle_illegal_instruction(struct pt_event_illegal_instruction *ev);
int pypt_handle_divide_by_zero(struct pt_event_divide_by_zero *ev);
int pypt_handle_priv_instruction(struct pt_event_priv_instruction *ev);
int pypt_handle_unknown_exception(struct pt_event_unknown_exception *ev);

#endif	/* !PYPT_EVENT_INTERNAL_H */
