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
 */
#ifndef PT_CORE_INTERNAL_H
#define PT_CORE_INTERNAL_H

#include <libptrace/core.h>
#include <libptrace/event.h>
#include <libptrace/charset.h>
#include <libptrace/process.h>
#include <libptrace/types.h>
#include "avl.h"
#include "queue.h"

struct pt_core;

extern struct pt_core pt_core_main_;

struct pt_core_operations
{
	int                (*destroy)(struct pt_core *);

	struct pt_process *(*attach)(struct pt_core *, pt_pid_t, struct pt_event_handlers *, int);
	int                (*detach)(struct pt_core *, struct pt_process *);
	struct pt_process *(*exec)(struct pt_core *, const utf8_t *, const utf8_t *, struct pt_event_handlers *, int);
	struct pt_process *(*execv)(struct pt_core *, const utf8_t *, utf8_t *const [], struct pt_event_handlers *, int);
	int                (*event_wait)(struct pt_core *core);
};

struct pt_core
{
	int				options;
	int				quit;
	struct avl_tree			process_tree;
	void				*private_data;
	struct pt_core_operations	*c_op;
	struct pt_queue			msg_queue;
};

int pt_core_init(struct pt_core *);
int pt_core_destroy(struct pt_core *);

struct pt_process *pt_process_find(pt_pid_t);
struct pt_process *pt_core_process_find(struct pt_core *, pt_pid_t);

#endif	/* !PT_CORE_INTERNAL_H */
