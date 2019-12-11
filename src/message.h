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
 * message.h
 *
 * libptrace inter-core message passing definitions.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_MESSAGE_INTERNAL_H
#define PT_MESSAGE_INTERNAL_H

#include <libptrace/event.h>
#include <libptrace/types.h>
#include "error.h"

#define PT_MESSAGE_TYPE_ATTACH	1
#define PT_MESSAGE_TYPE_EXECV	2
#define PT_MESSAGE_TYPE_DETACH	3
#define PT_MESSAGE_TYPE_BREAK	4

#define PT_MESSAGE_COMMON						\
	int		type;						\
	struct pt_queue *response

struct pt_message
{
	PT_MESSAGE_COMMON;
};

struct pt_message_attach
{
	PT_MESSAGE_COMMON;

	pt_pid_t                  pid;
	struct pt_event_handlers *handlers;
	int                       options;
};

struct pt_message_detach
{
	PT_MESSAGE_COMMON;

	pt_handle_t handle;
};

struct pt_message_execv
{
	PT_MESSAGE_COMMON;

	const utf8_t *            filename;
	utf8_t *const            *argv;
	struct pt_event_handlers *handlers;
	int                       options;
};

struct pt_message_break
{
	PT_MESSAGE_COMMON;

	pt_handle_t handle;
};

struct pt_message_status
{
	union {
		pt_handle_t     handle;
		int		status;
	};
	struct pt_error error;
};

struct pt_message_storage
{
	union {
		struct pt_message        msg;
		struct pt_message_attach msg_attach;
		struct pt_message_execv  msg_execv;
		struct pt_message_detach msg_detach;
		struct pt_message_break  msg_break;
	};
};

#endif	/* !PT_MESSAGE_INTERNAL_H */
