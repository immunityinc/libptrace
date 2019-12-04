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
 * breakpoint.h
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_BREAKPOINT_H
#define PT_BREAKPOINT_H

#include <stdint.h>
#include <libptrace/event.h>
#include <libptrace/process.h>

#define PT_BREAKPOINT_FLAG_NONE		0
#define PT_BREAKPOINT_FLAG_ONESHOT	1
#define PT_BREAKPOINT_FLAG_DISABLED	2
#define PT_BREAKPOINT_FLAG_CONDITIONAL	4

#define PT_BREAKPOINT_SCOPE_PROCESS	0
#define PT_BREAKPOINT_SCOPE_THREAD	1

struct pt_breakpoint;
typedef void (*pt_breakpoint_handler_t)(struct pt_thread *, void *cookie);

#ifdef __cplusplus
extern "C" {
#endif

void pt_breakpoint_init(struct pt_breakpoint *);
void pt_breakpoint_destroy(struct pt_breakpoint *);
int  pt_breakpoint_handler(struct pt_thread *, struct pt_event_breakpoint *);
int  pt_breakpoint_set(struct pt_process *, struct pt_breakpoint *);
int  pt_breakpoint_remove(struct pt_process *, struct pt_breakpoint *);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_BREAKPOINT_H */
