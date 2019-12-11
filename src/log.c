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
 * log.c
 *
 * libptrace logging framework.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <libptrace/list.h>
#include <libptrace/log.h>

/* XXX: mark for review with multithreaded cores. This breaks. */
struct list_head log_hooks_ = LIST_HEAD_INIT(log_hooks_);

static int pt_log_hook_used_(struct pt_log_hook *log_hook)
{
	struct list_head *lh;

	list_for_each (lh, &log_hooks_) {
		if (log_hook->list.next == lh->next &&
		    log_hook->list.prev == lh->prev)
			return 1;
	}

	return 0;
}

void pt_log(const char *format, ...)
{
	struct list_head *lh;
	va_list ap;

	va_start(ap, format);

	list_for_each(lh, &log_hooks_) {
		struct pt_log_hook *log_hook;

		log_hook = list_entry(lh, struct pt_log_hook, list);
		log_hook->handler(log_hook->cookie, format, ap);
	}

	va_end(ap);
}


void pt_log_hook_register(struct pt_log_hook *log_hook)
{
	list_add(&log_hook->list, &log_hooks_);
}

int pt_log_hook_unregister(struct pt_log_hook *log_hook)
{
	if (!pt_log_hook_used_(log_hook))
		return -1;

	list_del(&log_hook->list);
	return 0;
}
