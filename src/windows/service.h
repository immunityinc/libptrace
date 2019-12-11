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
 * service.h
 *
 * libptrace windows services management.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_WINDOWS_SERVICE_INTERNAL_H
#define PT_WINDOWS_SERVICE_INTERNAL_H

#include <limits.h>
#include <libptrace/list.h>

#define service_for_each(l, s)						\
	for (struct list_head *lh = (l)->list.next, *lh2 = lh->next;	\
		s = list_entry(lh, struct service_list_entry, list),	\
		lh != (&(l)->list); lh = lh2, lh2 = lh->next)

#ifdef __cplusplus
extern "C" {
#endif

struct service_list
{
	struct list_head		list;
};

struct service_list_entry
{
	char				*name;
	char				*display_name;
	SERVICE_STATUS_PROCESS		status;
	struct list_head		list;
};

void service_list_init(struct service_list *service_list);
int service_list_get(struct service_list *service_list);
void service_list_destroy(struct service_list *);
int service_list_filter(struct service_list *dest,
                        struct service_list *src,
                        int (*compare)(struct service_list_entry *, void *),
                        void *cookie);

ssize_t service_list_get_string(struct service_list *, char *, size_t);
ssize_t
service_list_entry_get_string(struct service_list_entry *, char *, size_t);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_WINDOWS_SERVICE_INTERNAL_H */
