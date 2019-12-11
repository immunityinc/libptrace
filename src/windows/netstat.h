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
 * netstat.h
 *
 * libptrace windows netstat support code.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_WINDOWS_NETSTAT_INTERNAL_H
#define PT_WINDOWS_NETSTAT_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <libptrace/list.h>

#define TCP_STATE_NONE		0
#define TCP_STATE_LISTENING	1

#define tcp_table_for_each(l, s)					\
        for (struct list_head *lh = (l)->list.next, *lh2 = lh->next;	\
                s = list_entry(lh, struct tcp_table_entry, list),	\
                lh != (&(l)->list); lh = lh2, lh2 = lh->next)

#define udp_table_for_each(l, s)					\
        for (struct list_head *lh = (l)->list.next, *lh2 = lh->next;	\
                s = list_entry(lh, struct udp_table_entry, list),	\
                lh != (&(l)->list); lh = lh2, lh2 = lh->next)

#ifdef __cplusplus
extern "C" {
#endif

struct udp_table_entry
{
	uint32_t		local_addr;
	uint16_t		local_port;
	DWORD			pid;

	struct list_head	list;
};

struct tcp_table_entry
{
	int			state;
	uint32_t		local_addr;
	uint16_t		local_port;
	uint32_t		remote_addr;
	uint16_t		remote_port;
	DWORD			pid;

	struct list_head	list;
};

struct udp_table
{
	struct list_head	list;
};

struct tcp_table
{
	struct list_head	list;
};

void netstat_tcp_table_init(struct tcp_table *);
void netstat_udp_table_init(struct udp_table *);

int netstat_tcp_table_get(struct tcp_table *);
void netstat_tcp_table_destroy(struct tcp_table *);
int netstat_udp_table_get(struct udp_table *);
void netstat_udp_table_destroy(struct udp_table *);

int netstat_tcp_filter(struct tcp_table *,
                       struct tcp_table *,
                       int (*)(struct tcp_table_entry *, void *),
                       void *);
int netstat_udp_filter(struct udp_table *,
                       struct udp_table *,
                       int (*)(struct udp_table_entry *, void *),
                       void *);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_WINDOWS_NETSTAT_INTERNAL_H */
