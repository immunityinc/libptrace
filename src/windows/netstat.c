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
 * netstat.c
 *
 * libptrace windows netstat support code.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <winsock2.h>
#include <windows.h>
#include <iprtrmib.h>
#include <libptrace/list.h>
#include <libptrace/windows/error.h>
#include "netstat.h"
#include "wrappers/iphlpapi.h"

static int translate_state_(DWORD state)
{
	if (state == MIB_TCP_STATE_LISTEN)
		return TCP_STATE_LISTENING;

	return TCP_STATE_NONE;
}

void netstat_tcp_table_init(struct tcp_table *table)
{
	list_init(&table->list);
}

void netstat_udp_table_init(struct udp_table *table)
{
	list_init(&table->list);
}

int netstat_tcp_table_get(struct tcp_table *table)
{
	PMIB_TCPTABLE_OWNER_PID tcp_table = NULL;
	HANDLE heap;
	DWORD i;
	int ret;

	if ( (heap = GetProcessHeap()) == NULL)
		return -1;

	/* Get the TCP table from the OS.
	 *
	 * XXX: AllocateAndGetTcpExTableFromStack() is no longer available
	 * beginning with Windows Vista, need to port this part of the code for
	 * newer Windows OSes
	 */
	ret = pt_windows_api_allocate_and_get_tcp_ex_table_from_stack(
		(PVOID)&tcp_table,
		TRUE,
		heap,
		2,
		AF_INET
	);

	if (ret == -1)
		return -1;

	/* We're done if we didn't get a table; we consider it empty. */
	if (tcp_table == NULL)
		return 0;

	/* Add all structures to the list. */
	for (i = 0; i < tcp_table->dwNumEntries; i++) {
		struct tcp_table_entry *entry;

		entry = (struct tcp_table_entry *)malloc(sizeof(*entry));
		if (entry == NULL) {
			pt_error_errno_set(errno);
			netstat_tcp_table_destroy(table);
			HeapFree(heap, 0, tcp_table);
			return -1;
		}

		entry->state = translate_state_(tcp_table->table[i].dwState);
		entry->local_addr = tcp_table->table[i].dwLocalAddr;
		entry->local_port = htons(tcp_table->table[i].dwLocalPort);
		entry->remote_addr = tcp_table->table[i].dwRemoteAddr;
		entry->remote_port = htons(tcp_table->table[i].dwRemotePort);
		entry->pid = tcp_table->table[i].dwOwningPid;

		list_add_tail(&entry->list, &table->list);
	}

	HeapFree(heap, 0, tcp_table);
	return 0;
}

void netstat_tcp_table_destroy(struct tcp_table *table)
{
	struct tcp_table_entry *entry;

	tcp_table_for_each(table, entry) {
		list_del(&entry->list);
		free(entry);
	}
}

int netstat_udp_table_get(struct udp_table *table)
{
	PMIB_UDPTABLE_OWNER_PID udp_table;
	HANDLE heap;
	DWORD i;
	int ret;

	if ( (heap = GetProcessHeap()) == NULL)
		return -1;

	/* Get the UDP table from the OS.
	 *
	 * XXX: AllocateAndGetTcpExTableFromStack() is no longer available
	 * beginning with Windows Vista, need to port this part of the code for
	 * newer Windows OSes
	 */
	ret = pt_windows_api_allocate_and_get_udp_ex_table_from_stack(
		(PVOID *)&udp_table,
		TRUE,
		heap,
		2,
		AF_INET
	);

	if (ret == -1)
		return -1;

	if (udp_table == NULL)
		return 0;

	/* Do the translation from Windows to libptrace format in order to
	 * ensure object portability.
	 */
	for (i = 0; i < udp_table->dwNumEntries; i++) {
		struct udp_table_entry *entry;

		entry = (struct udp_table_entry *)malloc(sizeof(*entry));
		if (entry == NULL) {
			pt_error_errno_set(errno);
			netstat_udp_table_destroy(table);
			HeapFree(heap, 0, udp_table);
			return -1;
		}

		entry->local_addr = udp_table->table[i].dwLocalAddr;
		entry->local_port = htons(udp_table->table[i].dwLocalPort);
		entry->pid = udp_table->table[i].dwOwningPid;

		list_add(&entry->list, &table->list);
	}

	HeapFree(heap, 0, udp_table);
	return 0;
}

void netstat_udp_table_destroy(struct udp_table *table)
{
	struct udp_table_entry *entry;

	udp_table_for_each(table, entry) {
		list_del(&entry->list);
		free(entry);
	}
}

static struct tcp_table_entry *tcopy_(struct tcp_table_entry *entry)
{
	struct tcp_table_entry *new;

	if ( (new = malloc(sizeof(*new))) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	return memcpy(new, entry, sizeof(*new));
}

static struct udp_table_entry *ucopy_(struct udp_table_entry *entry)
{
	struct udp_table_entry *new;

	if ( (new = malloc(sizeof(*new))) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	return memcpy(new, entry, sizeof(*new));
}

/* Filter out all TCP ports as dictated by 'compare'. */
int netstat_tcp_filter(struct tcp_table *tcp_out,
	                   struct tcp_table *tcp_in,
	                   int (*compare)(struct tcp_table_entry *, void *),
	                   void *cookie)
{
	struct tcp_table_entry *entry;

	/* Initialize tcp_out. */
	netstat_tcp_table_init(tcp_out);

	tcp_table_for_each(tcp_in, entry) {
		if (compare(entry, cookie)) {
			struct tcp_table_entry *new;

			if ( (new = tcopy_(entry)) == NULL) {
				netstat_tcp_table_destroy(tcp_out);
				return -1;
			}

			list_add_tail(&new->list, &tcp_out->list);
		}
	}

	return 0;
}

/* Filter out all UDP ports as dictated by 'compare'. */
int netstat_udp_filter(struct udp_table *udp_out,
	                   struct udp_table *udp_in,
	                   int (*compare)(struct udp_table_entry *, void *),
	                   void *cookie)
{
	struct udp_table_entry *entry;

	/* Initialize udp_out. */
	netstat_udp_table_init(udp_out);

	udp_table_for_each(udp_in, entry) {
		if (compare(entry, cookie)) {
			struct udp_table_entry *new;

			if ( (new = ucopy_(entry)) == NULL) {
				netstat_udp_table_destroy(udp_out);
				return -1;
			}

			list_add_tail(&new->list, &udp_out->list);
		}
	}

	return 0;
}
