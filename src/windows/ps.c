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
 * ps.c
 *
 * libptrace windows process list management.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <stdio.h>
#include <windows.h>
#include <libptrace/charset.h>
#include <libptrace/windows/error.h>
#include "ps.h"
#include "netstat.h"
#include "service.h"
#include "wrappers/psapi.h"

#ifdef TEST_PS
#include <libptrace/windows/token.h>
#endif

_Static_assert(sizeof(DWORD) <= sizeof(void *),
               "'DWORD' cannot be stored in 'void *'");

/* Return the Win32 pathname of the executable associated with a given PID in UTF-8 */
utf8_t *ps_process_pathname_get(DWORD pid)
{
	utf8_t *ret;
	HANDLE ph;

	ph = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
	if (ph == NULL)
		return NULL;

	ret = pt_windows_api_get_module_filename_ex(ph, NULL);
	CloseHandle(ph);

	return ret;
}

/* this is kept as char* since will work both on ANSI and UTF-8 */
static char *basename_(char *pathname)
{
	char *p, *end, *retval;
	size_t i;

	/* Sanity checks */
	if (pathname == NULL || (p = strrchr(pathname, '\\')) == NULL)
		return NULL;

	/* Skip the '\' we found. */
	p++;

	/* Scan for the end of name */
	for (end = p; *end && *end != '.'; end++);

	/* Allocate the name member and initialize it. */
	if ( (retval = (char *)malloc(end - p + 1)) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	for (i = 0; i < end - p; i++)
		retval[i] = p[i];
	retval[i] = 0;

	return retval;
}

static int tcp_cmp_(struct tcp_table_entry *entry, void *cookie)
{
	DWORD pid = (DWORD)(uintptr_t)cookie;

	return entry->state == TCP_STATE_LISTENING &&
	       entry->pid == pid;
}

static int udp_cmp_(struct udp_table_entry *entry, void *cookie)
{
	DWORD pid = (DWORD)(uintptr_t)cookie;

	return entry->pid == pid;
}

static int service_cmp_(struct service_list_entry *entry, void *cookie)
{
	DWORD pid = (DWORD)(uintptr_t)cookie;

	return entry->status.dwProcessId == pid;
}

void process_list_init(struct process_list *list)
{
	list->data = NULL;
	list->count = 0;
}

void process_list_entry_init(struct process_list_entry *entry)
{
	entry->pid = -1;
	entry->name = NULL;
	entry->pathname = NULL;
	netstat_tcp_table_init(&entry->tcp_table);
	netstat_udp_table_init(&entry->udp_table);
	service_list_init(&entry->service_list);
}

int process_list_get(struct process_list *list)
{
	struct service_list services;
	struct tcp_table tcp_table;
	struct udp_table udp_table;
	DWORD *processes;
	HANDLE *handles;
	DWORD count, i;

	process_list_init(list);
	netstat_tcp_table_init(&tcp_table);
	netstat_udp_table_init(&udp_table);

	/* Enumerate all the processes on the system. */
	if (pt_windows_api_enum_processes(&processes, &count) == FALSE)
		return -1;

	/* Count is in bytes.  Make sure it counts the processes. */
	count /= sizeof(DWORD);

	/* We try to open each process with PROCESS_QUERY_INFORMATION.
	 * This is to keep a refcount on the process, so we can relate it
	 * to other snapshot data (such as the netstat TCP and UDP tables)
	 * without being race-prone.
	 */
	if ( (handles = malloc(count * sizeof(HANDLE))) == NULL) {
		pt_error_errno_set(errno);
		return -1;
	}

	/* Allocate the process list properly at this point. */
	list->data = (struct process_list_entry *)
		malloc(count * sizeof(struct process_list_entry));
	if (list->data == NULL) {
		pt_error_errno_set(errno);
		free(handles);
		return -1;
	}
	list->count = count;

	/* Now try to open all processes to keep a reference on them. */
	for (i = 0; i < count; i++)
		handles[i] = OpenProcess(PROCESS_QUERY_INFORMATION, 0,
		                         processes[i]);

	/* Get other snapshots we are interested in. */
	service_list_get(&services);
	netstat_tcp_table_get(&tcp_table);
	netstat_udp_table_get(&udp_table);

	/* Add each process to our list of processes, and query their data. */
	for (i = 0; i < count; i++) {
		process_list_entry_init(&list->data[i]);
		list->data[i].pid = processes[i];

		/* Perform these functions only if we got a handle. */
		if (handles[i] != NULL) {
			list->data[i].pathname =
				ps_process_pathname_get(processes[i]);
			list->data[i].name = basename_(list->data[i].pathname);

			netstat_tcp_filter(&list->data[i].tcp_table,
				&tcp_table, tcp_cmp_,
			        (void *)(uintptr_t)processes[i]);

			netstat_udp_filter(&list->data[i].udp_table,
				&udp_table, udp_cmp_,
			        (void *)(uintptr_t)processes[i]);

			service_list_filter(&list->data[i].service_list,
				&services, service_cmp_,
				(void *)(uintptr_t)processes[i]);

			CloseHandle(handles[i]);
		}
	}

	free(processes);
	netstat_tcp_table_destroy(&tcp_table);
	netstat_udp_table_destroy(&udp_table);
	service_list_destroy(&services);

	return 0;
}

void process_list_destroy(struct process_list *list)
{
	size_t i;

	for (i = 0; i < list->count; i++)
		process_list_entry_destroy(&list->data[i]);

	free(list->data);
}

void process_list_entry_destroy(struct process_list_entry *entry)
{
	if (entry->name != NULL)
		free(entry->name);

	if (entry->pathname != NULL)
		free(entry->pathname);

	netstat_tcp_table_destroy(&entry->tcp_table);
	netstat_udp_table_destroy(&entry->udp_table);
	service_list_destroy(&entry->service_list);
}

#ifdef TEST_PS
int main(void)
{
	struct tcp_table_entry *tcp_entry;
	struct udp_table_entry *udp_entry;
	struct service_list_entry *entry;
	struct process_list pl;
	size_t i, j;

	/* Try to get full debug privileges.  We don't care if this fails
	 * or not.
	 */
	token_add_privilege(SE_DEBUG_NAME);

	process_list_init(&pl);
	if (process_list_get(&pl) == -1) {
		fprintf(stderr, "ps_processes_list() failed\n");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < pl.count; i++) {
		printf("PID: %u name: %s pathname: %s",
			pl.data[i].pid, pl.data[i].name, pl.data[i].pathname);

		if (!list_empty(&pl.data[i].tcp_table.list))
			printf(" TCP:");

		tcp_table_for_each(&pl.data[i].tcp_table, tcp_entry)
			printf(" %d", htons(tcp_entry->local_port));

		if (!list_empty(&pl.data[i].udp_table.list))
			printf(" UDP:");

		udp_table_for_each(&pl.data[i].udp_table, udp_entry)
			printf(" %d", htons(udp_entry->local_port));

		if (!list_empty(&pl.data[i].service_list.list))
			printf(" SERVICES:");

		service_for_each(&pl.data[i].service_list, entry)
			printf(" %s", entry->name);

		printf("\n");
	}

	process_list_destroy(&pl);
}
#endif /* TEST_PS */
