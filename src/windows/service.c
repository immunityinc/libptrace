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
 * service.c
 *
 * libptrace windows services management.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <libptrace/windows/error.h>
#include "../compat.h"
#include "service.h"

void service_list_init(struct service_list *service_list)
{
	list_init(&service_list->list);
}

int service_list_get(struct service_list *service_list)
{
	LPENUM_SERVICE_STATUS_PROCESS services;
	DWORD i, needed, returned, rh = 0;
	BYTE services_buffer[65536];
	SC_HANDLE sh;
	int ret = -1;
	BOOL tmp;

	/* Initialization */
	services = (LPENUM_SERVICE_STATUS_PROCESS)services_buffer;
	service_list_init(service_list);

	/* Open SC_HANDLE for the local machine, using ServicesActive
	 * database with all access.
	 */
	if ( (sh = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == NULL)
		return ret;

	do {
		tmp = EnumServicesStatusEx(sh, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
			SERVICE_STATE_ALL, (LPBYTE)services, sizeof(services_buffer), &needed,
			&returned, &rh, NULL);
		if (tmp == 0 && GetLastError() != ERROR_MORE_DATA) {
			service_list_destroy(service_list);
			goto out;
		}

		for (i = 0; i < returned; i++) {
			struct service_list_entry *entry;

			if ( (entry = malloc(sizeof(*entry))) == NULL) {
				pt_error_errno_set(errno);
				service_list_destroy(service_list);
				goto out;
			}

			/* Initialize entry */
			entry->name = entry->display_name = NULL;

			/* Duplicate the name string. */
			entry->name = (char *)strdup(services[i].lpServiceName);
			if (entry->name == NULL) {
				pt_error_errno_set(errno);
				service_list_destroy(service_list);
				goto out;
			}

			/* And the display name string. */
			entry->display_name = strdup(services[i].lpDisplayName);
			if (entry->display_name == NULL) {
				pt_error_errno_set(errno);
				service_list_destroy(service_list);
				goto out;
			}

			/* Copy over all status fields. */
			memcpy(&entry->status,
			       &services[i].ServiceStatusProcess,
			       sizeof(entry->status));

			list_add_tail(&entry->list, &service_list->list);
		}
	} while (needed != 0);

	/* Success */
	ret = 0;
out:
	CloseServiceHandle(sh);
	return ret;
}

void service_list_destroy(struct service_list *service_list)
{
	struct service_list_entry *entry;

	service_for_each(service_list, entry) {
		list_del(&entry->list);
		if (entry->name)
			free(entry->name);
		if (entry->display_name)
			free(entry->display_name);
		free(entry);
	}
}

struct service_list_entry *copy_(struct service_list_entry *src)
{
	struct service_list_entry *entry;

	if ( (entry = malloc(sizeof(*entry))) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	memcpy(entry, src, sizeof(*entry));

	if ( (entry->name = strdup(src->name)) == NULL) {
		pt_error_errno_set(errno);
		free(entry);
		return NULL;
	}

	if ( (entry->display_name = strdup(src->display_name)) == NULL) {
		pt_error_errno_set(errno);
		free(entry->name);
		free(entry);
		return NULL;
	}

	return entry;
}

int service_list_filter(struct service_list *dest,
                        struct service_list *src,
                        int (*compare)(struct service_list_entry *, void *),
                        void *cookie)
{
	struct service_list_entry *entry;

	/* Initialize the destination list. */
	service_list_init(dest);

	/* And copy the relevant entries to the destination list. */
	service_for_each(src, entry) {
		if (compare(entry, cookie)) {
			struct service_list_entry *new;

			if ( (new = copy_(entry)) == NULL) {
				service_list_destroy(dest);
				return -1;
			}

			list_add_tail(&new->list, &dest->list);
		}
	}

	return 0;
}

ssize_t
service_list_get_string(struct service_list *list, char *dest, size_t n)
{
	struct service_list_entry *service;
	int init = 0;
	//ssize_t ret;

	if (n > SSIZE_MAX || n == 0)
		return -1;

	dest[0] = '\0';
	service_for_each(list, service) {
		if (init && sstrncat(dest, ", ", n) == -1)
			break;

		if (sstrncat(dest, service->name, n) == -1)
			break;

		init = 1;
	}

	return (ssize_t)strlen(dest);
}

ssize_t
service_list_entry_get_string(struct service_list_entry *entry,
                              char *dest, size_t n)
{
	if (n > SSIZE_MAX || n == 0)
		return -1;

	/* In case snprintf() fails, we initialize the string. */
	dest[0] = '\0';
	snprintf(dest, n, "%s", entry->name);

	return (ssize_t)strlen(dest);
}

#ifdef TEST_SERVICE
int main(void)
{
	struct service_list_entry *entry;
	struct service_list list;
	char buf[1024];

	if (service_list_get(&list) == -1) {
		fprintf(stderr, "service_list_get() failed\n");
		exit(EXIT_FAILURE);
	}

	service_for_each(&list, entry)
		printf("%s\n", entry->display_name);

	service_list_get_string(&list, buf, sizeof(buf));
	printf("buf: %s\n", buf);

	service_list_destroy(&list);
}
#endif /* TEST_SERVICE */
