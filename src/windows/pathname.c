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
 * pathname.c
 *
 * libptrace windows pathname handling code.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <libptrace/charset.h>
#include <libptrace/windows/error.h>
#include "../stringlist.h"
#include "win32util.h"
#include "wrappers/kernel32.h"

utf8_t *pathname_filename_base_get(const utf8_t *pathname)
{
	const utf8_t *start, *end;
	utf8_t *name;

	assert(pathname != NULL);

	start = strrchr(pathname, '\\');
	start = (start == NULL ? pathname : start + 1);

	if ( (end = strchr(start, '.')) == NULL)
		end = pathname + strlen(pathname);

	if ( (name = malloc(end - start + 1)) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	memcpy(name, start, end - start);
	name[end - start] = 0;

	return name;
}

int pathname_is_shortcut(const utf8_t *pathname)
{
	char *p;

	if ( (p = strrchr(pathname, '.')) == NULL)
		return 0;

	return !strcasecmp(p, ".lnk");
}

static inline utf8_t *pathname_nt_to_dos_unc(const utf8_t *pathname)
{
	utf8_t *ret;

	if ( (ret = strdup(pathname + 10)) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	ret[0] = ret[1] = '\\';
	return ret;
}

utf8_t *pathname_nt_to_dos(const utf8_t *pathname)
{
	struct pt_string_list drives;
	utf8_t *result = NULL;
	size_t i;

	assert(pathname != NULL);

	/* If the pathname starts with "\Device\Mup\" it is a UNC pathname,
	 * and we will treat it separately.
	 *
	 * XXX: Maybe should resolve the \\?\UNC symbolic link instead?
	 */
	if (_strnicmp(pathname, "\\Device\\Mup\\", 12) == 0)
		return pathname_nt_to_dos_unc(pathname);

	/* Get the MS-DOS drives on the system. */
	if ( (pt_windows_api_get_logical_drive_strings(&drives)) == -1)
		return NULL;

	/* Iterate over the MS-DOS drives, convert them to device names
	 * and see if one of them matches a pathname prefix.
	 */
	for (i = 0; i < drives.size; i++) {
		size_t drive_len = strlen(drives.strings[i]);
		utf8_t *drive = drives.strings[i];
		size_t device_len;
		utf8_t *device;

		/* Skip any possibly empty drive. */
		if (drive_len == 0)
			continue;

		/* QueryDosDevice needs the trailing '\' removed. */
		if (drive[drive_len - 1] == '\\') {
			drive[drive_len - 1] = 0;
			drive_len -= 1;
		}

		device = pt_windows_api_query_dos_device(drive);
		if (device == NULL)
			continue;

		/* Compare pathname to this name. */
		device_len = strlen(device);
		if (!strncmp(pathname, device, device_len)) {
			size_t rhs_len = strlen(pathname) - device_len;
			size_t result_size = rhs_len + drive_len + 1;

			if ( (result = malloc(result_size)) == NULL) {
				pt_error_errno_set(errno);
				pt_string_list_destroy_with(&drives, free);
				free(device);
				return NULL;
			}

			strcpy(result, drive);
			strcat(result, pathname + device_len);

			free(device);
			break;
		}
		free(device);
	}

	pt_string_list_destroy_with(&drives, free);
	return result;
}
