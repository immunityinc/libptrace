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
 * stringlist.c
 *
 * libptrace string list management.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <error.h>
#include <libptrace/error.h>
#include "stringlist.h"

int pt_string_list_init(struct pt_string_list *list, size_t size)
{
	utf8_t **strings;

	if (size > SIZE_MAX / sizeof(utf8_t *)) {
		pt_error_internal_set(PT_ERROR_ARITH_OVERFLOW);
		return -1;
	}

	strings = (utf8_t **)calloc(size, sizeof(utf8_t *));
	if (strings == NULL) {
		pt_error_errno_set(errno);
		return -1;
	}

	list->strings = strings;
	list->size = size;
	return 0;
}

void pt_string_list_destroy(struct pt_string_list *list)
{
	if (list->strings != NULL)
		free(list->strings);
}

void pt_string_list_destroy_with(struct pt_string_list *list, void (*f)(void *))
{
	size_t i;

	if (list->strings == NULL)
		return;

	for (i = 0; i < list->size; i++)
		f(list->strings[i]);

	free(list->strings);
}

void pt_string_list_print(struct pt_string_list *list)
{
	size_t i;

	for (i = 0; i < list->size; i++)
		if (list->strings[i] != NULL)
			printf("%s\n", list->strings[i]);
}
