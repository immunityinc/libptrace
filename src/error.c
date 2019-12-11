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
 * error.c
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 * Author: Massimiliano Oldani <max@immunityinc.com>
 *
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <libptrace/charset.h>
#include <libptrace/pe.h>
#include "error.h"

static const utf8_t *pt_error_internal_strerror(void);
static const utf8_t *pt_error_errno_strerror(void);
static const utf8_t *pt_error_pe_strerror(void);

struct pt_error_operations pt_error_internal_operations = {
	.save     = NULL,
	.restore  = NULL,
	.strerror = pt_error_internal_strerror
};

struct pt_error_operations pt_error_errno_operations = {
	.save     = NULL,
	.restore  = NULL,
	.strerror = pt_error_errno_strerror
};

struct pt_error_operations pt_error_pe_operations = {
	.save     = NULL,
	.restore  = NULL,
	.strerror = pt_error_pe_strerror
};

/* pt_errno is tracked per thread rather then per pt_core.  The reason for
 * this is two-fold.  It is more transparant within the API to do so, and
 * it allows API functions such that can be called from remote threads
 * to use pt_errno for their own reporting.
 *
 * In practice this shouldn't matter, as pt_core is designed to be unique
 * on a thread anyway.
 */
__thread struct pt_error pt_errno = {
	.type           = PT_ERROR_TYPE_INTERNAL,
	.flags          = PT_ERROR_FLAG_NONE,
	.p_op		= &pt_error_internal_operations,
	.private_data   = (void *)PT_ERROR_NONE
};

/* pt_errno_saved is used for convenience storing of the last error. */
__thread struct pt_error pt_errno_saved = {
	.type           = PT_ERROR_TYPE_INTERNAL,
	.flags          = PT_ERROR_FLAG_NONE,
	.p_op		= &pt_error_internal_operations,
	.private_data   = (void *)PT_ERROR_NONE
};

static const char *pt_error_internal_str_[] = {
	"Success",
	"Traced Process Exited",
	"Unsuitable Page Size",
	"Original Stack Error",
	"Stack Currently In Use",
	"Not Enough Memory",
	"Unsupported Function",
	"String Conversion Error",
	"Module is missing",
	"Cannot resume without a break",
	"Cannot resolve symbol",
	"Not attached to process",
	"Invalid argument",
	"Object not found",
	"Object already exists",
	"Resource not available",
	"WoW64 is currently not supported",
	"An arithmetic overflow occurred",
	"Invalid ptrace core",
	"Non-blocking operation would block",
	"Invalid message size",
	"Invalid handle"
};

void pt_error_internal_set(int err)
{
	assert(err >= 0 && err <= PT_ERROR_MAX);

	pt_errno.type         = PT_ERROR_TYPE_INTERNAL;
	pt_errno.p_op         = &pt_error_internal_operations;
	pt_errno.private_data = (void *)(intptr_t)err;
}

int pt_error_internal_test(int err)
{
	assert(err >= 0 && err <= PT_ERROR_MAX);

	if (pt_errno.type != PT_ERROR_TYPE_INTERNAL)
		return 0;

	if (pt_errno.p_op != &pt_error_internal_operations)
		return 0;

	if (pt_errno.private_data != (void *)(intptr_t)err)
		return 0;

	return 1;
}

void pt_error_errno_set(int err)
{
	pt_errno.type         = PT_ERROR_TYPE_ERRNO;
	pt_errno.p_op         = &pt_error_errno_operations;
	pt_errno.private_data = (void *)(intptr_t)err;
}

void pt_error_pe_set(int err)
{
	pt_errno.type         = PT_ERROR_TYPE_PE;
	pt_errno.p_op         = &pt_error_pe_operations;
	pt_errno.private_data = (void *)(intptr_t)err;
}

static const utf8_t *pt_error_internal_strerror(void)
{
	int code = (int)(intptr_t)pt_errno.private_data;
	return (const utf8_t *)pt_error_internal_str_[code];
}

static const utf8_t *pt_error_errno_strerror(void)
{
	int code = (int)(intptr_t)pt_errno.private_data;
	return (const utf8_t *)strerror(code);
}

static const utf8_t *pt_error_pe_strerror(void)
{
	int code = (int)(intptr_t)pt_errno.private_data;
	return (const utf8_t *)pe_errstr(code);
}

const utf8_t *pt_error_strerror(void)
{
	return pt_errno.p_op->strerror();
}

void pt_error_perror(const utf8_t *s)
{
	if (s == NULL)
		fprintf(stderr, "%s\n", pt_error_strerror());
	else
		fprintf(stderr, "%s: %s\n", s, pt_error_strerror());
}

void pt_error_save(void)
{
	pt_errno_saved = pt_errno;

	if (pt_errno.p_op->save != NULL)
		pt_errno.p_op->save();
}

void pt_error_restore(void)
{
	pt_errno = pt_errno_saved;

	if (pt_errno.p_op->restore != NULL)
		pt_errno.p_op->restore();
}

void pt_error_clear(void)
{
	pt_errno.type           = PT_ERROR_TYPE_INTERNAL;
	pt_errno.flags          = PT_ERROR_FLAG_NONE;
	pt_errno.p_op           = &pt_error_internal_operations;
	pt_errno.private_data   = (void *)PT_ERROR_NONE;
}

int pt_error_is_set(void)
{
	if (pt_errno.type != PT_ERROR_TYPE_INTERNAL)
		return 1;

	if (pt_errno.private_data != PT_ERROR_NONE)
		return 1;

	assert(pt_errno.flags == PT_ERROR_FLAG_NONE);
	assert(pt_errno.p_op == &pt_error_internal_operations);

	return 0;
}
