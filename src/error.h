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
 * error.h
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 */
#ifndef PT_ERROR_INTERNAL_H
#define PT_ERROR_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <limits.h>
#include <libptrace/charset.h>
#include <libptrace/error.h>

/* architecture specific errors has the MSB set to 1 */
#define PT_ERR_X86_64_COMPAT	0x80000001	/* Unknown compat mode */

/* libtrace error flags */
#define PT_ERROR_FLAG_NONE	0
#define PT_ERROR_FLAG_REMOTE	1

struct pt_error;

struct pt_error_operations
{
	void		(*save)(void);
	void		(*restore)(void);
	const utf8_t *	(*strerror)(void);
};

struct pt_error
{
	int				type;
	int				flags;
	struct pt_error_operations	*p_op;
	void				*private_data;
};

void pt_error_internal_set(int);
int  pt_error_internal_test(int);
void pt_error_errno_set(int);
void pt_error_pe_set(int);

const utf8_t *	pt_error_strerror(void);
void		pt_error_perror(const utf8_t *);
void		pt_error_save(void);
void		pt_error_restore(void);
void		pt_error_clear(void);
int		pt_error_is_set(void);

extern __thread struct pt_error pt_errno;
extern __thread struct pt_error pt_errno_saved;

#ifdef __cplusplus
};
#endif

#endif	/* !PT_ERROR_INTERNAL_H */
