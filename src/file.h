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
 * file.h
 *
 * Implementation of libptrace file/stream abstraction layer.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_FILE_INTERNAL_H
#define PT_FILE_INTERNAL_H

#include <stdio.h>
#include <libptrace/charset.h>
#include <libptrace/types.h>

/* Opening permissions. */
#define PT_FILE_RDONLY	1
#define PT_FILE_WRONLY	2
#define PT_FILE_RDWR	(PT_FILE_RDONLY | PT_FILE_WRONLY)

#define PT_FILE_C_TYPE		1
#define PT_FILE_PROCESS_TYPE	2
#define PT_FILE_BUFFER_TYPE	3
#define PT_FILE_NATIVE_TYPE	4

#define PT_FILE_COMMON							\
	int				type;				\
	const struct pt_file_operations	*file_ops

#define PT_FILE_C_INIT {						\
	type		: PT_FILE_C_TYPE,				\
	file_ops 	: &pt_file_c_operations,			\
	filename	: NULL,						\
	fp		: NULL						\
}

#define PT_FILE_NATIVE_INIT {						\
	type 		: PT_FILE_NATIVE_TYPE,				\
	file_ops	: &pt_file_native_operations,			\
	filename	: NULL,						\
	fd		: { (void*)-1 }					\
}

#define PT_FILE_BUFFER_INIT {						\
	type		: PT_FILE_BUFFER_TYPE,				\
	file_ops	: &pt_file_buffer_operations,			\
	start		: NULL,						\
	end		: NULL,						\
	pos		: 0						\
}

#define PT_FILE_PROCESS_INIT {						\
	type		: PT_FILE_PROCESS_TYPE,				\
	file_ops	: &pt_file_process_operations,			\
	process		: NULL,						\
	base		: PT_ADDRESS_NULL,				\
	pos		: 0						\
}

struct pt_file
{
	PT_FILE_COMMON;
};

struct pt_file_operations
{
	ssize_t	(*read)(struct pt_file *, void *, size_t);
	ssize_t	(*write)(struct pt_file *, const void *, size_t);
	int	(*open)(struct pt_file *, int flags);
	int	(*close)(struct pt_file *);
	off_t	(*seek)(struct pt_file *, off_t, int);
	off_t	(*tell)(struct pt_file *);
};

struct pt_file_c
{
	PT_FILE_COMMON;
	const char *filename;
	FILE	   *fp;
};


#define PT_FILE_NATIVE(x) ((struct pt_file_native*)(x))
struct pt_file_native
{
	PT_FILE_COMMON;
	const utf8_t *filename;
	union {
		void	*handle;
		FILE	*stream;
	} fd;
};


struct pt_file_process
{
	PT_FILE_COMMON;
	struct pt_process	*process;
	pt_address_t		base;
	off_t			pos;
};

struct pt_file_buffer
{
	PT_FILE_COMMON;
	uint8_t	*start;
	uint8_t	*end;
	off_t	pos;
};

extern const struct pt_file_operations pt_file_c_operations;
extern const struct pt_file_operations pt_file_native_operations;
extern const struct pt_file_operations pt_file_buffer_operations;
extern const struct pt_file_operations pt_file_process_operations;

#endif	/* !PT_FILE_INTERNAL_H */
