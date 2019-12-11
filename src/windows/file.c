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
 * file.c
 *
 * Implementation of libptrace windows file/stream abstraction layer.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 * Author: Massimiliano Oldani <max@immunityinc.com>
 *
 */
#include <windows.h>
#include <assert.h>
#include <libptrace/charset.h>
#include <libptrace/file.h>
#include <libptrace/windows/error.h>
#include "common.h"

#define PT_FILE_NATIVE(x) ((struct pt_file_native*)(x))

static inline int flags_to_desired_access_(int flags)
{
	switch(flags) {
	case PT_FILE_RDONLY:
		return GENERIC_READ;
	case PT_FILE_WRONLY:
		return GENERIC_WRITE;
	case PT_FILE_RDWR:
		return GENERIC_READ | GENERIC_WRITE;
	}

	return -1;
}

static inline int flags_to_share_mode_(int flags)
{
	switch (flags) {
	case PT_FILE_RDONLY:
		return FILE_SHARE_READ;
	case PT_FILE_WRONLY:
		return FILE_SHARE_WRITE;
	case PT_FILE_RDWR:
		return FILE_SHARE_READ | FILE_SHARE_WRITE;
	}

	return 0;
}

int pt_file_native_open(struct pt_file *file, int flags)
{
	struct pt_file_native *file_native;
	DWORD desired_access, share_mode;
	utf16_t *filename_w;
	HANDLE h;

	assert(file != NULL);
	assert(file->type == PT_FILE_NATIVE_TYPE);

	file_native = (struct pt_file_native *)file;

	if ( (desired_access = flags_to_desired_access_(flags)) == -1)
		return -1;

	if ( (filename_w = pt_utf8_to_utf16(file_native->filename)) == NULL)
		return -1;

	share_mode = flags_to_share_mode_(flags);

	h = CreateFileW(
		filename_w,
		desired_access,
		share_mode,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	free(filename_w);

	if (h == INVALID_HANDLE_VALUE) {
		pt_windows_error_winapi_set();
		return -1;
	}

	file_native->fd.handle = h;
	return 0;
}

int pt_file_native_close(struct pt_file *file)
{
	struct pt_file_native *file_native;

	assert(file != NULL);
	assert(file->type == PT_FILE_NATIVE_TYPE);

	file_native = (struct pt_file_native *)file;

	if (!HANDLE_VALID(file_native->fd.handle))
		return -1;

	if (CloseHandle(file_native->fd.handle) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	file_native->fd.handle = INVALID_HANDLE_VALUE;

	return 0;
}

ssize_t pt_file_native_read(struct pt_file *file_, void *dst, size_t size)
{
	DWORD bytes_read = 0;
	DWORD bytes_to_read = size;
	struct pt_file_native* file_native_ = PT_FILE_NATIVE(file_);
	assert(file_ && file_->type == PT_FILE_NATIVE_TYPE);

	if (file_native_->fd.handle == 0 || file_native_->fd.handle == INVALID_HANDLE_VALUE)
		return -1;

	if (ReadFile(file_native_->fd.handle, dst, bytes_to_read, &bytes_read, NULL) == FALSE) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return bytes_read;
}



ssize_t pt_file_native_write(struct pt_file *file_, const void *src, size_t size)
{
	DWORD bytes_to_write = size, bytes_written = 0;
	struct pt_file_native *file_native_ = PT_FILE_NATIVE(file_);

	assert(file_->type == PT_FILE_NATIVE_TYPE);
	if (file_native_->fd.handle == 0 || file_native_->fd.handle == INVALID_HANDLE_VALUE)
		return -1;

	if (WriteFile(file_native_->fd.handle, src, bytes_to_write, &bytes_written, NULL) == FALSE) {
		pt_windows_error_winapi_set();
		return -1;
	}
	return bytes_written;
}



static int convert_native_whence(int whence)
{
	int native_whence = 0;
	switch(whence)
	{
	case SEEK_SET:
		native_whence = FILE_BEGIN;
		break;
	case SEEK_CUR:
		native_whence = FILE_CURRENT;
		break;
	case SEEK_END:
		native_whence = FILE_END;
		break;
	default:
		native_whence = -1;
	}
	return native_whence;
}



off_t pt_file_native_seek(struct pt_file *file_, off_t off, int whence)
{
	LARGE_INTEGER li;
	li.QuadPart = off;
	int local_whence;
	off_t current;

	struct pt_file_native* file_native_ = PT_FILE_NATIVE(file_);

	assert(file_ && file_->type == PT_FILE_NATIVE_TYPE);

	current = file_->file_ops->tell(file_);
	if (current == -1)
		return -1;

	local_whence = convert_native_whence(whence);
	if (local_whence == -1)
		return -1;

	if (SetFilePointerEx(file_native_->fd.handle, li, NULL, local_whence) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	/* interface requires to return the older file position, before the API call */
	return current;
}



off_t   pt_file_native_tell(struct pt_file *file_)
{
	off_t ret = 0;
	LARGE_INTEGER li, out;
	li.QuadPart = 0;
	out.QuadPart = 0;

	assert(file_ && file_->type == PT_FILE_NATIVE_TYPE);
	struct pt_file_native *file_native_ = PT_FILE_NATIVE(file_);
	if (SetFilePointerEx(file_native_->fd.handle, li, &out, FILE_CURRENT) == FALSE)
	{
		pt_windows_error_winapi_set();
		return -1;
	}

	ret = (off_t)(out.QuadPart);
	return ret;
}




