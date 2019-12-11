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
 * Implementation of libptrace file/stream abstraction layer.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <libptrace/file.h>
#include <libptrace/process.h>

static int
pt_file_process_open(struct pt_file *file, int flags)
{
	assert(file->type == PT_FILE_PROCESS_TYPE);
	return 0;
}

static int
pt_file_process_close(struct pt_file *file)
{
	assert(file->type == PT_FILE_PROCESS_TYPE);
	return 0;
}

static ssize_t
pt_file_process_read(struct pt_file *file_, void *dst, size_t size)
{
	struct pt_file_process *file = (struct pt_file_process *)file_;
	ssize_t ret;

	assert(file->type == PT_FILE_PROCESS_TYPE);

	ret = pt_process_read(file->process, dst, file->base + file->pos, size);
	if (ret == -1)
		return -1;

	file->pos += ret;

	return ret;
}

static ssize_t
pt_file_process_write( )
{
	return 0;
}

static off_t
pt_file_process_seek(struct pt_file *file_, off_t off, int whence)
{
	struct pt_file_process *file = (struct pt_file_process *)file_;
	off_t old_pos;

	assert(file->type == PT_FILE_PROCESS_TYPE);
	old_pos = file->pos;

	switch (whence) {
	case SEEK_SET:
		file->pos = off;
		break;
	case SEEK_CUR:
		if (off < 0 && -off > file->pos)
			off = -file->pos;

		file->pos += off;
		break;
	case SEEK_END:
		if (off > 0)
			return -1;

		if (off < 0 && -off > file->pos)
			off = -file->pos;

		file->pos += off;
		break;
	default:
		return -1;
	}

	return old_pos;
}

static off_t
pt_file_process_tell(struct pt_file *file_)
{
	struct pt_file_process *file = (struct pt_file_process *)file_;

	assert(file->type == PT_FILE_PROCESS_TYPE);

	return file->pos;
}

const struct pt_file_operations pt_file_process_operations = {
	.open	= pt_file_process_open,
	.close	= pt_file_process_close,
	.read	= pt_file_process_read,
	.write	= pt_file_process_write,
	.seek	= pt_file_process_seek,
	.tell	= pt_file_process_tell
};

static int
pt_file_c_open(struct pt_file *file_, int flags)
{
	struct pt_file_c *file = (struct pt_file_c *)file_;
	char *mode;

	assert(file->type == PT_FILE_C_TYPE);

	switch (flags) {
	case PT_FILE_RDONLY:
		mode = "rb";
		break;
	case PT_FILE_WRONLY:
		mode = "wb";
		break;
	case PT_FILE_RDWR:
		mode = "r+b";
		break;
	default:
		return -1;
	}

	if ( (file->fp = fopen(file->filename, mode)) == NULL)
		return -1;

	return 0;
}

static int
pt_file_c_close(struct pt_file *file_)
{
	struct pt_file_c *file = (struct pt_file_c *)file_;

	assert(file->type == PT_FILE_C_TYPE);
	fclose(file->fp);

	return 0;
}

static ssize_t
pt_file_c_read(struct pt_file *file_, void *dst, size_t size)
{
	struct pt_file_c *file = (struct pt_file_c *)file_;
	size_t ret;

	assert(file->type == PT_FILE_C_TYPE);

	if (size > SSIZE_MAX)
		return -1;

	ret = fread(dst, 1, size, file->fp);
	if (ret == 0 && ferror(file->fp))
		return -1;

	return ret;
}

static ssize_t
pt_file_c_write(struct pt_file *file_, const void *src, size_t size)
{
	struct pt_file_c *file = (struct pt_file_c *)file_;
	size_t ret;

	assert(file->type == PT_FILE_C_TYPE);

	if (size > SSIZE_MAX)
		return -1;

	ret = fwrite(src, 1, size, file->fp);
	if (ret == 0 && ferror(file->fp))
		return -1;

	return ret;
}

static off_t
pt_file_c_seek(struct pt_file *file_, off_t off, int whence)
{
	struct pt_file_c *file = (struct pt_file_c *)file_;
	off_t current;

	assert(file->type == PT_FILE_C_TYPE);

	if ( (current = ftell(file->fp)) == -1)
		return -1;

	if (fseek(file->fp, off, whence) == -1)
		return -1;

	return current;
}

static off_t
pt_file_c_tell(struct pt_file *file_)
{
	struct pt_file_c *file = (struct pt_file_c *)file_;
	off_t ret;

	assert(file->type == PT_FILE_C_TYPE);

	errno = 0;
	ret = ftell(file->fp);

	/* We own the file descriptor, so this should never happen except
	 * when the API user is doing Bad Stuff.
	 */
	assert(ret != -1 || errno == 0);

	return ret;
}



const struct pt_file_operations pt_file_c_operations = {
	.open	= pt_file_c_open,
	.close	= pt_file_c_close,
	.read	= pt_file_c_read,
	.write	= pt_file_c_write,
	.seek	= pt_file_c_seek,
	.tell	= pt_file_c_tell
};


/* the following functions are defined in the respective OS modules */
extern int     pt_file_native_open(struct pt_file *file_, int flags);
extern int     pt_file_native_close(struct pt_file *file_);
extern ssize_t pt_file_native_read(struct pt_file *file_, void *dst, size_t size);
extern ssize_t pt_file_native_write(struct pt_file *file_, const void *src, size_t size);
extern off_t   pt_file_native_tell(struct pt_file *file_);
extern off_t   pt_file_native_seek(struct pt_file *file_, off_t off, int whence);


const struct pt_file_operations pt_file_native_operations = {
	.open   = pt_file_native_open,
	.close  = pt_file_native_close,
	.read   = pt_file_native_read,
	.write  = pt_file_native_write,
	.seek   = pt_file_native_seek,
	.tell   = pt_file_native_tell
};


static int
pt_file_buffer_open(struct pt_file *file, int flags)
{
	assert(file->type == PT_FILE_BUFFER_TYPE);
	return 0;
}

static int
pt_file_buffer_close(struct pt_file *file)
{
	assert(file->type == PT_FILE_BUFFER_TYPE);
	return 0;
}

static ssize_t
pt_file_buffer_read(struct pt_file *file_, void *dst, size_t size)
{
	struct pt_file_buffer *file = (struct pt_file_buffer *)file_;

	assert(file->type == PT_FILE_BUFFER_TYPE);

	if (size > file->end - &file->start[file->pos])
		size = file->end - &file->start[file->pos];

	memcpy(dst, file->start + file->pos, size);
	file->pos += size;

	return size;
}

static ssize_t
pt_file_buffer_write( )
{
	return 0;
}

static off_t
pt_file_buffer_seek(struct pt_file *file_, off_t off, int whence)
{
	struct pt_file_buffer *file = (struct pt_file_buffer *)file_;
	unsigned char *new_pos;
	off_t old_pos;

	assert(file->type == PT_FILE_BUFFER_TYPE);
	old_pos = file->pos;

	switch (whence) {
	case SEEK_SET:
		new_pos = file->start + off;

		if (new_pos < file->start || new_pos >= file->end) {
			errno = EINVAL;
			return -1;
		}

		file->pos = off;
		break;
	case SEEK_CUR:
		new_pos = file->start + file->pos + off;

		if (new_pos < file->start || new_pos >= file->end) {
			errno = EINVAL;
			return -1;
		}

		file->pos += off;
		break;
	case SEEK_END:
		new_pos = file->end + off;

		if (new_pos < file->start || new_pos >= file->end) {
			errno = EINVAL;
			return -1;
		}

		file->pos = (file->end - file->start) + off;
		break;
	default:
		return -1;
	}

	return old_pos;
}

static off_t
pt_file_buffer_tell(struct pt_file *file_)
{
	struct pt_file_buffer *file = (struct pt_file_buffer *)file_;

	assert(file->type == PT_FILE_BUFFER_TYPE);

	return file->pos;
}

const struct pt_file_operations pt_file_buffer_operations = {
	.open	= pt_file_buffer_open,
	.close	= pt_file_buffer_close,
	.read	= pt_file_buffer_read,
	.write	= pt_file_buffer_write,
	.seek	= pt_file_buffer_seek,
	.tell	= pt_file_buffer_tell
};
