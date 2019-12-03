/* libptrace, a process tracing and manipulation library.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Copyright (C) 2006-2019 Ronald Huizer <rhuizer@hexpedition.com>
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
 * libptrace_wrapper.c
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>
 *
 */
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

pid_t waitpid_no_EINTR(pid_t pid, int *status, int options)
{
	pid_t ret;

	do {
		ret = waitpid(pid, status, options);
	} while (ret == -1 && errno == EINTR);

	return ret;
}

FILE *fopen_no_EINTR(const char *path, const char *mode)
{
	FILE *ret;

	do {
		ret = fopen(path, mode);
	} while (ret == NULL && errno == EINTR);

	return ret;
}

int fclose_no_EINTR(FILE *fp)
{
	int ret;

	do {
		ret = fclose(fp);
	} while (ret == -1 && errno == EINTR);

	return ret;
}

static inline int open2_no_EINTR(const char *pathname, int flags)
{
	int ret;

	do {
		ret = open(pathname, flags);
	} while (ret == -1 && errno == EINTR);

	return ret;
}

static inline int open3_no_EINTR(const char *pathname, int flags, mode_t mode)
{
	int ret;

	do {
		ret = open(pathname, flags, mode);
	} while (ret == -1 && errno == EINTR);

	return ret;
}

int open_no_EINTR(const char *pathname, int flags, ...)
{
	if (flags & O_CREAT) {
		va_list ap;
		mode_t mode;

		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);

		return open3_no_EINTR(pathname, flags, mode);
	}

	return open2_no_EINTR(pathname, flags);
}

int close_no_EINTR(int fd)
{
	int ret;

	do {
		ret = close(fd);
	} while (ret == -1 && errno == EINTR);

	return ret;
}
