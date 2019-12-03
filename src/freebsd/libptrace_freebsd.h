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
 * libptrace_freebsd.h
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>
 *
 */
#ifndef __LIBPTRACE_FREEBSD_H
#define __LIBPTRACE_FREEBSD_H

#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/pioctl.h>
#include <libptrace_x86.h>
#include <libptrace_list.h>

/* XXX: fugly. */
typedef pid_t	ptrace_pid_t;
typedef void *	ptrace_library_handle_t;
typedef void *	ptrace_function_ptr_t;

#include "libptrace_elf.h"

#ifdef __i386__
  #include "libptrace_freebsd_x86.h"
#endif

#define PTRACE_FLAG_SUSPENDED		0x00000001
#define PTRACE_FLAG_FREEBSD_PIOCCONT	0x00000002

#define PTRACE_ERROR(p)							\
	((p)->error.internal != PTRACE_ERR_NONE ||			\
	 ((p)->error.external != 0 &&					\
	  (p)->error.flags & PTRACE_ERR_FLAG_EXTERNAL))

#define PTRACE_ERR_CLEAR(p)						\
	do {								\
		p->error.errmsg[0] = 0;					\
		p->error.external = 0;					\
		p->error.internal = PTRACE_ERR_NONE;			\
		p->error.flags = PTRACE_ERR_FLAG_NONE;			\
	} while(0)

#define PTRACE_ERR_SET_EXTERNAL(p)					\
	do {								\
		p->error.external = errno;				\
		p->error.internal = PTRACE_ERR_NONE;			\
		p->error.flags = PTRACE_ERR_FLAG_EXTERNAL;		\
	} while(0)

#define PTRACE_ERR_SET_INTERNAL(p, e)					\
	do {								\
		p->error.external = 0;					\
		p->error.internal = e;					\
		p->error.flags = PTRACE_ERR_FLAG_NONE;			\
	} while(0)

/* We do not need to distinguish between external and internal errors for
 * remote errors, as there is no such thing as a remote libptrace internal
 * error.
 */
#define PTRACE_ERR_SET_REMOTE(p, e)					\
	do {								\
		p->error.external = e;					\
		p->error.internal = PTRACE_ERR_NONE;			\
		p->error.flags = PTRACE_ERR_FLAG_REMOTE |		\
		                 PTRACE_ERR_FLAG_EXTERNAL;		\
	} while(0)


struct ptrace_error
{
	int	internal:24;
	int	flags:8;

	int	external;
	char	errmsg[128];
};

struct ptrace_context
{
	int			flags;
	int			options;
	ptrace_pid_t		tid;
	int			procmemfd;
	int			procctlfd;
	struct ptrace_error	error;
	struct ptrace_altstack	stack;
};

/* Linux specific functions. */
int ptrace_get_pagesize(struct ptrace_context *p, int *page_size);

int ptrace_wait_signal(struct ptrace_context *pctx, int signum);

void *ptrace_mmap(struct ptrace_context *pctx, void *start, size_t length,
                  int prot, int flags, int fd, off_t offset);
int ptrace_munmap(struct ptrace_context *pctx, void *start, size_t length);

int ptrace_stop(struct ptrace_context *pctx);

int ptrace_signal_send(struct ptrace_context *pctx, int signal);

#endif
