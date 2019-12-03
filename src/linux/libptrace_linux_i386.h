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
 * libptrace_linux_i386.h
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>
 *
 */
#ifndef __LIBPTRACE_LINUX_I386_H
#define __LIBPTRACE_LINUX_I386_H

#include <stdint.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include "libptrace_config.h"

#define ELF_HEADER_BASE ((void *)0x8048000)

struct ptrace_cpu_state {
	uint8_t __buf[sizeof(struct user_regs_struct)];
};

/* linux defines a software register called orig_eax; provide support for it.
 */
int ptrace_set_orig_eax(struct ptrace_context *p, uint32_t eax);
ptrace_x86_register_t ptrace_get_orig_eax(struct ptrace_context *p);
int __ptrace_get_orig_eax(struct ptrace_context *p, ptrace_x86_register_t *);

#endif	/* !__LIBPTRACE_LINUX_I386_H */
