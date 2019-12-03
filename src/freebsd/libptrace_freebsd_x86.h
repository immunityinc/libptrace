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
 * libptrace_freebsd_x86.h
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>
 *
 */
#ifndef __LIBPTRACE_FREEBSD_X86_H
#define __LIBPTRACE_FREEBSD_X86_H

#include <stdint.h>
#include <machine/reg.h>

struct ptrace_cpu_state {
	uint8_t __buf[sizeof(struct reg)];
};

struct ptrace_fpu_state {
	uint8_t __buf[sizeof(struct fpreg)];
};
	

/* This structure needs the same layout as machine/reg.h on freebsd!
 * It has been redefined to keep the libptrace naming scheme consistent, and
 * the code efficient.  DO NOT CHANGE.
 */
struct ptrace_registers {
	uint32_t	fs;
	uint32_t	es;
	uint32_t	ds;
	uint32_t	edi;
	uint32_t	esi;
	uint32_t	ebp;
	uint32_t	isp;
	uint32_t	ebx;
	uint32_t	edx;
	uint32_t	ecx;
	uint32_t	eax;
	uint32_t	trapno;
	uint32_t	err;
	uint32_t	eip;
	uint32_t	cs;
	uint32_t	eflags;
	uint32_t	esp;
	uint32_t	ss;
	uint32_t	gs;
};

#endif	/* !__LIBPTRACE_FREEBSD_X86_H */
