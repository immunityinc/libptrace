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
 * registers.h
 *
 * libptrace register management.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_REGISTERS_INTERNAL_H
#define PT_REGISTERS_INTERNAL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	PT_REGISTERS_I386,	PT_REGISTERS_I386_LINUX,
	PT_REGISTERS_X86_64,	PT_REGISTERS_X86_64_LINUX
};

struct pt_registers
{
	int		type;
};

struct pt_registers_i386
{
	int		type;
	uint32_t	eax;
	uint32_t	ebx;
	uint32_t	ecx;
	uint32_t	edx;
	uint32_t	esi;
	uint32_t	edi;
	uint32_t	esp;
	uint32_t	ebp;
	uint32_t	eip;
	uint16_t	cs;
	uint16_t	ds;
	uint16_t	es;
	uint16_t	fs;
	uint16_t	gs;
	uint16_t	ss;
	uint32_t	eflags;

	/* Debug registers */
	uint32_t	dr0;
	uint32_t	dr1;
	uint32_t	dr2;
	uint32_t	dr3;
	uint32_t	dr6;
	uint32_t	dr7;
};

/* Support software register orig_eax on Linux */
struct pt_registers_i386_linux
{
	int		type;
	uint32_t	eax;
	uint32_t	ebx;
	uint32_t	ecx;
	uint32_t	edx;
	uint32_t	esi;
	uint32_t	edi;
	uint32_t	esp;
	uint32_t	ebp;
	uint32_t	eip;
	uint32_t	cs;
	uint16_t	ds;
	uint16_t	es;
	uint16_t	fs;
	uint16_t	gs;
	uint32_t	ss;
	uint32_t	eflags;
	uint32_t	orig_eax;

	/* Debug registers */
	uint32_t	dr0;
	uint32_t	dr1;
	uint32_t	dr2;
	uint32_t	dr3;
	uint32_t	dr6;
	uint32_t	dr7;
};

struct pt_registers_x86_64
{
	int		type;
	uint64_t	rax;
	uint64_t	rbx;
	uint64_t	rcx;
	uint64_t	rdx;
	uint64_t	r8;
	uint64_t	r9;
	uint64_t	r10;
	uint64_t	r11;
	uint64_t	r12;
	uint64_t	r13;
	uint64_t	r14;
	uint64_t	r15;
	uint64_t	rsi;
	uint64_t	rdi;
	uint64_t	rsp;
	uint64_t	rbp;
	uint64_t	rip;
	uint16_t	cs;
	uint16_t	ds;
	uint16_t	es;
	uint16_t	fs;
	uint16_t	gs;
	uint16_t	ss;
	uint64_t	rflags;

	/* Debug registers */
	uint64_t	dr0;
	uint64_t	dr1;
	uint64_t	dr2;
	uint64_t	dr3;
	uint64_t	dr6;
	uint64_t	dr7;
};

/* support fs_base, gs_base, and orig_rax */
struct pt_registers_x86_64_linux
{
	int		type;
	uint64_t	rax;
	uint64_t	rbx;
	uint64_t	rcx;
	uint64_t	rdx;
	uint64_t	r8;
	uint64_t	r9;
	uint64_t	r10;
	uint64_t	r11;
	uint64_t	r12;
	uint64_t	r13;
	uint64_t	r14;
	uint64_t	r15;
	uint64_t	rsi;
	uint64_t	rdi;
	uint64_t	rsp;
	uint64_t	rbp;
	uint64_t	rip;
	uint16_t	cs;
	uint16_t	ds;
	uint16_t	es;
	uint16_t	fs;
	uint16_t	gs;
	uint16_t	ss;
	uint64_t	rflags;
	uint64_t	orig_rax;
	uint16_t	fs_base;
	uint16_t	gs_base;
};

int pt_registers_print(struct pt_registers *regs);
int pt_registers_get_size(struct pt_registers *regs);

#ifdef __cplusplus
};
#endif

#endif /* !PT_REGISTERS_INTERNAL_H */
