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
 * breakpoint_x86.h
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_BREAKPOINT_X86_INTERNAL_H
#define PT_BREAKPOINT_X86_INTERNAL_H

#include <stdint.h>
#include <libptrace/list.h>
#include <libptrace/process.h>

#define X86_DR_GET_TYPE(n, t)	((t) << (16 + (n) * 4))
#define X86_DR_GET_SIZE(n, s)	((s) << (18 + (n) * 4))
#define X86_DR_GET_ENABLE(n, e)	((e) << ((n) * 2))

#define X86_DR_SCOPE_NONE	0
#define X86_DR_SCOPE_LOCAL	1
#define X86_DR_SCOPE_GLOBAL	2
#define X86_DR_SCOPE_MASK	3

#define X86_DR_TYPE_EXEC	0
#define X86_DR_TYPE_WRITE	1
#define X86_DR_TYPE_IO		2
#define X86_DR_TYPE_RW		3

#define X86_DR_SIZE_1		0
#define X86_DR_SIZE_2		1
#define X86_DR_SIZE_4		3
#define X86_DR_SIZE_8		2


#ifdef __cplusplus
extern "C" {
#endif

struct x86_debug_register;
typedef void (*x86_dr_handler_t)(struct pt_process *, void *cookie);

struct x86_debug_register
{
	uint32_t		address;
	uint8_t			scope;
	uint8_t			type;
	uint8_t			size;
	uint8_t			used;

	x86_dr_handler_t	handler;
	void			*cookie;

	struct list_head	list;
};

struct x86_debug_registers
{
	struct list_head		free;
	struct x86_debug_register	regs[4];
};

void x86_debug_registers_init(struct x86_debug_registers *);
int x86_debug_register_set(struct x86_debug_registers *regs, int scope, int type, uint32_t address, int size,
	x86_dr_handler_t handler, void *cookie);

struct x86_debug_register *
x86_debug_register_find(struct x86_debug_registers *ctx, pt_address_t address, int type);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_BREAKPOINT_X86_INTERNAL_H */
