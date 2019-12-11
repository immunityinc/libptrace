/* libptrace, a process tracing and manipulation library.
 *
 * Copyright (C) 2006-2019, Ronald Huizer <rhuizer@hexpedition.com>
 * Copyright (C) 2019, Cyxtera Cybersecurity, Inc.  All rights reserved.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
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
 * thread_x86.h
 *
 * libptrace x86 thread management.
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#ifndef PT_THREAD_X86_INTERNAL_H
#define PT_THREAD_X86_INTERNAL_H

#include <stdint.h>
#include <libptrace/thread.h>

/* Flag masks for x86 EFLAGS registers */
#define X86_EFLAGS_CF	1
#define X86_EFLAGS_R0	2
#define X86_EFLAGS_PF	4
#define X86_EFLAGS_R1	8
#define X86_EFLAGS_AF	16
#define X86_EFLAGS_R2	32
#define X86_EFLAGS_ZF	64
#define X86_EFLAGS_SF	128
#define X86_EFLAGS_TF	256
#define X86_EFLAGS_IF	512
#define X86_EFLAGS_DF	1024
#define X86_EFLAGS_OF	2048
#define X86_EFLAGS_IOPL	4096 + 8192
#define X86_EFLAGS_NT	16384
#define X86_EFLAGS_R3	32768
#define X86_EFLAGS_RF	65536

#define X86_DR6_B0	1
#define X86_DR6_B1	2
#define X86_DR6_B2	4
#define X86_DR6_B3	8
#define X86_DR6_BD	8192
#define X86_DR6_BS	16384
#define X86_DR6_BT	32768
#define X86_DR6_MASK	(X86_DR6_B0 | X86_DR6_B1 | X86_DR6_B2 |		\
			 X86_DR6_B3 | X86_DR6_BD | X86_DR6_BS |		\
			 X86_DR6_BT)

struct pt_x86_descriptor
{
	uint32_t	base_mid:8;
	uint32_t	type:4;
	uint32_t	s:1;
	uint32_t	dpl:2;
	uint32_t	p:1;
	uint32_t	limit_hi:4;
	uint32_t	avl:1;
	uint32_t	l:1;
	uint32_t	db:1;
	uint32_t	g:1;
	uint32_t	base_hi:8;

	uint16_t	limit_lo;
	uint16_t	base_lo;
} __attribute__((packed));

#ifdef __cplusplus
extern "C" {
#endif

/* x86 register functions */
uint16_t pt_thread_x86_get_cs(struct pt_thread *);
uint16_t pt_thread_x86_get_ds(struct pt_thread *);
uint16_t pt_thread_x86_get_es(struct pt_thread *);
uint16_t pt_thread_x86_get_ss(struct pt_thread *);
uint16_t pt_thread_x86_get_fs(struct pt_thread *);
uint16_t pt_thread_x86_get_gs(struct pt_thread *);
uint32_t pt_thread_x86_get_eflags(struct pt_thread *);

int pt_thread_x86_set_cs(struct pt_thread *, uint16_t);
int pt_thread_x86_set_ds(struct pt_thread *, uint16_t);
int pt_thread_x86_set_es(struct pt_thread *, uint16_t);
int pt_thread_x86_set_ss(struct pt_thread *, uint16_t);
int pt_thread_x86_set_fs(struct pt_thread *, uint16_t);
int pt_thread_x86_set_gs(struct pt_thread *, uint16_t);
int pt_thread_x86_set_eflags(struct pt_thread *, uint32_t);

/* x86 debug registers */
int pt_thread_x86_set_dr6(struct pt_thread *, pt_register_t);

/* x86 descriptor functions. */
int pt_thread_x86_ldt_entry_get(struct pt_thread *,
                                struct pt_x86_descriptor *, int);
int pt_thread_x86_ldt_entry_set(struct pt_thread *,
                                struct pt_x86_descriptor *, int);
int pt_thread_x86_gdt_entry_get(struct pt_thread *,
                                struct pt_x86_descriptor *, int);

uint32_t pt_thread_x86_descriptor_base_get(struct pt_x86_descriptor *);
void pt_thread_x86_descriptor_base_set(struct pt_x86_descriptor *, uint32_t);
uint32_t pt_thread_x86_descriptor_limit_get(struct pt_x86_descriptor *);
void pt_thread_x86_descriptor_limit_set(struct pt_x86_descriptor *, uint32_t);
void pt_thread_x86_descriptor_print(struct pt_x86_descriptor *);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_THREAD_X86_INTERNAL_H */
