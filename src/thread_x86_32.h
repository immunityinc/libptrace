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
 * thread_x86_32.h
 *
 * libptrace i386 thread management.
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#ifndef PT_THREAD_X86_32_INTERNAL_H
#define PT_THREAD_X86_32_INTERNAL_H

#include "thread_x86.h"

struct pt_thread_x86_32_operations
{
	uint32_t (*get_eax)(struct pt_thread *);
	uint32_t (*get_ebx)(struct pt_thread *);
	uint32_t (*get_ecx)(struct pt_thread *);
	uint32_t (*get_edx)(struct pt_thread *);
	uint32_t (*get_esi)(struct pt_thread *);
	uint32_t (*get_edi)(struct pt_thread *);
	uint32_t (*get_esp)(struct pt_thread *);
	uint32_t (*get_ebp)(struct pt_thread *);
	uint32_t (*get_eip)(struct pt_thread *);
	uint32_t (*get_eflags)(struct pt_thread *);
	uint16_t (*get_cs)(struct pt_thread *);
	uint16_t (*get_ds)(struct pt_thread *);
	uint16_t (*get_es)(struct pt_thread *);
	uint16_t (*get_ss)(struct pt_thread *);
	uint16_t (*get_fs)(struct pt_thread *);
	uint16_t (*get_gs)(struct pt_thread *);
	uint32_t (*get_dr0)(struct pt_thread *);
	uint32_t (*get_dr1)(struct pt_thread *);
	uint32_t (*get_dr2)(struct pt_thread *);
	uint32_t (*get_dr3)(struct pt_thread *);
	uint32_t (*get_dr6)(struct pt_thread *);
	uint32_t (*get_dr7)(struct pt_thread *);

	int (*set_eax)(struct pt_thread *, uint32_t);
	int (*set_ebx)(struct pt_thread *, uint32_t);
	int (*set_ecx)(struct pt_thread *, uint32_t);
	int (*set_edx)(struct pt_thread *, uint32_t);
	int (*set_esi)(struct pt_thread *, uint32_t);
	int (*set_edi)(struct pt_thread *, uint32_t);
	int (*set_ebp)(struct pt_thread *, uint32_t);
	int (*set_esp)(struct pt_thread *, uint32_t);
	int (*set_eip)(struct pt_thread *, uint32_t);
	int (*set_eflags)(struct pt_thread *, uint32_t);
	int (*set_cs)(struct pt_thread *, uint16_t);
	int (*set_ds)(struct pt_thread *, uint16_t);
	int (*set_es)(struct pt_thread *, uint16_t);
	int (*set_ss)(struct pt_thread *, uint16_t);
	int (*set_fs)(struct pt_thread *, uint16_t);
	int (*set_gs)(struct pt_thread *, uint16_t);
	int (*set_dr0)(struct pt_thread *, uint32_t);
	int (*set_dr1)(struct pt_thread *, uint32_t);
	int (*set_dr2)(struct pt_thread *, uint32_t);
	int (*set_dr3)(struct pt_thread *, uint32_t);
	int (*set_dr6)(struct pt_thread *, uint32_t);
	int (*set_dr7)(struct pt_thread *, uint32_t);
};

#ifdef __cplusplus
extern "C" {
#endif

/* i386 register read functions */
uint32_t pt_thread_x86_32_get_eax(struct pt_thread *);
uint32_t pt_thread_x86_32_get_ebx(struct pt_thread *);
uint32_t pt_thread_x86_32_get_ecx(struct pt_thread *);
uint32_t pt_thread_x86_32_get_edx(struct pt_thread *);
uint32_t pt_thread_x86_32_get_esi(struct pt_thread *);
uint32_t pt_thread_x86_32_get_edi(struct pt_thread *);
uint32_t pt_thread_x86_32_get_esp(struct pt_thread *);
uint32_t pt_thread_x86_32_get_ebp(struct pt_thread *);
uint32_t pt_thread_x86_32_get_eip(struct pt_thread *);
uint32_t pt_thread_x86_32_get_eflags(struct pt_thread *);
uint16_t pt_thread_x86_32_get_cs(struct pt_thread *);
uint16_t pt_thread_x86_32_get_ds(struct pt_thread *);
uint16_t pt_thread_x86_32_get_es(struct pt_thread *);
uint16_t pt_thread_x86_32_get_ss(struct pt_thread *);
uint16_t pt_thread_x86_32_get_fs(struct pt_thread *);
uint16_t pt_thread_x86_32_get_gs(struct pt_thread *);
uint32_t pt_thread_x86_32_get_dr0(struct pt_thread *);
uint32_t pt_thread_x86_32_get_dr1(struct pt_thread *);
uint32_t pt_thread_x86_32_get_dr2(struct pt_thread *);
uint32_t pt_thread_x86_32_get_dr3(struct pt_thread *);
uint32_t pt_thread_x86_32_get_dr6(struct pt_thread *);
uint32_t pt_thread_x86_32_get_dr7(struct pt_thread *);

/* i386 register write functions */
int pt_thread_x86_32_set_eax(struct pt_thread *, uint32_t);
int pt_thread_x86_32_set_ebx(struct pt_thread *, uint32_t);
int pt_thread_x86_32_set_ecx(struct pt_thread *, uint32_t);
int pt_thread_x86_32_set_edx(struct pt_thread *, uint32_t);
int pt_thread_x86_32_set_esi(struct pt_thread *, uint32_t);
int pt_thread_x86_32_set_edi(struct pt_thread *, uint32_t);
int pt_thread_x86_32_set_ebp(struct pt_thread *, uint32_t);
int pt_thread_x86_32_set_esp(struct pt_thread *, uint32_t);
int pt_thread_x86_32_set_eip(struct pt_thread *, uint32_t);
int pt_thread_x86_32_set_eflags(struct pt_thread *, uint32_t);
int pt_thread_x86_32_set_cs(struct pt_thread *, uint16_t);
int pt_thread_x86_32_set_ds(struct pt_thread *, uint16_t);
int pt_thread_x86_32_set_es(struct pt_thread *, uint16_t);
int pt_thread_x86_32_set_fs(struct pt_thread *, uint16_t);
int pt_thread_x86_32_set_gs(struct pt_thread *, uint16_t);
int pt_thread_x86_32_set_ss(struct pt_thread *, uint16_t);
int pt_thread_x86_32_set_dr0(struct pt_thread *, uint32_t);
int pt_thread_x86_32_set_dr1(struct pt_thread *, uint32_t);
int pt_thread_x86_32_set_dr2(struct pt_thread *, uint32_t);
int pt_thread_x86_32_set_dr3(struct pt_thread *, uint32_t);
int pt_thread_x86_32_set_dr6(struct pt_thread *, uint32_t);
int pt_thread_x86_32_set_dr7(struct pt_thread *, uint32_t);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_THREAD_X86_32_INTERNAL_H */
