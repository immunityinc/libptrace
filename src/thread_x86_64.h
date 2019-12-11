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
 * thread_x86_64.h
 *
 * libptrace x86_64 thread management.
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#ifndef PT_THREAD_X86_64_INTERNAL_H
#define PT_THREAD_X86_64_INTERNAL_H

#include <stdint.h>
#include <libptrace/thread.h>

struct pt_thread_x86_64_operations
{
	uint64_t (*get_rax)(struct pt_thread *);
	uint64_t (*get_rbx)(struct pt_thread *);
	uint64_t (*get_rcx)(struct pt_thread *);
	uint64_t (*get_rdx)(struct pt_thread *);
	uint64_t (*get_rsi)(struct pt_thread *);
	uint64_t (*get_rdi)(struct pt_thread *);
	uint64_t (*get_rsp)(struct pt_thread *);
	uint64_t (*get_rbp)(struct pt_thread *);
	uint64_t (*get_rip)(struct pt_thread *);
	uint64_t (*get_r8)(struct pt_thread *);
	uint64_t (*get_r9)(struct pt_thread *);
	uint64_t (*get_r10)(struct pt_thread *);
	uint64_t (*get_r11)(struct pt_thread *);
	uint64_t (*get_r12)(struct pt_thread *);
	uint64_t (*get_r13)(struct pt_thread *);
	uint64_t (*get_r14)(struct pt_thread *);
	uint64_t (*get_r15)(struct pt_thread *);
	uint64_t (*get_rflags)(struct pt_thread *);
	uint16_t (*get_cs)(struct pt_thread *);
	uint16_t (*get_ds)(struct pt_thread *);
	uint16_t (*get_es)(struct pt_thread *);
	uint16_t (*get_fs)(struct pt_thread *);
	uint16_t (*get_gs)(struct pt_thread *);
	uint16_t (*get_ss)(struct pt_thread *);
	uint64_t (*get_dr0)(struct pt_thread *);
	uint64_t (*get_dr1)(struct pt_thread *);
	uint64_t (*get_dr2)(struct pt_thread *);
	uint64_t (*get_dr3)(struct pt_thread *);
	uint64_t (*get_dr6)(struct pt_thread *);
	uint64_t (*get_dr7)(struct pt_thread *);

	int (*set_rax)(struct pt_thread *, uint64_t);
	int (*set_rbx)(struct pt_thread *, uint64_t);
	int (*set_rcx)(struct pt_thread *, uint64_t);
	int (*set_rdx)(struct pt_thread *, uint64_t);
	int (*set_rsi)(struct pt_thread *, uint64_t);
	int (*set_rdi)(struct pt_thread *, uint64_t);
	int (*set_rbp)(struct pt_thread *, uint64_t);
	int (*set_rsp)(struct pt_thread *, uint64_t);
	int (*set_rip)(struct pt_thread *, uint64_t);
	int (*set_r8)(struct pt_thread *, uint64_t);
	int (*set_r9)(struct pt_thread *, uint64_t);
	int (*set_r10)(struct pt_thread *, uint64_t);
	int (*set_r11)(struct pt_thread *, uint64_t);
	int (*set_r12)(struct pt_thread *, uint64_t);
	int (*set_r13)(struct pt_thread *, uint64_t);
	int (*set_r14)(struct pt_thread *, uint64_t);
	int (*set_r15)(struct pt_thread *, uint64_t);
	int (*set_rflags)(struct pt_thread *, uint64_t);
	int (*set_cs)(struct pt_thread *, uint16_t);
	int (*set_ds)(struct pt_thread *, uint16_t);
	int (*set_es)(struct pt_thread *, uint16_t);
	int (*set_fs)(struct pt_thread *, uint16_t);
	int (*set_gs)(struct pt_thread *, uint16_t);
	int (*set_ss)(struct pt_thread *, uint16_t);
	int (*set_dr0)(struct pt_thread *, uint64_t);
	int (*set_dr1)(struct pt_thread *, uint64_t);
	int (*set_dr2)(struct pt_thread *, uint64_t);
	int (*set_dr3)(struct pt_thread *, uint64_t);
	int (*set_dr6)(struct pt_thread *, uint64_t);
	int (*set_dr7)(struct pt_thread *, uint64_t);
};

#ifdef __cplusplus
extern "C" {
#endif

/* x86_64 register read functions */
uint64_t pt_thread_x86_64_get_rax(struct pt_thread *);
uint64_t pt_thread_x86_64_get_rbx(struct pt_thread *);
uint64_t pt_thread_x86_64_get_rcx(struct pt_thread *);
uint64_t pt_thread_x86_64_get_rdx(struct pt_thread *);
uint64_t pt_thread_x86_64_get_rsi(struct pt_thread *);
uint64_t pt_thread_x86_64_get_rdi(struct pt_thread *);
uint64_t pt_thread_x86_64_get_rbp(struct pt_thread *);
uint64_t pt_thread_x86_64_get_rsp(struct pt_thread *);
uint64_t pt_thread_x86_64_get_rip(struct pt_thread *);
uint64_t pt_thread_x86_64_get_r8(struct pt_thread *);
uint64_t pt_thread_x86_64_get_r9(struct pt_thread *);
uint64_t pt_thread_x86_64_get_r10(struct pt_thread *);
uint64_t pt_thread_x86_64_get_r11(struct pt_thread *);
uint64_t pt_thread_x86_64_get_r12(struct pt_thread *);
uint64_t pt_thread_x86_64_get_r13(struct pt_thread *);
uint64_t pt_thread_x86_64_get_r14(struct pt_thread *);
uint64_t pt_thread_x86_64_get_r15(struct pt_thread *);
uint64_t pt_thread_x86_64_get_rflags(struct pt_thread *);
uint16_t pt_thread_x86_64_get_cs(struct pt_thread *);
uint16_t pt_thread_x86_64_get_ds(struct pt_thread *);
uint16_t pt_thread_x86_64_get_es(struct pt_thread *);
uint16_t pt_thread_x86_64_get_fs(struct pt_thread *);
uint16_t pt_thread_x86_64_get_gs(struct pt_thread *);
uint16_t pt_thread_x86_64_get_ss(struct pt_thread *);
uint64_t pt_thread_x86_64_get_dr0(struct pt_thread *);
uint64_t pt_thread_x86_64_get_dr1(struct pt_thread *);
uint64_t pt_thread_x86_64_get_dr2(struct pt_thread *);
uint64_t pt_thread_x86_64_get_dr3(struct pt_thread *);
uint64_t pt_thread_x86_64_get_dr6(struct pt_thread *);
uint64_t pt_thread_x86_64_get_dr7(struct pt_thread *);

/* x86_64 register write functions */
int pt_thread_x86_64_set_rax(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_rbx(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_rcx(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_rdx(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_rsi(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_rdi(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_rbp(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_rsp(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_rip(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_r8(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_r9(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_r10(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_r11(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_r12(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_r13(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_r14(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_r15(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_rflags(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_dr0(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_dr1(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_dr2(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_dr3(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_dr6(struct pt_thread *, uint64_t);
int pt_thread_x86_64_set_dr7(struct pt_thread *, uint64_t);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_THREAD_X86_64_INTERNAL_H */
