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
 * thread_x86_32.c
 *
 * libptrace i386 thread management.
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <libptrace/error.h>
#include <libptrace/types.h>
#include "arch.h"
#include "thread.h"
#include "thread_x86.h"
#include "thread_x86_32.h"

#define DEFINE_PT_THREAD_X86_32_GET_REG(r, s)				\
uint##s##_t pt_thread_x86_32_get_##r(struct pt_thread *thread)		\
{									\
	struct pt_arch_data_x86_32 *arch_data;				\
									\
	assert(thread->arch_data != NULL);				\
									\
	if (thread->arch_data->arch != PT_ARCH_I386) {			\
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);		\
		return -1;						\
	}								\
									\
	arch_data = (struct pt_arch_data_x86_32 *)thread->arch_data;	\
									\
	if (arch_data->t_op->get_##r == NULL) {				\
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);		\
		return -1;						\
	}								\
									\
	return arch_data->t_op->get_##r(thread);			\
}

#define DEFINE_PT_THREAD_X86_32_SET_REG(r, s)				\
int pt_thread_x86_32_set_##r(struct pt_thread *thread, uint##s##_t reg)	\
{									\
	struct pt_arch_data_x86_32 *arch_data;				\
									\
	assert(thread->arch_data != NULL);				\
									\
	if (thread->arch_data->arch != PT_ARCH_I386) {			\
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);		\
		return -1;						\
	}								\
									\
	arch_data = (struct pt_arch_data_x86_32 *)thread->arch_data;	\
									\
	if (arch_data->t_op->set_##r == NULL) {				\
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);		\
		return -1;						\
	}								\
									\
	return arch_data->t_op->set_##r(thread, reg);			\
}

DEFINE_PT_THREAD_X86_32_GET_REG(eax, 32);
DEFINE_PT_THREAD_X86_32_GET_REG(ebx, 32);
DEFINE_PT_THREAD_X86_32_GET_REG(ecx, 32);
DEFINE_PT_THREAD_X86_32_GET_REG(edx, 32);
DEFINE_PT_THREAD_X86_32_GET_REG(esi, 32);
DEFINE_PT_THREAD_X86_32_GET_REG(edi, 32);
DEFINE_PT_THREAD_X86_32_GET_REG(esp, 32);
DEFINE_PT_THREAD_X86_32_GET_REG(ebp, 32);
DEFINE_PT_THREAD_X86_32_GET_REG(eip, 32);
DEFINE_PT_THREAD_X86_32_GET_REG(eflags, 32);
DEFINE_PT_THREAD_X86_32_GET_REG(cs, 16);
DEFINE_PT_THREAD_X86_32_GET_REG(ds, 16);
DEFINE_PT_THREAD_X86_32_GET_REG(es, 16);
DEFINE_PT_THREAD_X86_32_GET_REG(fs, 16);
DEFINE_PT_THREAD_X86_32_GET_REG(gs, 16);
DEFINE_PT_THREAD_X86_32_GET_REG(ss, 16);
DEFINE_PT_THREAD_X86_32_GET_REG(dr0, 32);
DEFINE_PT_THREAD_X86_32_GET_REG(dr1, 32);
DEFINE_PT_THREAD_X86_32_GET_REG(dr2, 32);
DEFINE_PT_THREAD_X86_32_GET_REG(dr3, 32);
DEFINE_PT_THREAD_X86_32_GET_REG(dr6, 32);
DEFINE_PT_THREAD_X86_32_GET_REG(dr7, 32);

DEFINE_PT_THREAD_X86_32_SET_REG(eax, 32);
DEFINE_PT_THREAD_X86_32_SET_REG(ebx, 32);
DEFINE_PT_THREAD_X86_32_SET_REG(ecx, 32);
DEFINE_PT_THREAD_X86_32_SET_REG(edx, 32);
DEFINE_PT_THREAD_X86_32_SET_REG(esi, 32);
DEFINE_PT_THREAD_X86_32_SET_REG(edi, 32);
DEFINE_PT_THREAD_X86_32_SET_REG(esp, 32);
DEFINE_PT_THREAD_X86_32_SET_REG(ebp, 32);
DEFINE_PT_THREAD_X86_32_SET_REG(eip, 32);
DEFINE_PT_THREAD_X86_32_SET_REG(eflags, 32);
DEFINE_PT_THREAD_X86_32_SET_REG(cs, 16);
DEFINE_PT_THREAD_X86_32_SET_REG(ds, 16);
DEFINE_PT_THREAD_X86_32_SET_REG(es, 16);
DEFINE_PT_THREAD_X86_32_SET_REG(fs, 16);
DEFINE_PT_THREAD_X86_32_SET_REG(gs, 16);
DEFINE_PT_THREAD_X86_32_SET_REG(ss, 16);
DEFINE_PT_THREAD_X86_32_SET_REG(dr0, 32);
DEFINE_PT_THREAD_X86_32_SET_REG(dr1, 32);
DEFINE_PT_THREAD_X86_32_SET_REG(dr2, 32);
DEFINE_PT_THREAD_X86_32_SET_REG(dr3, 32);
DEFINE_PT_THREAD_X86_32_SET_REG(dr6, 32);
DEFINE_PT_THREAD_X86_32_SET_REG(dr7, 32);
