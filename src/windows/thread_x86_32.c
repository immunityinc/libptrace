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
 * libptrace windows i386 thread management.
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <windows.h>
#include <libptrace/log.h>
#include <libptrace/windows/error.h>
#include "../arch.h"
#include "../registers.h"
#include "../thread_x86_32.h"
#include "thread.h"
#include "thread_x86_32.h"

struct pt_thread_x86_32_operations pt_windows_thread_x86_32_operations = {
	.get_eax	= pt_windows_thread_x86_32_get_eax,
	.get_ebx	= pt_windows_thread_x86_32_get_ebx,
	.get_ecx	= pt_windows_thread_x86_32_get_ecx,
	.get_edx	= pt_windows_thread_x86_32_get_edx,
	.get_esi	= pt_windows_thread_x86_32_get_esi,
	.get_edi	= pt_windows_thread_x86_32_get_edi,
	.get_esp	= pt_windows_thread_x86_32_get_esp,
	.get_ebp	= pt_windows_thread_x86_32_get_ebp,
	.get_eip	= pt_windows_thread_x86_32_get_eip,
	.get_eflags	= pt_windows_thread_x86_32_get_eflags,
	.get_cs		= pt_windows_thread_x86_32_get_cs,
	.get_ds		= pt_windows_thread_x86_32_get_ds,
	.get_es		= pt_windows_thread_x86_32_get_es,
	.get_fs		= pt_windows_thread_x86_32_get_fs,
	.get_gs		= pt_windows_thread_x86_32_get_gs,
	.get_ss		= pt_windows_thread_x86_32_get_ss,
	.get_dr0	= pt_windows_thread_x86_32_get_dr0,
	.get_dr1	= pt_windows_thread_x86_32_get_dr1,
	.get_dr2	= pt_windows_thread_x86_32_get_dr2,
	.get_dr3	= pt_windows_thread_x86_32_get_dr3,
	.get_dr6	= pt_windows_thread_x86_32_get_dr6,
	.get_dr7	= pt_windows_thread_x86_32_get_dr7,

	.set_eax	= pt_windows_thread_x86_32_set_eax,
	.set_ebx	= pt_windows_thread_x86_32_set_ebx,
	.set_ecx	= pt_windows_thread_x86_32_set_ecx,
	.set_edx	= pt_windows_thread_x86_32_set_edx,
	.set_esi	= pt_windows_thread_x86_32_set_esi,
	.set_edi	= pt_windows_thread_x86_32_set_edi,
	.set_esp	= pt_windows_thread_x86_32_set_esp,
	.set_ebp	= pt_windows_thread_x86_32_set_ebp,
	.set_eip	= pt_windows_thread_x86_32_set_eip,
	.set_eflags	= pt_windows_thread_x86_32_set_eflags,
	.set_cs		= pt_windows_thread_x86_32_set_cs,
	.set_ds		= pt_windows_thread_x86_32_set_ds,
	.set_es		= pt_windows_thread_x86_32_set_es,
	.set_fs		= pt_windows_thread_x86_32_set_fs,
	.set_gs		= pt_windows_thread_x86_32_set_gs,
	.set_ss		= pt_windows_thread_x86_32_set_ss,
	.set_dr0	= pt_windows_thread_x86_32_set_dr0,
	.set_dr1	= pt_windows_thread_x86_32_set_dr1,
	.set_dr2	= pt_windows_thread_x86_32_set_dr2,
	.set_dr3	= pt_windows_thread_x86_32_set_dr3,
	.set_dr6	= pt_windows_thread_x86_32_set_dr6,
	.set_dr7	= pt_windows_thread_x86_32_set_dr7,
};

_Static_assert(sizeof(uint32_t) <= sizeof(void *),
               "'uint32_t' cannot be stored in 'void *'");

struct pt_arch_data_x86_32 pt_windows_thread_arch_data = {
	.arch           = PT_ARCH_I386,
	.pointer_size   = 4,
	.t_op           = &pt_windows_thread_x86_32_operations
};

void *pt_windows_thread_register_pc_get(struct pt_thread *thread)
{
	return (void *)pt_windows_thread_x86_32_get_eip(thread);
}

int pt_windows_thread_register_pc_set(struct pt_thread *thread, void *pc)
{
	return pt_windows_thread_x86_32_set_eip(thread, (uint32_t)pc);
}

int pt_windows_thread_debug_registers_apply(struct pt_thread *thread)
{
	struct x86_debug_registers *db = &thread->debug_registers;
	HANDLE h = pt_windows_thread_handle_get(thread);
	CONTEXT ctx;

	/* Translate our mirror representation of the debug registers
	 * to the i386 representation, and store it in the thread context.
	 */
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	ctx.Dr0 = db->regs[0].address;
	ctx.Dr1 = db->regs[1].address;
	ctx.Dr2 = db->regs[2].address;
	ctx.Dr3 = db->regs[3].address;
	ctx.Dr6 = 0;
	ctx.Dr7 = X86_DR_GET_ENABLE(0, db->regs[0].scope) |
		  X86_DR_GET_ENABLE(1, db->regs[1].scope) |
		  X86_DR_GET_ENABLE(2, db->regs[2].scope) |
		  X86_DR_GET_ENABLE(3, db->regs[3].scope) |
		  X86_DR_GET_TYPE(0, db->regs[0].type) |
		  X86_DR_GET_TYPE(1, db->regs[1].type) |
		  X86_DR_GET_TYPE(2, db->regs[2].type) |
		  X86_DR_GET_TYPE(3, db->regs[3].type) |
		  X86_DR_GET_SIZE(0, db->regs[0].size) |
		  X86_DR_GET_SIZE(1, db->regs[1].size) |
		  X86_DR_GET_SIZE(2, db->regs[2].size) |
		  X86_DR_GET_SIZE(3, db->regs[3].size);

	if (SetThreadContext(h, &ctx) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	/* We have set the debug registers, and flag this in the thread state,
	 * as we now expect single step events in our event loop.
	 */

	return 0;
}

struct pt_registers *
pt_windows_thread_registers_get(struct pt_thread *thread)
{
	HANDLE h = pt_windows_thread_handle_get(thread);
	struct pt_registers_i386 *regs;
	CONTEXT ctx;

	/* Get the registers from the given thread. */
	ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext(h, &ctx) == 0) {
		pt_windows_error_winapi_set();
		return NULL;
	}

	/* Allocate a pt_registers structure for this. */
	if ( (regs = malloc(sizeof(*regs))) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	/* Perform internal windows structure to ptrace translation. */
	regs->type = PT_REGISTERS_I386;
	regs->eax = ctx.Eax;
	regs->ebx = ctx.Ebx;
	regs->ecx = ctx.Ecx;
	regs->edx = ctx.Edx;
	regs->esi = ctx.Esi;
	regs->edi = ctx.Edi;
	regs->esp = ctx.Esp;
	regs->ebp = ctx.Ebp;
	regs->eip = ctx.Eip;
	regs->cs = ctx.SegCs;
	regs->ds = ctx.SegDs;
	regs->es = ctx.SegEs;
	regs->fs = ctx.SegFs;
	regs->gs = ctx.SegGs;
	regs->ss = ctx.SegSs;
	regs->eflags = ctx.EFlags;
	regs->dr0 = ctx.Dr0;
	regs->dr1 = ctx.Dr1;
	regs->dr2 = ctx.Dr2;
	regs->dr3 = ctx.Dr3;
	regs->dr6 = ctx.Dr6;
	regs->dr7 = ctx.Dr7;

	return (struct pt_registers *)regs;
}

int
pt_windows_thread_registers_set(struct pt_thread *thread, struct pt_registers *regs_)
{
	struct pt_registers_i386 *regs = (struct pt_registers_i386 *)regs_;
	HANDLE h = pt_windows_thread_handle_get(thread);
	CONTEXT ctx;

	/* XXX: set internal error information. */
	if (regs->type != PT_REGISTERS_I386)
		return -1;

	/* Translate the registers from ptrace specific structure into
	 * struct user_regs.  This is not necessary for native debugging,
	 * but we keep the API and structure views consistent over all
	 * platforms, including remote debugging ones.
	 */
	ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	ctx.Eax = regs->eax;
	ctx.Ebx = regs->ebx;
	ctx.Ecx = regs->ecx;
	ctx.Edx = regs->edx;
	ctx.Esi = regs->esi;
	ctx.Edi = regs->edi;
	ctx.Esp = regs->esp;
	ctx.Ebp = regs->ebp;
	ctx.Eip = regs->eip;
	ctx.SegCs = regs->cs;
	ctx.SegDs = regs->ds;
	ctx.SegEs = regs->es;
	ctx.SegFs = regs->fs;
	ctx.SegGs = regs->gs;
	ctx.SegSs = regs->ss;
	ctx.EFlags = regs->eflags;
	ctx.Dr0 = regs->dr0;
	ctx.Dr1 = regs->dr1;
	ctx.Dr2 = regs->dr2;
	ctx.Dr3 = regs->dr3;
	ctx.Dr6 = regs->dr6;
	ctx.Dr7 = regs->dr7;

	if (SetThreadContext(h, &ctx) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	return 0;
}

#define DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_INTEGER(c, r)		\
uint32_t pt_windows_thread_x86_32_get_##r(struct pt_thread *thread)	\
{									\
	HANDLE h = pt_windows_thread_handle_get(thread);		\
	CONTEXT ctx;							\
									\
	ctx.ContextFlags = CONTEXT_INTEGER;				\
	if (GetThreadContext(h, &ctx) == 0) {				\
		pt_windows_error_winapi_set();				\
		return -1;						\
	}								\
									\
	return ctx.c;							\
}

#define DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_SEGMENTS(c, r)		\
uint16_t pt_windows_thread_x86_32_get_##r(struct pt_thread *thread)	\
{									\
	HANDLE h = pt_windows_thread_handle_get(thread);		\
	CONTEXT ctx;							\
									\
	ctx.ContextFlags = CONTEXT_SEGMENTS;				\
	if (GetThreadContext(h, &ctx) == 0) {				\
		pt_windows_error_winapi_set();				\
		return -1;						\
	}								\
									\
	return ctx.c;							\
}

#define DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_CONTROL16(c, r)		\
uint16_t pt_windows_thread_x86_32_get_##r(struct pt_thread *thread)	\
{									\
	HANDLE h = pt_windows_thread_handle_get(thread);		\
	CONTEXT ctx;							\
									\
	ctx.ContextFlags = CONTEXT_CONTROL;				\
	if (GetThreadContext(h, &ctx) == 0) {				\
		pt_windows_error_winapi_set();				\
		return -1;						\
	}								\
									\
	return ctx.c;							\
}

#define DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_CONTROL32(c, r)		\
uint32_t pt_windows_thread_x86_32_get_##r(struct pt_thread *thread)	\
{									\
	HANDLE h = pt_windows_thread_handle_get(thread);		\
	CONTEXT ctx;							\
									\
	ctx.ContextFlags = CONTEXT_CONTROL;				\
	if (GetThreadContext(h, &ctx) == 0) {				\
		pt_windows_error_winapi_set();				\
		return -1;						\
	}								\
									\
	return ctx.c;							\
}

#define DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_DEBUG(c, r)		\
uint32_t pt_windows_thread_x86_32_get_##r(struct pt_thread *thread)	\
{									\
	HANDLE h = pt_windows_thread_handle_get(thread);		\
	CONTEXT ctx;							\
									\
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;			\
	if (GetThreadContext(h, &ctx) == 0) {				\
		pt_windows_error_winapi_set();				\
		return -1;						\
	}								\
									\
	return ctx.c;							\
}

#define DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_INTEGER(c, r)		\
int pt_windows_thread_x86_32_set_##r(struct pt_thread *thread,		\
                                     uint32_t r)			\
{									\
	HANDLE h = pt_windows_thread_handle_get(thread);		\
	CONTEXT ctx;							\
									\
	ctx.ContextFlags = CONTEXT_INTEGER;				\
	if (GetThreadContext(h, &ctx) == 0) {				\
		pt_windows_error_winapi_set();				\
		return -1;						\
	}								\
									\
	ctx.c = r;							\
									\
	if (SetThreadContext(h, &ctx) == 0) {				\
		pt_windows_error_winapi_set();				\
		return -1;						\
	}								\
									\
	return 0;							\
}

#define DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_SEGMENTS(c, r)		\
int pt_windows_thread_x86_32_set_##r(struct pt_thread *thread,		\
                                     uint16_t r)			\
{									\
	HANDLE h = pt_windows_thread_handle_get(thread);		\
	CONTEXT ctx;							\
									\
	ctx.ContextFlags = CONTEXT_SEGMENTS;				\
	if (GetThreadContext(h, &ctx) == 0) {				\
		pt_windows_error_winapi_set();				\
		return -1;						\
	}								\
									\
	ctx.c = r;							\
									\
	if (SetThreadContext(h, &ctx) == 0) {				\
		pt_windows_error_winapi_set();				\
		return -1;						\
	}								\
									\
	return 0;							\
}

#define DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_CONTROL16(c, r)		\
int pt_windows_thread_x86_32_set_##r(struct pt_thread *thread,		\
                                     uint16_t r)			\
{									\
	HANDLE h = pt_windows_thread_handle_get(thread);		\
	CONTEXT ctx;							\
									\
	ctx.ContextFlags = CONTEXT_CONTROL;				\
	if (GetThreadContext(h, &ctx) == 0) {				\
		pt_windows_error_winapi_set();				\
		return -1;						\
	}								\
									\
	ctx.c = r;							\
									\
	if (SetThreadContext(h, &ctx) == 0) {				\
		pt_windows_error_winapi_set();				\
		return -1;						\
	}								\
									\
	return 0;							\
}

#define DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_CONTROL32(c, r)		\
int pt_windows_thread_x86_32_set_##r(struct pt_thread *thread,		\
                                     uint32_t r)			\
{									\
	HANDLE h = pt_windows_thread_handle_get(thread);		\
	CONTEXT ctx;							\
									\
	ctx.ContextFlags = CONTEXT_CONTROL;				\
	if (GetThreadContext(h, &ctx) == 0) {				\
		pt_windows_error_winapi_set();				\
		return -1;						\
	}								\
									\
	ctx.c = r;							\
									\
	if (SetThreadContext(h, &ctx) == 0) {				\
		pt_windows_error_winapi_set();				\
		return -1;						\
	}								\
									\
	return 0;							\
}

#define DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_DEBUG(c, r)		\
int pt_windows_thread_x86_32_set_##r(struct pt_thread *thread,		\
                                     uint32_t r)			\
{									\
	HANDLE h = pt_windows_thread_handle_get(thread);		\
	CONTEXT ctx;							\
									\
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;			\
	if (GetThreadContext(h, &ctx) == 0) {				\
		pt_windows_error_winapi_set();				\
		return -1;						\
	}								\
									\
	ctx.c = r;							\
									\
	if (SetThreadContext(h, &ctx) == 0) {				\
		pt_windows_error_winapi_set();				\
		return -1;						\
	}								\
									\
	return 0;							\
}

/* Define i386 register read functions through the templates. */
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_INTEGER(Eax, eax);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_INTEGER(Ebx, ebx);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_INTEGER(Ecx, ecx);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_INTEGER(Edx, edx);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_INTEGER(Esi, esi);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_INTEGER(Edi, edi);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_SEGMENTS(SegDs, ds);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_SEGMENTS(SegEs, es);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_SEGMENTS(SegFs, fs);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_SEGMENTS(SegGs, gs);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_CONTROL16(SegCs, cs);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_CONTROL16(SegSs, ss);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_CONTROL32(Esp, esp);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_CONTROL32(Ebp, ebp);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_CONTROL32(Eip, eip);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_CONTROL32(EFlags, eflags);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_DEBUG(Dr0, dr0);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_DEBUG(Dr1, dr1);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_DEBUG(Dr2, dr2);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_DEBUG(Dr3, dr3);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_DEBUG(Dr6, dr6);
DEFINE_PT_WINDOWS_THREAD_X86_32_GET_REG_DEBUG(Dr7, dr7);

/* Define i386 register write functions through the templates. */
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_INTEGER(Eax, eax);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_INTEGER(Ebx, ebx);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_INTEGER(Ecx, ecx);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_INTEGER(Edx, edx);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_INTEGER(Esi, esi);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_INTEGER(Edi, edi);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_SEGMENTS(SegDs, ds);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_SEGMENTS(SegEs, es);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_SEGMENTS(SegFs, fs);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_SEGMENTS(SegGs, gs);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_CONTROL16(SegCs, cs);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_CONTROL16(SegSs, ss);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_CONTROL32(Esp, esp);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_CONTROL32(Ebp, ebp);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_CONTROL32(Eip, eip);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_CONTROL32(EFlags, eflags);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_DEBUG(Dr0, dr0);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_DEBUG(Dr1, dr1);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_DEBUG(Dr2, dr2);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_DEBUG(Dr3, dr3);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_DEBUG(Dr6, dr6);
DEFINE_PT_WINDOWS_THREAD_X86_32_SET_REG_DEBUG(Dr7, dr7);

struct pt_registers *
pt_windows_wow64_thread_registers_get(struct pt_thread *thread)
{
	return pt_windows_thread_registers_get(thread);
}

int
pt_windows_wow64_thread_registers_set(struct pt_thread *thread, struct pt_registers *regs_)
{
	return pt_windows_thread_registers_set(thread, regs_);

}

int pt_windows_thread_single_step_set(struct pt_thread *thread)
{
	uint32_t eflags;

	assert(thread->arch_data->arch == PT_ARCH_I386);

	pt_error_save(), pt_error_clear();

	eflags = pt_thread_x86_32_get_eflags(thread);

	if (eflags == -1 && pt_error_is_set())
		return -1;

	/* Set the trap flag in eflags. */
	eflags |= X86_EFLAGS_TF;

	if (pt_thread_x86_32_set_eflags(thread, eflags) == -1)
		return -1;

	pt_error_restore();

	return 0;
}

int pt_windows_thread_single_step_remove(struct pt_thread *thread)
{
	uint32_t eflags;

	pt_log("%s(tid: %d)\n", __FUNCTION__, thread->tid);

	assert(thread->arch_data->arch == PT_ARCH_I386);

	pt_error_save(), pt_error_clear();

	eflags = pt_thread_x86_32_get_eflags(thread);

	if (eflags == -1 && pt_error_is_set())
		return -1;

	eflags &= ~X86_EFLAGS_TF;

	if (pt_thread_x86_32_set_eflags(thread, eflags) == 1)
		return -1;

	pt_error_restore();

	return 0;
}
