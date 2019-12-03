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
 * libptrace_freebsd_x86.c
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>
 *
 */
#include <config.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <libptrace.h>

#if 0
int ptrace_wait_breakpoint_at(struct ptrace_context *pctx, void *location)
{
	ptrace_x86_register_t pc;

	do {
		if (ptrace_wait_signal(pctx, SIGTRAP) == -1)
			return -1;

		if (ptrace_get_program_ctr(pctx, &pc) == -1)
			return -1;
	} while ((ptrace_x86_register_t)location != pc);

	return 0;
}
#endif

/* Perform a mmap systemcall in the remote process.
 */
void *ptrace_mmap(struct ptrace_context *p, void *start, size_t length,
                  int prot, int flags, int fd, off_t offset)
{
	struct ptrace_registers regs;
	uint8_t __stub[] = {
		0x68, 0x00, 0x00, 0x00, 0x00,	/* push offset		*/
		0x68, 0x00, 0x00, 0x00, 0x00,	/* push offset		*/
		0x68, 0x00, 0x00, 0x00, 0x00,	/* push dummy		*/
		0x68, 0x00, 0x00, 0x00, 0x00,	/* push fd		*/
		0x68, 0x00, 0x00, 0x00, 0x00,	/* push flags		*/
		0x68, 0x00, 0x00, 0x00, 0x00,	/* push prot		*/
		0x68, 0x00, 0x00, 0x00, 0x00,	/* push length		*/
		0x68, 0x00, 0x00, 0x00, 0x00,	/* push start		*/
		0x68, 0x00, 0x00, 0x00, 0x00,	/* push dummy		*/
		0xb8, 0x00, 0x00, 0x00, 0x00,	/* mov eax, 0		*/
		0xcd, 0x80,			/* int 80h		*/
	};

	/* Fill in all dynamic data in our code stub */
	*(uint32_t *)(__stub + 1) = (uint32_t)
		(sizeof(offset) == 8 ? (offset >> 32) : 0);
	*(uint32_t *)(__stub + 6) = (uint32_t) offset;
	*(uint32_t *)(__stub + 16) = (uint32_t) fd;
	*(uint32_t *)(__stub + 21) = (uint32_t) flags;
	*(uint32_t *)(__stub + 26) = (uint32_t) prot;
	*(uint32_t *)(__stub + 31) = (uint32_t) length;
	*(uint32_t *)(__stub + 36) = (uint32_t) start;
	*(uint32_t *)(__stub + 46) = (uint32_t) SYS_mmap;

	if (__ptrace_run_code(p, __stub, sizeof(__stub), &regs) == -1)
		return MAP_FAILED;

	/* FreeBSD uses the carry-flag to set error conditions. */
	if (regs.eflags & PTRACE_X86_EFLAGS_CF) {
		PTRACE_ERR_SET_REMOTE(p, regs.eax);
		return MAP_FAILED;
	}

	return (void *)regs.eax;
}

int ptrace_munmap(struct ptrace_context *p, void *start, size_t length)
{
	struct ptrace_registers regs;
	uint8_t __stub[] = {
		0x68, 0x00, 0x00, 0x00, 0x00,	/* push length		*/
		0x68, 0x00, 0x00, 0x00, 0x00,	/* push start		*/
		0x68, 0x00, 0x00, 0x00, 0x00,	/* push dummy		*/
		0xb8, 0x00, 0x00, 0x00, 0x00,	/* mov eax, 0		*/
		0xcd, 0x80,			/* int 80h		*/
	};

	/* Fill in all dynamic data in our code stub */
	*(uint32_t *)(__stub + 1) = (uint32_t) length;
	*(uint32_t *)(__stub + 6) = (uint32_t) start;
	*(uint32_t *)(__stub + 16) = (uint32_t) SYS_munmap;

	if (__ptrace_run_code(p, __stub, sizeof(__stub), &regs) == -1)
		return -1;

	if (regs.eflags & PTRACE_X86_EFLAGS_CF) {
		PTRACE_ERR_SET_REMOTE(p, regs.eax);
		return -1;
	}

	return 0;
}

/* State saving functions. */
int ptrace_save_cpu_state(struct ptrace_context *p,
                          struct ptrace_cpu_state *state)
{
	if (ptrace(PT_GETREGS, p->tid, state, NULL) == -1) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	return 0;
}

int ptrace_load_cpu_state(struct ptrace_context *p,
                          struct ptrace_cpu_state *state)
{
	if (ptrace(PT_SETREGS, p->tid, state, NULL) == -1 ) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	return 0;
}

int ptrace_save_fpu_state(struct ptrace_context *p,
                          struct ptrace_fpu_state *state)
{
	if (ptrace(PT_SETFPREGS, p->tid, state, NULL) == -1 ) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	return 0;
}

int ptrace_load_fpu_state(struct ptrace_context *p,
                          struct ptrace_fpu_state *state)
{
	if (ptrace(PT_GETFPREGS, p->tid, (caddr_t)state, NULL) == -1) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	return 0;
}

#if 0

#if defined(__i386__)
/* Register access functions
 */
int ptrace_get_fpu_registers(
	struct ptrace_context *p,
	struct ptrace_fpu_registers *r
) {
	struct user_fpregs_struct __r;

	if ( ptrace(PTRACE_GETFPREGS, p->tid, NULL, &__r) == -1 ) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	/* We convert the floating point register data to the format libptrace
	 * uses for the i386 architecture.
	 * Linux tends to or in 0xFFFF words, and doesn't prepend 11011b to the
	 * opcodes, which we like.
	 */
	r->cwd = __r.cwd & 0xffff;
	r->swd = __r.swd & 0xffff;
	r->twd = __r.twd & 0xffff;
	r->fip = __r.fip;
	r->fcs = __r.fcs & 0xffff;
	r->foc = ((__r.fcs >> 16) & 0x07ff) | 0xd800;
	r->fop = __r.foo;
	r->fos = __r.fos & 0xffff;

	memcpy(r->st_space, __r.st_space, sizeof(__r.st_space));

	return 0;
}

int ptrace_set_fpu_registers(
	struct ptrace_context *p,
	struct ptrace_fpu_registers *r
) {
	struct user_fpregs_struct __r;

	/* XXX: we might want to error when r->foc has the five
	 * bits set to not 11011b...
	 */
	__r.cwd = r->cwd | 0xffff0000;
	__r.swd = r->swd | 0xffff0000;
	__r.twd = r->twd | 0xffff0000;
	__r.fip = r->fip;
	__r.fcs = ((r->foc & 0x7ff) << 16) | r->fcs;
	__r.foo = r->fop;
	__r.fos = r->fos;

	memcpy(__r.st_space, r->st_space, sizeof(__r.st_space));

	if ( ptrace(PTRACE_SETFPREGS, p->tid, NULL, &__r) == -1 ) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	return 0;
}

#ifdef USE_MMX
int ptrace_get_mmx_registers(
	struct ptrace_context *p,
	struct ptrace_mmx_registers *r
) {
	struct user_fpregs_struct __r;
	uint16_t *mmx_regp = (uint16_t *)__r.st_space;

	if ( ptrace(PTRACE_GETFPREGS, p->tid, NULL, &__r) == -1 ) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	/* We convert the floating point register data to the format libptrace
	 * uses for the i386 architecture.
	 * Linux tends to or in 0xFFFF words, and doesn't prepend 11011b to the
	 * opcodes, which we like.
	 */
	r->cwd = __r.cwd & 0xffff;
	r->swd = __r.swd & 0xffff;
	r->twd = __r.twd & 0xffff;
	r->fip = __r.fip;
	r->fcs = __r.fcs & 0xffff;
	r->foc = ((__r.fcs >> 16) & 0x07ff) | 0xd800;
	r->fop = __r.foo;
	r->fos = __r.fos & 0xffff;

	/* Store the MMX registers as well; the top 16 bits of the FPU
	 * registers (the exponent) which aren't used for MMX but set to 1 bits
	 * by MMX write instructions are provided for ease of use/sanity
	 * checking.
	 */
	r->mm0 = *(uint64_t *)mmx_regp;
	r->top0 = *(mmx_regp + 4);
	r->mm1 = *(uint64_t *)(mmx_regp + 5);
	r->top1 = *(mmx_regp + 9);
	r->mm2 = *(uint64_t *)(mmx_regp + 10);
	r->top2 = *(mmx_regp + 14);
	r->mm3 = *(uint64_t *)(mmx_regp + 15);
	r->top3 = *(mmx_regp + 19);
	r->mm4 = *(uint64_t *)(mmx_regp + 20);
	r->top4 = *(mmx_regp + 24);
	r->mm5 = *(uint64_t *)(mmx_regp + 25);
	r->top5 = *(mmx_regp + 29);
	r->mm6 = *(uint64_t *)(mmx_regp + 30);
	r->top6 = *(mmx_regp + 34);
	r->mm7 = *(uint64_t *)(mmx_regp + 35);
	r->top7 = *(mmx_regp + 39);

	return 0;
}

int ptrace_set_mmx_registers(
	struct ptrace_context *p,
	struct ptrace_mmx_registers *r
) {
	struct user_fpregs_struct __r;
	uint16_t *mmx_regp = (uint16_t *) __r.st_space;

	/* XXX: we might want to error when r->foc has the five
	 * bits set to not 11011b...
	 */
	__r.cwd = r->cwd | 0xffff0000;
	__r.swd = r->swd | 0xffff0000;
	__r.twd = r->twd | 0xffff0000;
	__r.fip = r->fip;
	__r.fcs = ((r->foc & 0x7ff) << 16) | r->fcs;
	__r.foo = r->fop;
	__r.fos = r->fos;

	*(uint64_t *)mmx_regp = r->mm0;
	*(mmx_regp + 4) = r->top0;
	*(uint64_t *)(mmx_regp + 5) = r->mm1;
	*(mmx_regp + 9) = r->top1;
	*(uint64_t *)(mmx_regp + 10) = r->mm2;
	*(mmx_regp + 14) = r->top2;
	*(uint64_t *)(mmx_regp + 15) = r->mm3;
	*(mmx_regp + 19) = r->top3;
	*(uint64_t *)(mmx_regp + 20) = r->mm4;
	*(mmx_regp + 24) = r->top4;
	*(uint64_t *)(mmx_regp + 25) = r->mm5;
	*(mmx_regp + 29) = r->top5;
	*(uint64_t *)(mmx_regp + 30) = r->mm6;
	*(mmx_regp + 34) = r->top6;
	*(uint64_t *)(mmx_regp + 35) = r->mm7;
	*(mmx_regp + 39) = r->top7;

	if ( ptrace(PTRACE_SETFPREGS, p->tid, NULL, &__r) == -1 ) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	return 0;
}
#endif	/* USE_MMX */

#ifdef USE_SSE
int ptrace_get_sse_registers(
	struct ptrace_context *p,
	struct ptrace_sse_registers *r
) {

}
#endif

#endif	/* __i386__ */

#endif

int ptrace_get_debug_registers(struct ptrace_context *p,
                               struct ptrace_debug_registers *r)
{
	struct dbreg regs;

	if (ptrace(PT_GETDBREGS, p->tid, (caddr_t)&regs, NULL) == -1) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	r->dr0 = regs.dr0;
	r->dr1 = regs.dr1;
	r->dr2 = regs.dr2;
	r->dr3 = regs.dr3;
	r->dr6 = regs.dr6;
	r->dr7 = regs.dr7;

	return 0;
}

int ptrace_set_debug_registers(struct ptrace_context *p,
                               struct ptrace_debug_registers *r)
{
	struct dbreg regs;

	/* XXX: copy now, do properly later. */
	regs.dr0 = r->dr0;
	regs.dr1 = r->dr1;
	regs.dr2 = r->dr2;
	regs.dr3 = r->dr3;
	regs.dr4 = 0;
	regs.dr5 = 0;
	regs.dr6 = r->dr6;
	regs.dr7 = r->dr7;

	if (ptrace(PT_SETDBREGS, p->tid, (caddr_t)&regs, NULL) == -1) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	return 0;
}

/* Macro facilitating function definitions for access to non segment register
 * elements of struct user_regs_struct.
 */
#define DEFINE_PTRACE_GET_REG(r)					\
int __ptrace_get_##r(struct ptrace_context *p,				\
                     ptrace_x86_register_t *r)				\
{									\
	struct ptrace_registers regs;					\
									\
	if (ptrace(PT_GETREGS, p->tid, (caddr_t)&regs, NULL) == -1) {	\
		PTRACE_ERR_SET_EXTERNAL(p);				\
		return -1;						\
	}								\
									\
	*r = regs.##r;							\
									\
	return 0;							\
}									\
									\
ptrace_x86_register_t ptrace_get_##r(struct ptrace_context *p)		\
{									\
	ptrace_x86_register_t reg;					\
									\
	if (__ptrace_get_##r(p, &reg) == -1)				\
		return -1;						\
									\
	return reg;							\
}

/* Macro facilitating function definitions for access to segment register
 * elements of struct user_regs_struct.
 */
#define DEFINE_PTRACE_GET_SEG_REG(r)					\
int __ptrace_get_##r(struct ptrace_context *p,				\
                     ptrace_x86_seg_register_t *r)			\
{									\
	struct ptrace_registers regs;					\
									\
	if (ptrace(PT_GETREGS, p->tid, (caddr_t)&regs, NULL) == -1) {	\
		PTRACE_ERR_SET_EXTERNAL(p);				\
		return -1;						\
	}								\
									\
	*r = regs.##r;							\
									\
	return 0;							\
}									\
									\
ptrace_x86_seg_register_t ptrace_get_##r(struct ptrace_context *p)	\
{									\
	ptrace_x86_seg_register_t reg;					\
									\
	if (__ptrace_get_##r(p, &reg) == -1)				\
		return -1;						\
									\
	return reg;							\
}

/* Macro facilitating function definitions for access to debug register
 * elements of struct user.
 */
#define DEFINE_PTRACE_GET_DEBUG_REG(num)				\
int __ptrace_get_dr##num(struct ptrace_context *p,			\
                         ptrace_x86_register_t *dr##num)		\
{									\
	struct dbreg regs;						\
									\
	if (ptrace(PT_GETDBREGS, p->tid, (caddr_t)&regs, NULL) == -1) {	\
		PTRACE_ERR_SET_EXTERNAL(p);				\
		return -1;						\
	}								\
									\
	*dr##num = regs.dr##num;					\
									\
	return 0;							\
}									\
									\
ptrace_x86_register_t ptrace_get_dr##num(struct ptrace_context *p)	\
{									\
	ptrace_x86_register_t reg;					\
									\
	if (__ptrace_get_dr##num(p, &reg) == -1)			\
		return -1;						\
									\
	return reg;							\
}


#define DEFINE_PTRACE_SET_REG(r)					\
int ptrace_set_##r(struct ptrace_context *p, ptrace_x86_register_t r)	\
{									\
	struct ptrace_registers regs;					\
									\
	if (ptrace_get_registers(p, &regs) == -1)			\
		return -1;						\
									\
	regs.##r = r;							\
									\
	if (ptrace(PT_SETREGS, p->tid, (caddr_t)&regs, NULL) == -1) {	\
		PTRACE_ERR_SET_EXTERNAL(p);				\
		return -1;						\
	}								\
									\
	return 0;							\
}

#define DEFINE_PTRACE_SET_SEG_REG(r)					\
int ptrace_set_##r(struct ptrace_context *p,				\
                   ptrace_x86_seg_register_t r)				\
{									\
	struct ptrace_registers regs;					\
									\
	if (ptrace_get_registers(p, &regs) == -1)			\
		return -1;						\
									\
	regs.##r = r;							\
									\
	if (ptrace(PT_SETREGS, p->tid, (caddr_t)&regs, NULL) == -1) {	\
		PTRACE_ERR_SET_EXTERNAL(p);				\
		return -1;						\
	}								\
									\
	return 0;							\
}

#define DEFINE_PTRACE_SET_DEBUG_REG(num)				\
int ptrace_set_dr##num(struct ptrace_context *p,			\
                       ptrace_x86_register_t dr##num)			\
{									\
	struct ptrace_debug_registers regs;				\
									\
	if (ptrace_get_debug_registers(p, &regs) == -1)			\
		return -1;						\
									\
	regs.dr##num = dr##num;						\
									\
	if (ptrace(PT_SETDBREGS, p->tid, (caddr_t)&regs, NULL) == -1) {	\
		PTRACE_ERR_SET_EXTERNAL(p);				\
		return -1;						\
	}								\
									\
	return 0;							\
}

/* Define all register accessor functions */
DEFINE_PTRACE_GET_REG(eax)
DEFINE_PTRACE_GET_REG(ebx)
DEFINE_PTRACE_GET_REG(ecx)
DEFINE_PTRACE_GET_REG(edx)
DEFINE_PTRACE_GET_REG(esi)
DEFINE_PTRACE_GET_REG(edi)
DEFINE_PTRACE_GET_REG(esp)
DEFINE_PTRACE_GET_REG(ebp)
DEFINE_PTRACE_GET_REG(eip)
DEFINE_PTRACE_GET_REG(eflags)

DEFINE_PTRACE_SET_REG(eax)
DEFINE_PTRACE_SET_REG(ebx)
DEFINE_PTRACE_SET_REG(ecx)
DEFINE_PTRACE_SET_REG(edx)
DEFINE_PTRACE_SET_REG(esi)
DEFINE_PTRACE_SET_REG(edi)
DEFINE_PTRACE_SET_REG(esp)
DEFINE_PTRACE_SET_REG(ebp)
DEFINE_PTRACE_SET_REG(eip)
DEFINE_PTRACE_SET_REG(eflags)

/* Define all segment register accessor functions */
DEFINE_PTRACE_GET_SEG_REG(cs)
DEFINE_PTRACE_GET_SEG_REG(ds)
DEFINE_PTRACE_GET_SEG_REG(es)
DEFINE_PTRACE_GET_SEG_REG(fs)
DEFINE_PTRACE_GET_SEG_REG(gs)
DEFINE_PTRACE_GET_SEG_REG(ss)

DEFINE_PTRACE_SET_SEG_REG(cs)
DEFINE_PTRACE_SET_SEG_REG(ds)
DEFINE_PTRACE_SET_SEG_REG(es)
DEFINE_PTRACE_SET_SEG_REG(fs)
DEFINE_PTRACE_SET_SEG_REG(gs)
DEFINE_PTRACE_SET_SEG_REG(ss)

DEFINE_PTRACE_GET_DEBUG_REG(0)
DEFINE_PTRACE_GET_DEBUG_REG(1)
DEFINE_PTRACE_GET_DEBUG_REG(2)
DEFINE_PTRACE_GET_DEBUG_REG(3)
DEFINE_PTRACE_GET_DEBUG_REG(6)
DEFINE_PTRACE_GET_DEBUG_REG(7)

DEFINE_PTRACE_SET_DEBUG_REG(0)
DEFINE_PTRACE_SET_DEBUG_REG(1)
DEFINE_PTRACE_SET_DEBUG_REG(2)
DEFINE_PTRACE_SET_DEBUG_REG(3)
DEFINE_PTRACE_SET_DEBUG_REG(6)
DEFINE_PTRACE_SET_DEBUG_REG(7)
