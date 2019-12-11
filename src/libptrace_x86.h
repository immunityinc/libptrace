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
 * libptrace_x86.h
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_X86_INTERNAL_H
#define PT_X86_INTERNAL_H

#include <stdint.h>

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

#if defined(__i386__)
typedef uint16_t ptrace_x86_seg_register_t;
typedef uint32_t ptrace_x86_register_t;
#elif defined(__x86_64__)
typedef uint16_t ptrace_x86_seg_register_t;
typedef uint64_t ptrace_x86_register_t;
#else
#error "libptrace is not usable with this architecture."
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* This header file defines common functions for all x86 families. */

/* Defined in other header files, but just forward declare it to prevent
 * preprocessing mess.
 */
struct pt_thread;
struct ptrace_context;
struct ptrace_cpu_state;
struct ptrace_fpu_state;
struct ptrace_altstack;
struct ptrace_registers;
struct ptrace_debug_registers;

/* According to the Intel Manual Volume 3 15.2.2:
* <QUOTE>
* Debug registers DR4 and DR5 are reserved when debug extentions are enabled
* (when the DE flag in control register CR4 is set), and attempts to reference
* the DR4 and DR5 registers cause an invalid-opcode exception (#UD) to be
* generated. When debug extentions are not enabled (when the DE flag is
* clear), these registers are aliased to debug registers DR6 and DR7.
* </QUOTE>
*
* On linux we seem to be able to read debug registers DR4 and DR5 through
* using ptrace, but these will always be 0. Attempts to write them result in
* EIO.
* As we're unable to read CR4 without ring0 access, we cannot implement the
* described aliasing in this library. Therefore, we omit functions allowing
* access to DR4 and DR5.
*/
struct ptrace_debug_registers {
       ptrace_x86_register_t dr0;
       ptrace_x86_register_t dr1;
       ptrace_x86_register_t dr2;
       ptrace_x86_register_t dr3;
       ptrace_x86_register_t dr6;
       ptrace_x86_register_t dr7;
};

/* Debug register read functions */
ptrace_x86_register_t ptrace_get_dr0(struct ptrace_context *);
ptrace_x86_register_t ptrace_get_dr1(struct ptrace_context *);
ptrace_x86_register_t ptrace_get_dr2(struct ptrace_context *);
ptrace_x86_register_t ptrace_get_dr3(struct ptrace_context *);
ptrace_x86_register_t ptrace_get_dr6(struct ptrace_context *);
ptrace_x86_register_t ptrace_get_dr7(struct ptrace_context *);

/* Debug register write functions */
int ptrace_set_dr0(struct pt_thread *, ptrace_x86_register_t);
int ptrace_set_dr1(struct pt_thread *, ptrace_x86_register_t);
int ptrace_set_dr2(struct pt_thread *, ptrace_x86_register_t);
int ptrace_set_dr3(struct pt_thread *, ptrace_x86_register_t);
int ptrace_set_dr6(struct pt_thread *, ptrace_x86_register_t);
int ptrace_set_dr7(struct pt_thread *, ptrace_x86_register_t);

/* Floating point registers structure.
 *
 * Note that according to Intel Manual Volume 1 Section 8.1.8 only the
 * last 3 bits of the first opcode byte are stored in the Opcode register,
 * as the first 5 bits are always 11011b.
 *
 * Please note that libptrace adds these 5 bits to the value of 'fop' in the
 * ptrace_fpu_registers structure.
 */
struct ptrace_fpu_registers {
	uint16_t cwd;		/* control word */
	uint16_t swd;		/* status word */
	uint16_t twd;		/* tag word */
	uint16_t foc;		/* last instruction opcode */
	uint32_t fip;		/* last instruction pointer */
	uint16_t fcs;		/* last instruction pointer segment */
	uint32_t fop;		/* last data operand pointer */
	uint16_t fos;		/* last data operand pointer segment */
	uint32_t st_space[20];	/* 8*10 bytes for each FP-reg = 80 bytes */
};

/* MMX registers structure.
 *
 * This is aliased to the FPU register state, but we name the registers
 * explicitly, as they are in fixed locations instead of stack based.
 *
 * This struct simply presents another way to look at the FPU state.
 */
struct ptrace_mmx_registers {
	uint16_t cwd;		/* control word */
	uint16_t swd;		/* status word */
	uint16_t twd;		/* tag word */
	uint16_t foc;		/* last instruction opcode */
	uint32_t fip;		/* last instruction pointer */
	uint16_t fcs;		/* last instruction pointer segment */
	uint32_t fop;		/* last data operand pointer */
	uint16_t fos;		/* last data operand pointer segment */

	uint64_t mm0;		/* MMX registers - MM0 through MM7 */
	uint64_t mm1;
	uint64_t mm2;
	uint64_t mm3;
	uint64_t mm4;
	uint64_t mm5;
	uint64_t mm6;
	uint64_t mm7;

	uint16_t top0;		/* Top 16 bit halves (exponents) */
	uint16_t top1;
	uint16_t top2;
	uint16_t top3;
	uint16_t top4;
	uint16_t top5;
	uint16_t top6;
	uint16_t top7;
};

/* SSE registers structure.
 *
 * This only presents the SSE specific registers, and not the full FPU state.
 */
struct ptrace_sse_registers {
	uint8_t	xmm0[16];	/* SSE registers - XMM0 through XMM7 */
	uint8_t	xmm1[16];
	uint8_t	xmm2[16];
	uint8_t	xmm3[16];
	uint8_t	xmm4[16];
	uint8_t	xmm5[16];
	uint8_t	xmm6[16];
	uint8_t	xmm7[16];
	uint32_t mxcsr;		/* SSE control and status register */
};

/* Alternative stack structure.
 * This is used for easy management of multiple stacks in a remote process.
 */
#define PTRACE_ALTSTACK_NONE	0
#define PTRACE_ALTSTACK_ORIG	1

struct ptrace_altstack {
	void			*base;
	size_t			size;
	ptrace_x86_register_t	stack_ptr;
	ptrace_x86_register_t	base_ptr;
	unsigned int		flags;
};

/* State saving functions.
 *
 * These should not be used for anything but saving and restoring state, as the
 * interfaces can change in the kernel and depending on support for extended
 * FPU data and so on.
 */
int ptrace_save_cpu_state(struct ptrace_context *,
                          struct ptrace_cpu_state *);
int ptrace_load_cpu_state(struct ptrace_context *,
                          struct ptrace_cpu_state *);
int ptrace_save_fpu_state(struct pt_thread *,
                          struct ptrace_fpu_state *);
int ptrace_load_fpu_state(struct pt_thread *,
                          struct ptrace_fpu_state *);

/* The FPU access functions are defined here for now, as an architecture
 * might not have an FPU in the first place.
 */
int ptrace_get_fpu_registers(struct ptrace_context *,
                             struct ptrace_fpu_registers *);
int ptrace_set_fpu_registers(struct ptrace_context *,
                             struct ptrace_fpu_registers *);

int ptrace_get_mmx_registers(struct ptrace_context *,
                             struct ptrace_mmx_registers *);

int ptrace_get_debug_registers(struct ptrace_context *,
                               struct ptrace_debug_registers *);
int ptrace_set_debug_registers(struct ptrace_context *,
                               struct ptrace_debug_registers *);

/* Alternative stack management functions. */
int ptrace_altstack_init(struct ptrace_context *pctx,
                         struct ptrace_altstack *stack, size_t size);
size_t ptrace_altstack_align(size_t size);
int ptrace_altstack_current(struct ptrace_context *pctx,
                            struct ptrace_altstack *stack);
int ptrace_altstack_switch(struct ptrace_context *pctx,
                           struct ptrace_altstack *stack,
                           struct ptrace_altstack *old_stack);
int ptrace_altstack_destroy(struct ptrace_context *pctx,
                           struct ptrace_altstack *stack);

/* Call functions/procedures in the remote process */
int ptrace_call_function(struct ptrace_context *p,
                         void *code, long *retval);
int ptrace_call_procedure(struct ptrace_context *p, void *code);
int ptrace_call_nowait(struct ptrace_context *p, void *code);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_X86_INTERNAL_H */
