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
 * types.h
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_TYPES_H
#define PT_TYPES_H

#include <stdint.h>

#define PT_ADDRESS_INIT(l, v)						\
	{ .value = (v), .length = (l) }

#define PT_ADDRESS_NULL ((uintptr_t)0)

/* Abstract registers and addresses will be represented as this type, as they
 * need to be stored in a portable manner where both the value and the size of
 * the original register need to be preserved.
 *
 * This will be used in functions such as pt_thread_get_pc() which returns
 * the program counter, no matter if it is 16-bit, 32-bit, or 128-bit in
 * size.  Additionally, as for remote debugging the debugger needs to handle
 * address space sizes of the debuggee, it is used for address encoding.
 *
 * The length is stored in bits, to account for odd architectures that use
 * register sizes not a multiple of bytes.  For instance a 32-bit architecture
 * using a 33-rd carry bit or sign bit.
 *
 * A function returning a pt_integer_t with a length of 0 indicates an error.
 *
 * XXX: Currently limited by a 64-bit maximum size.
 */
typedef uintptr_t	pt_address_t;
typedef uintptr_t	pt_register_t;

typedef uint32_t	pt_pid_t;
typedef uint32_t	pt_tid_t;

#ifdef __cplusplus
extern "C" {
#endif

char *pt_address_sprintf(pt_address_t address);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_TYPES_H */
