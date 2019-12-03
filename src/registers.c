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
 * registers.c
 *
 * libptrace register management.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include "registers.h"

int pt_registers_i386_print(struct pt_registers_i386 *regs)
{
	int total = 0;
	int ret;

	if ( (ret = printf("eax: 0x%.8"PRIx32"\n", regs->eax)) != -1)
		total += ret;

	if ( (ret = printf("ebx: 0x%.8"PRIx32"\n", regs->ebx)) != -1)
		total += ret;

	if ( (ret = printf("ecx: 0x%.8"PRIx32"\n", regs->ecx)) != -1)
		total += ret;

	if ( (ret = printf("edx: 0x%.8"PRIx32"\n", regs->edx)) != -1)
		total += ret;

	if ( (ret = printf("esi: 0x%.8"PRIx32"\n", regs->esi)) != -1)
		total += ret;

	if ( (ret = printf("edi: 0x%.8"PRIx32"\n", regs->edi)) != -1)
		total += ret;

	if ( (ret = printf("esp: 0x%.8"PRIx32"\n", regs->esp)) != -1)
		total += ret;

	if ( (ret = printf("ebp: 0x%.8"PRIx32"\n", regs->ebp)) != -1)
		total += ret;

	if ( (ret = printf("eip: 0x%.8"PRIx32"\n", regs->eip)) != -1)
		total += ret;

	if ( (ret = printf("cs: 0x%.4"PRIx16"\n", regs->cs)) != -1)
		total += ret;

	if ( (ret = printf("ds: 0x%.4"PRIx16"\n", regs->ds)) != -1)
		total += ret;

	if ( (ret = printf("es: 0x%.4"PRIx16"\n", regs->es)) != -1)
		total += ret;

	if ( (ret = printf("fs: 0x%.4"PRIx16"\n", regs->fs)) != -1)
		total += ret;

	if ( (ret = printf("gs: 0x%.4"PRIx16"\n", regs->gs)) != -1)
		total += ret;

	if ( (ret = printf("ss: 0x%.4"PRIx16"\n", regs->ss)) != -1)
		total += ret;

	if ( (ret = printf("eflags: 0x%.8"PRIx32"\n", regs->eflags)) != -1)
		total += ret;

	if ( (ret = printf("dr0: 0x%.8"PRIx32"\n", regs->dr0)) != -1)
		total += ret;

	if ( (ret = printf("dr1: 0x%.8"PRIx32"\n", regs->dr1)) != -1)
		total += ret;

	if ( (ret = printf("dr2: 0x%.8"PRIx32"\n", regs->dr2)) != -1)
		total += ret;

	if ( (ret = printf("dr3: 0x%.8"PRIx32"\n", regs->dr3)) != -1)
		total += ret;

	if ( (ret = printf("dr6: 0x%.8"PRIx32"\n", regs->dr6)) != -1)
		total += ret;

	if ( (ret = printf("dr7: 0x%.8"PRIx32"\n", regs->dr7)) != -1)
		total += ret;

	return total;
}


int pt_registers_get_size(struct pt_registers *regs)
{
	assert(regs->type == PT_REGISTERS_I386);
	switch (regs->type) {
	case PT_REGISTERS_I386:
		return sizeof(struct pt_registers_i386);
	}

	return 0;
}

int pt_registers_print(struct pt_registers *regs)
{
	assert(regs->type == PT_REGISTERS_I386);
	switch (regs->type) {
	case PT_REGISTERS_I386:
		return pt_registers_i386_print((struct pt_registers_i386 *)regs);
	}

	return 0;
}
