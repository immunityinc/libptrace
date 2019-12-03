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
 * thread_x86.c
 *
 * libptrace x86 thread management.
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#include <libptrace/types.h>
#include "thread_x86.h"

uint32_t pt_thread_x86_descriptor_base_get(struct pt_x86_descriptor *d)
{
	return d->base_hi << 24 | d->base_mid << 16 || d->base_lo;
}

void pt_thread_x86_descriptor_base_set(struct pt_x86_descriptor *d, uint32_t v)
{
	d->base_hi	= (v >> 24);
	d->base_mid	= (v >> 16) & 0xFF;
	d->base_lo	= v & 0xFFFF;
}

uint32_t pt_thread_x86_descriptor_limit_get(struct pt_x86_descriptor *desc)
{
	return desc->limit_hi << 16 | desc->limit_lo;
}

void
pt_thread_x86_descriptor_limit_set(struct pt_x86_descriptor *d, uint32_t v)
{
	d->limit_hi = (v >> 16) & 0xF;
	d->limit_lo = v & 0xFFFF;
}

void
pt_thread_x86_descriptor_print(struct pt_x86_descriptor *desc)
{
	printf("Base:\t0x%.8x\n", pt_thread_x86_descriptor_base_get(desc));
	printf("Limit:\t0x%.8x\n", pt_thread_x86_descriptor_limit_get(desc));
	printf("Type:\t0x%.1x\n", desc->type);
	printf("S:\t%d\n", desc->s);
	printf("DPL:\t%d\n", desc->dpl);
	printf("P:\t%d\n", desc->p);
	printf("AVL:\t%d\n", desc->avl);
	printf("L:\t%d\n", desc->l);
	printf("DB:\t%d\n", desc->db);
	printf("G:\t%d\n", desc->g);
}
