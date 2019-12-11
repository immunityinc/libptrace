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
 * breakpoint_x86.c
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 */
#include <libptrace/log.h>
#include <libptrace/error.h>
#include <libptrace/breakpoint_x86.h>

static inline int translate_size_(int dr_size)
{
	switch (dr_size) {
	case X86_DR_SIZE_1:
		return 1;
	case X86_DR_SIZE_2:
		return 2;
	case X86_DR_SIZE_4:
		return 4;
	case X86_DR_SIZE_8:
		return 8;
	}

	return -1;
}

void x86_debug_registers_init(struct x86_debug_registers *ctx)
{
	int i;

	list_init(&ctx->free);

	/* Init all registers and add them to the free list. */
	for (i = 0; i < 4; i++) {
		ctx->regs[i].address = 0;
		ctx->regs[i].scope = X86_DR_SCOPE_NONE;
		ctx->regs[i].type = 0;
		ctx->regs[i].size = 0;
		ctx->regs[i].used = 0;
		ctx->regs[i].handler = NULL;
		ctx->regs[i].cookie = NULL;
		list_add(&ctx->regs[i].list, &ctx->free);
	}
}

/* address:type specify a unique debug regiser.  Only address is not enough,
 * as we can have exec and rw triggers on the same address.
 */
struct x86_debug_register *
x86_debug_register_find(struct x86_debug_registers *ctx, pt_address_t address, int type)
{
	int size;
	int i;

	for (i = 0; i < 4; i++) {
		if (ctx->regs[i].used == 0)
			continue;

		size = translate_size_(ctx->regs[i].size);
		if (ctx->regs[i].type == type &&
		    ctx->regs[i].address <= (uintptr_t)address &&
		    ctx->regs[i].address + size > (uintptr_t)address)
			return &ctx->regs[i];
	}

	pt_error_internal_set(PT_ERROR_NOT_FOUND);
	return NULL;
}

struct x86_debug_register *
x86_debug_register_alloc(struct x86_debug_registers *ctx)
{
	struct x86_debug_register *reg;

	/* Make sure we have a free entry available. */
	if (list_empty(&ctx->free))
		return NULL;

	/* Unlink the entry from the free list. */
	reg = list_entry(ctx->free.next, struct x86_debug_register, list);
	list_del(&reg->list);
	reg->used = 1;

	return reg;
}

void x86_debug_register_free(struct x86_debug_registers *ctx, struct x86_debug_register *reg)
{
	reg->address = 0;
	reg->scope = X86_DR_SCOPE_NONE;
	reg->type = 0;
	reg->size = 0;
	reg->used = 0;
	reg->handler = NULL;
	reg->cookie = NULL;
	list_add(&reg->list, &ctx->free);
}

int x86_debug_register_set(struct x86_debug_registers *regs, int scope, int type, uint32_t address, int size,
	x86_dr_handler_t handler, void *cookie)
{
	struct x86_debug_register *reg;

	/* Sanity check the parameters we got. */
	if (size != X86_DR_SIZE_1 && size != X86_DR_SIZE_2 &&
	    size != X86_DR_SIZE_4 && size != X86_DR_SIZE_8) {
		pt_error_internal_set(PT_ERROR_INVALID_ARG);
		pt_log("%s(): invalid size %d\n", __FUNCTION__, size);
		return -1;
	}

	if (type != X86_DR_TYPE_EXEC && type != X86_DR_TYPE_WRITE &&
	    type != X86_DR_TYPE_IO && type != X86_DR_TYPE_RW) {
		pt_error_internal_set(PT_ERROR_INVALID_ARG);
		pt_log("%s(): invalid type %d\n", __FUNCTION__, type);
		return -1;
	}

	if (scope != X86_DR_SCOPE_LOCAL && scope != X86_DR_SCOPE_GLOBAL) {
		pt_error_internal_set(PT_ERROR_INVALID_ARG);
		pt_log("%s(): invalid scope %d\n", __FUNCTION__, scope);
		return -1;
	}

	/* See if we have a free debug register slot available. */
	if ( (reg = x86_debug_register_alloc(regs)) == NULL) {
		pt_error_internal_set(PT_ERROR_RESOURCE_LIMIT);
		pt_log("%s(): no free debug registers\n", __FUNCTION__);
		return -1;
	}

	reg->address = address;
	reg->scope = scope;
	reg->type = type;
	reg->size = size;

	return 0;
}
