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
 * process.c
 *
 * libptrace process management.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <stdarg.h>
#include <libptrace/log.h>
#include <libptrace/error.h>
#include "breakpoint.h"
#include "core.h"
#include "event.h"
#include "process.h"
#include "module.h"
#include "thread.h"

int thread_avl_compare_(struct avl_node *a, struct avl_node *b_);

/** Initializes the process using the native interface for this build. */
int pt_process_init(struct pt_process *process)
{
	process->pid                = -1;
	process->private_data       = NULL;
	process->state              = PT_PROCESS_STATE_INIT;
	process->remote_break_count = 0;
	process->options            = PT_PROCESS_OPTION_NONE;
	process->creation_time      = 0;
	process->main_thread        = NULL;
	process->main_module        = NULL;
	process->p_op               = NULL;
	process->core               = NULL;
	process->smgr               = NULL;
	process->remote_break_addr  = PT_ADDRESS_NULL;
	process->super_             = NULL;

	INIT_AVL_TREE(&process->threads, thread_avl_compare_);
	list_init(&process->modules);
	INIT_AVL_TREE(&process->breakpoints, breakpoint_avl_compare_);
	pt_mmap_init(&process->mmap);
	pt_event_handlers_internal_init(&process->handlers);

	return 0;
}

int pt_process_destroy(struct pt_process *process)
{
	struct pt_breakpoint_internal *bp;
	struct pt_module *module;
	struct pt_thread *thread;

	assert(process != NULL);
	assert(process->p_op != NULL);

	if (process->p_op->destroy != NULL &&
	    process->p_op->destroy(process) == -1)
		return -1;

	/* Free the handler functions we had allocated. */
	pt_event_handlers_internal_destroy(&process->handlers);

	/* Remove all breakpoints. */
	pt_process_for_each_breakpoint_internal (process, bp)
		bp->breakpoint->b_op->process_remove(process, bp);

	/* Free all threads we tracked. */
	pt_process_for_each_thread (process, thread)
		pt_thread_delete(thread);

	/* Free all modules we tracked. */
	pt_process_for_each_module (process, module)
		pt_module_delete(module);

	/* Free the memory map. */
	pt_mmap_destroy(&process->mmap);

	if (process->core != NULL)
		avl_tree_delete(&process->core->process_tree, &process->avl_node);

	return 0;
}

int pt_process_delete(struct pt_process *process)
{
	if (pt_process_destroy(process) == -1)
		return -1;
	free(process);
	return 0;
}

/* Can be called from other threads to interrupt the pt_main loop. */
int pt_process_brk(struct pt_process *process)
{
	if (process->p_op->brk == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	return process->p_op->brk(process);
}

int pt_process_option_set(struct pt_process *process, int option)
{
	switch (option) {
	case PT_PROCESS_OPTION_EVENT_SECOND_CHANCE:
		process->options |= option;
		break;
	default:
		return -1;
	}

	return 0;
}


ssize_t
pt_process_read(struct pt_process *process, void *dst,
                const pt_address_t src, size_t size)
{
	if (process->p_op->read == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	return process->p_op->read(process, dst, src, size);
}

int pt_process_suspend(struct pt_process *process)
{
	if (process->p_op->suspend == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	return process->p_op->suspend(process);
}

int pt_process_resume(struct pt_process *process)
{
	if (process->p_op->resume == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	return process->p_op->resume(process);
}

int
pt_process_write(struct pt_process *process, pt_address_t dst,
                 const void *src, size_t size)
{
	if (process->p_op->write == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	return process->p_op->write(process, dst, src, size);
}

int pt_process_thread_create(struct pt_process *process,
                             pt_address_t handler, pt_address_t cookie)
{
	if (process->p_op->thread_create == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	return process->p_op->thread_create(process, handler, cookie);
}

pt_address_t pt_process_malloc(struct pt_process *process, size_t size)
{
	if (process->p_op->malloc == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return PT_ADDRESS_NULL;
	}

	return process->p_op->malloc(process, size);
}

int pt_process_free(struct pt_process *process, pt_address_t p)
{
	if (process->p_op->free == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return -1;
	}

	return process->p_op->free(process, p);
}

/** Retrieve the length of a C-style string from a remote process.
 *
 * Retrieves the length of a 0-terminated C-style string from a remote
 * process.
 *
 * \param pctx Pointer to the ptrace_context of the traced thread.
 * \param string Pointer to the location of the string in the remote process.
 * \param size Pointer to the size_t which will hold the string length.
 *
 * \return 0 on success, -1 on failure.
 */
int
pt_process_strlen(struct pt_process *pctx, const pt_address_t src, size_t *size)
{
	size_t length = 0;
	char byte;

	do {
		if (pt_process_read(pctx, &byte, src + length, 1) == -1)
			return -1;
		length++;
	} while (byte != 0);

	*size = length - 1;
	return 0;
}

int
pt_process_strlen16(struct pt_process *pctx, const pt_address_t src, size_t *size)
{
	size_t length = 0;
	uint16_t ch;

	do {
		if (pt_process_read(pctx, &ch, src + length, 2) == -1)
			return -1;
		length += 2;
	} while (ch != 0);

	*size = (length - 2) / 2;
	return 0;
}

/** Read a C-style string from a remote process.
 *
 * Retrieves a 0-terminated C-style string from a remote process.  The
 * memory to hold this string is dynamically allocated and needs to be
 * free()d by the caller.
 *
 * The result will always be 0-terminated.
 *
 * \param pctx Pointer to the pt_process of the traced process.
 * \param src Pointer to the location of the string in the remote process.
 *
 * \return Pointer to the allocated string on success, NULL on failure.
 */
utf8_t *
pt_process_read_string(struct pt_process *pctx, const pt_address_t src)
{
	utf8_t *string;
	size_t i;

	if (pt_process_strlen(pctx, src, &i) == -1)
		return NULL;

	if ( (string = malloc(i + 1)) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	if (pt_process_read(pctx, string, src, i + 1) == -1) {
		free(string);
		return NULL;
	}

	return string;
}

static utf16_t *
pt_process_read_string_utf16_(struct pt_process *pctx, const pt_address_t src)
{
	utf16_t *utf16;
	size_t i;

	if (pt_process_strlen16(pctx, src, &i) == -1)
		return NULL;

	if ( (utf16 = malloc((i + 1) * 2)) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	if (pt_process_read(pctx, utf16, src, (i + 1) * 2) == -1) {
		free(utf16);
		return NULL;
	}

	return utf16;
}

utf8_t *
pt_process_read_string_utf16(struct pt_process *pctx, const pt_address_t src)
{
	utf16_t *utf16_s = pt_process_read_string_utf16_(pctx, src);
	utf8_t *utf8_s;

	if (utf16_s == NULL)
		return NULL;

	utf8_s = pt_utf16_to_utf8(utf16_s);
	free(utf16_s);

	return utf8_s;
}

int pt_process_breakpoint_remove(struct pt_process *process,
                                 struct pt_breakpoint *bp)
{
	struct pt_breakpoint_internal *bpi;
	pt_address_t address = bp->address;
	char *symbol = bp->symbol;

	assert(process != NULL);
	assert(bp != NULL);
	assert(bp->b_op != NULL);

	pt_log("%s(0x%p, 0x%p)\n", __FUNCTION__, process, bp);

	/* If this is a breakpoint on a symbol, we resolve it now. */
	if (symbol != NULL) {
		address = pt_process_export_find(process, symbol);
		if (address == PT_ADDRESS_NULL) {
			pt_log("%s(): failed to resolve symbol %s\n", __FUNCTION__, symbol);
			return -1;
		}
	}

	/* Do not allow multiple breakpoints on the same address. */
	bpi = pt_process_breakpoint_find_internal(process, address);
	if (bpi == NULL) {
		pt_log("%s(): breakpoint does not exist -- returning -1\n", __FUNCTION__);
		return -1;
	}

	return bp->b_op->process_remove(process, bpi);
}

int pt_process_breakpoint_set(struct pt_process *process,
                              struct pt_breakpoint *bp)
{
	struct pt_breakpoint_internal *bpi;
	pt_address_t address = bp->address;
	char *symbol = bp->symbol;
	int ret;

	assert(process != NULL);
	assert(bp != NULL);
	assert(bp->b_op != NULL);

	pt_log("%s(0x%p, 0x%p)\n", __FUNCTION__, process, bp);

	/* If this is a breakpoint on a symbol, we resolve it now. */
	if (symbol != NULL) {
		pt_log("%s(): resolving symbol %s\n", __FUNCTION__, symbol);
		address = pt_process_export_find(process, symbol);
		if (address == PT_ADDRESS_NULL) {
			pt_log("%s(): failed to resolve symbol %s: %s\n",
			       __FUNCTION__, symbol, pt_error_strerror());
			return -1;
		}
		pt_log("%s(): resolved symbol %s to 0x%.8x\n", __FUNCTION__, symbol, address);
	}

	/* Do not allow multiple breakpoints on the same address. */
	if (pt_process_breakpoint_find(process, address) != NULL) {
		pt_error_internal_set(PT_ERROR_EXISTS);
		pt_log("%s(): breakpoint exists -- returning -1\n", __FUNCTION__);
		return -1;
	}

	/* Allocate our new per process breakpoint structure. */
	if ( (bpi = malloc(sizeof *bpi)) == NULL) {
		pt_error_errno_set(errno);
		return -1;
	}

	/* And fill in the resolved address. */
	bpi->address = address;
	bpi->breakpoint = bp;

	if ( (ret = bp->b_op->process_set(process, bpi)) == 0)
		avl_tree_insert(&process->breakpoints, &bpi->avl_node);
	else
		free(bp);

	pt_log("%s(): returning %d\n", __FUNCTION__, ret);
	return ret;
}

int
process_read_uint32(struct pt_process *process,
                    uint32_t *dest, const pt_address_t src)
{
	uint32_t dummy;

	if (pt_process_read(process, &dummy, src, sizeof(uint32_t)) == -1)
		return -1;

	*dest = dummy;
	return 0;
}

struct pt_thread *
pt_process_thread_find(struct pt_process *process, pt_pid_t tid)
{
	struct pt_thread *thread;

	pt_process_for_each_thread (process, thread) {
		if (thread->tid == tid)
			return thread;
	}

	return NULL;
}

/* Sees if this process has an internal on address. */
struct pt_breakpoint_internal *
pt_process_breakpoint_find_internal(struct pt_process *process, pt_address_t address)
{
	struct avl_node *an;

	an = process->breakpoints.root;
	while (an != NULL) {
		struct pt_breakpoint_internal *bp;

		bp = container_of(an, struct pt_breakpoint_internal, avl_node);
		if (bp->address == address)
                        return bp;

		if (bp->address > address)
			an = an->left;
		else
			an = an->right;
	}

	pt_error_internal_set(PT_ERROR_NOT_FOUND);
        return NULL;
}

struct pt_breakpoint *
pt_process_breakpoint_find(struct pt_process *process, pt_address_t address)
{
	struct pt_breakpoint_internal *breakpoint;

	breakpoint = pt_process_breakpoint_find_internal(process, address);
	if (breakpoint == NULL)
		return NULL;

	return breakpoint->breakpoint;
}

pt_pid_t pt_process_pid_get(struct pt_process *process)
{
	return process->pid;
}

struct pt_module *pt_process_main_module_get(struct pt_process *process)
{
	return process->main_module;
}

struct pt_thread *pt_process_main_thread_get(struct pt_process *process)
{
	return process->main_thread;
}
