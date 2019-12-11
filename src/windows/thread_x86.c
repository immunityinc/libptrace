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
 * libptrace windows x86 thread management.
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <windows.h>
#include <ntdef.h>
#include "compat.h"
#include "../thread_x86.h"
#include "process.h"
#include "thread.h"

static inline void
x86_descriptor_translate_(struct pt_x86_descriptor *desc, LDT_ENTRY *entry)
{
	assert(desc != NULL);
	assert(entry != NULL);

	desc->base_mid	= entry->HighWord.Bits.BaseMid;
	desc->type	= entry->HighWord.Bits.Type;
	desc->s		= entry->HighWord.Bits.Type & 0x10;
	desc->dpl	= entry->HighWord.Bits.Dpl;
	desc->p		= entry->HighWord.Bits.Pres;
	desc->limit_hi	= entry->HighWord.Bits.LimitHi;
	desc->avl	= entry->HighWord.Bits.Sys;
	desc->l		= entry->HighWord.Bits.Reserved_0;
	desc->db	= entry->HighWord.Bits.Default_Big;
	desc->g		= entry->HighWord.Bits.Granularity;
	desc->base_hi	= entry->HighWord.Bits.BaseHi;
	desc->limit_lo	= entry->LimitLow;
	desc->base_lo	= entry->BaseLow;
}

static inline void
x86_descriptor_to_ldt_(struct pt_x86_descriptor *desc, LDT_ENTRY *entry)
{
	assert(desc != NULL);
	assert(entry != NULL);

	entry->HighWord.Bits.BaseMid		= desc->base_mid;
	entry->HighWord.Bits.Type		= desc->type;
	entry->HighWord.Bits.Type		|= desc->s << 4;
	entry->HighWord.Bits.Dpl		= desc->dpl;
	entry->HighWord.Bits.Pres		= desc->p;
	entry->HighWord.Bits.LimitHi		= desc->limit_hi;
	entry->HighWord.Bits.Sys		= desc->avl;
	entry->HighWord.Bits.Reserved_0		= desc->l;
	entry->HighWord.Bits.Default_Big	= desc->db;
	entry->HighWord.Bits.Granularity	= desc->g;
	entry->HighWord.Bits.BaseHi		= desc->base_hi;
	entry->LimitLow				= desc->limit_lo;
	entry->BaseLow				= desc->base_lo;
}

int pt_thread_x86_ldt_entry_get(struct pt_thread *thread,
                                struct pt_x86_descriptor *descriptor,
                                int index)
{
	HANDLE h = pt_windows_thread_handle_get(thread);
	LDT_ENTRY entry;
	BOOL ret;

	assert(thread != NULL);
	assert(descriptor != NULL);

	ret = GetThreadSelectorEntry(h, index << 3 | 7, &entry);
	if (ret == 0)
		return -1;

	x86_descriptor_translate_(descriptor, &entry);

	return 0;
}

int pt_thread_x86_ldt_entry_set(struct pt_thread *thread,
                                struct pt_x86_descriptor *descriptor,
                                int index)
{
	struct {
		DWORD		selector;
		DWORD		size;
		LDT_ENTRY	entry;
	} __attribute__((packed)) entry;
	NTSTATUS ret;

	assert(thread != NULL);
	assert(descriptor != NULL);

	/* On Windows we can only set LDT entries through a process handle.
	 * If there is no process descriptor belonging to this thread, we
	 * need to bail out.
	 */
	if (thread->process == NULL)
		return -1;

	/* Initialize the entry structure as ProcessLdtInformation wants it. */
	entry.selector = index << 3;
//	entry.size = 8;
	entry.size = 0;
//	x86_descriptor_to_ldt_(descriptor, &entry.entry);

	ret = NtSetInformationProcess(pt_windows_process_handle_get(thread->process),
	                              ProcessLdtInformation, &entry, sizeof entry);

        if (!NT_SUCCESS(ret))
                return -1;

	return 0;
}


int pt_thread_x86_gdt_entry_get(struct pt_thread *thread,
                                struct pt_x86_descriptor *descriptor,
                                int index)
{
	HANDLE h = pt_windows_thread_handle_get(thread);
	LDT_ENTRY entry;
	BOOL ret;

	assert(thread != NULL);
	assert(descriptor != NULL);

	ret = GetThreadSelectorEntry(h, index << 3, &entry);
	if (ret == 0)
		return -1;

	x86_descriptor_translate_(descriptor, &entry);

	return 0;
}

void pt_windows_x86_ldt_entry_print(LDT_ENTRY *entry)
{
	assert(entry != NULL);

	printf("BaseLow:\t0x%.8x\n", entry->BaseLow);
	printf("LimitLow:\t0x%.8x\n", entry->LimitLow);
	printf("BaseMid:\t0x%.8x\n", entry->HighWord.Bits.BaseMid);
	printf("Type:\t\t%d\n", entry->HighWord.Bits.Type);
	printf("Dpl:\t\t%d\n", entry->HighWord.Bits.Dpl);
	printf("Pres:\t\t%d\n", entry->HighWord.Bits.Pres);
	printf("LimitHi:\t0x%.8x\n", entry->HighWord.Bits.LimitHi);
	printf("Sys:\t\t%d\n", entry->HighWord.Bits.Sys);
	printf("Reserved_0:\t%d\n", entry->HighWord.Bits.Reserved_0);
	printf("Default_Big:\t%d\n", entry->HighWord.Bits.Default_Big);
	printf("Granularity:\t%d\n", entry->HighWord.Bits.Granularity);
	printf("BaseHi:\t\t0x%.8x\n", entry->HighWord.Bits.BaseHi);
}
