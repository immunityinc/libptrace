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
 * mmap.c
 *
 * libptrace windows memory map implementation.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 * Author: Massimiliano Oldani <max@immunityinc.com>
 * Author: Roderick Asselineau <roderick@immunityinc.com>
 *
 */
#include <assert.h>
#include <windows.h>
#include <libptrace/log.h>
#include <libptrace/windows/error.h>
#include "../mmap.h"
#include "process.h"
#include "wrappers/kernel32.h"

INTERVAL_TREE_DECLARE_C(mmap, struct pt_mmap_area, node, start_, end_);

void pt_mmap_init(struct pt_mmap *pm)
{
	interval_tree_mmap_init_tree(&pm->t);
}

void pt_mmap_destroy(struct pt_mmap *pm)
{
	struct pt_mmap_area *area;

	pt_mmap_for_each_area(pm, area)
	        pt_mmap_area_delete(pm,area);
}

void pt_mmap_area_init(struct pt_mmap_area *area)
{
	area->start_ = 0;
	area->end_   = 0;
	area->flags  = 0;
	interval_tree_mmap_init_node(area);
}

void pt_mmap_area_destroy(struct pt_mmap *pm, struct pt_mmap_area *area)
{
	interval_tree_mmap_delete(&pm->t, area);
}

struct pt_mmap_area *pt_mmap_area_new(void)
{
	struct pt_mmap_area *area;

	if ( (area = malloc(sizeof *area)) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	pt_mmap_area_init(area);
	return area;
}

void pt_mmap_delete(struct pt_mmap *pm)
{
	assert(pm != NULL);

	pt_mmap_destroy(pm);
	free(pm);
}

struct pt_mmap *pt_mmap_new(void)
{
	struct pt_mmap *pm;

	if ( (pm = malloc(sizeof *pm)) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	pt_mmap_init(pm);
	return pm;
}

void pt_mmap_area_delete(struct pt_mmap *pm, struct pt_mmap_area *area)
{
	assert(pm != NULL);
	assert(area != NULL);

	pt_mmap_area_destroy(pm, area);
	free(area);
}

void pt_mmap_add_area(struct pt_mmap *pm, struct pt_mmap_area *area)
{
	interval_tree_mmap_insert(&pm->t, area);
}

struct pt_mmap_area *pt_mmap_find_area_from_address(struct pt_mmap *pm, unsigned long addr)
{
	struct pt_mmap_area *area;
	area = interval_tree_mmap_find(&pm->t, addr, addr);
	return area;
}

struct pt_mmap_area *pt_mmap_find_all_area_from_address_start(struct pt_mmap *pm, unsigned long addr)
{
	struct pt_mmap_area *area;
	area = interval_tree_mmap_find_start(&pm->t, addr, addr);
	return area;
}

struct pt_mmap_area *pt_mmap_find_all_area_from_address_next(void)
{
	struct pt_mmap_area *area;
	area = interval_tree_mmap_find_next();
	return area;
}

struct pt_mmap_area *pt_mmap_find_area_from_range(struct pt_mmap *pm, unsigned long begin, unsigned long end)
{
	struct pt_mmap_area *area;
	area = interval_tree_mmap_find(&pm->t, begin, end);
	return area;
}

struct pt_mmap_area *pt_mmap_find_all_area_from_range_start(struct pt_mmap *pm, unsigned long begin, unsigned long end)
{
	struct pt_mmap_area *area;
	area = interval_tree_mmap_find_start(&pm->t, begin, end);
	return area;
}

struct pt_mmap_area *pt_mmap_find_all_area_from_range_next(void)
{
	struct pt_mmap_area *area;

	area = interval_tree_mmap_find_next();
	return area;
}

struct pt_mmap_area *pt_mmap_find_exact_area(struct pt_mmap *pm, unsigned long begin, unsigned long end)
{
	struct pt_mmap_area *area;
	area = interval_tree_mmap_find_exact(&pm->t, begin, end);
	return area;
}

static int translate_protection_(DWORD protect)
{
	switch (protect) {
	case PAGE_EXECUTE:
		return PT_VMA_PROT_EXEC;
	case PAGE_EXECUTE_READ:
		return PT_VMA_PROT_READ | PT_VMA_PROT_EXEC;
	case PAGE_EXECUTE_READWRITE:
	case PAGE_EXECUTE_WRITECOPY:
		return PT_VMA_PROT_READ | PT_VMA_PROT_WRITE;
	case PAGE_NOACCESS:
		return 0;
	case PAGE_READONLY:
		return PT_VMA_PROT_READ;
	case PAGE_READWRITE:
	case PAGE_WRITECOPY:
		return PT_VMA_PROT_READ | PT_VMA_PROT_WRITE;
	}

	return 0;
}

int pt_mmap_load(struct pt_process *process)
{
	MEMORY_BASIC_INFORMATION mbi;
	struct pt_mmap_area *area;
	uint8_t *start = NULL;
	size_t ret;

	/* Destroy the old memory map of the process. */
	pt_mmap_destroy(&process->mmap);

	do {
		ret = pt_windows_api_virtual_query_ex(
			pt_windows_process_handle_get(process),
			start,
			&mbi,
			sizeof mbi
		);

		/* An invalid parameter shows there are no more regions to
		 * iterate over.  Anything else is a real error.
		 */
		if (ret == 0) {
			if (pt_windows_error_winapi_test(ERROR_INVALID_PARAMETER))
				break;
			else
				goto out_err;
		}

		start += mbi.RegionSize;

		if (mbi.State == MEM_FREE)
			continue;

#ifndef NDEBUG
		printf("BaseAddress: %p\n", mbi.BaseAddress);
		printf("AllocationBase: %p\n", mbi.AllocationBase);
		printf("RegionSize: %u\n", mbi.RegionSize);
		printf("State: %x\n", mbi.State);
		printf("Type: %x\n\n", mbi.Type);
#endif
		/* Translate the mmap area and add it to the mmap region. */
		if ( (area = pt_mmap_area_new()) == NULL)
			goto out_err;

		/* Set up the area descriptor. */
		area->start_ = (uintptr_t)mbi.BaseAddress;
		area->end_   = (uintptr_t)mbi.BaseAddress+mbi.RegionSize;
		area->flags |= translate_protection_(mbi.Protect);

		/* And add it to the process memory map. */
		pt_mmap_add_area(&process->mmap, area);
	} while (1);

	return 0;

out_err:
	pt_mmap_destroy(&process->mmap);
	return -1;
}
