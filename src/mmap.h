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
 * mmap.h
 *
 * libptrace memory map definitions.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 * Author: Roderick Asselineau <roderick@immunityinc.com>
 *
 */
#ifndef __LIBPTRACE_MMAP_H
#define __LIBPTRACE_MMAP_H

#include <stdint.h>
#include "interval_tree.h"

#define PT_VMA_PROT_READ	1
#define PT_VMA_PROT_WRITE	2
#define PT_VMA_PROT_EXEC	4

struct pt_process;

struct pt_mmap_area
{
	uintptr_t  _start;
	uintptr_t  _end;
	int        flags;

	struct interval_tree_node node;
};

INTERVAL_TREE_DECLARE_H(mmap, struct pt_mmap_area, node, _start, _end);

struct pt_mmap
{
	struct interval_tree t;
};

#define pt_mmap_for_each_area(_p, _t) \
        for(_t = interval_tree_mmap_start(&((_p)->t)); _t; _t = interval_tree_mmap_next())

struct pt_mmap *pt_mmap_new(void);
void pt_mmap_init(struct pt_mmap *);
void pt_mmap_destroy(struct pt_mmap *);
void pt_mmap_delete(struct pt_mmap *);
void pt_mmap_add_area(struct pt_mmap *, struct pt_mmap_area *);

void pt_mmap_area_init(struct pt_mmap_area *);
void pt_mmap_area_destroy(struct pt_mmap *, struct pt_mmap_area *);
struct pt_mmap_area *pt_mmap_area_new(void);
void pt_mmap_area_delete(struct pt_mmap *, struct pt_mmap_area *);

struct pt_mmap_area *pt_mmap_find_exact_area(struct pt_mmap *, unsigned long, unsigned long);

struct pt_mmap_area *pt_mmap_find_area_from_address(struct pt_mmap *, unsigned long);
struct pt_mmap_area *pt_mmap_find_all_area_from_address_start(struct pt_mmap *, unsigned long);
struct pt_mmap_area *pt_mmap_find_all_area_from_address_next(void);

struct pt_mmap_area *pt_mmap_find_area_from_range(struct pt_mmap *, unsigned long, unsigned long);
struct pt_mmap_area *pt_mmap_find_all_area_from_range_start(struct pt_mmap *, unsigned long, unsigned long);
struct pt_mmap_area *pt_mmap_find_all_area_from_range_next(void);

int pt_mmap_flags_supported(struct pt_process *);

int pt_mmap_load(struct pt_process *);

#endif
