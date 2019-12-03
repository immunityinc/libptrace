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
 * libptrace_linux_procfs.h
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>
 *
 */
#ifndef __LIBPTRACE_LINUX_PROCFS_H
#define __LIBPTRACE_LINUX_PROCFS_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include "libptrace_list.h"

#define VM_READ         0x00000001
#define VM_WRITE        0x00000002
#define VM_EXEC         0x00000004
#define VM_SHARED       0x00000008
#define VM_MAYSHARE     0x00000080

struct proc_maps_entry
{
	void			*start;
	void			*end;
	int			flags;
	unsigned long long	offset;
	dev_t			device;
	unsigned long		inode;
	char			*name;

	struct list_head	list;
};

FILE *ptrace_procfs_maps_open(pid_t pid);
FILE *ptrace_procfs_status_open(pid_t pid);
int ptrace_procfs_maps_close(FILE *fp);
void ptrace_procfs_map_entry_destroy(struct proc_maps_entry *entry);
struct proc_maps_entry *ptrace_procfs_maps_read_entry(FILE *fp);
struct list_head *ptrace_procfs_maps_read(FILE *fp, struct list_head *list);
void ptrace_procfs_maps_print_entry(struct proc_maps_entry *entry);
void *ptrace_procfs_maps_find_exec(pid_t pid);
int ptrace_procfs_status_is_stopped(pid_t pid);

#endif
