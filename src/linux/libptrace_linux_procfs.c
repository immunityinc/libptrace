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
 * libptrace_linux_procfs.c
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>
 *
 */
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/kdev_t.h>
#include "libptrace_wrapper.h"
#include "libptrace_linux_procfs.h"

#define PROC_DIR	"/proc"
#define PROC_MAPS	"maps"
#define PROC_STATUS	"status"

FILE *ptrace_procfs_maps_open(pid_t pid)
{
	char buf[128];

	snprintf(buf, sizeof(buf), PROC_DIR "/%u/" PROC_MAPS, pid);
	return fopen_no_EINTR(buf, "r");
}

FILE *ptrace_procfs_status_open(pid_t pid)
{
	char buf[128];

	snprintf(buf, sizeof(buf), PROC_DIR "/%u/" PROC_STATUS, pid);
	return fopen_no_EINTR(buf, "r");
}

int ptrace_procfs_maps_close(FILE *fp)
{
	return fclose_no_EINTR(fp);
}

static inline void skip_ws(FILE *fp)
{
	while (!feof(fp)) {
		int ch = fgetc(fp);

		if (ch == EOF || (ch != '\t' && ch != ' ')) {
			if (ch != EOF)
				ungetc(ch, fp);
			break;
		}
	}
}

static inline size_t file_strlen(FILE *fp)
{
	register int ch;
	register size_t len = 0;
	long offset = ftell(fp);

	if (offset == -1)
		return -1;

	while ( (ch = fgetc(fp)) != EOF && ch != 0 && ch != '\n')
		len++;

	if (fseek(fp, offset, SEEK_SET) == -1)
		return -1;

	return len;
}

void ptrace_procfs_map_entry_destroy(struct proc_maps_entry *entry)
{
	assert(entry != NULL);

	if (entry->name)
		free(entry->name);

	free(entry);
}

struct proc_maps_entry *
ptrace_procfs_maps_read_entry(FILE *fp)
{
	struct proc_maps_entry *entry;
	unsigned long long offset;
	void *vm_start, *vm_end;
	unsigned long inode;
	int major, minor;
	char flags[5];
	char *name;
	size_t len;
	int ch;

	/* read vma->vm_start and vma->vm_end */
	if (fscanf(fp, "%llx-%llx", &vm_start, &vm_end) != 2)
		return NULL;

	/* read flags */
	if (fscanf(fp, "%4s", flags) != 1)
		return NULL;

	/* read offset */
	if (fscanf(fp, "%llx", &offset) != 1)
		return NULL;

	/* read major and minor into dev_t */
	if (fscanf(fp, "%x:%x", &major, &minor) != 2)
		return NULL;

	/* read the inode */
	if (fscanf(fp, "%lu", &inode) != 1)
		return NULL;

	/* Finally we will read the filename, but this one is dynamic in
	 * length, so we process the file twice.
	 */
	skip_ws(fp);

	if ( (len = file_strlen(fp)) == -1)
		return NULL;

	if ( (name = malloc(len + 1)) == NULL)
		return NULL;

	if (len != 0 && fscanf(fp, "%s", name) != 1) {
		free(name);
		return NULL;
	}

	/* 0-terminate, in case len == 0 and we have an empty string. */
	name[len] = 0;

	if ( (entry = malloc(sizeof(*entry))) == NULL) {
		free(name);
		return NULL;
	}

	entry->flags = 0;
	if (flags[0] != '-')
		entry->flags |= VM_READ;
	if (flags[1] != '-')
		entry->flags |= VM_WRITE;
	if (flags[2] != '-')
		entry->flags |= VM_EXEC;
	if (flags[3] == 's')
		entry->flags |= VM_MAYSHARE;

	entry->start = vm_start;
	entry->end = vm_end;
	entry->offset = offset;
	entry->device = MKDEV(major, minor);
	entry->inode = inode;
	entry->name = name;
	list_init(&entry->list);

	return entry;
}

struct list_head *
ptrace_procfs_maps_read(FILE *fp, struct list_head *list)
{
	struct proc_maps_entry *entry;

	while ( (entry = ptrace_procfs_maps_read_entry(fp)) != NULL)
		list_add_tail(&entry->list, list);

	return list;
}

/* As seen in fs/proc/task_mmu.c */
void ptrace_procfs_maps_print_entry(struct proc_maps_entry *entry)
{
	int len;

	assert (entry != NULL);

	printf("%08lx-%08lx %c%c%c%c %08lx %02x:%02x %lu %n",
		entry->start, entry->end,
		entry->flags & VM_READ ? 'r' : '-',
		entry->flags & VM_WRITE ? 'w' : '-',
		entry->flags & VM_EXEC ? 'x' : '-',
		entry->flags & VM_MAYSHARE ? 's' : 'p',
		entry->offset, MAJOR(entry->device), MINOR(entry->device),
		entry->inode, &len);

	len = 25 + sizeof(void*) * 6 - len;
	if (len < 1)
		len = 1;
	printf("%*c%s\n", len, ' ', entry->name);
}

void *ptrace_procfs_maps_find_exec(pid_t pid)
{
	struct proc_maps_entry *entry;
	long address;
	FILE *fp;

	/* errno already set here */
	if ( (fp = ptrace_procfs_maps_open(pid)) == NULL)
		return (void *)-1;

	while ( (entry = ptrace_procfs_maps_read_entry(fp)) != NULL) {
		if (entry->flags & VM_EXEC) {
			address = entry->start;
			ptrace_procfs_map_entry_destroy(entry);
			ptrace_procfs_maps_close(fp);
			errno = 0;
			return address;
		}
		ptrace_procfs_map_entry_destroy(entry);
	}

	ptrace_procfs_maps_close(fp);
	errno = ENXIO;	/* no such address */
	return (void *)-1;
}

/* As taken from the gdb source code */
int ptrace_procfs_status_is_stopped(pid_t pid)
{
	char buf[256];
	int ret = 0;
	FILE *fp;

	if ( (fp = ptrace_procfs_status_open(pid)) == NULL)
		return -1;

	while (fgets(buf, sizeof (buf), fp) != 0)
		if (strncmp(buf, "State:", 6) == 0)
			if (strstr(buf, "T (stopped)") != NULL)
				ret = 1;

	fclose_no_EINTR(fp);
	return ret;
}
