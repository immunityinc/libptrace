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
 * adapter.c
 *
 * Adapter module to convert libptrace pt_address_t types into the native
 * Windows address type.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include "adapter.h"

ssize_t pt_windows_process_read_adapter(struct pt_process *process,
	void *dst, pt_address_t src, size_t len)
{
	return pt_windows_process_read(process, dst, (void *)src, len);
}

int pt_windows_process_write_adapter(struct pt_process *process,
	pt_address_t dst, const void *src, size_t len)
{
	return pt_windows_process_write(process, (void *)dst, src, len);
}

int pt_windows_process_thread_create_adapter(struct pt_process *process,
	pt_address_t handler, pt_address_t cookie)
{
	return pt_windows_process_thread_create(
		process,
		(const void *)handler,
		(const void *)cookie
	);
}

pt_address_t pt_windows_process_malloc_adapter(
	struct pt_process *process, size_t len)
{
	return (pt_address_t)pt_windows_process_malloc(process, len);
}

int pt_windows_process_free_adapter(struct pt_process *process, pt_address_t p)
{
	return pt_windows_process_free(process, (const void *)p);
}

struct pt_process_operations pt_windows_process_operations = {
	.destroy       = pt_windows_process_destroy,
	.brk           = pt_windows_process_brk,
	.suspend       = pt_windows_process_suspend,
	.resume        = pt_windows_process_resume,
	.read          = pt_windows_process_read_adapter,
	.write         = pt_windows_process_write_adapter,
	.thread_create = pt_windows_process_thread_create_adapter,
	.malloc        = pt_windows_process_malloc_adapter,
	.free          = pt_windows_process_free_adapter
};

pt_address_t pt_windows_thread_register_pc_get_adapter(struct pt_thread *thread)
{
	return (pt_address_t)pt_windows_thread_register_pc_get(thread);
}

int pt_windows_thread_register_pc_set_adapter(struct pt_thread *thread, pt_address_t pc)
{
	return pt_windows_thread_register_pc_set(thread, (void *)pc);
}

#ifdef __x86_64__
pt_address_t pt_windows_wow64_thread_register_pc_get_adapter(struct pt_thread *thread)
{
	return (pt_address_t)pt_windows_thread_register_pc_get(thread);
}

int pt_windows_wow64_thread_register_pc_set_adapter(struct pt_thread *thread, pt_address_t pc)
{
	return pt_windows_thread_register_pc_set(thread, (void *)pc);
}
#endif

struct pt_thread_operations pt_windows_thread_operations = {
	.destroy            = pt_windows_thread_destroy,
	.suspend            = pt_windows_thread_suspend,
	.resume             = pt_windows_thread_resume,
	.single_step_set    = pt_windows_thread_single_step_set,
	.single_step_remove = pt_windows_thread_single_step_remove,
	.registers_set      = pt_windows_thread_registers_set,
	.registers_get      = pt_windows_thread_registers_get,
	.debug_registers_apply = pt_windows_thread_debug_registers_apply,

	.register_pc_get = pt_windows_thread_register_pc_get_adapter,
	.register_pc_set = pt_windows_thread_register_pc_set_adapter,
};

#ifdef __x86_64__
struct pt_thread_operations pt_windows_wow64_thread_operations = {
	.destroy            = pt_windows_thread_destroy,
	.suspend            = pt_windows_wow64_thread_suspend,
	.resume             = pt_windows_thread_resume,
	.single_step_set    = pt_windows_wow64_thread_single_step_set,
	.single_step_remove = pt_windows_wow64_thread_single_step_remove,
	.registers_set      = pt_windows_wow64_thread_registers_set,
	.registers_get      = pt_windows_wow64_thread_registers_get,
	.debug_registers_apply = pt_windows_thread_debug_registers_apply,

	.register_pc_get = pt_windows_wow64_thread_register_pc_get_adapter,
	.register_pc_set = pt_windows_wow64_thread_register_pc_set_adapter,
};
#endif
