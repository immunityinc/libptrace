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
 * process_x86_32.c
 *
 * libptrace windows i386 process management.
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>, <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <stdint.h>
#include <windows.h>
#include <libptrace/log.h>
#include <libptrace/windows/error.h>
#include "core.h"
#include "process.h"
#include "thread_x86_32.h"

static int
handle_debug_register_(struct pt_process *process,
                       struct pt_thread *thread,
                       LPEXCEPTION_RECORD exception,
                       int index)
{
	struct pt_event_breakpoint ev;
	struct x86_debug_register *reg;

	reg = &thread->debug_registers.regs[index];

	/* We did not set this register.  It was done by the debuggee, so
	 * we invoke the low-level handler.
	 */
	if (reg->scope == X86_DR_SCOPE_NONE) {
		struct pt_event_x86_dr ev;

		if (process->handlers.x86_dr == NULL)
			return PT_EVENT_FORWARD;

		ev.address = exception->ExceptionAddress;
		ev.thread = thread;

		return process->handlers.x86_dr(&ev);
	}


	ev.address = (pt_address_t)exception->ExceptionAddress;
	ev.thread = thread;

	return pt_breakpoint_handler(thread, &ev);
}

static uint32_t handle_debug_registers_(
	struct pt_process *process,
	struct pt_thread *thread,
	LPEXCEPTION_RECORD exception,
	uint32_t dr6)
{
	int status;

	if (dr6 & X86_DR6_B0) {
		status = handle_debug_register_(process, thread, exception, 0);

		if (status == PT_EVENT_DROP)
			dr6 &= ~X86_DR6_B0;
	}

	if (dr6 & X86_DR6_B1) {
		status = handle_debug_register_(process, thread, exception, 1);

		if (status == PT_EVENT_DROP)
			dr6 &= ~X86_DR6_B1;
	}


	if (dr6 & X86_DR6_B2) {
		status = handle_debug_register_(process, thread, exception, 2);

		if (status == PT_EVENT_DROP)
			dr6 &= ~X86_DR6_B2;
	}

	if (dr6 & X86_DR6_B3) {
		status = handle_debug_register_(process, thread, exception, 3);

		if (status == PT_EVENT_DROP)
			dr6 &= ~X86_DR6_B3;
	}

	return dr6;
}

int windows_x86_32_handle_exception_single_step_(
	struct pt_process *process,
	struct pt_thread *thread,
	LPEXCEPTION_RECORD exception)
{
	uint64_t dr6;

	pt_log("%s(): handling single step event.\n", __FUNCTION__);

	pt_error_save(), pt_error_clear();

	dr6 = pt_windows_thread_x86_32_get_dr6(thread);

	/* If we cannot read DR6 assume we have a regular single step
	 * and be done continue.
	 */
	if (pt_error_is_set()) {
		pt_log("%s(): pt_thread_x86_32_get_dr6() failed.\n", __FUNCTION__);
		return handle_debug_single_step_(process, thread, exception);
	}

	pt_log("%s(): DR6: 0x%8x\n", __FUNCTION__, dr6);

	/* We have a single step event flagged.  Note that we also
	 * explicitly check the case where dr6 is 0, due to Windows
	 * not forwarding the dr6 BS flag to us.  This could make
	 * the entire process ambiguous, when BS would be flagged
	 * with debug registers.  *sigh*
	 */
	if (dr6 & X86_DR6_BS || dr6 == 0) {
		int ret = handle_debug_single_step_(process, thread, exception);

		if (ret == PT_EVENT_DROP)
			dr6 &= ~X86_DR6_BS;
	}

	/* Sanitize DR6 to include only flags we expect. */
	dr6 &= X86_DR6_MASK;

	/* Handle debug registers that have set. */
	dr6 = handle_debug_registers_(process, thread, exception, dr6);

	/* Write back dr6.  If it is not 0 at this time, this means we
	 * have been requested to PT_EVENT_FORWARD one of the
	 * events and will do so with updated DR6.
	 *
	 * XXX: error
	 */

	pt_windows_thread_x86_32_set_dr6(thread, dr6);

	return dr6 == 0 ? PT_EVENT_DROP : PT_EVENT_FORWARD;
}
