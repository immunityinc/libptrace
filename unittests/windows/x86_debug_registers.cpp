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
 * x86_debug_registers.cpp
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#define BOOST_TEST_MODULE windows_native
#include <iostream>
#include <windows.h>
#include <boost/test/included/unit_test.hpp>
#include <libptrace/libptrace.h>
#include <libptrace/breakpoint.h>

using namespace std;

struct hex_char
{
	hex_char(char _c) : c(_c) { }
	unsigned char c;
};

inline std::ostream &operator<<(std::ostream &o, const hex_char &hc)
{
	return (o << std::hex << "0x" << static_cast<int>(hc.c));
}

inline hex_char hex(char c)
{
	return hex_char(c);
}

void logger(void *cookie, const char *format, va_list ap)
{
	vfprintf(stderr, format, ap);
}

void breakpoint_top_handler(struct pt_thread *thread, void *cookie)
{
	printf("yadda\n");
}

int breakpoint_sw_event(struct ptrace_event_breakpoint *ev)
{
	struct breakpoint *bp;
	char buf[128];
	int ret;

	cout << "Breakpoint at: " << hex << ev->address << endl;

	ret = process_read(ev->thread->process, buf, ev->address, 1);
	BOOST_REQUIRE(ret != -1);

	/* Address will be pointing to the breakpoint instruction itself. */
	cout << "Byte at breakpoint: " << hex(buf[0]) << endl;

	bp = breakpoint_sw_new();
	bp->address = ev->address + 1;
	bp->size = 1;
	bp->handler = breakpoint_top_handler;
	bp->cookie = bp;
	thread_breakpoint_set(ev->thread, bp);

	return PTRACE_EVENT_DROP;
}

int breakpoint_hw_event(struct ptrace_event_breakpoint *ev)
{
	struct breakpoint *bp;
	char buf[128];
	int ret;

	cout << "Breakpoint at: " << hex << ev->address << endl;

	ret = process_read(ev->thread->process, buf, ev->address, 1);
	BOOST_REQUIRE(ret != -1);

	/* Address will be pointing to the breakpoint instruction itself. */
	cout << "Byte at breakpoint: " << hex(buf[0]) << endl;

	bp = breakpoint_hw_new();
	bp->address = ev->address + 1;
	bp->size = 1;
	bp->handler = breakpoint_top_handler;
	bp->cookie = bp;
	thread_breakpoint_set(ev->thread, bp);

	return PTRACE_EVENT_DROP;
}

int single_step_event(struct ptrace_event_single_step *ev)
{
	cout << "Single step event at: " << hex << ev->address << endl;

	return PTRACE_EVENT_DROP;
}

int debug_register_event(struct ptrace_event_x86_dr *ev)
{
	cout << "Debug register event at: " << hex << ev->address << endl;

	return PTRACE_EVENT_DROP;
}

BOOST_AUTO_TEST_CASE(test_breakpoint_sw)
{
	struct ptrace_process process;
	int ret;

	ptrace_log_register_hook(logger, NULL);

	ptrace_process_init(&process);
	process.handlers.breakpoint = breakpoint_hw_event;
	process.handlers.single_step = single_step_event;
	process.handlers.x86_dr = debug_register_event;
	ret = ptrace_process_exec(&process, "C:\\Windows\\notepad.exe", NULL);
	if (ret == -1)
		cerr << "Failed: " << GetLastError() << endl;
	BOOST_REQUIRE(ret != -1);

	do {
		ret = ptrace_process_event_wait(&process, INFINITE);
	} while (ret == 0 && !ptrace_process_exited(&process));

	/* Not all platforms can detach cleanly (think of Win98), so do not
	 * require this to succeed.
	 */
	BOOST_CHECK(ptrace_process_detach(&process) == 0);
}

BOOST_AUTO_TEST_CASE(test_breakpoint_hw)
{
	struct ptrace_process process;
	int ret;

	ptrace_log_register_hook(logger, NULL);

	ptrace_process_init(&process);
	process.handlers.breakpoint = breakpoint_hw_event;
	process.handlers.single_step = single_step_event;
	process.handlers.x86_dr = debug_register_event;
	ret = ptrace_process_exec(&process, "C:\\Windows\\notepad.exe", NULL);
	if (ret == -1)
		cerr << "Failed: " << GetLastError() << endl;
	BOOST_REQUIRE(ret != -1);

	do {
		ret = ptrace_process_event_wait(&process, INFINITE);
	} while (ret == 0 && !ptrace_process_exited(&process));

	/* Not all platforms can detach cleanly (think of Win98), so do not
	 * require this to succeed.
	 */
	BOOST_CHECK(ptrace_process_detach(&process) == 0);
}
