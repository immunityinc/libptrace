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
 * debug.cpp
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

using namespace std;

int attached_event(struct pt_event_attached *ev)
{
	struct pt_thread *thread;

	process_for_each_thread(ev->process, thread) {
		cout << "Thread " << thread->tid << " handle "
		     << hex << thread->handle << endl;
		BOOST_REQUIRE(pt_thread_print_registers(thread) != -1);
	}

	return PTRACE_EVENT_DROP;
}

int module_load_event(struct pt_event_module_load *ev)
{
	cout << "Module " << ev->module->name << " loaded at "
	     << hex << ev->module->base << endl;

	return PTRACE_EVENT_DROP;
}

int module_unload_event(struct pt_event_module_unload *ev)
{
	cout << "Module " << ev->module->name << " unloaded from "
	     << hex << ev->module->base << endl;

	return PTRACE_EVENT_DROP;
}

int breakpoint_event(struct pt_event_breakpoint *ev)
{
	cout << "Breakpoint at: " << hex << ev->address << endl;

	return PTRACE_EVENT_DROP;
}

int process_exit_event(struct pt_event_process_exit *ev)
{
	cout << "Process exited" << endl;
	return PTRACE_EVENT_DROP;
}

BOOST_AUTO_TEST_CASE(process_debug)
{
	PROCESS_INFORMATION process_info;
	char program[] = "notepad.exe";
	struct pt_process process;
	STARTUPINFO startup_info;
	int ret;

	/* Create a notepad instance to work with. */
	memset(&startup_info, 0, sizeof(startup_info));
	startup_info.cb = sizeof(startup_info);
	ret = CreateProcess(NULL, program, NULL, NULL, FALSE, 0,
	                    NULL, NULL, &startup_info, &process_info);
	BOOST_REQUIRE(ret != 0);

	/* Attach the libptrace debug framework. */
	pt_process_init(&process);
	process.handlers.attached = attached_event;
	process.handlers.module_load = module_load_event;
	process.handlers.module_unload = module_unload_event;
	process.handlers.breakpoint = breakpoint_event;
	process.handlers.process_exit = process_exit_event;

	ret = pt_process_attach(&process, process_info.dwProcessId);
	BOOST_REQUIRE(ret == 0);

	pt_main();
}
