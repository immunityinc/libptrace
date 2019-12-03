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
 * process_obj_utf8.cpp
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Massimiliano Oldani <max@immunityinc.com>
 *
 */
#define BOOST_TEST_MODULE windows_native
#include <iostream>
#include <windows.h>
#include <dbghelp.h>
#include <boost/test/included/unit_test.hpp>
#include <libptrace/libptrace.h>
#include <libptrace/windows/ps.h>
#include <libptrace/windows/token.h>
#include <libptrace/error.h>
#include <libptrace/symbol.h>




using namespace std;

static void print_symbol_entry(struct pt_symbol_entry *sym)
{
	int n = 0;
	while(sym)
	{
		char *unmangled = sym->undecorated_symname;
		char *unmangled2 = pt_symbol_undecorate(sym->symname);

		printf("n: %d, => %s, undecorated: %s, module_name: %s - flags: 0x%x, new undecorated: %s\n",
			   n, sym->symname, unmangled, sym->module->name, sym->flags, unmangled2);

		sym = sym->next;
		n++;
		xfree(unmangled2);
	}
}

static void test_symbol_resolution(const utf8_t *symbol, 
							struct pt_process *proc, 
							struct pt_module *module)
{
	/* try resolve single entry */
	struct pt_symbol_entry *sym = pt_resolve_symbol(symbol,
	                                                proc,
													module,
	                                                0);
	
	print_symbol_entry(sym);
	pt_symbol_free(&sym);
}

void logger(void *cookie, const char *format, va_list ap)
{
	vfprintf(stderr, format, ap);
}



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


static void test_ole_module(struct pt_process *proc, struct pt_module *module)
{
	//test_symbol_resolution("*", proc, module);
	//test_symbol_resolution("CoLeaveServiceDomain", proc, module);
	//test_symbol_resolution("*CoLeaveServiceDomain*", proc, module);
	test_symbol_resolution("*", proc, module);
}


int module_load_event(struct pt_event_module_load *ev)
{
	cout << "Module " << ev->module->name << " loaded at "
	     << hex << ev->module->base << endl;

	
	struct pt_process *proc    = ev->module->process;
	struct pt_module  *module  = ev->module;

	//if (strstr(module->name, "ole"))
	//	test_ole_module(proc, module);
	test_ole_module(proc, module);

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

/*
void call_ps(void)
{
	struct process_list pl;

    token_add_privilege(SE_DEBUG_NAME);

    process_list_init(&pl);
    if (process_list_get(&pl) == -1) {
        fprintf(stderr, "ps_processes_list() failed\n");
        exit(EXIT_FAILURE);
    }
}
*/

BOOST_AUTO_TEST_CASE(process_spawn)
{
	int ret;
	struct pt_process target_proc, *p_tp = &target_proc;
	pt_process_init(&target_proc);
	
	//struct pt_log_hook log_hook = PT_LOG_HOOK_INIT;
	//log_hook.handler = logger;
	//pt_log_hook_register(&log_hook);

	//call_ps();
	//utf8_t* procname = ps_process_pathname_get(2948);
	//if(procname != NULL)
	//	printf("Procname: %s\n", procname);

	pt_symbol_set_search_path("Q:\\symbols");


	char *argv[] = { NULL }; // no parameters
	ret = p_tp->p_op->execv(p_tp, "C:\\Users\\anonymous\\Desktop\\calc.exe.lnkX", argv);
	BOOST_REQUIRE(ret == -1);
	printf("WINAPI Error: %s\n", pt_error_get_msg());
	ret = p_tp->p_op->execv(p_tp, "C:\\Users\\anonymous\\Desktop\\calc.exe.lnk", argv);
	BOOST_REQUIRE(ret == 0);
	BOOST_REQUIRE(p_tp->pid > 0);
	std::cout << "PID: " << p_tp->pid << std::endl;
	//Sleep(100000);

	target_proc.handlers.attached = attached_event;
	target_proc.handlers.module_load = module_load_event;
	target_proc.handlers.module_unload = module_unload_event;
	target_proc.handlers.breakpoint = breakpoint_event;
	target_proc.handlers.process_exit = process_exit_event;
	pt_main();
	
	pt_process_release(&target_proc);

}


/*
BOOST_AUTO_TEST_CASE(process_debug)
{
	PROCESS_INFORMATION process_info;
	char program[] = "notepad.exe";
	struct pt_process process;
	STARTUPINFO startup_info;
	int ret;

	// Create a notepad instance to work with.
	memset(&startup_info, 0, sizeof(startup_info));
	startup_info.cb = sizeof(startup_info);
	ret = CreateProcess(NULL, program, NULL, NULL, FALSE, 0,
	                    NULL, NULL, &startup_info, &process_info);
	BOOST_REQUIRE(ret != 0);

	//  Attach the libptrace debug framework.
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
*/


BOOST_AUTO_TEST_CASE(XXXXXX)
{
	
}




