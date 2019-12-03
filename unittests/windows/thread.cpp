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
 * thread.cpp
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#define BOOST_TEST_MODULE windows_native
#include <windows.h>
#include <boost/test/included/unit_test.hpp>
#include <libptrace.h>

DWORD WINAPI sleeper(LPVOID parameter)
{
	while(1)
		Sleep(1000);
}

BOOST_AUTO_TEST_CASE(thread_attach_detach)
{
	struct pt_thread thread;
	HANDLE th;
	DWORD tid;

	th = CreateThread(NULL, 0, sleeper, NULL, 0, &tid);
	BOOST_REQUIRE(th != NULL);
	BOOST_REQUIRE(pt_thread_attach(&thread, tid) == 0);
	BOOST_REQUIRE(pt_thread_detach(&thread) == 0);
	BOOST_REQUIRE(TerminateThread(th, 0) != 0);
}

BOOST_AUTO_TEST_CASE(thread_get_registers)
{
	struct ptrace_registers *regs;
	struct pt_thread thread;
	HANDLE th;
	DWORD tid;

	th = CreateThread(NULL, 0, sleeper, NULL, 0, &tid);
	BOOST_REQUIRE(th != NULL);
	BOOST_REQUIRE(pt_thread_attach(&thread, tid) == 0);
	regs = pt_thread_get_registers(&thread);
	BOOST_CHECK(regs != NULL);
	ptrace_registers_print(regs);
	free(regs);
	BOOST_REQUIRE(pt_thread_detach(&thread) == 0);
	BOOST_REQUIRE(TerminateThread(th, 0) != 0);
}

BOOST_AUTO_TEST_CASE(thread_set_registers)
{
	struct ptrace_registers *regs;
	struct pt_thread thread;
	uint8_t *ptr;
	HANDLE th;
	DWORD tid;

	th = CreateThread(NULL, 0, sleeper, NULL, 0, &tid);
	BOOST_REQUIRE(th != NULL);
	BOOST_REQUIRE(pt_thread_attach(&thread, tid) == 0);
	regs = pt_thread_get_registers(&thread);
	BOOST_CHECK(regs != NULL);
	ptr = ((uint8_t *)regs) + sizeof(regs->type);
	memset(ptr, 'A', ptrace_registers_get_size(regs) - sizeof(regs->type));
	BOOST_CHECK(pt_thread_set_registers(&thread, regs) == 0);
	free(regs);
	regs = pt_thread_get_registers(&thread);
	BOOST_CHECK(regs != NULL);
	ptrace_registers_print(regs);
	BOOST_REQUIRE(pt_thread_detach(&thread) == 0);
	BOOST_REQUIRE(TerminateThread(th, 0) != 0);
}
