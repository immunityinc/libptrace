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
 * error_code.cpp
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Massimiliano Oldani <max@immunityinc.com>
 *
 */
#define BOOST_TEST_MODULE windows_native
#include <iostream>
#include <windows.h>
#include <mq.h>
#include <ntstatus.h>
#include <boost/test/included/unit_test.hpp>
#include <libptrace/libptrace.h>
#include <libptrace/windows/ps.h>
#include <libptrace/windows/token.h>
#include <libptrace/error.h>
#include <libptrace/windows/error.h>



using namespace std;


void error_test(void)
{

	pt_error_set_windows_oleapi_error(COMQC_E_APPLICATION_NOT_QUEUED);
	BOOST_REQUIRE(pt_error_get_ext() == COMQC_E_APPLICATION_NOT_QUEUED);
	printf("pt_error_get_msg(): %s\n", pt_error_get_msg());

	/* test on internal error  */
	PT_ERR_SET_INTERNAL(PT_ERR_PAGESIZE);
	BOOST_REQUIRE(pt_error_get_int() == PT_ERR_PAGESIZE);
	BOOST_REQUIRE(!strcmp(pt_error_get_msg(), "Unsuitable Page Size"));

	PT_ERR_SET_INTERNAL(PT_ERR_ALTSTACK_ORIG);
	BOOST_REQUIRE(pt_error_get_int() == PT_ERR_ALTSTACK_ORIG);
	BOOST_REQUIRE(!strcmp(pt_error_get_msg(), "Original Stack Error"));
	

	PT_ERR_SET_INTERNAL(PT_ERR_ALTSTACK_INUSE);
	BOOST_REQUIRE(pt_error_get_int() == PT_ERR_ALTSTACK_INUSE);
	BOOST_REQUIRE(!strcmp(pt_error_get_msg(), "Stack Currently In Use"));
	PT_ERR_SET_INTERNAL(PT_ERR_NOMEMORY);
	BOOST_REQUIRE(pt_error_get_int() == PT_ERR_NOMEMORY);
	BOOST_REQUIRE(!strcmp(pt_error_get_msg(), "Not Enough Memory"));

	PT_ERR_SET_INTERNAL(PT_ERR_UNSUPPORTED);
	BOOST_REQUIRE(pt_error_get_int() == PT_ERR_UNSUPPORTED);
	BOOST_REQUIRE(!strcmp(pt_error_get_msg(), "Unsupported Function"));



	/* test on external error WINAPI */


	pt_error_set_windows_winapi_error(ERROR_FILE_NOT_FOUND);
	BOOST_REQUIRE(pt_error_get_ext() == ERROR_FILE_NOT_FOUND);
	printf("pt_error_get_msg(): %s\n", pt_error_get_msg());

	pt_error_set_windows_winapi_error(ERROR_ACCESS_DENIED);
	BOOST_REQUIRE(pt_error_get_ext() == ERROR_ACCESS_DENIED);
	printf("pt_error_get_msg(): %s\n", pt_error_get_msg());

	/* test on external error HRESULT */
	pt_error_set_windows_oleapi_error(E_UNEXPECTED);
	BOOST_REQUIRE(pt_error_get_ext() == E_UNEXPECTED);
	printf("pt_error_get_msg(): %s\n", pt_error_get_msg());
	

	pt_error_set_windows_oleapi_error(E_NOTIMPL);
	BOOST_REQUIRE(pt_error_get_ext() == E_NOTIMPL);
	printf("pt_error_get_msg(): %s\n", pt_error_get_msg());


	/* should print Unkown HRESULT */	
	pt_error_set_windows_oleapi_error(0x45454545);
	BOOST_REQUIRE(pt_error_get_ext() == 0x45454545);
	printf("pt_error_get_msg(): %s\n", pt_error_get_msg());
	
	/* test OLE external module */
	pt_error_set_windows_oleapi_error(MQ_ERROR_ACCESS_DENIED);
	BOOST_REQUIRE(pt_error_get_ext() == MQ_ERROR_ACCESS_DENIED);
	printf("pt_error_get_msg(): %s\n", pt_error_get_msg());
}





BOOST_AUTO_TEST_CASE(error_code_test)
{
	error_test();
}
