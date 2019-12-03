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
 * factory.c
 *
 * Implementation of libptrace architecture specific factories.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <libptrace/error.h>
#include <libptrace/process.h>
#include <libptrace/thread.h>
#include "factory.h"

#ifdef WIN32
#include "windows/core.h"
#include "windows/process.h"
#include "windows/thread.h"
#ifdef __x86_64__
#include "windows/process_x86_64.h"
#include "windows/thread_x86_64.h"
#endif
#endif

struct pt_core *pt_factory_core_new(int type)
{
	switch (type) {
#ifdef WIN32
	case PT_FACTORY_CORE_WINDOWS:
		return pt_windows_core_new();
#endif
	}

	pt_error_internal_set(PT_ERROR_UNSUPPORTED);
	return NULL;
}

struct pt_process *pt_factory_process_new(int type)
{
	switch (type) {
#ifdef WIN32
	case PT_FACTORY_PROCESS_WINDOWS:
		return pt_windows_process_new();
#ifdef __x86_64__
	case PT_FACTORY_PROCESS_WINDOWS_WOW64:
		return pt_windows_wow64_process_new();
#endif
#endif
	}

	pt_error_internal_set(PT_ERROR_UNSUPPORTED);
	return NULL;
}

struct pt_thread *pt_factory_thread_new(int type)
{
	switch (type) {
#ifdef WIN32
	case PT_FACTORY_THREAD_WINDOWS:
		return pt_windows_thread_new();
#ifdef __x86_64__
	case PT_FACTORY_THREAD_WINDOWS_WOW64:
		return pt_windows_wow64_thread_new();
#endif
#endif
	}

	pt_error_internal_set(PT_ERROR_UNSUPPORTED);
	return NULL;
}
