#
# Copyright (C) 2019, Cyxtera Cybersecurity, Inc.  All rights reserved.
#
# This library is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License version 2.1 as
# published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
# version 2.1 for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# version 2.1 along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301,
# USA.
#
# THE CODE AND SCRIPTS POSTED ON THIS WEBSITE ARE PROVIDED ON AN "AS IS" BASIS
# AND YOUR USE OF SUCH CODE AND/OR SCRIPTS IS AT YOUR OWN RISK.  CYXTERA
# DISCLAIMS ALL EXPRESS AND IMPLIED WARRANTIES, EITHER IN FACT OR BY OPERATION
# OF LAW, STATUTORY OR OTHERWISE, INCLUDING, BUT NOT LIMITED TO, ALL
# WARRANTIES OF MERCHANTABILITY, TITLE, FITNESS FOR A PARTICULAR PURPOSE,
# NON-INFRINGEMENT, ACCURACY, COMPLETENESS, COMPATABILITY OF SOFTWARE OR
# EQUIPMENT OR ANY RESULTS TO BE ACHIEVED THEREFROM.  CYXTERA DOES NOT WARRANT
# THAT SUCH CODE AND/OR SCRIPTS ARE OR WILL BE ERROR-FREE.  IN NO EVENT SHALL
# CYXTERA BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, RELIANCE,
# EXEMPLARY, PUNITIVE OR CONSEQUENTIAL DAMAGES, OR ANY LOSS OF GOODWILL, LOSS
# OF ANTICIPATED SAVINGS, COST OF PURCHASING REPLACEMENT SERVICES, LOSS OF
# PROFITS, REVENUE, DATA OR DATA USE, ARISING IN ANY WAY OUT OF THE USE AND/OR
# REDISTRIBUTION OF SUCH CODE AND/OR SCRIPTS, REGARDLESS OF THE LEGAL THEORY
# UNDER WHICH SUCH LIABILITY IS ASSERTED AND REGARDLESS OF WHETHER CYXTERA HAS
# BEEN ADVISED OF THE POSSIBILITY OF SUCH LIABILITY.
#
# CMakeLists.txt
#
# Dedicated to Yuzuyu Arielle Huizer.
#
# Author: Ronald Huizer <ronald@immunityinc.com>
#
include_directories(${PROJECT_SOURCE_DIR}/include)

set(CMAKE_SHARED_LINKER_FLAGS "-static -static-libgcc")
set(SOURCES arch.h avl.c avl.h breakpoint.c breakpoint.h breakpoint_hw.c
            breakpoint_hw.h breakpoint_sw.c breakpoint_sw.h charset.c
            compat.c compat.h error.h error.c event.c event.h
            file.c file.h getput.h interval_tree.h core.c symbol.c
            core.h libptrace_x86.h list.h log.c log.h
            mmap.h module.c module.h pe.c pe.h process.c process.h registers.c
            registers.h symbol.h thread.c thread.h inject.c
	    stringlist.c stringlist.h breakpoint_x86.c breakpoint_x86.h
            thread_x86.c thread_x86.h vector.h
            factory.c factory.h queue.c queue.h message.h
            iterator.c iterator.h handle.c handle.h
            ${PROJECT_SOURCE_DIR}/include/libptrace/charset.h
            ${PROJECT_SOURCE_DIR}/include/libptrace/factory.h
            ${PROJECT_SOURCE_DIR}/include/libptrace/handle.h
            ${PROJECT_SOURCE_DIR}/include/libptrace/inject.h
            ${PROJECT_SOURCE_DIR}/include/libptrace/iterator.h
            ${PROJECT_SOURCE_DIR}/include/libptrace/types.h
            ${PROJECT_SOURCE_DIR}/include/libptrace/util.h
)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
	# i386 compatibility mode means we also include 32-bit threads.
	# There is no target architecture dependent functionality in the src/
	# part of the libptrace tree, so builds include everything.
	set(SOURCES ${SOURCES} thread_x86_32.c thread_x86_32.h)
	set(SOURCES ${SOURCES} thread_x86_64.c thread_x86_64.h)
elseif (CMAKE_SIZEOF_VOID_P EQUAL 4)
	set(SOURCES ${SOURCES} thread_x86_32.c thread_x86_32.h)
else()
	message(FATAL_ERROR, "Unsupported processor.")
endif()

if(WIN32)
	add_subdirectory(windows/wrappers)

	set(WINDOWS_SOURCES 
	    windows/adapter.c windows/adapter.h
            windows/cconv.c windows/cconv.h windows/compat.h
            windows/error.h
            windows/error.c windows/core.c windows/core.h windows/mmap.c
	    windows/module.c windows/module.h
            windows/netstat.c windows/file.c windows/netstat.h
            windows/pathname.c windows/pathname.h windows/process.c
            windows/process.h
            windows/ps.c windows/ps.h windows/service.c
            windows/service.h windows/shortcut.c windows/shortcut.h
            windows/symbol.c windows/symbol.h windows/thread.c windows/thread.h
            windows/thread_x86.c windows/token.c
            windows/token.h windows/uuid.c windows/util.c
	    windows/win32util.c windows/win32util.h
	)

	if (CMAKE_SIZEOF_VOID_P EQUAL 8)
		# Do /not/ include windows/*_x86_32.c here.  32-bit
		# support is implemented in windows/*.c using
		# WoW64 routines.
		set(WINDOWS_SOURCES ${WINDOWS_SOURCES} windows/process_x86_64.c)
		set(WINDOWS_SOURCES ${WINDOWS_SOURCES} windows/process_x86_64.h)
		set(WINDOWS_SOURCES ${WINDOWS_SOURCES} windows/thread_x86_64.c)
		set(WINDOWS_SOURCES ${WINDOWS_SOURCES} windows/thread_x86_64.h)
	elseif (CMAKE_SIZEOF_VOID_P EQUAL 4)
		set(WINDOWS_SOURCES ${WINDOWS_SOURCES} windows/process_x86_32.c)
		set(WINDOWS_SOURCES ${WINDOWS_SOURCES} windows/process_x86_32.h)
		set(WINDOWS_SOURCES ${WINDOWS_SOURCES} windows/thread_x86_32.c)
		set(WINDOWS_SOURCES ${WINDOWS_SOURCES} windows/thread_x86_32.h)
	else()
		message(FATAL_ERROR, "Unsupported processor.")
	endif()

	add_library(ptrace SHARED ${SOURCES} ${WINDOWS_SOURCES}
	            $<TARGET_OBJECTS:win32_wrappers>)
	add_library(ptrace_static STATIC ${SOURCES} ${WINDOWS_SOURCES}
	            $<TARGET_OBJECTS:win32_wrappers>)
	target_link_libraries(ptrace ntdll ws2_32 pthread)
	target_link_libraries(ptrace_static ntdll ws2_32 pthread)
else()
	message(FATAL_ERROR, "Unsupported platform.")
endif()
