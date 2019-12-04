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
# CMake configuration for libptrace Python bindings.
#
# Dedicated to Yuzuyu Arielle Huizer.
#
# Author: Ronald Huizer <ronald@immunityinc.com>
#
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-strict-aliasing")

include_directories(${PROJECT_SOURCE_DIR}/include)

if (SIZEOF_VOID_P EQUAL 8)
	link_directories(${CMAKE_CURRENT_SOURCE_DIR}/lib64)
elseif (SIZEOF_VOID_P EQUAL 4)
	link_directories(${CMAKE_CURRENT_SOURCE_DIR}/lib)
else()
	message(FATAL_ERROR, "Unsupported processor.")
endif()

set(SOURCES breakpoint.c breakpoint.h breakpoint_sw.c compat.c compat.h
            core.c core.h utils.c utils.h
            breakpoint_sw.h cconv.c cconv.h event.c event.h inject.c inject.h
            log.c log.h mmap.c mmap.h module.c module.h process.c process.h
            ptrace.c ptrace.h thread.c thread.h)

add_library(py27ptrace SHARED ${SOURCES})
target_include_directories(py27ptrace PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/python2.7)
target_link_libraries(py27ptrace python27.a ptrace)

add_library(py37ptrace SHARED ${SOURCES})
target_include_directories(py37ptrace PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/python3.7)
target_link_libraries(py37ptrace python37.lib ptrace)
