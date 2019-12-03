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
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static -static-libgcc")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
include_directories(${PROJECT_SOURCE_DIR}/include)

add_executable(inject inject.c)
target_link_libraries(inject ptrace_static)

add_executable(pt_core pt_core.c)
target_link_libraries(pt_core ptrace_static pthread)

#add_executable(test_debug debug.cpp)
#target_link_libraries(test_debug ptrace_static)

#add_executable(test_filenative file_native.cpp)
#target_link_libraries(test_filenative ptrace_static)

#add_executable(test_process_obj_utf8 process_obj_utf8.cpp)
#target_link_libraries(test_process_obj_utf8 ptrace_static)

#add_executable(test_error_code error_code.cpp)
#target_link_libraries(test_error_code ptrace_static)
