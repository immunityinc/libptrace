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
# Author: Christos Kalkanis <chris@immunityinc.com>
# Author: Ronald Huizer <ronald@immunityinc.com>
#
set(CMAKE_SYSTEM_NAME Windows)
set(COMPILER_PREFIX "i686-w64-mingw32")

# which compilers to use for C and C++
find_program(CMAKE_RC_COMPILER NAMES ${COMPILER_PREFIX}-windres)
find_program(CMAKE_C_COMPILER NAMES ${COMPILER_PREFIX}-gcc)
set(CMAKE_C_COMPILER ${COMPILER_PREFIX}-gcc)

find_program(CMAKE_CXX_COMPILER NAMES ${COMPILER_PREFIX}-g++)
set(CMAKE_CXX_COMPILER ${COMPILER_PREFIX}-g++)

set(CMAKE_FIND_ROOT_PATH  /usr/${COMPILER_PREFIX} ${USER_ROOT_PATH})

# adjust the default behaviour of the FIND_XXX() commands: search headers and
# libraries in the target environment, search programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
