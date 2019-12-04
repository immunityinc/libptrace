#!/usr/bin/env python
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
# events.py
#
# Dedicated to Yuzuyu Arielle Huizer.
#
# Author: Ronald Huizer <ronald@immunityinc.com>
#
from __future__ import print_function
import sys
import _ptrace
import argparse

def logger(cookie, string):
    print(string, end='')

def attached(process):
    print("[{}] attached".format(process.id))

def process_exit(process):
    print("[{}] exited".format(process.id))

def thread_create(process, thread):
    print("[{}] Created thread with tid {}".format(process.id, thread.id))

def thread_exit(process, thread):
    print("[{}] Thread with tid {} exited".format(process.id, thread.id))

def module_load(process, module):
    print("[{}] Module {} loaded at 0x{:08x}".format(process.id, module.name, module.base))

def module_unload(process, module):
    print("[{}] Module {} unloaded".format(process.id, module.name))

def breakpoint(process, breakpoint, chance):
    print("[{}] Breakpoint".format(process.id))

def single_step(process, thread):
    print("[{}] Single step".format(process.id))

def illegal_instruction(process, thread, chance=None):
    print("[{}/{}] Illegal instruction".format(process.id, thread.id))

def segfault(process, thread, address, fault_address):
    print("[{}] Thread {} segmentation fault on address 0x{:08x}"
          .format(process.id, thread.id, fault_address))

def divide_by_zero(process, thread, chance=None):
    print("[{}/{}] Divide by zero".format(process.id, thread.id))

def priv_instruction(process, thread, chance=None):
    print("[{}/{}] Privileged instruction".format(process.id, thread.id))

parser = argparse.ArgumentParser(description='Event handler demonstration script.')
parser.add_argument('file', nargs='?', metavar='filename', help='executable.')
parser.add_argument('args', nargs='*', metavar='args', help='arguments.')
parser.add_argument('--debug', '-d', action='store_true')
parser.add_argument('--pid', '-p', type=int)
parser.add_argument('--second-chance', '-s', action='store_true')
args = parser.parse_args(sys.argv[1:])

if (not args.file and not args.pid) or (args.file and args.pid):
    parser.print_help()
    sys.exit(1)

if args.debug:
    _ptrace.log_hook_add(_ptrace.log_hook(logger))

handlers                     = _ptrace.event_handlers()
handlers.attached            = attached
handlers.process_exit        = process_exit
handlers.thread_create       = thread_create
handlers.thread_exit         = thread_exit
handlers.module_load         = module_load
handlers.module_unload       = module_unload
handlers.breakpoint          = breakpoint
handlers.single_step         = single_step
handlers.segfault            = segfault
handlers.illegal_instruction = illegal_instruction
handlers.divide_by_zero      = divide_by_zero
handlers.priv_instruction    = priv_instruction

options = 0
if args.second_chance:
    options = _ptrace.PROCESS_OPTION_EVENT_SECOND_CHANCE

if args.pid:
    _ptrace.process_attach(args.pid, handlers, options)

if args.file:
    _ptrace.execv(args.file, args.args, handlers, options)

_ptrace.main()
