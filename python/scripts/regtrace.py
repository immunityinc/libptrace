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
# regtrace.py
#
# Dedicated to Yuzuyu Arielle Huizer.
#
# Author: Ronald Huizer <ronald@immunityinc.com>
#
from __future__ import print_function
import sys
import signal
import _ptrace
import argparse

keys = {
    0x80000000: "HKEY_CLASSES_ROOT",
    0x80000001: "HKEY_CLASSES_USER",
    0x80000002: "HKEY_LOCAL_MACHINE",
    0x80000003: "HKEY_USERS",
    0x80000004: "HKEY_PERFORMANCE_DATA",
    0x80000005: "HKEY_CURRENT_CONFIG",
    0x80000006: "HKEY_DYN_DATA"
}

def break_handler(signum, frame):
    _ptrace.quit();

def logger(cookie, string):
    print(string, end='')

def attached_handler(process):
    bpRegOpenKeyEx  = _ptrace.breakpoint_sw("advapi32!RegOpenKeyExW", regOpenKeyEx)
    #bpRegGetValue   = _ptrace.breakpoint_sw("advapi32!RegGetValueW", regGetValue)
    bpRegQueryValueEx = _ptrace.breakpoint_sw("advapi32!RegQueryValueExW", regQueryValueEx)

    process.breakpoint_set(bpRegOpenKeyEx)
    process.breakpoint_set(bpRegQueryValueEx)

def bp_end_handler(breakpoint, thread):
    print(" = {}".format(_ptrace.cconv.retval_get(thread)))

def regOpenKeyEx(breakpoint, thread):
    retaddr = _ptrace.cconv.retaddr_get(thread)
    (key, subkey, options, sam, result) = _ptrace.cconv.args_get(thread, "%u%p%u%u%p")

    if key in keys:
        key = keys[key]
    else:
        key = "0x{:08x}".format(key)

    subkey = thread.process.read_utf16(subkey)

    print('T{}: RegOpenKeyEx({}, "{}", 0x{:08x}, 0x{:08x}, 0x{:08x})'
          .format(thread.id, key, subkey, options, sam, result), end='')

    # Set breakpoint after function returns, so we can print the results.
    if thread.process.breakpoint_find(retaddr) is None:
        bp_end = _ptrace.breakpoint_sw(retaddr, bp_end_handler)
        thread.process.breakpoint_set(bp_end)

def regGetValue(breakpoint, thread):
    retaddr = _ptrace.cconv.retaddr_get(thread)
    (key, subkey, value, flags, type, data, size) = _ptrace.cconv.args_get(thread, "%p%p%p%u%p%p%p")

    if key in keys:
        key = keys[key]
    else:
        key = "0x{:08x}".format(key)

    subkey = thread.process.read_utf16(subkey)
    value  = thread.process.read_utf16(value)

    print('T{}: RegGetValue({}, "{}", "{}")'.format(thread.id, key, subkey, value), end='')

    # Set breakpoint after function returns, so we can print the results.
    if thread.process.breakpoint_find(retaddr) is None:
        bp_end = _ptrace.breakpoint_sw(retaddr, bp_end_handler)
        thread.process.breakpoint_set(bp_end)

def regQueryValueEx(breakpoint, thread):
    retaddr = _ptrace.cconv.retaddr_get(thread)
    (key, value, reserved, type, data, size) = _ptrace.cconv.args_get(thread, "%u%p%p%p%p%p")

    if key in keys:
        key = keys[key]
    else:
        key = "0x{:08x}".format(key)

    value = thread.process.read_utf16(value)

    print('T{}: RegQueryValueEx({}, "{}", 0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x})'
          .format(thread.id, key, value, reserved, type, data, size), end='')

    # Set breakpoint after function returns, so we can print the results.
    if thread.process.breakpoint_find(retaddr) is None:
        bp_end = _ptrace.breakpoint_sw(retaddr, bp_end_handler)
        thread.process.breakpoint_set(bp_end)

parser = argparse.ArgumentParser(description='Heap activity tracer.')
parser.add_argument('file', nargs='?', metavar='filename', help='executable to trace.')
parser.add_argument('args', nargs='*', metavar='args', help='arguments.')
parser.add_argument('--debug', '-d', action='store_true')
parser.add_argument('--pid', '-p', type=int)
args = parser.parse_args(sys.argv[1:])

if (not args.file and not args.pid) or (args.file and args.pid):
    parser.print_help()
    sys.exit(1)

if hasattr(signal, "SIGBREAK"):
    signal.signal(signal.SIGBREAK, break_handler)

signal.signal(signal.SIGINT, break_handler)

if args.debug:
    _ptrace.log_hook_add(_ptrace.log_hook(logger))

handlers          = _ptrace.event_handlers()
handlers.attached = attached_handler

if args.pid:
    _ptrace.process_attach(args.pid, handlers, 0)

if args.file:
    _ptrace.execv(args.file, args.args, handlers, 0)

_ptrace.main()
