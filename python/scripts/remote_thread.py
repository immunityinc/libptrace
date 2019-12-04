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
# remote_thread.py
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
    handler, cookie = int(args.handler, 16), int(args.cookie, 16)
    print("Attached to PID: {}".format(process.id))
    print("Threads: ", [t.id for t in process.threads])
    process.thread_create(handler, cookie)

def process_exit(process):
    print("[{}] exited".format(process.id))

def thread_create(process, thread):
    print("[{}] Created thread with tid {}".format(process.id, thread.id))

def thread_exit(process, thread):
    print("[{}] Thread with tid {} exited".format(process.id, thread.id))

parser = argparse.ArgumentParser(description='Remote thread demonstration script.')
parser.add_argument('handler', metavar='handler', help='handler.')
parser.add_argument('cookie', metavar='cookie', help='cookie.')
parser.add_argument('file', nargs='?', metavar='filename', help='executable.')
parser.add_argument('args', nargs='*', metavar='args', help='arguments.')
parser.add_argument('--debug', '-d', action='store_true')
parser.add_argument('--pid', '-p', type=int)
parser.add_argument('--second-chance', '-s', action='store_true')
args = parser.parse_args(sys.argv[1:])

if (not args.file and not args.pid) or (args.file and args.pid):
    parser.print_help()
    sys.exit(1)

if (args.handler is None or args.cookie is None):
    parser.print_help()
    sys.exit(1)

if args.debug:
    _ptrace.log_hook_add(_ptrace.log_hook(logger))

handlers               = _ptrace.event_handlers()
handlers.attached      = attached
handlers.thread_create = thread_create
handlers.thread_exit   = thread_exit

options = 0
if args.second_chance:
    options = _ptrace.PROCESS_OPTION_EVENT_SECOND_CHANCE

if args.pid:
    p = _ptrace.process_attach(args.pid, handlers, options)

if args.file:
    p = _ptrace.execv(args.file, args.args, handlers, options)

_ptrace.main()
