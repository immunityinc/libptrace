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
# processes.py
#
# Sample script demonstrating the process list.
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

def p1_attached(process):
    print("attached to {}".format(process.id))
    print(_ptrace.processes())
    process.detach()

def p2_attached(process):
    print("attached to {}".format(process.id))
    print(_ptrace.processes())

def exited(process):
    print("{} exited".format(process.id))
    print(_ptrace.processes())

parser = argparse.ArgumentParser(description='Processes demonstration script.')
parser.add_argument('--debug', '-d', action='store_true')
parser.add_argument('--second-chance', '-s', action='store_true')
args = parser.parse_args(sys.argv[1:])

if args.debug:
    _ptrace.log_hook_add(_ptrace.log_hook(logger))

handlers              = _ptrace.event_handlers()
handlers.attached     = p1_attached
handlers.process_exit = exited
_ptrace.execv(r'c:\windows\notepad.exe', [], handlers, 0)

handlers.attached     = p2_attached
_ptrace.execv(r'c:\windows\notepad.exe', [], handlers, 0)

_ptrace.main()
