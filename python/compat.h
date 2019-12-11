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
 * compat.h
 *
 * Python2 and Python3 compatibility definitions.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@hexpedition.com>
 *
 */
#ifndef PYPT_COMPAT_INTERNAL_H
#define PYPT_COMPAT_INTERNAL_H

#include <python/Python.h>

#if PY_MAJOR_VERSION >= 3
  #define MODULE_INIT_FUNC_NAME_(name) PyInit_##name
  #define MODULE_INIT_FUNC_RETURN(x)  return (x)
#else
  #define MODULE_INIT_FUNC_NAME_(name) init##name
  #define MODULE_INIT_FUNC_RETURN(x)  return
#endif

#define MODULE_INIT_FUNC_NAME(name) MODULE_INIT_FUNC_NAME_(name)

#if PY_MAJOR_VERSION >= 3
  #define PyInt_FromLong      PyLong_FromLong
  #define PyInt_FromSize_t    PyLong_FromSize_t
  #define PyInt_FromSsize_t   PyLong_FromSsize_t
  #define PyString_FromFormat PyUnicode_FromFormat
  #define PyString_FromString PyUnicode_FromString
#else
  #define PyBytes_FromStringAndSize PyString_FromStringAndSize
  #define PyBytes_AsStringAndSize   PyString_AsStringAndSize
#endif

#ifdef __cplusplus
extern "C" {
#endif

int                py_num_check(PyObject *o);
int                py_string_check(PyObject *o);
long               py_num_to_long(PyObject *o);
unsigned long long py_num_to_ulonglong(PyObject *o);
char *             py_string_to_utf8(PyObject *o);

#ifdef __cplusplus
};
#endif

#endif	/* !PYPT_COMPAT_INTERNAL_H */
