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
 * compat.c
 *
 * Python2 and Python3 compatibility definitions.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include "compat.h"

int py_num_check(PyObject *o)
{
	return
#if PY_MAJOR_VERSION < 3
		PyInt_Check(o) ||
#endif
		PyLong_Check(o);
}

int py_string_check(PyObject *o)
{
	return
#if PY_MAJOR_VERSION < 3
		PyString_Check(o) ||
#endif
		PyUnicode_Check(o);
}

long py_num_to_long(PyObject *o)
{
#if PY_MAJOR_VERSION < 3
	if (PyInt_Check(o))
		return PyInt_AsLong(o);
#endif
	return PyLong_AsLong(o);
}

unsigned long long py_num_to_ulonglong(PyObject *o)
{
#if PY_MAJOR_VERSION < 3
	/* Python 2.7 PyLong_AsUnsignedLong will also handle PyInt types.
	 * This is not the case for PyLong_AsUnsignedLongLong so we make
	 * the adjustment here.
	 */
	if (PyInt_Check(o)) {
		unsigned long n = PyLong_AsUnsignedLong(o);
		if (n == (unsigned long)-1 && PyErr_Occurred())
			return (unsigned long long)-1;

		return n;
	}
#endif
	return PyLong_AsUnsignedLongLong(o);
}

char *py_strdup(const char *s)
{
	char *ret;

	if ( (ret = strdup(s)) == NULL)
		PyErr_SetNone(PyExc_MemoryError);

	return ret;
}

char *py_string_to_utf8(PyObject *o)
{
	const char *s;

#if PY_MAJOR_VERSION < 3
	if (PyUnicode_Check(o)) {
		if ( (o = PyUnicode_AsUTF8String(o)) == NULL)
			return NULL;

		s = PyString_AsString(o);
		Py_DECREF(o);
	} else {
		s = PyString_AsString(o);
	}
#else
	 s = PyUnicode_AsUTF8(o);
#endif

	return s != NULL ? py_strdup(s) : NULL;
}
