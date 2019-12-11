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
 * breakpoint_sw.c
 *
 * Python bindings for libptrace software breakpoints.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <python/Python.h>
#include <python/structmember.h>
#include "../src/thread.h"

#include "compat.h"
#include "breakpoint.h"
#include "breakpoint_sw.h"
#include "thread.h"
#include "utils.h"

static PyMethodDef pypt_breakpoint_sw_methods[] = {
	{ NULL }
};

static PyMemberDef pypt_breakpoint_sw_members[] = {
	{ NULL }
};

static PyGetSetDef pypt_breakpoint_sw_getset[] = {
	{"__dict__", (getter)pypt_dict_get, (setter)pypt_dict_set,
	"The __dict__ for this breakpoint.", &pypt_breakpoint_sw_type},
	{NULL}
};

static void
pypt_breakpoint_sw_handler_(struct pt_thread *pt_thread, void *cookie)
{
	PyGILState_STATE gstate;
	struct pypt_breakpoint_sw *bp = (struct pypt_breakpoint_sw *)cookie;
	struct pypt_thread *thread;
	PyObject *ret;

	thread = (struct pypt_thread *)pt_thread->super_;

	gstate = PyGILState_Ensure();

	ret = PyObject_CallFunctionObjArgs(bp->handler, bp, thread, NULL);

	if (ret != NULL)
		Py_DECREF(ret);

	if (PyErr_Occurred())
		PyErr_Print();

	PyGILState_Release(gstate);
}

static int
pypt_breakpoint_sw_init(struct pypt_breakpoint_sw *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = { "address", "handler", NULL };
	unsigned long long address;
	PyObject *handler = NULL;
	PyObject *symbol = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OO:breakpoint",
	                                 kwlist, &symbol, &handler))
		return -1;

	if (!py_num_check(symbol) && !py_string_check(symbol)) {
		PyErr_SetString(PyExc_TypeError, "'symbol' must be an integer or a string");
		return -1;
	}

	/* XXX: short circuit this now, as it'll wreak havoc. */
	if (self->initialized)
		return -1;

	if (!handler || !PyCallable_Check(handler))
		return -1;

	/* Initialize the breakpoint structure. */
	pt_breakpoint_sw_init(&self->breakpoint);
	self->breakpoint.handler = pypt_breakpoint_sw_handler_;
	self->breakpoint.cookie  = self;

	/* Depending on the type we got, initialize address or symbol. */
	if (py_num_check(symbol)) {
		address = py_num_to_ulonglong(symbol);
		if (address == (unsigned long long)-1 && PyErr_Occurred())
			return -1;

		self->breakpoint.address = (pt_address_t)address;
	} else {
		/* breakpoint.symbol takes ownership of malloced string. */
		self->breakpoint.symbol = py_string_to_utf8(symbol);
		if (self->breakpoint.symbol == NULL)
			return -1;
	}

	/* Initialize the python structure. */
	Py_INCREF(handler);
	self->handler = handler;
	self->initialized = 1;

	return 0;
}

static PyObject*
pypt_breakpoint_sw_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	struct pypt_breakpoint_sw *self;

	if ((self = (struct pypt_breakpoint_sw *)type->tp_alloc(type, 0)) == NULL)
		return NULL;

	self->dict = PyDict_New();

	if (!self->dict) {
		Py_TYPE(self)->tp_free((PyObject *)self);
		return NULL;
	}

	return (PyObject*)self;
}

static void
pypt_breakpoint_sw_dealloc(struct pypt_breakpoint_sw *self)
{
	Py_XDECREF(self->handler);
	Py_XDECREF(self->dict);
	Py_TYPE(self)->tp_free((PyObject *)self);
}



PyTypeObject pypt_breakpoint_sw_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_ptrace.breakpoint_sw",		   /* tp_name */
	sizeof(struct pypt_breakpoint_sw),	   /* tp_basicsize */
	0,					   /* tp_itemsize */
	(destructor)pypt_breakpoint_sw_dealloc,	   /* tp_dealloc */
	0,					   /* tp_print */
	0,					   /* tp_getattr */
	0,					   /* tp_setattr */
	0,					   /* tp_compare */
	0,	                                   /* tp_repr */
	0,					   /* tp_as_number */
	0,					   /* tp_as_sequence */
	0,					   /* tp_as_mapping */
	0,					   /* tp_hash */
	0,					   /* tp_call */
	0,					   /* tp_str */
	PyObject_GenericGetAttr,		   /* tp_getattro */
	PyObject_GenericSetAttr,		   /* tp_setattro */
	0,					   /* tp_as_buffer */
	Py_TPFLAGS_DEFAULT	|		   /* tp_flags */
	Py_TPFLAGS_BASETYPE,
	"Software breakpoint",			   /* tp_doc */
	0,					   /* tp_traverse */
	0,					   /* tp_clear */
	0,					   /* tp_richcompare */
	0,					   /* tp_weaklistoffset */
	0,					   /* tp_iter */
	0,					   /* tp_iternext */
	pypt_breakpoint_sw_methods,		   /* tp_methods */
	pypt_breakpoint_sw_members,		   /* tp_members */
	pypt_breakpoint_sw_getset,		   /* tp_getset */
	&pypt_breakpoint_type,			   /* tp_base */
	0,					   /* tp_dict */
	0,					   /* tp_descr_get */
	0,					   /* tp_descr_set */
	offsetof(struct pypt_breakpoint_sw, dict), /* tp_dictoffset */
	(initproc)pypt_breakpoint_sw_init,	   /* tp_init */
	0,					   /* tp_alloc */
	pypt_breakpoint_sw_new,			   /* tp_new */
};
