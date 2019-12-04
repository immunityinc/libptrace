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
 * breakpoint.c
 *
 * Python bindings for libptrace breakpoints.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <python/Python.h>
#include <python/structmember.h>
#include <libptrace/breakpoint.h>
#include "compat.h"
#include "breakpoint.h"

static int pypt_breakpoint_init(struct pypt_breakpoint *, PyObject *, PyObject *);
static PyObject *pypt_breakpoint__repr__(struct pypt_breakpoint *);

static PyMethodDef pypt_breakpoint_methods[] = {
	{ NULL }
};

static PyMemberDef pypt_breakpoint_members[] = {
	{ NULL }
};

PyTypeObject pypt_breakpoint_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_ptrace.breakpoint",			/* tp_name */
	sizeof(struct pypt_breakpoint),		/* tp_basicsize */
	0,					/* tp_itemsize */
	0,					/* tp_dealloc */
	0,					/* tp_print */
	0,					/* tp_getattr */
	0,					/* tp_setattr */
	0,					/* tp_compare */
	(reprfunc)pypt_breakpoint__repr__,	/* tp_repr */
	0,					/* tp_as_number */
	0,					/* tp_as_sequence */
	0,					/* tp_as_mapping */
	0,					/* tp_hash */
	0,					/* tp_call */
	0,					/* tp_str */
	0,					/* tp_getattro */
	0,					/* tp_setattro */
	0,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT	|		/* tp_flags */
	Py_TPFLAGS_BASETYPE,
	"Process breakpoint",			/* tp_doc */
	0,					/* tp_traverse */
	0,					/* tp_clear */
	0,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	0,					/* tp_iter */
	0,					/* tp_iternext */
	pypt_breakpoint_methods,		/* tp_methods */
	pypt_breakpoint_members,		/* tp_members */
	0,					/* tp_getset */
	0,					/* tp_base */
	0,					/* tp_dict */
	0,					/* tp_descr_get */
	0,					/* tp_descr_set */
	0,					/* tp_dictoffset */
	(initproc)pypt_breakpoint_init,		/* tp_init */
	0,					/* tp_alloc */
	NULL,					/* tp_new */
};

static int
pypt_breakpoint_init(struct pypt_breakpoint *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = { "address", "handler", NULL };
	unsigned long long address = 0;
	PyObject *handler = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|KO:breakpoint",
	                                 kwlist, &address, &handler))
		return -1;

	pt_breakpoint_init(&self->breakpoint);
	self->breakpoint.address = (pt_address_t)address;
	self->handler = handler;

	return 0;
}

static PyObject *pypt_breakpoint__repr__(struct pypt_breakpoint *self)
{
	return PyString_FromFormat("<%s(%p) address:%p, handler:%p>",
		Py_TYPE(self)->tp_name, self,
		(void *)self->breakpoint.address, self->handler);
}
