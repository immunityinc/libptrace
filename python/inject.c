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
 * inject.c
 *
 * Python bindings for libptrace injection.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <python/Python.h>
#include <python/structmember.h>
#include <libptrace/error.h>
#include <libptrace/inject.h>
#include <libptrace/log.h>
#include "compat.h"
#include "process.h"
#include "inject.h"
#include "utils.h"

static int pypt_inject_handler_pre_(struct pt_process *process, void *cookie)
{
	struct pypt_inject *self = (struct pypt_inject *)cookie;
	PyGILState_STATE gstate;
	PyObject *pyret;
	int ret;

	if (self->handler_pre == NULL) {
		/* XXX: raise an error. */
		return PT_EVENT_FORWARD;
	}

	gstate = PyGILState_Ensure();

	if (PyCallable_Check(self->handler_pre) == 0) {
		/* XXX: raise an error. */
		PyGILState_Release(gstate);
		return PT_EVENT_FORWARD;
	}

	/* Call the python handler function. */
	pyret = PyObject_CallFunctionObjArgs(
		self->handler_pre,
		process->super_,
		self->cookie_pre,
		NULL
	);

	if (pyret == NULL) {
		/* XXX: raise an error. */
		PyGILState_Release(gstate);
		return PT_EVENT_FORWARD;
	}

	/* Not an error, just the default. */
	if (pyret == Py_None) {
		Py_DECREF(pyret);
		PyGILState_Release(gstate);
		return PT_EVENT_FORWARD;
	}

	/* Convert the python return value into an integer. */
	ret = py_num_to_long(pyret);
	Py_DECREF(pyret);
	if (ret == -1 && PyErr_Occurred()) {
		/* XXX: raise an error. */
		PyGILState_Release(gstate);
		return PT_EVENT_FORWARD;
	}

	PyGILState_Release(gstate);
	return ret;
}

static int pypt_inject_handler_post_(struct pt_process *process, void *cookie)
{
	struct pypt_inject *self = (struct pypt_inject *)cookie;
	PyGILState_STATE gstate;
	PyObject *pyret;
	int ret;

	if (self->handler_post == NULL) {
		/* XXX: raise an error. */
		return PT_EVENT_FORWARD;
	}

	gstate = PyGILState_Ensure();

	if (PyCallable_Check(self->handler_post) == 0) {
		/* XXX: raise an error. */
		PyGILState_Release(gstate);
		return PT_EVENT_FORWARD;
	}

	/* Call the python handler function. */
	pyret = PyObject_CallFunctionObjArgs(
		self->handler_post,
		process->super_,
		self->cookie_post,
		NULL
	);

	if (pyret == NULL) {
		/* XXX: raise an error. */
		PyGILState_Release(gstate);
		return PT_EVENT_FORWARD;
	}

	/* Not an error, just the default. */
	if (pyret == Py_None) {
		PyGILState_Release(gstate);
		return PT_EVENT_FORWARD;
	}

	/* Convert the python return value into an integer. */
	ret = py_num_to_long(pyret);
	Py_DECREF(pyret);
	if (ret == -1 && PyErr_Occurred()) {
		/* XXX: raise an error. */
		PyGILState_Release(gstate);
		return PT_EVENT_FORWARD;
	}

	PyGILState_Release(gstate);
	return ret;
}

static int
pypt_inject_init(struct pypt_inject *self, PyObject *args, PyObject *kwds)
{
	if (!PyArg_ParseTuple(args, ""))
		return -1;

	Py_INCREF(Py_None);
	self->cookie_pre  = Py_None;
	Py_INCREF(Py_None);
	self->cookie_post = Py_None;

	return 0;
}

static PyObject *
pypt_inject_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	struct pypt_inject *self;

	if ( (self = (struct pypt_inject *)type->tp_alloc(type, 0)) == NULL)
		return NULL;

	self->dict = PyDict_New();

	if (!self->dict) {
		Py_TYPE(self)->tp_free((PyObject*)self);
		return NULL;
	}

	return (PyObject *)self;
}


static void
pypt_inject_dealloc(struct pypt_inject *self)
{
	Py_XDECREF(self->dict);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
pypt_inject_inject(struct pypt_inject *self, PyObject *args)
{
	struct pt_process *process;
	struct pt_inject inject;
	PyObject *pyprocess;
	int ret;

	if (!PyArg_ParseTuple(args, "O:inject.inject", &pyprocess))
		return NULL;

	/* Get the pt_process pointer. */
	if (PyObject_TypeCheck(pyprocess, &pypt_process_type) == 0)
		return NULL;
	process = ((struct pypt_process *)pyprocess)->process;

	/* Get the code and size of the code to inject. */
	ret = PyBytes_AsStringAndSize(
		self->data,
		(char **)&inject.data,
		(Py_ssize_t *)&inject.data_size
	);
	if (ret == -1)
		return NULL;

	/* Get the argument and size of the argument to inject. */
	ret = PyBytes_AsStringAndSize(
		self->data,
		(char **)&inject.argument,
		(Py_ssize_t *)&inject.argument_size
	);
	if (ret == -1)
		return NULL;

	/* Setup the inject structure. */
	inject.handler_pre  = pypt_inject_handler_pre_;
	inject.cookie_pre   = self;
	inject.handler_post = pypt_inject_handler_post_;
	inject.cookie_post  = self;

	/* Do not disappear until the callback is called. */
	Py_INCREF(self);

	if (pt_inject(&inject, process) == -1) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *pypt_inject__repr__(struct pypt_inject *self)
{
	return PyString_FromFormat("<%s(%p)>",
			Py_TYPE(self)->tp_name,
			self);
}

static PyGetSetDef pypt_inject_getset[] = {
	{"__dict__", (getter)pypt_dict_get, (setter)pypt_dict_set,
	 "The __dict__ for this injection object.", &pypt_inject_type},
	{ NULL }
};

static PyMethodDef pypt_inject_methods[] = {
        { "inject", (PyCFunction)pypt_inject_inject, METH_VARARGS, "Inject code into a process." },
	{ NULL }
};

static PyMemberDef pypt_inject_members[] = {
	{ "data", T_OBJECT, offsetof(struct pypt_inject, data), 0, "data" },
	{ "argument", T_OBJECT, offsetof(struct pypt_inject, argument), 0, "argument" },
	{ "handler_pre", T_OBJECT, offsetof(struct pypt_inject, handler_pre), 0, "handler_pre" },
	{ "handler_post", T_OBJECT, offsetof(struct pypt_inject, handler_post), 0, "handler_post" },
	{ NULL }
};

PyTypeObject pypt_inject_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_ptrace.inject",			/* tp_name */
	sizeof(struct pypt_inject),		/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)pypt_inject_dealloc,	/* tp_dealloc */
	0,					/* tp_print */
	0,					/* tp_getattr */
	0,					/* tp_setattr */
	0,					/* tp_compare */
	(reprfunc)pypt_inject__repr__,		/* tp_repr */
	0,					/* tp_as_number */
	0,					/* tp_as_sequence */
	0,					/* tp_as_mapping */
	0,					/* tp_hash */
	0,					/* tp_call */
	0,					/* tp_str */
	PyObject_GenericGetAttr,		/* tp_getattro */
	PyObject_GenericSetAttr,		/* tp_setattro */
	0,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT	|		/* tp_flags */
	Py_TPFLAGS_BASETYPE,
	"Inject object",			/* tp_doc */
	0,					/* tp_traverse */
	0,					/* tp_clear */
	0,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	0,					/* tp_iter */
	0,					/* tp_iternext */
	pypt_inject_methods,			/* tp_methods */
	pypt_inject_members,			/* tp_members */
	pypt_inject_getset,			/* tp_getset */
	0,					/* tp_base */
	0,					/* tp_dict */
	0,					/* tp_descr_get */
	0,					/* tp_descr_set */
	offsetof(struct pypt_inject, dict),	/* tp_dictoffset */
	(initproc)pypt_inject_init,		/* tp_init */
	0,					/* tp_alloc */
	pypt_inject_new,			/* tp_new */
};
