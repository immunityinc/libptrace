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
 * cconv.c
 *
 * Python bindings for libptrace calling conventions.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <stdint.h>
#include <python/Python.h>
#include <python/structmember.h>
#include <libptrace/thread.h>
#include <libptrace/error.h>
#include "../src/windows/cconv.h"

#include "compat.h"
#include "cconv.h"
#include "thread.h"
#include "utils.h"

static int
pypt_cconv_init(struct pypt_cconv *self, PyObject *args, PyObject *kwds)
{
	if (!PyArg_ParseTuple(args, ""))
		return -1;

	return 0;
}

static PyObject *
pypt_cconv_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	struct pypt_cconv *self;

	if ( (self = (struct pypt_cconv *)type->tp_alloc(type, 0)) == NULL)
		return NULL;

	self->dict = PyDict_New();

	if (!self->dict) {
		Py_TYPE(self)->tp_free((PyObject *)self);
		return NULL;
	}

	return (PyObject *)self;
}

static void
pypt_cconv_dealloc(struct pypt_cconv *self)
{
	Py_XDECREF(self->dict);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static const char fmt_valid_[] = "diulpz";

static PyObject *
pypt_cconv_args_get(PyObject *cls, PyObject *args)
{
	struct pypt_thread *thread;
	pt_register_t *argv;
	PyObject *ret;
	char *fmt, *p;
	int argc, i;

	if (!PyArg_ParseTuple(args, "Os:cconv.args_get", &thread, &fmt))
		return NULL;

	if (!PyObject_TypeCheck(thread, &pypt_thread_type)) {
		PyErr_SetString(PyExc_TypeError, "arg must be _ptrace.thread object");
		return NULL;
	}

	/* XXX: for now the format string is ignored. */
	argc = 0;

	for (p = fmt; *p != 0; p++) {
		if (p[0] != '%') continue;

		if (p[1] == 0 || strchr(fmt_valid_, p[1]) == NULL) {
			PyErr_SetString(PyExc_TypeError, "invalid format string");
			return NULL;
		}

		argc++;
	}

	/* Allocate argv space. */
	if ( (argv = malloc(argc * sizeof *argv)) == NULL)
		return NULL;

	/* XXX: for now, static compilation dependent on arch. */
	if (pt_cconv_function_argv_get(thread->thread, argc, argv) == -1) {
		free(argv);
		PyErr_SetString(PyExc_IOError, "pt_cconv_function_argv_get failed");
		return NULL;
	}

	/* New tuple to return the arguments in. */
	if ( (ret = PyTuple_New(argc)) == NULL) {
		free(argv);
		return NULL;
	}

	/* Populate the tuple. */
	i = 0;

	for (p = fmt; *p != 0; p++) {
		PyObject *integer = NULL;

		if (p[0] != '%') continue;

		switch (p[1]) {
		case 'd':
		case 'i':
			integer = PyInt_FromLong((long)argv[i]);
			break;
		case 'u':
			integer = PyInt_FromSize_t((size_t)(unsigned int)argv[i]);
			break;
		case 'l':
			integer = PyLong_FromLong((long)argv[i]);
			break;
		case 'p':
		case 'z':
			integer = PyInt_FromSize_t((size_t)argv[i]);
			break;
		}

		if (integer == NULL) {
			free(argv);
			Py_DECREF(ret);
			return NULL;
		}

		assert(i >= 0 && i < argc);
		if (PyTuple_SetItem(ret, i, integer) != 0) {
			free(argv);
			Py_DECREF(ret);
			return NULL;
		}

		i++;
	}

	free(argv);
	return ret;
}

static PyObject *
pypt_cconv_retaddr_get(PyObject *cls, PyObject *args)
{
	struct pypt_thread *thread;
	pt_register_t retaddr;

	if (!PyArg_ParseTuple(args, "O:cconv.retaddr_get", &thread))
		return NULL;

	if (!PyObject_TypeCheck(thread, &pypt_thread_type)) {
		PyErr_SetString(PyExc_TypeError, "arg must be _ptrace.thread object");
		return NULL;
	}

	/* XXX: for now, static compilation dependent on arch. */
	retaddr = pt_cconv_function_retaddr_get(thread->thread);
	if (retaddr == -1 && pt_error_is_set()) {
		PyErr_SetString(PyExc_IOError, "pt_cconv_function_retaddr_get failed");
		return NULL;
	}

	return PyInt_FromSize_t((size_t)retaddr);
}

static PyObject *
pypt_cconv_retval_get(PyObject *cls, PyObject *args)
{
	struct pypt_thread *thread;
	pt_register_t retval;

	if (!PyArg_ParseTuple(args, "O:cconv.retval_get", &thread))
		return NULL;

	if (!PyObject_TypeCheck(thread, &pypt_thread_type)) {
		PyErr_SetString(PyExc_TypeError, "arg must be _ptrace.thread object");
		return NULL;
	}

	/* XXX: for now, static compilation dependent on arch. */
	retval = pt_cconv_function_retval_get(thread->thread);
	if (retval == -1 && pt_error_is_set()) {
		PyErr_SetString(PyExc_IOError, "pt_cconv_function_retval_get failed");
		return NULL;
	}

	return PyInt_FromSize_t((size_t)retval);
}

static PyGetSetDef pypt_cconv_getset[] = {
	{"__dict__", (getter)pypt_dict_get, (setter)pypt_dict_set,
	 "The __dict__ for this cconv.", &pypt_cconv_type},
	{ NULL }
};

static PyMethodDef pypt_cconv_methods[] = {
	/* Class methods. */
	{ "args_get", (PyCFunction)pypt_cconv_args_get, METH_VARARGS | METH_CLASS, "Get function arguments." },
	{ "retaddr_get", (PyCFunction)pypt_cconv_retaddr_get, METH_VARARGS | METH_CLASS, "Get function return address." },
	{ "retval_get", (PyCFunction)pypt_cconv_retval_get, METH_VARARGS | METH_CLASS, "Get function return address." },
	{ NULL }
};

static PyMemberDef pypt_cconv_members[] = {
	{ NULL }
};

PyTypeObject pypt_cconv_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_ptrace.cconv",		        /* tp_name */
	sizeof(struct pypt_cconv),		/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)pypt_cconv_dealloc,		/* tp_dealloc */
	0,					/* tp_print */
	0,					/* tp_getattr */
	0,					/* tp_setattr */
	0,					/* tp_compare */
	0,					/* tp_repr */
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
	"Calling convention object",		/* tp_doc */
	0,					/* tp_traverse */
	0,					/* tp_clear */
	0,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	0,					/* tp_iter */
	0,					/* tp_iternext */
	pypt_cconv_methods,			/* tp_methods */
	pypt_cconv_members,			/* tp_members */
	pypt_cconv_getset,			/* tp_getset */
	0,					/* tp_base */
	0,					/* tp_dict */
	0,					/* tp_descr_get */
	0,					/* tp_descr_set */
	offsetof(struct pypt_cconv, dict),	/* tp_dictoffset */
	(initproc)pypt_cconv_init,		/* tp_init */
	0,					/* tp_alloc */
	pypt_cconv_new,				/* tp_new */
};
