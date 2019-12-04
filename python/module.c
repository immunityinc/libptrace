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
 * module.c
 *
 * Python bindings for libptrace dynamically loaded modules.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <python/Python.h>
#include <python/structmember.h>
#include "compat.h"
#include "module.h"
#include "utils.h"

static int
pypt_module_init(struct pypt_module *self, PyObject *args, PyObject *kwds)
{
	if (!PyArg_ParseTuple(args, ""))
		return -1;

	return 0;
}

static PyObject *
pypt_module_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	struct pypt_module *self;

	if ((self = (struct pypt_module *)type->tp_alloc(type, 0)) == NULL)
		return NULL;

        self->dict = PyDict_New();

	if (!self->dict) {
		Py_TYPE(self)->tp_free((PyObject *)self);
		return NULL;
	}

	self->process = NULL;
	return (PyObject *)self;
}

static void
pypt_module_dealloc(struct pypt_module *self)
{
	/* If this module is associated with a process, we release the
	 * reference we hold on it.
	 */
	Py_XDECREF(self->process);
	Py_XDECREF(self->dict);

	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
pypt_module_base_get(struct pypt_module *self, void *closure)
{
	return PyInt_FromSize_t((size_t)self->module->base);
}


static PyObject *
pypt_module_exports_get(struct pypt_module *self, PyObject *args)
{
	struct pt_module_exports exports;
	PyObject *exports_dict;
	PyObject *integer;
	size_t i;
	int ret;

	/* Allocate new dictionary. */
	if ( (exports_dict = PyDict_New()) == NULL)
		goto err;

	/* Get all the exports.  If this fails, return an empty dictionary.
	 * XXX: better error handling.
	 */
	ret = pt_module_exports_get(self->module->process,
	                            self->module, &exports);
	if (ret == -1)
		return exports_dict;

	/* Populate the dictionary with exports. */
	for (i = 0; i < exports.count; i++) {
		integer = PyInt_FromSize_t((size_t)exports.addresses[i]);
		if (integer == NULL)
			goto err_free;

		ret = PyDict_SetItemString(exports_dict, exports.strings[i], integer);
		if (ret == -1) {
			Py_DECREF(integer);
			goto err_free;
		}

		Py_DECREF(integer);
	}

	return exports_dict;

err_free:
	pt_module_exports_delete(&exports);
	Py_DECREF(exports_dict);
err:
	return NULL;
}

static PyObject *
pypt_module_name_get(struct pypt_module *self, void *closure)
{
	if (self->module->name == NULL) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	return PyString_FromString(self->module->name);
}

static PyObject *
pypt_module_path_get(struct pypt_module *self, void *closure)
{
	if (self->module->pathname == NULL) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	return PyString_FromString(self->module->pathname);
}

static PyObject *
pypt_module_export_find(struct pypt_module *self, PyObject *args)
{
	pt_address_t result;
	char *symbol;

	if (!PyArg_ParseTuple(args, "s:module", &symbol))
		return NULL;

	result = pt_module_export_find(self->module->process, self->module, symbol);
	if (result == PT_ADDRESS_NULL) {
		PyErr_SetString(PyExc_KeyError, symbol);
		return NULL;
	}

	return PyInt_FromSize_t((size_t)result);
}

static PyGetSetDef pypt_module_getset[] = {
	{"__dict__", (getter)pypt_dict_get, (setter)pypt_dict_set,
	 "The __dict__ for this module.", &pypt_module_type},
  	{ "base", (getter)pypt_module_base_get, NULL, "module base", NULL },
	{ "exports", (getter)pypt_module_exports_get, NULL, "module exports", NULL },
	{ "name", (getter)pypt_module_name_get, NULL, "module name", NULL },
	{ "path", (getter)pypt_module_path_get, NULL, "module path", NULL },
	{ NULL }
};

static PyMethodDef pypt_module_methods[] = {
	{ "export_find", (PyCFunction)pypt_module_export_find, METH_VARARGS, "Find an exported symbol." },
	{ NULL }
};

static PyMemberDef pypt_module_members[] = {
	{ NULL }
};


static PyObject *pypt_module__repr__(struct pypt_module *self)
{
	return PyString_FromFormat("<%s(%p) at %p as %s from %s>",
				   Py_TYPE(self)->tp_name, self,
				   (void *)self->module->base,
				   self->module->name,
				   self->module->pathname);
}

PyTypeObject pypt_module_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_ptrace.module",			/* tp_name */
	sizeof(struct pypt_module),		/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)pypt_module_dealloc,	/* tp_dealloc */
	0,					/* tp_print */
	0,					/* tp_getattr */
	0,					/* tp_setattr */
	0,					/* tp_compare */
	(reprfunc)pypt_module__repr__,		/* tp_repr */
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
	"Module object",			/* tp_doc */
	0,					/* tp_traverse */
	0,					/* tp_clear */
	0,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	0,					/* tp_iter */
	0,					/* tp_iternext */
	pypt_module_methods,			/* tp_methods */
	pypt_module_members,			/* tp_members */
	pypt_module_getset,			/* tp_getset */
	0,					/* tp_base */
	0,					/* tp_dict */
	0,					/* tp_descr_get */
	0,					/* tp_descr_set */
	offsetof(struct pypt_module, dict),	/* tp_dictoffset */
	(initproc)pypt_module_init,		/* tp_init */
	0,					/* tp_alloc */
	pypt_module_new,			/* tp_new */
};
