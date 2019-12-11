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
 * process.c
 *
 * Python bindings for libptrace processes.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <python/Python.h>
#include <python/structmember.h>
#include <libptrace/error.h>
#include "../src/windows/process.h"

#include "compat.h"
#include "breakpoint.h"
#include "event.h"
#include "module.h"
#include "ptrace.h"
#include "thread.h"
#include "utils.h"

_Static_assert(sizeof(unsigned long long) == sizeof(uint64_t), "T_ULONGLONG is not 64-bit");

static PyObject *
pypt_process_pid_get(struct pypt_process *self, void *closure)
{
	return PyInt_FromLong(pt_process_pid_get(self->process));
}

static PyObject *
pypt_process_creation_time_get(struct pypt_process *self, void *closure)
{
	return PyLong_FromUnsignedLongLong(self->process->creation_time);
}

int
pypt_process_init(struct pypt_process *self, PyObject *args, PyObject *kwds)
{
	PyObject *handlers;

	if (!PyArg_ParseTuple(args, "O:process.__init__", &handlers))
		return -1;

	if (!PyObject_TypeCheck(handlers, &pypt_event_handlers_type)) {
		PyErr_SetString(PyExc_TypeError, "arg must be _ptrace.event_handlers object");
		return -1;
	}

	if (self->handlers != NULL)
		Py_DECREF(self->handlers);

	Py_INCREF(handlers);
	self->handlers = (struct pypt_event_handlers *)handlers;

	return 0;
}

static PyObject *
pypt_process_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	struct pypt_process *self;

	if ( (self = (struct pypt_process *)type->tp_alloc(type, 0)) == NULL)
		goto err;

	if ( (self->dict = PyDict_New()) == NULL)
		goto err_free;

	if ( (self->threads = PyList_New(0)) == NULL)
		goto err_dict;

	if ( (self->modules = PyList_New(0)) == NULL)
		goto err_threads;

	self->process = NULL;

	/* Initialize the event handlers.
	 * XXX: break this up in New() and Init()
	 */
	self->handlers = (struct pypt_event_handlers *)
		PyObject_CallObject((PyObject *)&pypt_event_handlers_type, NULL);
	if (self->handlers == NULL)
		goto err_modules;

	return (PyObject *)self;

err_modules:
	Py_DECREF(self->modules);
err_threads:
	Py_DECREF(self->threads);
err_dict:
	Py_DECREF(self->dict);
err_free:
	Py_TYPE(self)->tp_free((PyObject*)self);
err:
	return NULL;
}

static void
pypt_process_dealloc(struct pypt_process *self)
{
	Py_XDECREF(self->dict);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
pypt_process_breakpoint_find(struct pypt_process *self, PyObject *args)
{
	struct pypt_breakpoint *pybp;
	unsigned long long address;
	struct pt_breakpoint *bp;

	if (!PyArg_ParseTuple(args, "K:process.breakpoint_find", &address))
		return NULL;

	bp = pt_process_breakpoint_find(self->process, (pt_address_t)address);
	if (bp == NULL) {
		if (pt_error_internal_test(PT_ERROR_NOT_FOUND))
			Py_RETURN_NONE;

		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	/* XXX: ugly, should toss this in a macro or so. */
	pybp = (struct pypt_breakpoint *)
		((uint8_t *)bp - offsetof(struct pypt_breakpoint, breakpoint));
	Py_INCREF(pybp);
	return (PyObject *)pybp;
}

static PyObject *
pypt_process_breakpoint_set(struct pypt_process *self, PyObject *args)
{
	struct pypt_breakpoint *b;
	PyObject *object;

	if (!PyArg_ParseTuple(args, "O:process.breakpoint_set", &object))
		return NULL;

	if (!PyObject_TypeCheck(object, &pypt_breakpoint_type)) {
		PyErr_SetString(PyExc_TypeError, "arg must be _ptrace.breakpoint object");
		return NULL;
	}

	b = (struct pypt_breakpoint *)object;

	if (pt_process_breakpoint_set(self->process, &b->breakpoint) == -1) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	Py_INCREF(object);
	Py_RETURN_NONE;
}

static PyObject *
pypt_process_breakpoint_unset(struct pypt_process *self, PyObject *args)
{
	struct pypt_breakpoint *b;
	PyObject *object;
	int ret;

	if (!PyArg_ParseTuple(args, "O:process", &object))
		return NULL;

	if (!PyObject_TypeCheck(object, &pypt_breakpoint_type)) {
		PyErr_SetString(PyExc_TypeError,
		                "arg must be _ptrace.breakpoint object");
		return NULL;
	}

	b = (struct pypt_breakpoint *)object;

	ret = pt_process_breakpoint_remove(self->process, &b->breakpoint);
	if (ret == -1) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	Py_DECREF(object);
	Py_RETURN_NONE;
}

static PyObject *
pypt_process_export_find(struct pypt_process *self, PyObject *args)
{
	pt_address_t result;
	char *symbol;

	if (!PyArg_ParseTuple(args, "s:process", &symbol))
		return NULL;

	result = pt_process_export_find(self->process, symbol);
	if (result == PT_ADDRESS_NULL) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	return (void *)PyInt_FromSize_t((size_t)result);
}

static PyObject *
pypt_process_read(struct pypt_process *self, PyObject *args)
{
	unsigned long long address;
	PyObject *object;
	Py_ssize_t size;
	char *p;

	if (!PyArg_ParseTuple(args, "Kn:process_read", &address, &size))
		return NULL;

	if ( (p = malloc(size)) == NULL) {
		pt_error_errno_set(errno);
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	if (pt_process_read(self->process, p, (pt_address_t)address, size) == -1) {
		free(p);
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	object = PyBytes_FromStringAndSize(p, size);
	free(p);

	return object;
}

static PyObject *
pypt_process_read_utf8(struct pypt_process *self, PyObject *args)
{
	unsigned long long address;
	PyObject *object;
	char *p;

	if (!PyArg_ParseTuple(args, "K:process_read_utf8", &address))
		return NULL;

	p = pt_process_read_string(self->process, (pt_address_t)address);
	if (p == NULL) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	object = PyString_FromString(p);
	free(p);

	return object;
}

static PyObject *
pypt_process_read_utf16(struct pypt_process *self, PyObject *args)
{
	unsigned long long address;
	PyObject *object;
	char *p;

	if (!PyArg_ParseTuple(args, "K:process_read_utf16", &address))
		return NULL;

	p = pt_process_read_string_utf16(self->process, (pt_address_t)address);
	if (p == NULL) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	object = PyString_FromString(p);
	free(p);

	return object;
}

static PyObject *
pypt_process_resume(struct pypt_process *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	if (pt_process_resume(self->process) == -1) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *
pypt_process_suspend(struct pypt_process *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	if (pt_process_suspend(self->process) == -1) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *
pypt_process_mmap(struct pypt_process *self, PyObject *args)
{
	PyTypeObject *type;
	struct pypt_mmap *mmap;

	if (self->mmap)
		goto good;

	type = (PyTypeObject *) &pypt_mmap_type;
	mmap = (struct pypt_mmap *)type->tp_alloc(type, 0);

	if(!mmap)
		goto err;

	pt_mmap_load(self->process);

	Py_INCREF(self);
	mmap->mmap = &self->process->mmap;
	mmap->pyprocess = self;
	Py_INCREF(mmap);
	self->mmap = (PyObject *)mmap;

good:
	return self->mmap;
err:
	return NULL;
}

static PyObject *
pypt_process_option_set(struct pypt_process *self, PyObject *args)
{
	int option;

	if (!PyArg_ParseTuple(args, "i:process_option_set", &option))
		return NULL;

	if (pt_process_option_set(self->process, option) == -1) {
		PyErr_SetString(PyExc_ValueError, "invalid option.");
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *
pypt_process_brk(struct pypt_process *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	if (pt_process_brk(self->process) == -1) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *
pypt_process_thread_create(struct pypt_process *self, PyObject *args)
{
	unsigned long long handler, cookie;
	int ret;

	ret = PyArg_ParseTuple(args, "KK:process_thread_create",
	                       &handler, &cookie);
	if (ret == 0)
		return NULL;

	ret = pt_process_thread_create(self->process, (pt_address_t)handler,
	                               (pt_address_t)cookie);
	if (ret == -1) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *
pypt_process_malloc(struct pypt_process *self, PyObject *args)
{
	pt_address_t ret;
	Py_ssize_t size;

	if (PyArg_ParseTuple(args, "n:process_malloc", &size) == 0)
		return NULL;

	ret = pt_process_malloc(self->process, (size_t)size);
	if (ret == PT_ADDRESS_NULL) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	return PyInt_FromSize_t((size_t)ret);
}

static PyObject *
pypt_process_free(struct pypt_process *self, PyObject *args)
{
	unsigned long long address;
	int ret;

	ret = PyArg_ParseTuple(args, "K:process_free", &address);
	if (ret == 0)
		return NULL;

	ret = pt_process_free(self->process, (pt_address_t)address);
	if (ret == -1) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *
pypt_process_name_get(struct pypt_process *self, void *closure)
{
	struct pt_process *process = self->process;

	if (process->main_module == NULL)
		Py_RETURN_NONE;

	if (process->main_module->name == NULL)
		Py_RETURN_NONE;

        return PyString_FromString(process->main_module->name);
}

static PyMethodDef pypt_process_methods[] = {
	{ "brk", (PyCFunction)pypt_process_brk, METH_VARARGS, "Debug break the process remotely." },
	{ "breakpoint_find", (PyCFunction)pypt_process_breakpoint_find, METH_VARARGS, "Find a breakpoint." },
	{ "breakpoint_set", (PyCFunction)pypt_process_breakpoint_set, METH_VARARGS, "Set a breakpoint." },
	{ "breakpoint_unset", (PyCFunction)pypt_process_breakpoint_unset, METH_VARARGS, "Unset a breakpoint." },
	{ "export_find", (PyCFunction)pypt_process_export_find, METH_VARARGS, "Find an exported symbol." },
	{ "read", (PyCFunction)pypt_process_read, METH_VARARGS, "Read process memory." },
	{ "read_utf8", (PyCFunction)pypt_process_read_utf8, METH_VARARGS, "Read a UTF-8 string from process memory." },
	{ "read_utf16", (PyCFunction)pypt_process_read_utf16, METH_VARARGS, "Read a UTF-16 string from process memory." },
	{ "resume", (PyCFunction)pypt_process_resume, METH_VARARGS, "Resume all threads in the process." },
	{ "suspend", (PyCFunction)pypt_process_suspend, METH_VARARGS, "Suspend all threads in the process." },
	{ "mmap", (PyCFunction)pypt_process_mmap, METH_VARARGS, "Get the area list of the process." },
	{ "option_set", (PyCFunction)pypt_process_option_set, METH_VARARGS, "Set process options." },
	{ "thread_create", (PyCFunction)pypt_process_thread_create, METH_VARARGS, "Create a remote thread." },
	{ "malloc", (PyCFunction)pypt_process_malloc, METH_VARARGS, "Allocate memory in process." },
	{ "free", (PyCFunction)pypt_process_free, METH_VARARGS, "Free memory in process." },
	{ NULL }
};

static PyMemberDef pypt_process_members[] = {
	{ "handlers", T_OBJECT, offsetof(struct pypt_process, handlers), READONLY, "event handlers" },
	{ "modules", T_OBJECT, offsetof(struct pypt_process, modules), READONLY, "module list" },
	{ "threads", T_OBJECT, offsetof(struct pypt_process, threads), READONLY, "thread list" },
	{ NULL }
};

static PyGetSetDef pypt_process_getset[] = {
	{ "__dict__",      (getter)pypt_dict_get, (setter)pypt_dict_set, "The __dict__ for this process.", &pypt_process_type },
	{ "creation_time", (getter)pypt_process_creation_time_get, NULL, "process creation time", NULL },
	{ "id",            (getter)pypt_process_pid_get,           NULL, "process id",            NULL },
        { "name",          (getter)pypt_process_name_get,          NULL, "process name",          NULL },
	{ NULL }
};

static char *process_state_[] = {
	[PT_PROCESS_STATE_INIT]          = "PT_PROCESS_STATE_INIT",
	[PT_PROCESS_STATE_CREATED]       = "PT_PROCESS_STATE_CREATED",
	[PT_PROCESS_STATE_ATTACHED]      = "PT_PROCESS_STATE_ATTACHED",
	[PT_PROCESS_STATE_DETACH_BOTTOM] = "PT_PROCESS_STATE_DETACH_BOTTOM",
	[PT_PROCESS_STATE_DETACH_TOP]    = "PT_PROCESS_STATE_DETACH_TOP",
	[PT_PROCESS_STATE_DETACHED]      = "PT_PROCESS_STATE_DETACHED",
	[PT_PROCESS_STATE_EXITED]        = "PT_PROCESS_STATE_EXITED"
};

static PyObject *pypt_process__repr__(struct pypt_process *self)
{
	return PyString_FromFormat("<%s(%p) pid:%d %s>",
				   Py_TYPE(self)->tp_name, self,
				   pt_process_pid_get(self->process),
				   process_state_[self->process->state]);
}

PyTypeObject pypt_process_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_ptrace.process",			/* tp_name */
	sizeof(struct pypt_process),		/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)pypt_process_dealloc,	/* tp_dealloc */
	0,					/* tp_print */
	0,					/* tp_getattr */
	0,					/* tp_setattr */
	0,					/* tp_compare */
	(reprfunc)pypt_process__repr__,		/* tp_repr */
	0,					/* tp_as_number */
	0,					/* tp_as_sequence */
	0,					/* tp_as_mapping */
	0,					/* tp_hash */
	0,					/* tp_call */
	0,					/* tp_str */
	PyObject_GenericGetAttr,		/* tp_getattro */
	PyObject_GenericSetAttr,	        /* tp_setattro */
	0,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT	|		/* tp_flags */
	Py_TPFLAGS_BASETYPE,
	"Process object",			/* tp_doc */
	0,					/* tp_traverse */
	0,					/* tp_clear */
	0,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	0,					/* tp_iter */
	0,					/* tp_iternext */
	pypt_process_methods,			/* tp_methods */
	pypt_process_members,			/* tp_members */
	pypt_process_getset,			/* tp_getset */
	0,					/* tp_base */
	0,					/* tp_dict */
	0,					/* tp_descr_get */
	0,					/* tp_descr_set */
	offsetof(struct pypt_process, dict),	/* tp_dictoffset */
	(initproc)pypt_process_init,		/* tp_init */
	0,					/* tp_alloc */
	pypt_process_new,			/* tp_new */
};
