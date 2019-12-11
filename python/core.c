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
 * core.c
 *
 * Python bindings for libptrace cores.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <stdint.h>
#include <python/Python.h>
#include <python/structmember.h>
#include <libptrace/error.h>
#include <libptrace/factory.h>
#include "compat.h"
#include "core.h"
#include "ptrace.h"
#include "thread.h"
#include "utils.h"
#include "../src/handle.h"

static int
pypt_core_init(struct pypt_core *self, PyObject *args, PyObject *kwds)
{
	int core_type;

	if (!PyArg_ParseTuple(args, "i", &core_type))
		return -1;

	if ( (self->core = pt_factory_core_new(core_type)) == NULL) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return -1;
	}

	return 0;
}

static PyObject *
pypt_core_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	struct pypt_core *self;

	if ( (self = (struct pypt_core *)type->tp_alloc(type, 0)) == NULL)
		return NULL;

	if ( (self->dict = PyDict_New()) == NULL) {
		Py_TYPE(self)->tp_free((PyObject*)self);
		return NULL;
	}

	self->core = NULL;

	return (PyObject *)self;
}

static void
pypt_core_dealloc(struct pypt_core *self)
{
	Py_XDECREF(self->dict);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
pypt_core_options_get(struct pypt_core *self, void *closure)
{
	return PyInt_FromLong(pt_core_options_get(self->core));
}

static int
pypt_core_options_set(struct pypt_core *self, PyObject *value, void *closure)
{
	long options;

	if (value == NULL) {
		PyErr_SetString(PyExc_TypeError, "Cannot delete the 'options' attribute.");
		return -1;
	}

	if (!py_num_check(value)) {
		PyErr_SetString(PyExc_TypeError,
		                "'value' must be an integer type.");
		return -1;
	}

	options = py_num_to_long(value);
	if (options == -1 && PyErr_Occurred())
		return -1;

	pt_core_options_set(self->core, options);

	return 0;
}

static PyObject *
process_to_handle(struct pt_process *process)
{
	PyObject *creation_time;
	PyObject *handle = NULL;
	PyObject *lit_64;
	PyObject *pid;
	PyObject *tmp;

	/* Prepare the handle. */
	if ( (pid = PyLong_FromUnsignedLong(process->pid)) == NULL)
		goto out;

	_Static_assert(sizeof(unsigned PY_LONG_LONG) == sizeof(uint64_t),
	               "sizeof(PY_LONG_LONG) != sizeof(uint64_t)");

	creation_time = PyLong_FromUnsignedLongLong(process->creation_time);
	if (creation_time == NULL)
		goto out_pid;

	if ( (lit_64 = PyInt_FromLong(64)) == NULL)
		goto out_creation_time;

	tmp = PyNumber_Lshift(pid, lit_64);
	if (tmp == NULL)
		goto out_lit_64;

	handle = PyNumber_Or(tmp, creation_time);

	Py_DECREF(tmp);
out_lit_64:
	Py_DECREF(lit_64);
out_creation_time:
	Py_DECREF(creation_time);
out_pid:
	Py_DECREF(pid);
out:
	return handle;
}

pt_handle_t
pyhandle_to_handle(PyObject *ph)
{
	pt_handle_process_t *process_handle;
	pt_handle_t handle;
	PyObject *mask;
	PyObject *tmp;

	process_handle = (pt_handle_process_t *)&handle;

	mask = PyLong_FromUnsignedLongLong((unsigned long long)-1);
	if (mask == NULL)
		return PT_HANDLE_NULL;

	if ( (tmp = PyNumber_Rshift(ph, PyInt_FromLong(64))) == NULL) {
		Py_DECREF(mask);
		return PT_HANDLE_NULL;
	}

	process_handle->pid = PyLong_AsUnsignedLongLong(tmp);
	Py_DECREF(tmp);

	tmp = PyNumber_And(ph, mask);
	Py_DECREF(mask);

	process_handle->creation_time = PyLong_AsUnsignedLongLong(tmp);
	Py_DECREF(tmp);

	return handle;
}

PyObject *pypt_core_process_attach(struct pypt_core *self, PyObject *args)
{
	struct pt_event_handlers handlers;
	struct pypt_process *pyprocess;
	struct pt_process *process;
	PyObject *process_args;
	PyObject *pyhandlers;
	int options, pid;

	if (!PyArg_ParseTuple(args, "iOi", &pid, &pyhandlers, &options))
		return NULL;

	if (!PyObject_TypeCheck(pyhandlers, &pypt_event_handlers_type)) {
		PyErr_SetString(PyExc_TypeError, "arg 2 must be _ptrace.event_handlers object");
		return NULL;
	}

	/* Set up all the python based handlers. */
	pt_event_handlers_init(&handlers);
	handlers.attached.handler      = pypt_handle_attached;
	handlers.process_exit.handler  = pypt_handle_process_exit;
	handlers.thread_create.handler = pypt_handle_thread_create;
	handlers.thread_exit.handler   = pypt_handle_thread_exit;
	handlers.module_load.handler   = pypt_handle_module_load;
	handlers.module_unload.handler = pypt_handle_module_unload;
	handlers.breakpoint            = pypt_handle_breakpoint;
	handlers.remote_break          = pypt_handle_remote_break;
	handlers.single_step           = pypt_handle_single_step;
	handlers.segfault              = pypt_handle_segfault;
	handlers.illegal_instruction   = pypt_handle_illegal_instruction;
	handlers.divide_by_zero        = pypt_handle_divide_by_zero;
	handlers.priv_instruction      = pypt_handle_priv_instruction;
	handlers.unknown_exception     = pypt_handle_unknown_exception;

	if ( (process_args = PyTuple_Pack(1, pyhandlers)) == NULL)
		return NULL;

        pyprocess = (struct pypt_process *)
                PyObject_CallObject((PyObject *)&pypt_process_type, process_args);

	Py_DECREF(process_args);

	if (pyprocess == NULL)
		return NULL;

	/* A possible thread remote call through the message queue can block,
	 * so we need to allow other python threads to run event handlers.
	 */
	if (self->core->c_op->attach == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	process = self->core->c_op->attach(self->core, pid, &handlers, options);
	Py_END_ALLOW_THREADS

	if (process == NULL) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	pyprocess->process = process;
	process->super_    = pyprocess;

	/* XXX: error check. */
	return process_to_handle(process);
}

PyObject *pypt_core_process_attach_remote(struct pypt_core *self, PyObject *args)
{
	Py_RETURN_NONE;
}

PyObject *pypt_core_main(struct pypt_core *self, PyObject *args)
{
	int ret;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = pt_core_main(self->core);
	Py_END_ALLOW_THREADS

	if (ret == -1) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	return PyInt_FromLong(ret);
}

PyObject *pypt_core_process_detach(struct pypt_core *self, PyObject *args)
{
	struct pypt_process *process;
	PyObject *object;

	if (!PyArg_ParseTuple(args, "O:process_detach", &object))
		return NULL;

	if (!PyObject_TypeCheck(object, &pypt_process_type)) {
		PyErr_SetString(PyExc_TypeError, "arg must be _ptrace.process object");
		return NULL;
	}

	process = (struct pypt_process *)object;

	if (pt_core_process_detach(self->core, process->process) == -1) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	Py_RETURN_NONE;
}

PyObject *pypt_core_process_detach_remote(struct pypt_core *self, PyObject *args)
{
	pt_handle_t handle;
	PyObject *object;

	if (!PyArg_ParseTuple(args, "O:process_detach_remote", &object))
		return NULL;

	if (!PyNumber_Check(object)) {
		PyErr_SetString(PyExc_TypeError, "arg must be numeric object");
		return NULL;
	}

	handle = pyhandle_to_handle(object);

	if (pt_core_process_detach_remote(self->core, handle) == -1) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	Py_RETURN_NONE;
}

PyObject *pypt_core_process_break(struct pypt_core *self, PyObject *args)
{
	struct pypt_process *process;
	PyObject *object;

	if (!PyArg_ParseTuple(args, "O:process_break", &object))
		return NULL;

	if (!PyObject_TypeCheck(object, &pypt_process_type)) {
		PyErr_SetString(PyExc_TypeError, "arg must be _ptrace.process object");
		return NULL;
	}

	process = (struct pypt_process *)object;

	if (pt_core_process_break(self->core, process->process) == -1) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	Py_RETURN_NONE;
}

PyObject *pypt_core_process_break_remote(struct pypt_core *self, PyObject *args)
{
	pt_handle_t handle;
	PyObject *object;

	if (!PyArg_ParseTuple(args, "O:process_break_remote", &object))
		return NULL;

	if (!PyNumber_Check(object)) {
		PyErr_SetString(PyExc_TypeError, "arg must be numeric object");
		return NULL;
	}

	handle = pyhandle_to_handle(object);

	if (pt_core_process_break_remote(self->core, handle) == -1) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		return NULL;
	}

	Py_RETURN_NONE;
}

PyObject *pypt_core_execv(struct pypt_core *self, PyObject *args)
{
	struct pt_event_handlers handlers;
	struct pypt_process *pyprocess;
	struct pt_process *process;
	PyObject *process_args;
	PyObject *pyhandlers;
	Py_ssize_t count, i;
	PyObject *pyargv;
	char *pathname;
	char **argv;
	int options;

	if (!PyArg_ParseTuple(args, "sOOi", &pathname, &pyargv, &pyhandlers, &options))
		goto err;

	if (!PyList_Check(pyargv)) {
		PyErr_SetString(PyExc_TypeError, "arg 2 must be a list object");
		goto err;
	}

	if (!PyObject_TypeCheck(pyhandlers, &pypt_event_handlers_type)) {
		PyErr_SetString(PyExc_TypeError, "arg 3 must be _ptrace.event_handlers object");
		goto err;
	}

	/* The first argument is the pathname, and must be present. */
	count = PyList_Size(pyargv);

	/* Allocate our argv array. */
	if ( (argv = malloc( (count + 1) * sizeof(char *))) == NULL) {
		pt_error_errno_set(errno);
		PyErr_SetString(pypt_exception, pt_error_strerror());
		goto err;
	}

	/* Populate argv. */
	for (i = 0; i < count; i++) {
		PyObject *item;

		if ( (item = PyList_GetItem(pyargv, i)) == NULL)
			goto err_argv;

		if (!py_string_check(item)) {
			PyErr_SetString(PyExc_TypeError, "Expected a string.");
			goto err_argv;
		}

		if ( (argv[i] = py_string_to_utf8(item)) == NULL)
			goto err_argv;
	}
	argv[i] = NULL;

	/* Set up all the python based handlers. */
	pt_event_handlers_init(&handlers);
	handlers.attached.handler      = pypt_handle_attached;
	handlers.process_exit.handler  = pypt_handle_process_exit;
	handlers.thread_create.handler = pypt_handle_thread_create;
	handlers.thread_exit.handler   = pypt_handle_thread_exit;
	handlers.module_load.handler   = pypt_handle_module_load;
	handlers.module_unload.handler = pypt_handle_module_unload;
	handlers.breakpoint            = pypt_handle_breakpoint;
	handlers.remote_break          = pypt_handle_remote_break;
	handlers.single_step           = pypt_handle_single_step;
	handlers.segfault              = pypt_handle_segfault;
	handlers.illegal_instruction   = pypt_handle_illegal_instruction;
	handlers.divide_by_zero        = pypt_handle_divide_by_zero;
	handlers.priv_instruction      = pypt_handle_priv_instruction;
	handlers.unknown_exception     = pypt_handle_unknown_exception;

        if ( (process_args = PyTuple_Pack(1, pyhandlers)) == NULL)
		goto err_argv;

        pyprocess = (struct pypt_process *)
                PyObject_CallObject((PyObject *)&pypt_process_type, process_args);

        Py_DECREF(process_args);

        if (pyprocess == NULL)
		goto err_argv;

	/* A possible thread remote call through the message queue can block,
	 * so we need to allow other python threads to run event handlers.
	 */
	if (self->core->c_op->execv == NULL) {
		pt_error_internal_set(PT_ERROR_UNSUPPORTED);
		return NULL;
	}

        Py_BEGIN_ALLOW_THREADS
	process = self->core->c_op->execv(self->core, pathname, (char * const *)argv, &handlers, options);
	Py_END_ALLOW_THREADS

	while (i-- > 0)
		free(argv[i]);
	free(argv);

	if (process == NULL) {
		PyErr_SetString(pypt_exception, pt_error_strerror());
		goto err;
	}

	pyprocess->process = process;
	process->super_    = pyprocess;

	return process_to_handle(process);

err_argv:
	while (i-- > 0)
		free(argv[i]);

	free(argv);
err:
	return NULL;
}

PyObject *pypt_core_execv_remote(struct pypt_core *self, PyObject *args)
{
	Py_RETURN_NONE;
}

PyObject *pypt_core_quit(struct pypt_core *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	pt_core_quit(self->core);

	Py_RETURN_NONE;
}

static PyObject *pypt_core__repr__(struct pypt_core *self)
{
	return PyString_FromFormat("<%s(%p)>", Py_TYPE(self)->tp_name, self);
}

static PyGetSetDef pypt_core_getset[] = {
	{ "__dict__", (getter)pypt_dict_get, (setter)pypt_dict_set, "The __dict__ for this core.", &pypt_core_type },
	{ "options", (getter)pypt_core_options_get, (setter)pypt_core_options_set, "Options for this code.", NULL },
	{ NULL }
};

static PyMethodDef pypt_core_methods[] = {
	{ "process_attach",        (PyCFunction)pypt_core_process_attach, METH_VARARGS, "Attach to a process." },
	{ "process_attach_remote", (PyCFunction)pypt_core_process_attach_remote, METH_VARARGS, "Attach to a process from a different thread." },
	{ "process_detach",        (PyCFunction)pypt_core_process_detach, METH_VARARGS, "Detach from a process." },
	{ "process_detach_remote", (PyCFunction)pypt_core_process_detach_remote, METH_VARARGS, "Detach from a process from a different thread." },
	{ "process_break",         (PyCFunction)pypt_core_process_break, METH_VARARGS, "Break a running process." },
	{ "process_break_remote",  (PyCFunction)pypt_core_process_break_remote, METH_VARARGS, "Break a running process from a different thread." },

	{ "main",                  (PyCFunction)pypt_core_main, METH_VARARGS, "Main loop." },
//	{ "event_wait",            (PyCFunction)pypt_core_event_wait, METH_VARARGS, "Wait for an event." },
	{ "execv",                 (PyCFunction)pypt_core_execv, METH_VARARGS, "Execute a process." },
	{ "execv_remote",          (PyCFunction)pypt_core_execv_remote, METH_VARARGS, "Execute a process from a different thread." },
	{ "quit",                  (PyCFunction)pypt_core_quit, METH_VARARGS, "Quit the main loop of this core." },
	{ NULL }
};

static PyMemberDef pypt_core_members[] = {
	{ NULL }
};

PyTypeObject pypt_core_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_ptrace.core",				/* tp_name */
	sizeof(struct pypt_core),		/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)pypt_core_dealloc,		/* tp_dealloc */
	0,					/* tp_print */
	0,					/* tp_getattr */
	0,					/* tp_setattr */
	0,					/* tp_compare */
	(reprfunc)pypt_core__repr__,		/* tp_repr */
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
	"Core object",				/* tp_doc */
	0,					/* tp_traverse */
	0,					/* tp_clear */
	0,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	0,					/* tp_iter */
	0,					/* tp_iternext */
	pypt_core_methods,			/* tp_methods */
	pypt_core_members,			/* tp_members */
	pypt_core_getset,			/* tp_getset */
	0,					/* tp_base */
	0,					/* tp_dict */
	0,					/* tp_descr_get */
	0,					/* tp_descr_set */
	offsetof(struct pypt_core, dict),	/* tp_dictoffset */
	(initproc)pypt_core_init,		/* tp_init */
	0,					/* tp_alloc */
	pypt_core_new,				/* tp_new */
};
