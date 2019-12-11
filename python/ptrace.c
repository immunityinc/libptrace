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
 * ptrace.c
 *
 * Python bindings for libptrace.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <python/Python.h>
#include <python/structmember.h>
#include <libptrace/core.h>
#include <libptrace/error.h>
#include <libptrace/factory.h>
#include <libptrace/util.h>
#include "compat.h"
#include "core.h"
#include "event.h"
#include "breakpoint.h"
#include "breakpoint_sw.h"
#include "cconv.h"
#include "log.h"
#include "module.h"
#include "process.h"
#include "thread.h"
#include "inject.h"
#include "../src/core.h"

#define MODULE      _ptrace
#define MODULE_NAME "_ptrace"

PyObject *pypt_exception;
struct pypt_core *pypt_core_main_;

static PyObject *pypt_process_attach(PyObject *, PyObject *);
static PyObject *pypt_process_attach_remote(PyObject *self, PyObject *args);
static PyObject *pypt_process_detach(PyObject *, PyObject *);
static PyObject *pypt_process_detach_remote(PyObject *, PyObject *);
static PyObject *pypt_process_break(PyObject *self, PyObject *args);
static PyObject *pypt_process_break_remote(PyObject *self, PyObject *args);

static PyObject *pypt_execv(PyObject *, PyObject *);
static PyObject *pypt_log_hook_add(PyObject *, PyObject *);
static PyObject *pypt_log_hook_del(PyObject *, PyObject *);
static PyObject *pypt_main(PyObject *, PyObject *);
static PyObject *pypt_processes(PyObject *, PyObject *);
static PyObject *pypt_quit(PyObject *, PyObject *);

static PyMethodDef pypt_ptrace_module_methods[] = {
	{ "process_attach",        (PyCFunction)pypt_process_attach, METH_VARARGS, "Attach to a process." },
	{ "process_attach_remote", (PyCFunction)pypt_process_attach_remote, METH_VARARGS, "Attach to a process from a different thread." },
	{ "process_detach",        (PyCFunction)pypt_process_detach, METH_VARARGS, "Detach from a process." },
	{ "process_detach_remote", (PyCFunction)pypt_process_detach_remote, METH_VARARGS, "Detach from a process from a different thread." },
	{ "process_break",         (PyCFunction)pypt_process_break, METH_VARARGS, "Break a running process." },
	{ "process_break_remote",  (PyCFunction)pypt_process_break_remote, METH_VARARGS, "Break a running process from a different thread." },

	{ "execv", pypt_execv, METH_VARARGS, "Execute a process." },
	{ "log_hook_add", pypt_log_hook_add, METH_VARARGS, "Adds a logger hook." },
	{ "log_hook_del", pypt_log_hook_del, METH_VARARGS, "Deletes a logger hook." },
	{ "main", pypt_main, METH_VARARGS, "Main event loop." },
	{ "processes", pypt_processes, METH_VARARGS, "Get a list of attached processes." },
	{ "quit", pypt_quit, METH_VARARGS, "Quit main event loop." },
	{ NULL }
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef pypt_module_def = {
	PyModuleDef_HEAD_INIT,
	MODULE_NAME,			/* m_name */
	NULL,				/* m_doc */
	-1,				/* m_size */
	pypt_ptrace_module_methods,	/* m_methods */
	NULL,				/* m_reload */
	NULL,				/* m_traverse */
	NULL,				/* m_clear */
	NULL,				/* m_free */
};
#endif

static void add_constants(PyObject *m)
{
	PyObject *i;

	if ( (i = PyInt_FromLong(PT_CORE_OPTION_NONE)) != NULL)
		PyModule_AddObject(m, "PROCESS_OPTION_NONE", i);

	if ( (i = PyInt_FromLong(PT_CORE_OPTION_EVENT_SECOND_CHANCE)) != NULL)
		PyModule_AddObject(m, "PROCESS_OPTION_EVENT_SECOND_CHANCE", i);

	if ( (i = PyInt_FromLong(PT_FACTORY_CORE_WINDOWS)) != NULL)
		PyModule_AddObject(m, "CORE_WINDOWS", i);
}

PyMODINIT_FUNC MODULE_INIT_FUNC_NAME(MODULE)(void)
{
	PyObject *m;

	pypt_breakpoint_type.tp_new = PyType_GenericNew;

	pypt_exception = PyErr_NewException(MODULE_NAME ".error", NULL, NULL);
	if (pypt_exception == NULL)
		MODULE_INIT_FUNC_RETURN(NULL);

	if (PyType_Ready(&pypt_breakpoint_type) < 0)
		MODULE_INIT_FUNC_RETURN(NULL);

	if (PyType_Ready(&pypt_breakpoint_sw_type) < 0)
		MODULE_INIT_FUNC_RETURN(NULL);

	if (PyType_Ready(&pypt_core_type) < 0)
		MODULE_INIT_FUNC_RETURN(NULL);

	if (PyType_Ready(&pypt_log_hook_type) < 0)
		MODULE_INIT_FUNC_RETURN(NULL);

	if (PyType_Ready(&pypt_module_type) < 0)
		MODULE_INIT_FUNC_RETURN(NULL);

	if (PyType_Ready(&pypt_process_type) < 0)
		MODULE_INIT_FUNC_RETURN(NULL);

	if (PyType_Ready(&pypt_thread_type) < 0)
		MODULE_INIT_FUNC_RETURN(NULL);

	if (PyType_Ready(&pypt_cconv_type) < 0)
		MODULE_INIT_FUNC_RETURN(NULL);

	if (PyType_Ready(&pypt_mmap_type) < 0)
		MODULE_INIT_FUNC_RETURN(NULL);

	if (PyType_Ready(&pypt_event_handlers_type) < 0)
		MODULE_INIT_FUNC_RETURN(NULL);

	if (PyType_Ready(&pypt_inject_type) < 0)
		MODULE_INIT_FUNC_RETURN(NULL);

#if PY_MAJOR_VERSION >= 3
	m = PyModule_Create(&pypt_module_def);
#else
	m = Py_InitModule(MODULE_NAME, pypt_ptrace_module_methods);
#endif

	add_constants(m);

	Py_INCREF(&pypt_breakpoint_type);
	PyModule_AddObject(m, "breakpoint", (PyObject *)&pypt_breakpoint_type);
	Py_INCREF(&pypt_breakpoint_sw_type);
	PyModule_AddObject(m, "breakpoint_sw", (PyObject *)&pypt_breakpoint_sw_type);
	Py_INCREF(&pypt_cconv_type);
	PyModule_AddObject(m, "cconv", (PyObject *)&pypt_cconv_type);
	Py_INCREF(&pypt_core_type);
	PyModule_AddObject(m, "core", (PyObject *)&pypt_core_type);
	Py_INCREF(&pypt_event_handlers_type);
	PyModule_AddObject(m, "event_handlers", (PyObject *)&pypt_event_handlers_type);
	Py_INCREF(&pypt_log_hook_type);
	PyModule_AddObject(m, "log_hook", (PyObject *)&pypt_log_hook_type);
	Py_INCREF(&pypt_module_type);
	PyModule_AddObject(m, "module", (PyObject *)&pypt_module_type);
	Py_INCREF(&pypt_process_type);
	PyModule_AddObject(m, "process", (PyObject *)&pypt_process_type);
	Py_INCREF(&pypt_thread_type);
	PyModule_AddObject(m, "thread", (PyObject *)&pypt_thread_type);
	Py_INCREF(&pypt_mmap_type);
	PyModule_AddObject(m, "mmap", (PyObject *)&pypt_mmap_type);
	Py_INCREF(&pypt_inject_type);
	PyModule_AddObject(m, "inject", (PyObject *)&pypt_inject_type);

	pypt_core_main_ = (struct pypt_core *)
                PyObject_CallMethod((PyObject *)&pypt_core_type, "__new__", "O", &pypt_core_type);
	if (pypt_core_main_ == NULL)
		MODULE_INIT_FUNC_RETURN(NULL);

	pypt_core_main_->core = &pt_core_main_;
	MODULE_INIT_FUNC_RETURN(m);
}

static PyObject *pypt_log_hook_add(PyObject *self, PyObject *args)
{
	struct pypt_log_hook *log_hook;
	PyObject *object;

	if (!PyArg_ParseTuple(args, "O:_ptrace", &object))
		return NULL;

	if (!PyObject_TypeCheck(object, &pypt_log_hook_type)) {
		PyErr_SetString(PyExc_TypeError, "arg must be _ptrace.log_hook object");
		return NULL;
	}

	Py_INCREF(object);
	log_hook = (struct pypt_log_hook *)object;
	pt_log_hook_register(&log_hook->log_hook);

	Py_RETURN_NONE;
}

static PyObject *pypt_log_hook_del(PyObject *self, PyObject *args)
{
	struct pypt_log_hook *log_hook;
	PyObject *object;

	if (!PyArg_ParseTuple(args, "O:_ptrace", &object))
		return NULL;

	if (!PyObject_TypeCheck(object, &pypt_log_hook_type)) {
		PyErr_SetString(PyExc_TypeError, "arg must be _ptrace.log_hook object");
		return NULL;
	}

	log_hook = (struct pypt_log_hook *)object;

	if (pt_log_hook_unregister(&log_hook->log_hook) == 0)
		Py_DECREF(object);
	else {
		PyErr_SetString(PyExc_ValueError, "log hook not found");
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *pypt_main(PyObject *self, PyObject *args)
{
	return pypt_core_main(pypt_core_main_, args);
}

static PyObject *pypt_quit(PyObject *self, PyObject *args)
{
	return pypt_core_quit(pypt_core_main_, args);
}

static PyObject *
pypt_processes(PyObject *self, PyObject *args)
{
	PyObject *process_list;
	struct pt_process *p;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	if ( (process_list = PyList_New(0)) == NULL)
		return NULL;

	pt_core_for_each_process (pypt_core_main_->core, p) {
		if (PyList_Append(process_list, p->super_) == -1) {
			Py_DECREF(process_list);
			return NULL;
		}
	}

	return process_list;
}

static PyObject *pypt_process_attach(PyObject *self, PyObject *args)
{
	return pypt_core_process_attach(pypt_core_main_, args);
}

static PyObject *pypt_process_attach_remote(PyObject *self, PyObject *args)
{
	return pypt_core_process_attach_remote(pypt_core_main_, args);
}

static PyObject *pypt_process_detach(PyObject *self, PyObject *args)
{
	return pypt_core_process_detach(pypt_core_main_, args);
}

static PyObject *pypt_process_detach_remote(PyObject *self, PyObject *args)
{
	return pypt_core_process_detach_remote(pypt_core_main_, args);
}

static PyObject *pypt_execv(PyObject *self, PyObject *args)
{
	return pypt_core_execv(pypt_core_main_, args);
}

static PyObject *pypt_process_break(PyObject *self, PyObject *args)
{
	return pypt_core_process_break(pypt_core_main_, args);
}

static PyObject *pypt_process_break_remote(PyObject *self, PyObject *args)
{
	return pypt_core_process_break_remote(pypt_core_main_, args);
}
