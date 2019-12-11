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
 * event.c
 *
 * Python bindings for libptrace events.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <python/Python.h>
#include <python/structmember.h>

#include <libptrace/event.h>
#include "compat.h"
#include "event.h"
#include "module.h"
#include "thread.h"
#include "process.h"
#include "utils.h"

#define NULL_OR_PY_NONE(X) ((!X) || (X) == Py_None ? 0 : (X))

static struct pypt_thread *pypt_handle_thread_create_internal_(struct pt_event_thread_create *);
static struct pypt_module *pypt_handle_module_load_internal_(struct pt_event_module_load *);

static PyMethodDef pypt_event_handlers_methods[] = {
	{ NULL }
};

static PyMemberDef pypt_event_handlers_members[] = {
	{ "attached", T_OBJECT, offsetof(struct pypt_event_handlers, attached), 0, "attached handler"},
	{ "process_exit", T_OBJECT, offsetof(struct pypt_event_handlers, process_exit), 0, "process exit handler"},
	{ "thread_create", T_OBJECT, offsetof(struct pypt_event_handlers, thread_create), 0, "thread create handler"},
	{ "thread_exit", T_OBJECT, offsetof(struct pypt_event_handlers, thread_exit), 0, "thread exit handler"},
	{ "module_load", T_OBJECT, offsetof(struct pypt_event_handlers, module_load), 0, "module load handler"},
	{ "module_unload", T_OBJECT, offsetof(struct pypt_event_handlers, module_unload), 0, "module unload handler"},
	{ "breakpoint", T_OBJECT, offsetof(struct pypt_event_handlers, breakpoint), 0, "breakpoint handler"},
	{ "remote_break", T_OBJECT, offsetof(struct pypt_event_handlers, remote_break), 0, "remote break handler"},
	{ "single_step", T_OBJECT, offsetof(struct pypt_event_handlers, single_step), 0, "single step handler"},
	{ "segfault", T_OBJECT, offsetof(struct pypt_event_handlers, segfault), 0, "segfault handler"},
	{ "illegal_instruction", T_OBJECT, offsetof(struct pypt_event_handlers, illegal_instruction), 0,
	  "illegal instruction handler" },
	{ "divide_by_zero", T_OBJECT, offsetof(struct pypt_event_handlers, divide_by_zero), 0, "divide by zero handler"},
	{ "priv_instruction", T_OBJECT, offsetof(struct pypt_event_handlers, priv_instruction), 0, "privileged instruction"},
	{ "unknown_exception", T_OBJECT, offsetof(struct pypt_event_handlers, unknown_exception), 0, "unsupported exception"},
	{ NULL }
};


static PyGetSetDef pypt_event_handlers_getset[] = {
	{"__dict__", (getter)pypt_dict_get, (setter)pypt_dict_set,
	 "The __dict__ for this event_handlers instance.", &pypt_event_handlers_type},
	{NULL}
};

int pypt_handle_attached(struct pt_event_attached *event)
{
	struct pypt_process *self = event->process->super_;
	PyGILState_STATE gstate;
	PyObject *ret;

	/* We have attached.  At this point, we need to represent the
	 * main thread, as it doesn't get a separate event.  We use the
	 * callback handler for this.
	 */
	/* XXX: THIS IS WRONG.  NEEDS TO BE LIBPTRACE C API LEVEL. */
	if (self->process->main_thread != NULL) {
		struct pt_event_thread_create ev;

		ev.thread = self->process->main_thread;

		/* Does its own GIL management */
		if (pypt_handle_thread_create_internal_(&ev) == NULL)
			PyErr_Print();
	}

	/* Same for the main module. */
	if (self->process->main_module != NULL) {
		struct pt_event_module_load ev;

		ev.module = self->process->main_module;
		ev.cookie = self;

		/* Does its own GIL management */
		if (pypt_handle_module_load_internal_(&ev) == NULL)
			PyErr_Print();
	}

	/* If we have no attached handler, we're done. */
	if (self->handlers->attached == NULL)
		goto out;

	gstate = PyGILState_Ensure();

	/* Time to invoke the registered callback. */
	ret = PyObject_CallFunctionObjArgs(self->handlers->attached,
	                                   self, NULL);
	if (ret == NULL)
		PyErr_Print();
	else
		Py_DECREF(ret);

	PyGILState_Release(gstate);
out:
	return PT_EVENT_DROP;
}

int pypt_handle_process_exit(struct pt_event_process_exit *event)
{
	struct pypt_process *self = event->process->super_;
	PyGILState_STATE gstate;
	PyObject *ret;

	/* If we have no process_exit handler, we're done. */
	if (self->handlers->process_exit == NULL)
		goto out;

	gstate = PyGILState_Ensure();

	ret = PyObject_CallFunctionObjArgs(self->handlers->process_exit, self, NULL);
	if (ret == NULL)
		PyErr_Print();
	else
		Py_DECREF(ret);

	PyGILState_Release(gstate);
out:
	return PT_EVENT_DROP;
}

int pypt_handle_module_load(struct pt_event_module_load *event)
{
	struct pypt_process *self = event->module->process->super_;
	struct pypt_module *module;
	PyGILState_STATE gstate;
	PyObject *ret;

        /* Does its own GIL management */
	module = pypt_handle_module_load_internal_(event);
	if (module == NULL)
		goto out;

	/* If we have no process_exit handler, we're done. */
	if (self->handlers->module_load == NULL)
		goto out;

	gstate = PyGILState_Ensure();

	/* Time to invoke the registered callback. */
	ret = PyObject_CallFunctionObjArgs(self->handlers->module_load,
	                                   self, module, NULL);
	if (ret == NULL)
		PyErr_Print();
	else
		Py_DECREF(ret);

	PyGILState_Release(gstate);
out:
	return PT_EVENT_DROP;
}

static struct pypt_module *
pypt_handle_module_load_internal_(struct pt_event_module_load *ev)
{
	struct pypt_process *self = ev->module->process->super_;
	struct pypt_module *module;
	PyGILState_STATE gstate;

	gstate = PyGILState_Ensure();

	module = (struct pypt_module *)PyObject_CallObject((PyObject *)&pypt_module_type, NULL);
	if (module == NULL)
		goto fail;

	/* Set up the python module. */
	Py_INCREF(self);
	module->process = self;
	module->module = ev->module;

	/* XXX: need to cause exception... */
	if (PyList_Append(self->modules, (PyObject *)module) == -1) {
		Py_DECREF(module);
		goto fail;
	}

	/* And link the python module in the module.  We do this here, so we
 	 * do not need to undo it on error or PyList_Append().
 	 */
	ev->module->super_ = module;

	/* The list now holds the reference.  We don't need ours. */
	Py_DECREF(module);
	PyGILState_Release(gstate);
	return module;

fail:
	PyGILState_Release(gstate);
	return NULL;
}

int pypt_handle_module_unload(struct pt_event_module_unload *event)
{
	struct pypt_module *module = (struct pypt_module *)event->module->super_;
	struct pypt_process *self = event->module->process->super_;
	PyGILState_STATE gstate;
	PyObject *ret;
	Py_ssize_t i;

	/* No super?  Strange, this is a module we don't track... */
	if (!module)
		goto out;

	gstate = PyGILState_Ensure();

	/* Get the index of this module in the list. */
	if ( (i = PySequence_Index(self->modules, (PyObject *)module)) == -1) {
		PyErr_Print();
		goto out_release;
	}

	/* self->modules could hold the last reference to the module; we want
	 * to pass it as a callback argument, so we grab it here.
	 */
	Py_INCREF(module);
	if (PySequence_DelItem(self->modules, i) == -1) {
		PyErr_Print();
		goto out_release;
	}

	if (self->handlers->module_unload == NULL)
		goto out_module;

	/* Time to invoke the registered callback. */
	ret = PyObject_CallFunctionObjArgs(
		self->handlers->module_unload,
		self, module, NULL);
	if (ret == NULL)
		PyErr_Print();
	else
		Py_DECREF(ret);
out_module:
	Py_DECREF(module);
out_release:
	PyGILState_Release(gstate);
out:
	return PT_EVENT_DROP;
}

int pypt_handle_thread_create(struct pt_event_thread_create *event)
{
	struct pypt_process *self = event->thread->process->super_;
	struct pypt_thread *thread;
	PyGILState_STATE gstate;
	PyObject *ret;

	/* Create a new thread and add it internally. */
	/* Does its own GIL management */
	thread = pypt_handle_thread_create_internal_(event);
	if (thread == NULL)
		goto out;

	if (self->handlers->thread_create == NULL)
		goto out;

	gstate = PyGILState_Ensure();

	/* If we have a handler for thread_create events, call it. */
	ret = PyObject_CallFunctionObjArgs(self->handlers->thread_create, self, thread, NULL);
	if (ret == NULL)
		PyErr_Print();
	else
		Py_DECREF(ret);

	PyGILState_Release(gstate);
out:
	return PT_EVENT_DROP;
}

static struct pypt_thread *
pypt_handle_thread_create_internal_(struct pt_event_thread_create *ev)
{
	struct pypt_process *self = ev->thread->process->super_;
	struct pypt_thread *thread;
	PyGILState_STATE gstate;

	gstate = PyGILState_Ensure();

	thread = (struct pypt_thread *)PyObject_CallObject((PyObject *)&pypt_thread_type, NULL);
	if (thread == NULL)
		goto fail;

	/* Set up the python thread. */
	Py_INCREF(self);
	thread->process = self;
	thread->thread  = ev->thread;

	if (PyList_Append(self->threads, (PyObject *)thread) == -1) {
		Py_DECREF(thread);
		goto fail;
	}

	/* And link the python thread in the thread. */
	ev->thread->super_ = thread;

	/* The list now holds the reference.  We don't need ours. */
	Py_DECREF(thread);
	PyGILState_Release(gstate);

	return thread;
fail:
	PyGILState_Release(gstate);
	return NULL;
}

int pypt_handle_thread_exit(struct pt_event_thread_exit *event)
{
	struct pypt_thread *thread = (struct pypt_thread *)event->thread->super_;
	struct pypt_process *self = event->thread->process->super_;
	PyGILState_STATE gstate;
	PyObject *ret;
	Py_ssize_t i;

	/* No super?  Strange, this is a thread we don't track... */
	if (!thread)
		goto out;

	gstate = PyGILState_Ensure();

	/* Get the index of this thread in the list. */
	if ( (i = PySequence_Index(self->threads, (PyObject *)thread)) == -1) {
		PyErr_Print();
		goto out_release;
	}

	/* self->threads could hold the last reference to the thread; we want
	 * to pass it as a callback argument, so we grab it here.
	 */
	Py_INCREF(thread);
	if (PySequence_DelItem(self->threads, i) == -1) {
		PyErr_Print();
		goto out_release;
	}

	if (self->handlers->thread_exit == NULL)
		goto out_thread;

	/* If we have a handler for thread_exit events, call it. */
	ret = PyObject_CallFunctionObjArgs(
		self->handlers->thread_exit,
		self, thread, NULL);
	if (ret == NULL)
		PyErr_Print();
	else
		Py_DECREF(ret);

out_thread:
	Py_DECREF(thread);
out_release:
	PyGILState_Release(gstate);
out:
	return PT_EVENT_DROP;
}

int pypt_handle_breakpoint(struct pt_event_breakpoint *ev)
{
	struct pypt_thread *thread = ev->thread->super_;
	struct pypt_process *self = thread->process;
	PyGILState_STATE gstate;
	PyObject *ret, *chance;

	if (self->handlers->breakpoint == NULL)
		goto out;

	gstate = PyGILState_Ensure();

	if ( (chance = PyInt_FromLong(ev->chance)) == NULL) {
		PyErr_Print();
		goto out_release;
	}

	ret = PyObject_CallFunctionObjArgs(
		self->handlers->breakpoint,
		self, thread, chance, NULL);
	if (ret == NULL)
		PyErr_Print();
	else
		Py_DECREF(ret);

	Py_DECREF(chance);
out_release:
	PyGILState_Release(gstate);
out:
	return PT_EVENT_DROP;
}

int pypt_handle_remote_break(struct pt_event_breakpoint *ev)
{
	struct pypt_thread *thread = ev->thread->super_;
	struct pypt_process *self = thread->process;
	PyGILState_STATE gstate;
	PyObject *ret, *chance;

	if (self->handlers->remote_break == NULL)
		goto out;

	gstate = PyGILState_Ensure();

	if ( (chance = PyInt_FromLong(ev->chance)) == NULL) {
		PyErr_Print();
		goto out_release;
	}

	ret = PyObject_CallFunctionObjArgs(
		self->handlers->remote_break,
		self, thread, chance, NULL);
	if (ret == NULL)
		PyErr_Print();
	else
		Py_DECREF(ret);

	Py_DECREF(chance);
out_release:
	PyGILState_Release(gstate);
out:
	return PT_EVENT_DROP;
}

int pypt_handle_single_step(struct pt_event_single_step *ev)
{
	struct pypt_thread *thread = ev->thread->super_;
	struct pypt_process *self = thread->process;
	PyGILState_STATE gstate;
	PyObject *ret;

	if (self->handlers->single_step == NULL)
		goto out;

	gstate = PyGILState_Ensure();

	ret = PyObject_CallFunctionObjArgs(
		self->handlers->single_step,
		self, thread, NULL);
	if (ret == NULL)
		PyErr_Print();
	else
		Py_DECREF(ret);

	PyGILState_Release(gstate);
out:
	return PT_EVENT_DROP;
}

int pypt_handle_segfault(struct pt_event_segfault *ev)
{
	struct pypt_thread *thread = ev->thread->super_;
	struct pypt_process *self = thread->process;
	PyObject *address, *chance, *fault_address;
	PyGILState_STATE gstate;
	PyObject *ret;

	if (self->handlers->segfault == NULL)
		goto out;

	gstate = PyGILState_Ensure();

	/* If integer conversion fails, forward the event and be done.
	 * This is a tricky corner-case event, and the handling is not
	 * ideal.  Thankfully this should not occur often.
	 */
	address = PyInt_FromSize_t((size_t)ev->address);
	if (address == NULL) {
		PyErr_Print();
		goto out_release;
	}

	fault_address = PyInt_FromSize_t((size_t)ev->fault_address);
	if (fault_address == NULL) {
		PyErr_Print();
		goto out_address;
	}

	if ( (chance = PyInt_FromLong(ev->chance)) == NULL) {
		PyErr_Print();
		goto out_fault_address;
	}

	ret = PyObject_CallFunctionObjArgs(
		self->handlers->segfault,
		self, thread, address, fault_address,
		chance, NULL);
	if (ret == NULL)
		PyErr_Print();
	else
		Py_DECREF(ret);

	Py_DECREF(chance);
out_fault_address:
	Py_DECREF(fault_address);
out_address:
	Py_DECREF(address);
out_release:
	PyGILState_Release(gstate);
out:
	return PT_EVENT_FORWARD;
}

int pypt_handle_illegal_instruction(struct pt_event_illegal_instruction *ev)
{
	struct pypt_thread *thread = ev->thread->super_;
	struct pypt_process *self = thread->process;
	PyGILState_STATE gstate;
	PyObject *ret, *chance;

	if (self->handlers->illegal_instruction == NULL)
		goto out;

	gstate = PyGILState_Ensure();

	if ( (chance = PyInt_FromLong(ev->chance)) == NULL) {
		PyErr_Print();
		goto out_release;
	}

	ret = PyObject_CallFunctionObjArgs(
		self->handlers->illegal_instruction,
		self, thread, chance, NULL);
	if (ret == NULL)
		PyErr_Print();
	else
		Py_DECREF(ret);

	Py_DECREF(chance);
out_release:
	PyGILState_Release(gstate);
out:
	return PT_EVENT_FORWARD;
}

int pypt_handle_divide_by_zero(struct pt_event_divide_by_zero *ev)
{
	struct pypt_thread *thread = ev->thread->super_;
	struct pypt_process *self = thread->process;
	PyGILState_STATE gstate;
	PyObject *ret, *chance;

	if (self->handlers->divide_by_zero == NULL)
		goto out;

	gstate = PyGILState_Ensure();

	if ( (chance = PyInt_FromLong(ev->chance)) == NULL) {
		PyErr_Print();
		goto out_release;
	}

	ret = PyObject_CallFunctionObjArgs(
		self->handlers->divide_by_zero,
		self, thread, chance, NULL);
	if (ret == NULL)
		PyErr_Print();
	else
		Py_DECREF(ret);

	Py_DECREF(chance);
out_release:
	PyGILState_Release(gstate);
out:
	return PT_EVENT_FORWARD;
}

int pypt_handle_priv_instruction(struct pt_event_priv_instruction *ev)
{
	struct pypt_thread *thread = ev->thread->super_;
	struct pypt_process *self = thread->process;
	PyGILState_STATE gstate;
	PyObject *ret, *chance;

	if (self->handlers->priv_instruction == NULL)
		goto out;

	gstate = PyGILState_Ensure();

	if ( (chance = PyInt_FromLong(ev->chance)) == NULL) {
		PyErr_Print();
		goto out_release;
	}

	ret = PyObject_CallFunctionObjArgs(
		self->handlers->priv_instruction,
		self, thread, chance, NULL);
	if (ret == NULL)
		PyErr_Print();
	else
		Py_DECREF(ret);

	Py_DECREF(chance);
out_release:
	PyGILState_Release(gstate);
out:
	return PT_EVENT_FORWARD;
}

int pypt_handle_unknown_exception(struct pt_event_unknown_exception *ev)
{
	struct pypt_thread *thread = ev->thread->super_;
	struct pypt_process *self = thread->process;
	PyGILState_STATE gstate;
	PyObject *ret, *chance;
	PyObject *number;

	if (self->handlers->unknown_exception == NULL)
		goto out;

	gstate = PyGILState_Ensure();

	if ( (number = PyInt_FromLong(ev->number)) == NULL) {
		PyErr_Print();
		goto out_release;
	}

	if ( (chance = PyInt_FromLong(ev->chance)) == NULL) {
		PyErr_Print();
		goto out_number;
	}

	ret = PyObject_CallFunctionObjArgs(
		self->handlers->priv_instruction,
		self, thread, number, chance, NULL);
	if (ret == NULL)
		PyErr_Print();
	else
		Py_DECREF(ret);

	Py_DECREF(chance);
out_number:
	Py_DECREF(number);
out_release:
	PyGILState_Release(gstate);
out:
	return PT_EVENT_FORWARD;
}

static PyObject *
pypt_event_handlers_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	struct pypt_event_handlers *self;

	self = (struct pypt_event_handlers *)type->tp_alloc(type, 0);

	if (self == NULL)
		return NULL;

	self->dict = PyDict_New();
	if (!self->dict) {
		Py_TYPE(self)->tp_free((PyObject*)self);
		return NULL;
	}

	self->attached            = NULL;
	self->process_exit        = NULL;
	self->thread_create       = NULL;
	self->thread_exit         = NULL;
	self->module_load         = NULL;
	self->module_unload       = NULL;
	self->breakpoint          = NULL;
	self->remote_break        = NULL;
	self->single_step         = NULL;
	self->segfault            = NULL;
	self->illegal_instruction = NULL;
	self->divide_by_zero      = NULL;
	self->priv_instruction    = NULL;
	self->unknown_exception   = NULL;

	return (PyObject *)self;
}

static void
pypt_event_handlers_dealloc(struct pypt_event_handlers *self)
{
	Py_XDECREF(self->dict);
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
pypt_event_handlers_init(struct pypt_event_handlers *self, PyObject *args, PyObject *kwds)
{
	if (!PyArg_ParseTuple(args, ""))
		return -1;

	return 0;
}

static PyObject *pypt_event_handlers__repr__(struct pypt_event_handlers *self)
{
	return PyString_FromFormat("<%s(%p) attached:%p\n"
				   "  process_exit:%p thread_create:%p\n"
				   "  thread_exit:%p module_load:%p\n"
				   "  module_unload:%p breakpoint:%p\n"
				   "  remote_break:%p single_step:%p\n"
				   "  segfault:%p illegal_instruction:%p\n"
				   "  divide_by_zero:%p priv_instruction:%p\n"
				   "  unknown_exception:%p\n",
				   Py_TYPE(self)->tp_name, self,
				   NULL_OR_PY_NONE(self->attached),
				   NULL_OR_PY_NONE(self->process_exit),
				   NULL_OR_PY_NONE(self->thread_create),
				   NULL_OR_PY_NONE(self->thread_exit),
				   NULL_OR_PY_NONE(self->module_load),
				   NULL_OR_PY_NONE(self->module_unload),
				   NULL_OR_PY_NONE(self->breakpoint),
				   NULL_OR_PY_NONE(self->remote_break),
				   NULL_OR_PY_NONE(self->single_step),
				   NULL_OR_PY_NONE(self->segfault),
				   NULL_OR_PY_NONE(self->illegal_instruction),
				   NULL_OR_PY_NONE(self->divide_by_zero),
				   NULL_OR_PY_NONE(self->priv_instruction),
				   NULL_OR_PY_NONE(self->unknown_exception));
}

PyTypeObject pypt_event_handlers_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_ptrace.event_handlers",		    /* tp_name */
	sizeof(struct pypt_event_handlers),	    /* tp_basicsize */
	0,					    /* tp_itemsize */
	(destructor)pypt_event_handlers_dealloc,    /* tp_dealloc */
	0,					    /* tp_print */
	0,					    /* tp_getattr */
	0,					    /* tp_setattr */
	0,					    /* tp_compare */
	(reprfunc)pypt_event_handlers__repr__,	    /* tp_repr */
	0,					    /* tp_as_number */
	0,					    /* tp_as_sequence */
	0,					    /* tp_as_mapping */
	0,					    /* tp_hash */
	0,					    /* tp_call */
	0,					    /* tp_str */
	PyObject_GenericGetAttr,		    /* tp_getattro */
	PyObject_GenericSetAttr,		    /* tp_setattro */
	0,					    /* tp_as_buffer */
	Py_TPFLAGS_DEFAULT	|		    /* tp_flags */
	Py_TPFLAGS_BASETYPE,
	"Event handlers object",		    /* tp_doc */
	0,					    /* tp_traverse */
	0,					    /* tp_clear */
	0,					    /* tp_richcompare */
	0,					    /* tp_weaklistoffset */
	0,					    /* tp_iter */
	0,					    /* tp_iternext */
	pypt_event_handlers_methods,		    /* tp_methods */
	pypt_event_handlers_members,		    /* tp_members */
	pypt_event_handlers_getset,		    /* tp_getset */
	0,					    /* tp_base */
	0,					    /* tp_dict */
	0,					    /* tp_descr_get */
	0,				      	    /* tp_descr_set */
	offsetof(struct pypt_event_handlers, dict), /* tp_dictoffset */
	(initproc)pypt_event_handlers_init,         /* tp_init */
	0,					    /* tp_alloc */
	pypt_event_handlers_new,		    /* tp_new */
};
