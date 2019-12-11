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
 * log.c
 *
 * Python bindings for libptrace logging.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <python/Python.h>
#include <python/structmember.h>
#include "compat.h"
#include "log.h"
#include "utils.h"

static int pypt_log_hook_init(struct pypt_log_hook *, PyObject *, PyObject *);
static PyObject *pypt_log_hook__repr__(struct pypt_log_hook *self);

static PyMethodDef pypt_log_hook_methods[] = {
	{ NULL }
};

static PyMemberDef pypt_log_hook_members[] = {
	{ "handler", T_OBJECT, offsetof(struct pypt_log_hook, handler), 0, "log hook handler"},
	{ "cookie", T_OBJECT, offsetof(struct pypt_log_hook, cookie), 0, "log hook cookie"},
	{ NULL }
};


static PyGetSetDef pypt_log_hook_getset[] = {
	{"__dict__", (getter)pypt_dict_get, (setter)pypt_dict_set,
	 "The __dict__ for this log hook.", &pypt_log_hook_type},
	{NULL}
};


static void pypt_log_hook_handler_(void *cookie, const char *fmt, va_list va)
{
	struct pypt_log_hook *log_hook = (struct pypt_log_hook *)cookie;
	PyGILState_STATE gstate;
	PyObject *pyret;
	PyObject *pystr;
	ssize_t ret;
	char *str;

	gstate = PyGILState_Ensure();

	if ( (ret = vasprintf(&str, fmt, va)) == -1)
		goto end;

	/* XXX: change 'replace' to 'strict' once we support handler
         * exceptions properly.
	 */
	pystr = PyUnicode_Decode(str, ret, "utf-8", "replace");
	if (pystr == NULL)
		goto end_free;

	/* Call the handler.  In case the programmer decided to return
	 * something, we clean it up.
	 */
	pyret = PyObject_CallFunctionObjArgs(log_hook->handler, log_hook->cookie, pystr, NULL);
	if (pyret != NULL)
		Py_DECREF(pyret);

	Py_DECREF(pystr);

end_free:
	free(str);
end:
	PyGILState_Release(gstate);
}

static int
pypt_log_hook_init(struct pypt_log_hook *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = { "handler", "cookie", NULL };
	PyObject *handler = NULL;
	PyObject *cookie = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OO:log_hook",
	                                 kwlist, &handler, &cookie))
		return -1;

	if (!handler || !PyCallable_Check(handler))
		return -1;

	/* Set up the libptrace callback already. */
	/* XXX: is this safe if handler/cookie have odd destructors? */
	self->log_hook.handler = pypt_log_hook_handler_;
	self->log_hook.cookie  = self;

	/* If cookie is NULL, refer it to None instead. */
	if (cookie == NULL)
		cookie = Py_None;

	/* Set up the new handler. */
	Py_INCREF(handler);
	Py_XDECREF(self->handler);
	self->handler = handler;

	/* Set up the new cookie. */
	Py_INCREF(cookie);
	Py_XDECREF(self->cookie);
	self->cookie = cookie;

	return 0;
}


static PyObject*
pypt_log_hook_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	struct pypt_log_hook *self;

	if ((self = (struct pypt_log_hook *)type->tp_alloc(type, 0)) == NULL)
		return NULL;

	self->dict = PyDict_New();

	if (!self->dict) {
		Py_TYPE(self)->tp_free((PyObject *)self);
		return NULL;
	}

	return (PyObject*)self;
}

static void
pypt_log_hook_dealloc(struct pypt_log_hook *self)
{
	Py_XDECREF(self->dict);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *pypt_log_hook__repr__(struct pypt_log_hook *self)
{
	return PyString_FromFormat("<%s(%p) handler:%p cookie:%p>",
				   Py_TYPE(self)->tp_name, self,
	                           self->handler, self->cookie);
}

PyTypeObject pypt_log_hook_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_ptrace.log_hook",			/* tp_name */
	sizeof(struct pypt_log_hook),		/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)pypt_log_hook_dealloc,	/* tp_dealloc */
	0,					/* tp_print */
	0,					/* tp_getattr */
	0,					/* tp_setattr */
	0,					/* tp_compare */
	(reprfunc)pypt_log_hook__repr__,	/* tp_repr */
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
	"Log hook object",			/* tp_doc */
	0,					/* tp_traverse */
	0,					/* tp_clear */
	0,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	0,					/* tp_iter */
	0,					/* tp_iternext */
	pypt_log_hook_methods,			/* tp_methods */
	pypt_log_hook_members,			/* tp_members */
	pypt_log_hook_getset,			/* tp_getset */
	0,					/* tp_base */
	0,					/* tp_dict */
	0,					/* tp_descr_get */
	0,					/* tp_descr_set */
	offsetof(struct pypt_log_hook, dict),	/* tp_dictoffset */
	(initproc)pypt_log_hook_init,		/* tp_init */
	0,					/* tp_alloc */
	pypt_log_hook_new,			/* tp_new */
};
