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
 * mmap.c
 *
 * Python bindings for libptrace memory maps.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <python/Python.h>
#include <python/structmember.h>
#include "compat.h"
#include "mmap.h"
#include "utils.h"

static PyObject *
pypt_mmap_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	struct pypt_mmap *self;

	if ( (self = (struct pypt_mmap *)type->tp_alloc(type, 0)) == NULL)
		return NULL;

	self->dict = PyDict_New();
	if (!self->dict) {
		Py_TYPE(self)->tp_free((PyObject*)self);
		return NULL;
	}

        self->mmap = NULL;
        self->pyprocess = NULL;

	return (PyObject *)self;
}

static int
pypt_mmap_init(struct pypt_mmap *self, PyObject *args, PyObject *kwds)
{
        struct pypt_process *pyprocess = NULL;

	if (!PyArg_ParseTuple(args, "|O!", &pypt_process_type, &pyprocess))
		return -1;

        if(pyprocess) {
                Py_INCREF(pyprocess);
                self->pyprocess = pyprocess;
                // TODO: raise an exception if virtual_query_ex fails.
                pt_mmap_load(pyprocess->process);
                self->mmap = &pyprocess->process->mmap;
        } else {
                self->mmap = pt_mmap_new();
        }

	return 0;
}


static void
pypt_mmap_dealloc(struct pypt_mmap *self)
{
        if(self->pyprocess && self->mmap) {
                self->pyprocess->mmap = NULL;
                Py_XDECREF(self->pyprocess);
        }

	Py_XDECREF(self->dict);
	self->pyprocess = NULL;
	pt_mmap_delete(self->mmap);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

// TODO: Add a real userland range depending on:
//              - architecture x86/amd64 (bounds + possible uncanonical addresses)
//              - OS (linux/windows)

static int
is_valid_range_(unsigned long start, unsigned long end)
{
        if (!end || end < start)
                return 0;
        return 1;
}

static PyObject *
pypt_mmap_add(struct pypt_mmap *self, PyObject *args)
{
        struct pt_mmap_area *area;
        unsigned long start=0, end=0, flags=0;
        char buffer[1024];

	if (!PyArg_ParseTuple(args, "ll|l", &start, &end, &flags))
		goto err;

        if (is_valid_range_(start,end)) {
                area = pt_mmap_find_exact_area(self->mmap, start, end);
                if(area) {
                        PyOS_snprintf( buffer, sizeof(buffer), "Range [0x%.8lx,0x%.8lx] already in AVL tree.", start,end);
                        PyErr_SetString(PyExc_KeyError, buffer);
                        goto err;
                }

                area = pt_mmap_area_new();
                if(area) {
                        area->start_ = start;
                        area->end_   = end;
                        area->flags  = flags;
                        pt_mmap_add_area(self->mmap, area);
                        Py_RETURN_NONE;
                } else {
                        PyErr_SetString(PyExc_MemoryError, "Not enough memory to append an item into the tree.");
                        goto err;
                }

        }

        PyOS_snprintf( buffer, sizeof(buffer), "Invalid range [0x%.8lx,0x%.8lx].", start,end);
        PyErr_SetString(PyExc_KeyError, buffer);
err:
        return NULL;
}

static PyObject *
pypt_mmap_remove(struct pypt_mmap *self, PyObject *args)
{
        char buffer[1024];
        struct pt_mmap_area *area;
        unsigned long start, end;

	if (!PyArg_ParseTuple(args, "ii", &start, &end))
		goto err;

        if (is_valid_range_(start, end)) {
                area = pt_mmap_find_exact_area(self->mmap, start, end);
                if(!area) {
                        PyOS_snprintf( buffer, sizeof(buffer), "Range [0x%.8lx,0x%.8lx] not found.", start,end);
                        PyErr_SetString(PyExc_KeyError, buffer);
                        goto err;
                } else {
                        pt_mmap_area_delete(self->mmap, area);
                        Py_RETURN_NONE;
                }
        } else {
                PyOS_snprintf( buffer, sizeof(buffer), "Invalid range [0x%.8lx,0x%.8lx].", start,end);
                PyErr_SetString(PyExc_KeyError, buffer);
                goto err;
        }
err:
        return NULL;
}

#define PYPT_MAP_INT32(n, x)						\
	do {								\
		integer = PyInt_FromLong(x);				\
		if (integer == NULL)					\
			goto err_dict;					\
									\
		if (PyDict_SetItemString(dict, #n, integer) == -1)	\
			goto err_integer;				\
									\
		Py_DECREF(integer);					\
	} while (0)

static PyObject *
pypt_mmap_find(struct pypt_mmap *self, PyObject *args)
{
        struct pt_mmap_area *area = NULL;
        unsigned long start=0, end=0;
        PyObject *integer;
        PyObject *dict;
        char buffer[1024];
	PyObject* pyList = PyList_New(1);

	if(!(dict = PyDict_New()))
		goto err;

	if (!PyArg_ParseTuple(args, "i|i", &start, &end))
		goto err;

        if(start && !end){
                area = pt_mmap_find_all_area_from_address_start(self->mmap, start);
                if(area) {
                        dict = PyDict_New();
                        PYPT_MAP_INT32(start, area->start_);
	                PYPT_MAP_INT32(end, area->end_);
	                PYPT_MAP_INT32(flags, area->flags);
	                PyList_SetItem(pyList, 0, dict);
	                while(area) {
	                        area = pt_mmap_find_all_area_from_address_next();
                                if(area) {
                                        dict = PyDict_New();
                                        PYPT_MAP_INT32(start, area->start_);
	                                PYPT_MAP_INT32(end, area->end_);
	                                PYPT_MAP_INT32(flags, area->flags);
	                                PyList_Append(pyList, dict);
	                        }
	                }
	                return pyList;
	        }

        } else {
                if (is_valid_range_(start, end)) {
                        area = pt_mmap_find_all_area_from_range_start(self->mmap, start, end);
                        if(area) {
                                dict = PyDict_New();
                                PYPT_MAP_INT32(start, area->start_);
	                        PYPT_MAP_INT32(end, area->end_);
	                        PYPT_MAP_INT32(flags, area->flags);
	                        PyList_SetItem(pyList, 0, dict);

	                        while(area) {
	                                area = pt_mmap_find_all_area_from_range_next();
                                        if(area) {
                                                dict = PyDict_New();
                                                PYPT_MAP_INT32(start, area->start_);
	                                        PYPT_MAP_INT32(end, area->end_);
	                                        PYPT_MAP_INT32(flags, area->flags);
	                                        PyList_Append(pyList, dict);
	                                }
	                        }
	                        return pyList;
	                }
                }
        }

        if(!area) {
                if(end)
                        PyOS_snprintf( buffer, sizeof(buffer), "Range [0x%.8lx,0x%.8lx] not found.", start, end);
                else
                        PyOS_snprintf( buffer, sizeof(buffer), "Address 0x%.8lx was not found in any range.", start);
                PyErr_SetString(PyExc_KeyError, buffer);
                goto err;
        }

err_integer:
	Py_DECREF(integer);
err_dict:
	Py_DECREF(dict);
err:
        return NULL;
}

static PyGetSetDef pypt_mmap_getset[] = {
	{"__dict__", (getter)pypt_dict_get, (setter)pypt_dict_set,
	 "The __dict__ for this mmap instance.", &pypt_mmap_type},
	{ NULL }
};

static PyMethodDef pypt_mmap_methods[] = {
        { "add", (PyCFunction)pypt_mmap_add, METH_VARARGS, "Add an area" },
        { "remove", (PyCFunction)pypt_mmap_remove, METH_VARARGS, "Delete an area" },
        { "find", (PyCFunction)pypt_mmap_find, METH_VARARGS, "Find an area" },
	{ NULL }
};

static PyMemberDef pypt_mmap_members[] = {
	{ NULL }
};

PyTypeObject pypt_mmap_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_ptrace.mmap",				/* tp_name */
	sizeof(struct pypt_mmap),		/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)pypt_mmap_dealloc,		/* tp_dealloc */
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
	"Memory map object",			/* tp_doc */
	0,					/* tp_traverse */
	0,					/* tp_clear */
	0,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	0,					/* tp_iter */
	0,					/* tp_iternext */
	pypt_mmap_methods,			/* tp_methods */
	pypt_mmap_members,			/* tp_members */
	pypt_mmap_getset,			/* tp_getset */
	0,					/* tp_base */
	0,					/* tp_dict */
	0,					/* tp_descr_get */
	0,					/* tp_descr_set */
	offsetof(struct pypt_mmap, dict),	/* tp_dictoffset */
	(initproc)pypt_mmap_init,		/* tp_init */
	0,					/* tp_alloc */
	pypt_mmap_new,				/* tp_new */
};
