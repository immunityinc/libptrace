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
 * thread.c
 *
 * Python bindings for libptrace threads.
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
#include "../src/registers.h"
#include "../src/thread_x86.h"

#include "compat.h"
#include "ptrace.h"
#include "thread.h"
#include "utils.h"

static int
pypt_thread_init(struct pypt_thread *self, PyObject *args, PyObject *kwds)
{
	if (!PyArg_ParseTuple(args, ""))
		return -1;

	return 0;
}

static PyObject *
pypt_thread_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	struct pypt_thread *self;

	if ( (self = (struct pypt_thread *)type->tp_alloc(type, 0)) == NULL)
		return NULL;

	self->dict = PyDict_New();

	if (!self->dict) {
		Py_TYPE(self)->tp_free((PyObject*)self);
		return NULL;
	}

	self->process = NULL;

	return (PyObject *)self;
}


static void
pypt_thread_dealloc(struct pypt_thread *self)
{
	Py_XDECREF(self->process);
	Py_XDECREF(self->dict);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
pypt_thread_id_get(struct pypt_thread *self, void *closure)
{
	return PyInt_FromLong(self->thread->tid);
}

#define PYPT_MAP_REG32(t, x)						\
	do {								\
		integer = PyLong_FromUnsignedLong(((t)pt_regs)->x);	\
		if (integer == NULL)					\
			goto err_regs;					\
									\
		if (PyDict_SetItemString(regs, #x, integer) == -1)	\
			goto err_integer;				\
									\
		Py_DECREF(integer);					\
	} while (0)

#define PYPT_MAP_REG64(t, x)						\
	do {								\
		integer = PyLong_FromUnsignedLongLong(((t)pt_regs)->x);	\
		if (integer == NULL)					\
			goto err_regs;					\
									\
		if (PyDict_SetItemString(regs, #x, integer) == -1)	\
			goto err_integer;				\
									\
		Py_DECREF(integer);					\
	} while (0)

static PyObject *
pypt_thread_registers_get(struct pypt_thread *self, void *closure)
{
	struct pt_registers *pt_regs;
	PyObject *integer;
	PyObject *regs;

	if ( (pt_regs = pt_thread_registers_get(self->thread)) == NULL)
		goto err;

	if ( (regs = PyDict_New()) == NULL)
		goto err_pt_regs;

	switch (pt_regs->type) {
	case PT_REGISTERS_I386:
		PYPT_MAP_REG32(struct pt_registers_i386 *, eax);
		PYPT_MAP_REG32(struct pt_registers_i386 *, ebx);
		PYPT_MAP_REG32(struct pt_registers_i386 *, ecx);
		PYPT_MAP_REG32(struct pt_registers_i386 *, edx);
		PYPT_MAP_REG32(struct pt_registers_i386 *, esi);
		PYPT_MAP_REG32(struct pt_registers_i386 *, edi);
		PYPT_MAP_REG32(struct pt_registers_i386 *, esp);
		PYPT_MAP_REG32(struct pt_registers_i386 *, ebp);
		PYPT_MAP_REG32(struct pt_registers_i386 *, eip);
		PYPT_MAP_REG32(struct pt_registers_i386 *, cs);
		PYPT_MAP_REG32(struct pt_registers_i386 *, ds);
		PYPT_MAP_REG32(struct pt_registers_i386 *, es);
		PYPT_MAP_REG32(struct pt_registers_i386 *, fs);
		PYPT_MAP_REG32(struct pt_registers_i386 *, gs);
		PYPT_MAP_REG32(struct pt_registers_i386 *, ss);
		PYPT_MAP_REG32(struct pt_registers_i386 *, eflags);
		PYPT_MAP_REG32(struct pt_registers_i386 *, dr0);
		PYPT_MAP_REG32(struct pt_registers_i386 *, dr1);
		PYPT_MAP_REG32(struct pt_registers_i386 *, dr2);
		PYPT_MAP_REG32(struct pt_registers_i386 *, dr3);
		PYPT_MAP_REG32(struct pt_registers_i386 *, dr6);
		PYPT_MAP_REG32(struct pt_registers_i386 *, dr7);
		break;
	case PT_REGISTERS_X86_64:
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, rax);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, rbx);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, rcx);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, rdx);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, r8);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, r9);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, r10);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, r11);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, r12);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, r13);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, r14);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, r15);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, rsi);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, rdi);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, rsp);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, rbp);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, rip);
		PYPT_MAP_REG32(struct pt_registers_x86_64 *, cs);
		PYPT_MAP_REG32(struct pt_registers_x86_64 *, ds);
		PYPT_MAP_REG32(struct pt_registers_x86_64 *, es);
		PYPT_MAP_REG32(struct pt_registers_x86_64 *, fs);
		PYPT_MAP_REG32(struct pt_registers_x86_64 *, gs);
		PYPT_MAP_REG32(struct pt_registers_x86_64 *, ss);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, rflags);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, dr0);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, dr1);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, dr2);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, dr3);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, dr6);
		PYPT_MAP_REG64(struct pt_registers_x86_64 *, dr7);
		break;
	}

	free(pt_regs);
	return regs;

err_integer:
	Py_DECREF(integer);
err_regs:
	Py_DECREF(regs);
err_pt_regs:
	free(pt_regs);
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
pypt_thread_single_step_set(struct pypt_thread *self, PyObject *args)
{
	int single_step;

	if (!PyArg_ParseTuple(args, "b", &single_step))
		return NULL;

	if (single_step) {
		if (pt_thread_single_step_set(self->thread) == -1)
			return NULL;
	} else {
		if (pt_thread_single_step_remove(self->thread) == -1)
			return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *
pypt_thread_x86_ldt_entry_get(struct pypt_thread *self, PyObject *args)
{
	struct pt_x86_descriptor desc;
	PyObject *integer;
	PyObject *dict;
	int i;

	if (!PyArg_ParseTuple(args, "i", &i))
		return NULL;

	if (pt_thread_x86_ldt_entry_get(self->thread, &desc, i) == -1)
		goto err;

	if ( (dict = PyDict_New()) == NULL)
		goto err;

	PYPT_MAP_INT32("base", pt_thread_x86_descriptor_base_get(&desc));
	PYPT_MAP_INT32("limit", pt_thread_x86_descriptor_limit_get(&desc));
	PYPT_MAP_INT32("type", desc.type);
	PYPT_MAP_INT32("s", desc.s);
	PYPT_MAP_INT32("dpl", desc.dpl);
	PYPT_MAP_INT32("p", desc.p);
	PYPT_MAP_INT32("avl", desc.avl);
	PYPT_MAP_INT32("l", desc.l);
	PYPT_MAP_INT32("db", desc.db);
	PYPT_MAP_INT32("g", desc.g);

	return dict;

err_integer:
	Py_DECREF(integer);
err_dict:
	Py_DECREF(dict);
err:
	return NULL;
}

#define PYPT_MAP_INT32_GET(m, n)					\
	do {								\
		if ( (integer = PyDict_GetItemString(m, n)) == NULL)	\
			return NULL;					\
									\
		value = py_num_to_long(integer);			\
		if (value == -1 && PyErr_Occurred())			\
			return NULL;					\
	} while (0)

static PyObject *
pypt_thread_x86_ldt_entry_set(struct pypt_thread *self, PyObject *args)
{
	struct pt_x86_descriptor desc;
	PyObject *integer;
	PyObject *dict;
	long value;
	int i;

	if (!PyArg_ParseTuple(args, "iO", &i, &dict))
		return NULL;

	if (!PyDict_Check(dict)) {
		PyErr_SetString(PyExc_TypeError, "arg must be a dictionary object.");
		return NULL;
	}

	/* Get all dictionary members.  They need to exist. */
	PYPT_MAP_INT32_GET(dict, "base");
	pt_thread_x86_descriptor_base_set(&desc, value);
	PYPT_MAP_INT32_GET(dict, "limit");
	pt_thread_x86_descriptor_limit_set(&desc, value);
	PYPT_MAP_INT32_GET(dict, "type");
	desc.type = value;
	PYPT_MAP_INT32_GET(dict, "s");
	desc.s = value;
	PYPT_MAP_INT32_GET(dict, "dpl");
	desc.dpl = value;
	PYPT_MAP_INT32_GET(dict, "p");
	desc.p = value;
	PYPT_MAP_INT32_GET(dict, "avl");
	desc.avl = value;
	PYPT_MAP_INT32_GET(dict, "l");
	desc.l = value;
	PYPT_MAP_INT32_GET(dict, "db");
	desc.db = value;
	PYPT_MAP_INT32_GET(dict, "g");
	desc.g = value;

	if (pt_thread_x86_ldt_entry_set(self->thread, &desc, i) == -1)
		return NULL;

	Py_RETURN_NONE;
}

static PyObject *
pypt_thread_x86_gdt_entry_get(struct pypt_thread *self, PyObject *args)
{
	struct pt_x86_descriptor desc;
	PyObject *integer;
	PyObject *dict;
	int i;

	if (!PyArg_ParseTuple(args, "i", &i))
		return NULL;

	if (pt_thread_x86_gdt_entry_get(self->thread, &desc, i) == -1)
		goto err;

	if ( (dict = PyDict_New()) == NULL)
		goto err;

	PYPT_MAP_INT32("base", pt_thread_x86_descriptor_base_get(&desc));
	PYPT_MAP_INT32("limit", pt_thread_x86_descriptor_limit_get(&desc));
	PYPT_MAP_INT32("type", desc.type);
	PYPT_MAP_INT32("s", desc.s);
	PYPT_MAP_INT32("dpl", desc.dpl);
	PYPT_MAP_INT32("p", desc.p);
	PYPT_MAP_INT32("avl", desc.avl);
	PYPT_MAP_INT32("l", desc.l);
	PYPT_MAP_INT32("db", desc.db);
	PYPT_MAP_INT32("g", desc.g);

	return dict;

err_integer:
	Py_DECREF(integer);
err_dict:
	Py_DECREF(dict);
err:
	return NULL;
}

static PyObject *
pypt_thread_resume(struct pypt_thread *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	if (pt_thread_resume(self->thread) == -1)
		return NULL;

	Py_RETURN_NONE;
}

static PyObject *
pypt_thread_suspend(struct pypt_thread *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	if (pt_thread_suspend(self->thread) == -1)
		return NULL;

	Py_RETURN_NONE;
}

#define pypt_read_type_signed_(p, t, src_, type)				\
	do {									\
		pt_address_t src = (pt_address_t)(src_);			\
		Py_ssize_t size = PyTuple_GET_SIZE((t));			\
		PyObject *pyarg;						\
		type arg;							\
										\
		if (pt_process_read((p), &arg, src, sizeof arg) == -1) {	\
			PyErr_SetString(pypt_exception, pt_error_strerror());	\
			Py_DECREF((t));						\
			return NULL;						\
		}								\
										\
		if (_PyTuple_Resize(&(t), size + 1) == -1)			\
			return NULL;						\
										\
		if ( (pyarg = PyInt_FromSsize_t(arg)) == NULL) {		\
			Py_DECREF((t));						\
			return NULL;						\
		}								\
										\
		if (PyTuple_SetItem((t), size, pyarg) == -1) {			\
			Py_DECREF((t));						\
			return NULL;						\
		}								\
										\
		src_ += sizeof(arg);						\
	} while (0)

#define pypt_read_type_unsigned_(p, t, src_, type)				\
	do {									\
		pt_address_t src = (pt_address_t)(src_);			\
		Py_ssize_t size = PyTuple_GET_SIZE((t));			\
		PyObject *pyarg;						\
		type arg;							\
										\
		if (pt_process_read((p), &arg, src, sizeof arg) == -1) {	\
			PyErr_SetString(pypt_exception, pt_error_strerror());	\
			Py_DECREF((t));						\
			return NULL;						\
		}								\
										\
		if (_PyTuple_Resize(&(t), size + 1) == -1)			\
			return NULL;						\
										\
		if ( (pyarg = PyInt_FromSize_t((size_t)arg)) == NULL) {		\
			Py_DECREF((t));						\
			return NULL;						\
		}								\
										\
		if (PyTuple_SetItem((t), size, pyarg) == -1) {			\
			Py_DECREF((t));						\
			return NULL;						\
		}								\
										\
		src_ += sizeof(arg);						\
	} while (0)

static PyObject *
pypt_thread_sscanf(struct pypt_thread *self, PyObject *args)
{
	struct pt_process *process = self->process->process;
	unsigned long long address;
	PyObject *ret;
	char *fmt, *p;

	if (!PyArg_ParseTuple(args, "Ks:thread_sscanf", &address, &fmt))
		return NULL;

        /* New tuple to return the arguments in. */
        if ( (ret = PyTuple_New(0)) == NULL)
		return NULL;

	for (p = fmt; *p != '\0'; p++) {
		/* XXX: support literals that have to match later. */
		if (*p != '%')
			continue;

		/* Ensure we do not overindex. */
		if (*++p == '\0')
			break;

		switch (*p) {
		case 'i':
			pypt_read_type_signed_(process, ret, address, int);
			break;
		case 'u':
			pypt_read_type_unsigned_(process, ret, address, unsigned int);
			break;
		case 'p':
			/* XXX: kludge. */
			if (self->thread->arch_data->pointer_size == 4)
				pypt_read_type_unsigned_(process, ret, address, uint32_t);
			else if (self->thread->arch_data->pointer_size == 8)
				pypt_read_type_unsigned_(process, ret, address, uint64_t);
			else
				return NULL;
			break;
		default:
			break;
		}
	}

	return ret;
}


static PyObject *pypt_thread__repr__(struct pypt_thread *self)
{
	return PyString_FromFormat("<%s(%p) tid:%u handle:0x%p exit_code:%u%s>",
				   Py_TYPE(self)->tp_name, self,
				   self->thread->tid,
				   self->thread->private_data,
				   self->thread->exit_code,
				   self->thread->flags & THREAD_FLAG_SINGLE_STEP ? " SINGLE_STEP" : "");
}


static PyGetSetDef pypt_thread_getset[] = {
	{"__dict__", (getter)pypt_dict_get, (setter)pypt_dict_set,
	 "The __dict__ for this thread.", &pypt_thread_type},
	{ "id", (getter)pypt_thread_id_get, NULL, "thread identifier", NULL},
	{ "registers", (getter)pypt_thread_registers_get, NULL, "thread registers", NULL },
	{ NULL }
};

static PyMethodDef pypt_thread_methods[] = {
        { "sscanf", (PyCFunction)pypt_thread_sscanf, METH_VARARGS, "Read formatted data from thread memory." },
	{ "single_step_set", (PyCFunction)pypt_thread_single_step_set, METH_VARARGS, "Set or disable single stepping." },
        { "gdt_entry_get", (PyCFunction)pypt_thread_x86_gdt_entry_get, METH_VARARGS, "Get a GDT entry." },
        { "ldt_entry_get", (PyCFunction)pypt_thread_x86_ldt_entry_get, METH_VARARGS, "Get a LDT entry." },
        { "ldt_entry_set", (PyCFunction)pypt_thread_x86_ldt_entry_set, METH_VARARGS, "Set a LDT entry." },
	{ "resume", (PyCFunction)pypt_thread_resume, METH_VARARGS, "Resume the thread." },
	{ "suspend", (PyCFunction)pypt_thread_suspend, METH_VARARGS, "Suspend the thread." },
	{ NULL }
};

static PyMemberDef pypt_thread_members[] = {
	{ "process", T_OBJECT, offsetof(struct pypt_thread, process), READONLY, "process" },
	{ NULL }
};

PyTypeObject pypt_thread_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_ptrace.thread",			/* tp_name */
	sizeof(struct pypt_thread),		/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)pypt_thread_dealloc,	/* tp_dealloc */
	0,					/* tp_print */
	0,					/* tp_getattr */
	0,					/* tp_setattr */
	0,					/* tp_compare */
	(reprfunc)pypt_thread__repr__,		/* tp_repr */
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
	"Thread object",			/* tp_doc */
	0,					/* tp_traverse */
	0,					/* tp_clear */
	0,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	0,					/* tp_iter */
	0,					/* tp_iternext */
	pypt_thread_methods,			/* tp_methods */
	pypt_thread_members,			/* tp_members */
	pypt_thread_getset,			/* tp_getset */
	0,					/* tp_base */
	0,					/* tp_dict */
	0,					/* tp_descr_get */
	0,					/* tp_descr_set */
	offsetof(struct pypt_thread, dict),	/* tp_dictoffset */
	(initproc)pypt_thread_init,		/* tp_init */
	0,					/* tp_alloc */
	pypt_thread_new,			/* tp_new */
};
