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
 * core.h
 *
 * Python bindings for libptrace cores.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PYPT_CORE_INTERNAL_H
#define PYPT_CORE_INTERNAL_H

struct pypt_core
{
	PyObject_HEAD;
	PyObject *dict;

	struct pt_core *core;
};

extern PyTypeObject pypt_core_type;

#ifdef __cplusplus
extern "C" {
#endif

PyObject *pypt_core_process_attach(struct pypt_core *, PyObject *);
PyObject *pypt_core_process_attach_remote(struct pypt_core *, PyObject *);
PyObject *pypt_core_process_detach(struct pypt_core *, PyObject *);
PyObject *pypt_core_process_detach_remote(struct pypt_core *self, PyObject *args);
PyObject *pypt_core_process_break(struct pypt_core *self, PyObject *args);
PyObject *pypt_core_process_break_remote(struct pypt_core *self, PyObject *args);

PyObject *pypt_core_main(struct pypt_core *, PyObject *);
PyObject *pypt_core_execv(struct pypt_core *, PyObject *);
PyObject *pypt_core_execv_remote(struct pypt_core *, PyObject *);
PyObject *pypt_core_quit(struct pypt_core *, PyObject *);

#ifdef __cplusplus
};
#endif

#endif	/* !PYPT_CORE_INTERNAL_H */
