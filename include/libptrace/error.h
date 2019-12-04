/* libptrace, a process tracing and manipulation library.
 *
 * Copyright (C) 2006-2019, Ronald Huizer <rhuizer@hexpedition.com>
 * Copyright (C) 2019, Cyxtera Cybersecurity, Inc.  All rights reserved.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
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
 * error.h
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#ifndef PT_ERROR_H
#define PT_ERROR_H

#define PT_ERROR_NONE		0	/* No error */
#define PT_ERROR_EXITED		1	/* Remote process exited */
#define PT_ERROR_PAGESIZE	2	/* Unsuitable page size */
#define PT_ERROR_ALTSTACK_ORIG	3	/* Original stack error */
#define PT_ERROR_ALTSTACK_INUSE	4	/* Stack currently in use */
#define PT_ERROR_NOMEMORY	5
#define PT_ERROR_UNSUPPORTED	6	/* Unsupported function */
#define PT_ERROR_BAD_ENCODING	7	/* Unable to convert string encoding */
#define PT_ERROR_MODULE_MISSING	8
#define PT_ERROR_RESUME_NO_BRK	9	/* Cannot resume without a break. */
#define PT_ERROR_SYMBOL_UNKNOWN	10	/* The symbol cannot be resolved. */
#define PT_ERROR_NOT_ATTACHED	11	/* We are detached from the process. */
#define PT_ERROR_INVALID_ARG	12	/* Invalid argument. */
#define PT_ERROR_NOT_FOUND	13	/* An object wasn't found. */
#define PT_ERROR_EXISTS		14	/* An object already exists. */
#define PT_ERROR_RESOURCE_LIMIT	15	/* Ran out of a specific resource. */
#define PT_ERROR_WINDOWS_WOW64	16	/* WoW64 is currently unsupported. */
#define PT_ERROR_ARITH_OVERFLOW	17	/* Arithmetic overflow occurred. */
#define PT_ERROR_INVALID_CORE   18	/* Wrong ptrace core for operation. */
#define PT_ERROR_WOULD_BLOCK	19	/* Block on non-blocking operation. */
#define PT_ERROR_MSGSIZE        20      /* Invalid message size. */
#define PT_ERROR_HANDLE		21	/* Invalid handle. */
#define PT_ERROR_MAX		21	/* Mark the end of the error codes */

#define PT_ERR_SUCCESS		PT_ERR_NONE

#define PT_ERROR_TYPE_INTERNAL	0	/* Internal libptrace errors.	*/
#define PT_ERROR_TYPE_ERRNO	1	/* errno based errors.		*/
#define PT_ERROR_TYPE_PE	2	/* pe.c based errors.		*/
#define PT_ERROR_TYPE_WINDOWS	3	/* Windows OS specific errors.	*/

#ifdef __cplusplus
extern "C" {
#endif

#include <libptrace/charset.h>

struct pt_error;

void            pt_error_internal_set(int);
int             pt_error_internal_test(int);
void            pt_error_errno_set(int);
void            pt_error_pe_set(int);

const utf8_t *	pt_error_strerror(void);
void		pt_error_perror(const utf8_t *);
void		pt_error_save(void);
void		pt_error_restore(void);
void		pt_error_clear(void);
int		pt_error_is_set(void);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_ERROR_H */
