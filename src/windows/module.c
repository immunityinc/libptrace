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
 * libptrace windows module management.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <limits.h>
#include <windows.h>
#include <libptrace/log.h>
#include <libptrace/file.h>
#include <libptrace/windows/error.h>
#include <libptrace/pe.h>
#include <libptrace/charset.h>
#include "module.h"
#include "symbol.h"

struct pt_module_operations pt_windows_module_operations = {
	.destroy = pt_windows_module_destroy
};

int pt_windows_module_init(struct pt_module *module)
{
	struct pt_windows_module_data *module_data;

	assert(module != NULL);

	/* Initialize Windows specific data for this module. */
	module_data = malloc(sizeof(struct pt_windows_module_data));
	if (module_data == NULL) {
		pt_error_errno_set(errno);
		return -1;
	}
	module_data->h       = INVALID_HANDLE_VALUE;

	/* Initialize the module itself. */
	pt_module_init(module);
	module->private_data = module_data;
	module->m_op         = &pt_windows_module_operations;

	return 0;
}

struct pt_module *pt_windows_module_new(void)
{
	struct pt_module *module;

	if ( (module = malloc(sizeof *module)) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	if (pt_windows_module_init(module) == -1) {
		free(module);
		return NULL;
	}

	return module;
}

int pt_windows_module_destroy(struct pt_module *module)
{
	struct pt_process *process;
	HANDLE h;

	assert(module != NULL);
	assert(module->process != NULL);
	assert(module->private_data != NULL);

	h = pt_windows_module_handle_get(module);
	if (h != INVALID_HANDLE_VALUE && CloseHandle(h) == 0) {
		pt_windows_error_winapi_set();
		return -1;
	}

	/* remove sym env from the module */
	process = module->process;
	if (module->pathname != NULL && process->smgr && process->smgr->sop &&
	    process->smgr->sop->module_detach) {
		pt_log("%s(): deleting symbol for module module: %s\n",
		       __FUNCTION__, module->pathname);
		process->smgr->sop->module_detach(module);
	}

	if (module->name != NULL)
		free(module->name);

	if (module->pathname != NULL)
		free(module->pathname);

	free(module->private_data);

	return 0;
}

void pt_module_exports_delete(struct pt_module_exports *exports)
{
	size_t i;

	for (i = 0; i < exports->count; i++)
		free(exports->strings[i]);

	free(exports->strings);
	free(exports->addresses);
}

int
pt_module_exports_get(
	struct pt_process *proc,
	struct pt_module *mod,
	struct pt_module_exports *exports)
{
	struct pt_file_process pt_file_proc = PT_FILE_PROCESS_INIT;
	struct pe_image_export_directory ed;
	struct pe_context pe;
	int32_t ordinal, offset;
	int ret = -1;
	rva_t *vas;
	rva_t rva;
	size_t i;

	pt_file_proc.process = proc;
	pt_file_proc.base    = mod->base;

	if (pe_open(&pe, (struct pt_file *)&pt_file_proc, PT_FILE_RDONLY) == -1)
		goto out;

	if (pe_export_directory_get(&pe, &ed) == -1)
		goto out_close;

	if (ed.number_of_names >= UINT_MAX / sizeof *exports->strings)
		goto out_close;

	if (ed.number_of_names >= UINT_MAX / sizeof *exports->addresses)
		goto out_close;

	if ( (vas = pe_export_directory_get_names_rva(&pe, &ed)) == NULL)
		goto out_close;

	exports->strings = malloc(ed.number_of_names * sizeof *exports->strings);
	if (exports->strings == NULL) {
		pt_error_errno_set(errno);
		goto out_vas;
	}

	exports->addresses = malloc(ed.number_of_names * sizeof *exports->addresses);
	if (exports->addresses == NULL) {
		pt_error_errno_set(errno);
		free(exports->strings);
		goto out_vas;
	}

	exports->count = ed.number_of_names;
	for (i = 0; i < exports->count; i++) {
	        /* pe_ascii_string_read() is taking an offset and not an RVA */
	        offset = pe_rva_to_offset(&pe, vas[i]);
	        if (offset == -1)
	                continue;
		/* XXX: strings from the PE file related to exports should be ANSI and thus valid UTF-8 strings,
		 * a further check on the PE (and on PE+ when we will support PE+) is needed
		 */
		exports->strings[i] = pe_ascii_string_read(&pe, offset);

		ordinal = pe_export_directory_get_names_ordinal(&pe, &ed, i);
		if (ordinal == -1) {
			exports->addresses[i] = PT_ADDRESS_NULL;
			continue;
		}

		rva = pe_export_directory_get_function_rva(&pe, &ed, ordinal);
		if (rva == -1) {
			exports->addresses[i] = PT_ADDRESS_NULL;
			continue;
		}

		exports->addresses[i] = mod->base + rva;
	}

	ret = 0;
out_vas:
	free(vas);
out_close:
	pe_close(&pe);
out:
	return ret;
}

pt_address_t pt_module_export_find(struct pt_process *proc, struct pt_module *mod, const utf8_t *symbol)
{
	struct pt_file_process pt_file_proc = PT_FILE_PROCESS_INIT;
	struct pe_image_export_directory ed;
	struct pe_context pe;
	int32_t ordinal, offset;
	char *name;
	rva_t *vas;
	rva_t rva;
	int i;

	pt_log("%s(%p, %p, \"%s\"): entry.\n", __FUNCTION__, proc, mod, symbol);

	pt_file_proc.process = proc;
	pt_file_proc.base = mod->base;

	/* XXX: need to close.  Not necessary now, as its a stub, but in
	 * case things change later.
	 */
	if (pe_open(&pe, (struct pt_file *)&pt_file_proc, PT_FILE_RDONLY) == -1)
		return PT_ADDRESS_NULL;

	if (pe_export_directory_get(&pe, &ed) == -1)
		return PT_ADDRESS_NULL;

	if ( (vas = pe_export_directory_get_names_rva(&pe, &ed)) == NULL)
		return PT_ADDRESS_NULL;

	for (i = 0; i < ed.number_of_names; i++) {
	        /* pe_ascii_string_read() is taking an offset and not an RVA */
	        offset = pe_rva_to_offset(&pe, vas[i]);
	        if (offset == -1)
	                continue;

		/* XXX: by now names in the PE file are treated as ANSI string
		 * and thus already a valid UTF-8, TODO: check if they could be
		 * stored with a different encoding other than ANSI keeping
		 * single-byte encoding form
		 */
		if ( (name = pe_ascii_string_read(&pe, offset)) != NULL) {
			if (!strcmp(name, symbol)) {
				free(name);
				break;
			}
			free(name);
		}
	}
	free(vas);

	/* No luck. */
	if (i == ed.number_of_names)
		return PT_ADDRESS_NULL;

	/* We know the index of our symbol in the table now, so read the
	 * corresponding address.
	 */
	ordinal = pe_export_directory_get_names_ordinal(&pe, &ed, i);
	if (ordinal == -1)
		return PT_ADDRESS_NULL;

	rva = pe_export_directory_get_function_rva(&pe, &ed, ordinal);
	if (rva == -1)
		return PT_ADDRESS_NULL;

	return mod->base + rva;
}
