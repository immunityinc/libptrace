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
 * pe.c
 *
 * libptrace PE handling library.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 * Author: Roderick Asselineau <roderick@immunityinc.com>
 * Author: Massimiliano Oldani <max@immunityinc.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <libptrace/file.h>
#include <libptrace/pe.h>
#include "getput.h"

static const char *pe_error_strings[] = {
	[PE_ERROR_NONE] = "Success",
	[PE_ERROR_OPEN_FAILED] = "Failure opening file",
	[PE_ERROR_READ_DOS_HEADER] = "Failure reading MS-DOS header",
	[PE_ERROR_MAGIC_DOS_HEADER] = "Invalid MS-DOS signature",
	[PE_ERROR_INVALID_PE_OFFSET] = "Invalid PE header offset",
	[PE_ERROR_READ_IMAGE_HEADERS] = "Failure reading image headers",
	[PE_ERROR_MAGIC_PE_HEADER] = "Invalid PE signature",
	[PE_ERROR_READ_IMAGE_FILE_HEADER] = "Failure reading image file header",
	[PE_ERROR_UNSUPPORTED_ARCHITECTURE] = "Unsupported architecture",
	[PE_ERROR_INVALID_OPTIONAL_SIZE] = "Invalid optional header size",
	[PE_ERROR_READ_OPTIONAL_HEADER] = "Failure reading optional header",
	[PE_ERROR_INVALID_OPTIONAL_OFFSET] = "Invalid optional header offset",
	[PE_ERROR_WRITE_OPTIONAL_HEADER] = "Failure writing optional header",
	[PE_ERROR_CORRUPTED_MODULE] = "Failure while parsing image file",
	[PE_ERROR_NO_EXPORT] = "No export in the image file",
	[PE_ERROR_NO_IMPORT] = "No import in the image file",
	[PE_ERROR_NO_DELAY] = "No delayed imports in the image file",
	[PE_ERROR_NO_TLS_CALLBACK] = "No TLS callback in the image file",
        [PE_ERROR_TLS_CALLBACK_IN_MEMORY] = "The TLS callback is built in memory",
	[PE_ERROR_READ_SECTION_TABLE] = "Failure reading section table",
	[PE_ERROR_SECTION_NOT_FOUND] = "Specified section cannot be found",
	[PE_ERROR_INVALID_PARAMETER] = "The function vas called with an invalid parameter",
	[PE_ERROR_NO_MORE_MEMORY] = "No more memory",
	[PE_ERROR_END_OF_ARRAY] = "End of array has been reached"
};

struct pe_img_opt_hdr_operations pe32_img_opt_hdr_operations = {
	.size			= sizeof(struct pe32_image_optional_header),
	.major_img_version_get	= pe32_opt_hdr_major_img_version_get,
	.major_img_version_set	= pe32_opt_hdr_major_img_version_set,
	.major_os_version_get	= pe32_opt_hdr_major_os_version_get,
	.major_os_version_set	= pe32_opt_hdr_major_os_version_set,
	.major_ss_version_get	= pe32_opt_hdr_major_ss_version_get,
	.major_ss_version_set	= pe32_opt_hdr_major_ss_version_set,
	.minor_img_version_get	= pe32_opt_hdr_minor_img_version_get,
	.minor_img_version_set	= pe32_opt_hdr_minor_img_version_set,
	.minor_os_version_get	= pe32_opt_hdr_minor_os_version_get,
	.minor_os_version_set	= pe32_opt_hdr_minor_os_version_set,
	.minor_ss_version_get	= pe32_opt_hdr_minor_ss_version_get,
	.minor_ss_version_set	= pe32_opt_hdr_minor_ss_version_set,
	.subsystem_get		= pe32_opt_hdr_subsystem_get,
	.subsystem_set		= pe32_opt_hdr_subsystem_set,
	.entry_point_get        = pe32_opt_hdr_entry_point_get,
	.entry_point_set        = pe32_opt_hdr_entry_point_set,
	.directory_get		= pe32_opt_hdr_directory_get,
	.base_of_code_get       = pe32_opt_hdr_base_of_code_get,
	.base_of_code_set       = pe32_opt_hdr_base_of_code_set,
	.size_of_code_get       = pe32_opt_hdr_size_of_code_get,
	.size_of_code_set       = pe32_opt_hdr_size_of_code_set,
	.section_alignment_get  = pe32_opt_hdr_section_alignment_get,
};

struct pe_img_opt_hdr_operations pe64_img_opt_hdr_operations = {
	.size			= sizeof(struct pe64_image_optional_header),
	.major_img_version_get	= pe64_opt_hdr_major_img_version_get,
	.major_img_version_set	= pe64_opt_hdr_major_img_version_set,
	.major_os_version_get	= pe64_opt_hdr_major_os_version_get,
	.major_os_version_set	= pe64_opt_hdr_major_os_version_set,
	.major_ss_version_get	= pe64_opt_hdr_major_ss_version_get,
	.major_ss_version_set	= pe64_opt_hdr_major_ss_version_set,
	.minor_img_version_get	= pe64_opt_hdr_minor_img_version_get,
	.minor_img_version_set	= pe64_opt_hdr_minor_img_version_set,
	.minor_os_version_get	= pe64_opt_hdr_minor_os_version_get,
	.minor_os_version_set	= pe64_opt_hdr_minor_os_version_set,
	.minor_ss_version_get	= pe64_opt_hdr_minor_ss_version_get,
	.minor_ss_version_set	= pe64_opt_hdr_minor_ss_version_set,
	.subsystem_get		= pe64_opt_hdr_subsystem_get,
	.subsystem_set		= pe64_opt_hdr_subsystem_set,
	.entry_point_get        = pe64_opt_hdr_entry_point_get,
	.entry_point_set        = pe64_opt_hdr_entry_point_set,
	.directory_get		= pe64_opt_hdr_directory_get,
	.base_of_code_get       = pe64_opt_hdr_base_of_code_get,
	.base_of_code_set       = pe64_opt_hdr_base_of_code_set,
	.size_of_code_get       = pe64_opt_hdr_size_of_code_get,
	.size_of_code_set       = pe64_opt_hdr_size_of_code_set,
	.section_alignment_get  = pe64_opt_hdr_section_alignment_get,
};

static int pe_write32_(struct pe_context *pex, off_t offset, uint32_t dword)
{
	struct pt_file *file = pex->file_;
	uint8_t buf[4];

	/* Seek to the location of the 'subsystem' entry in the optional
	 * header.
	 */
	if (file->file_ops->seek(file, offset, SEEK_SET) == -1) {
		pex->error = PE_ERROR_INVALID_OPTIONAL_OFFSET;
		return -1;
	}

	/* Convert to little endian, in case we're on big endian. */
	PUT_32BIT_LSB(buf, dword);

	/* Write the new subsystem value. */
	/* XXX: can fubar on int write.  What do? */
	if (file->file_ops->write(file, buf, 4) != 4) {
		pex->error = PE_ERROR_WRITE_OPTIONAL_HEADER;
		return -1;
	}

	return 0;
}

static int pe_write16_(struct pe_context *pex, off_t offset, uint16_t word)
{
	struct pt_file *file = pex->file_;
	uint8_t buf[2];

	/* Seek to the location of the 'subsystem' entry in the optional
	 * header.
	 */
	if (file->file_ops->seek(file, offset, SEEK_SET) == -1) {
		pex->error = PE_ERROR_INVALID_OPTIONAL_OFFSET;
		return -1;
	}

	/* Convert to little endian, in case we're on big endian. */
	PUT_16BIT_LSB(buf, word);

	/* Write the new subsystem value. */
	/* XXX: can fubar on short write.  What do? */
	if (file->file_ops->write(file, buf, 2) != 2) {
		pex->error = PE_ERROR_WRITE_OPTIONAL_HEADER;
		return -1;
	}

	return 0;
}

const char *pe_errstr(int error)
{
	return pe_error_strings[error];
}

static inline void pe_rva_translation_init_(struct pe_context *pex)
{
	struct pt_file *file = pex->file_;

	if (file->file_ops == &pt_file_c_operations)
		pex->flags |= PE_FLAG_RVA_TRANSLATION;
}

int pe_open(struct pe_context *pex, struct pt_file *file, int flags)
{
	struct pe_image_dos_header dos_hdr;
	uint32_t section_table_size;
	uint32_t signature;
	uint16_t opt_size;
	uint8_t buf[4];
	ssize_t ret;

	pex->flags = 0;
	pex->error = PE_ERROR_NONE;

	pex->delay_directory.array = NULL;
	pex->delay_directory.nbr_entries = 0;
	pex->import_directory.array = NULL;
	pex->import_directory.nbr_entries = 0;

	if (file->file_ops->open(file, flags) == -1) {
		pex->error = PE_ERROR_OPEN_FAILED;
		return -1;
	}

	ret = file->file_ops->read(file, &dos_hdr, sizeof dos_hdr);
	if (ret != sizeof dos_hdr) {
		pex->error = PE_ERROR_READ_DOS_HEADER;
		file->file_ops->close(file);
		return -1;
	}

	if (dos_hdr.e_magic != PE_IMAGE_DOS_SIGNATURE) {
		pex->error = PE_ERROR_MAGIC_DOS_HEADER;
		file->file_ops->close(file);
		return -1;
	}

	/* Seek to the NT header in the file. */
	if (file->file_ops->seek(file, dos_hdr.e_lfanew, SEEK_SET) == -1) {
		pex->error = PE_ERROR_INVALID_PE_OFFSET;
		file->file_ops->close(file);
		return -1;
	}

	/* Read the signature of IMAGE_NT_HEADERS32 */
	ret = file->file_ops->read(file, &buf, sizeof buf);
	if (ret != sizeof buf) {
		pex->error = PE_ERROR_READ_IMAGE_HEADERS;
		file->file_ops->close(file);
		return -1;
	}
	signature = GET_32BIT_LSB(buf);

	/* See if we are indeed dealing with a PE file. */
	if (signature != PE_IMAGE_NT_SIGNATURE) {
		pex->error = PE_ERROR_MAGIC_PE_HEADER;
		file->file_ops->close(file);
		return -1;
	}

	/* Read and cache the image file header. */
	ret = file->file_ops->read(file, &pex->img_header,
				   sizeof pex->img_header);
	if (ret != sizeof pex->img_header) {
		pex->error = PE_ERROR_READ_IMAGE_FILE_HEADER;
		file->file_ops->close(file);
		return -1;
	}

	/* Read and cache the image optional header. */
	switch (pex->img_header.machine) {
	case PE_IMAGE_FILE_MACHINE_I386:
		pex->opt_header_ops = &pe32_img_opt_hdr_operations;
		break;
	case PE_IMAGE_FILE_MACHINE_AMD64:
		pex->opt_header_ops = &pe64_img_opt_hdr_operations;
		break;
	default:
		pex->error = PE_ERROR_UNSUPPORTED_ARCHITECTURE;
		file->file_ops->close(file);
		return -1;
	}

	opt_size = pe_image_header_get_optional_size(pex);
	if (opt_size != pex->opt_header_ops->size) {
		pex->error = PE_ERROR_INVALID_OPTIONAL_SIZE;
		file->file_ops->close(file);
		return -1;
	}

	/* Cache the optional header offset. */
	pex->opt_header_offset = file->file_ops->tell(file);

	/* Read the optional header. */
	ret = file->file_ops->read(file, &pex->opt_header, opt_size);
	if (ret != opt_size) {
		pex->error = PE_ERROR_READ_OPTIONAL_HEADER;
		file->file_ops->close(file);
		return -1;
	}

	/* Cache the section table offset. */
	pex->section_header_offset = file->file_ops->tell(file);

	/* Read the section table array. */
	section_table_size = pe_image_header_get_number_of_sections(pex);
	section_table_size *= sizeof(struct pe_image_section_header);

	if ( (pex->section_header = malloc(section_table_size)) == NULL) {
		pex->error = PE_ERROR_NO_MORE_MEMORY;
		file->file_ops->close(file);
		return -1;
	}

	ret = file->file_ops->read(file, pex->section_header, section_table_size);
	if (ret != section_table_size) {
		pex->error = PE_ERROR_READ_SECTION_TABLE;
		file->file_ops->close(file);
		return -1;
	}

	pex->file_ = file;
	pe_rva_translation_init_(pex);

	return 0;
}

void pe_close(struct pe_context *pex)
{
	pex->file_->file_ops->close(pex->file_);

	if (pex->import_directory.array)
		free(pex->import_directory.array);

	if (pex->delay_directory.array)
		free(pex->delay_directory.array);

	if (pex->section_header)
		free(pex->section_header);
}

char *pe_ascii_string_read(struct pe_context *pex, off_t va)
{
	struct pt_file *file = pex->file_;
	size_t length = 0;
	char buf[4096];
	off_t off_old;
	ssize_t ret;
	char *p;

	/* Seek to the string. */
	off_old = file->file_ops->seek(file, va, SEEK_SET);
	if (off_old == -1)
		goto err;

	/* Determine the length of the string to read. */
	do {
		ret = file->file_ops->read(file, buf, sizeof buf);
		if (ret == 0 || ret == -1)
			goto err_seek;

		/* We've found the end of the string. */
		if ( (p = memchr(buf, '\0', ret)) != NULL) {
			length += p - buf;
			break;
		}

		length += ret;
	} while (1);

	if ( (p = malloc(length + 1)) == NULL) {
		pex->error = PE_ERROR_NO_MORE_MEMORY;
		goto err_seek;
	}

	/* And we have to reset the internal pointer. */
	if (file->file_ops->seek(file, va, SEEK_SET) == -1)
		goto err_free;

	/* Read the string. */
	ret = file->file_ops->read(file, p, length + 1);
	if (ret != length + 1)
		goto err_free;

	/* Seek back to the original position. */
	if (file->file_ops->seek(file, off_old, SEEK_SET) == -1)
		goto err_free;

	/* All done, return the string we read. */
	/* XXX: we're reading ASCII string, but PE (mainly PE32+ etc.. can hold UTF16 resources), need to add this API too */
	return p;

err_free:
	free(p);
err_seek:
	/* We seek to the old offset.  If this fails, can't do much. */
	file->file_ops->seek(file, off_old, SEEK_SET);
err:
	return NULL;
}

int pe_data_read(struct pe_context *pex, off_t foffset, char *buffer, uint32_t length)
{
	struct pt_file *file = pex->file_;
	off_t off_old;
	ssize_t ret;

	/* Seek to the string. */
	off_old = file->file_ops->seek(file, foffset, SEEK_SET);
	if (off_old == -1) {
	        pex->error = PE_ERROR_INVALID_PE_OFFSET;
		goto err;
	}

	/* Read the string. */
	ret = file->file_ops->read(file, buffer, length);
	if (ret != length) {
	        pex->error = PE_ERROR_CORRUPTED_MODULE;
		goto err_seek;
	}

	return 0;
err_seek:
	file->file_ops->seek(file, off_old, SEEK_SET);
err:
	return -1;
}

off_t pe_rva_to_offset(struct pe_context *pex, rva_t rva)
{
	struct pe_image_section_header *sect_hdr;
	off_t file_offset;

	/* If we do not use access that needs rva-> offset translation,
	 * such as when handling PE headers in memory, we're done.
	 */
	if ( (pex->flags & PE_FLAG_RVA_TRANSLATION) == 0)
		return rva;

	/* We have the special case where the RVA is actually below the first
	 * section. If it ever happens, then we need to actually return the
	 * rva as the required offset */

	sect_hdr = &pex->section_header[0];
	if (rva < sect_hdr->virtual_address)
		return (off_t)rva;

	/* The default case is an RVA addressing memory inside a section */

	sect_hdr = pe_section_from_rva_get(pex, rva);
	if (!sect_hdr) {
		pex->error = PE_ERROR_SECTION_NOT_FOUND;
		return -1;
	}

	file_offset = rva - sect_hdr->virtual_address;
        if(file_offset < sect_hdr->size_of_raw_data) {
	        file_offset += sect_hdr->pointer_to_raw_data;
	        return file_offset;
        }

        pex->error = PE_ERROR_INVALID_PE_OFFSET;
        return -1;
}

uint16_t pe_image_header_get_optional_size(struct pe_context *pex)
{
	return pex->img_header.size_of_optional_header;
}

uint16_t pe_image_header_get_machine(struct pe_context *pex)
{
	return pex->img_header.machine;
}

uint16_t pe_image_header_get_characteristics(struct pe_context *pex)
{
	return pex->img_header.characteristics;
}

uint16_t pe_image_header_get_number_of_sections(struct pe_context *pex)
{
	return pex->img_header.number_of_sections;
}

//TODO: rewrite the function using opt_header_ops struct. This is a hack for now.
uint32_t pe_opt_hdr_image_base_get(struct pe_context *pex)
{
	return pex->opt_header32.image_base;
}


/******************************************************************************
 * pe_opt_hdr_major_img_version_get()
 *
 * Retrieves the major image version from the PE optional header cached in the
 * PE context 'pex'.
 *****************************************************************************/
uint16_t pe_opt_hdr_major_img_version_get(struct pe_context *pex)
{
	return pex->opt_header_ops->major_img_version_get(pex);
}

/******************************************************************************
 * pe_opt_hdr_major_img_version_set()
 *
 * Sets the major image version in the PE optional header cached in the PE
 * context 'pex'.  This uses a write-through policy, which means the cache
 * backend store is also updated.
 *****************************************************************************/
int pe_opt_hdr_major_img_version_set(struct pe_context *pex, uint16_t version)
{
	return pex->opt_header_ops->major_img_version_set(pex, version);
}

/******************************************************************************
 * pe_opt_hdr_minor_img_version_get()
 *
 * Retrieves the minor image version from the PE optional header cached in the
 * PE context 'pex'.
 *****************************************************************************/
uint16_t pe_opt_hdr_minor_img_version_get(struct pe_context *pex)
{
	return pex->opt_header_ops->minor_img_version_get(pex);
}

/******************************************************************************
 * pe_opt_hdr_minor_img_version_set()
 *
 * Sets the minor image version in the PE optional header cached in the PE
 * context 'pex'.  This uses a write-through policy, which means the cache
 * backend store is also updated.
 *****************************************************************************/
int pe_opt_hdr_minor_img_version_set(struct pe_context *pex, uint16_t version)
{
	return pex->opt_header_ops->minor_img_version_set(pex, version);
}

/******************************************************************************
 * pe_opt_hdr_major_os_version_get()
 *
 * Retrieves the major operating system version from the PE optional header
 * cached in the PE context 'pex'.
 *****************************************************************************/
uint16_t pe_opt_hdr_major_os_version_get(struct pe_context *pex)
{
	return pex->opt_header_ops->major_os_version_get(pex);
}

/******************************************************************************
 * pe_opt_hdr_major_os_version_set()
 *
 * Sets the major operating system version in the PE optional header cached in
 * the PE context 'pex'.  This uses a write-through policy, which means the
 * cache backend store is also updated.
 *****************************************************************************/
int pe_opt_hdr_major_os_version_set(struct pe_context *pex, uint16_t version)
{
	return pex->opt_header_ops->major_os_version_set(pex, version);
}

/******************************************************************************
 * pe_opt_hdr_minor_os_version_get()
 *
 * Retrieves the minor operating system version from the PE optional header
 * cached in the PE context 'pex'.
 *****************************************************************************/
uint16_t pe_opt_hdr_minor_os_version_get(struct pe_context *pex)
{
	return pex->opt_header_ops->minor_os_version_get(pex);
}

/******************************************************************************
 * pe_opt_hdr_minor_os_version_set()
 *
 * Sets the minor operating system version in the PE optional header cached in
 * the PE context 'pex'.  This uses a write-through policy, which means the
 * cache backend store is also updated.
 *****************************************************************************/
int pe_opt_hdr_minor_os_version_set(struct pe_context *pex, uint16_t version)
{
	return pex->opt_header_ops->minor_os_version_set(pex, version);
}

/******************************************************************************
 * pe_opt_hdr_major_ss_version_get()
 *
 * Retrieves the major subsystem version from the PE optional header cached in
 * the PE context 'pex'.
 *****************************************************************************/
uint16_t pe_opt_hdr_major_ss_version_get(struct pe_context *pex)
{
	return pex->opt_header_ops->major_ss_version_get(pex);
}

/******************************************************************************
 * pe_opt_hdr_major_ss_version_set()
 *
 * Sets the major subsystem version in the PE optional header cached in the PE
 * context 'pex'.  This uses a write-through policy, which means the cache
 * backend store is also updated.
 *****************************************************************************/
int pe_opt_hdr_major_ss_version_set(struct pe_context *pex, uint16_t version)
{
	return pex->opt_header_ops->major_ss_version_set(pex, version);
}

/******************************************************************************
 * pe_opt_hdr_minor_ss_version_get()
 *
 * Retrieves the minor subsystem version from the PE optional header cached in
 * the PE context 'pex'.
 *****************************************************************************/
uint16_t pe_opt_hdr_minor_ss_version_get(struct pe_context *pex)
{
	return pex->opt_header_ops->minor_ss_version_get(pex);
}

/******************************************************************************
 * pe_opt_hdr_minor_ss_version_set()
 *
 * Sets the minor subsystem version in the PE optional header cached in the PE
 * context 'pex'.  This uses a write-through policy, which means the cache
 * backend store is also updated.
 *****************************************************************************/
int pe_opt_hdr_minor_ss_version_set(struct pe_context *pex, uint16_t version)
{
	return pex->opt_header_ops->minor_ss_version_set(pex, version);
}

/******************************************************************************
 * pe_opt_hdr_subsystem_get()
 *
 * Retrieves the subsystem from the PE optional header cached in the PE
 * context 'pex'.
 *****************************************************************************/
uint16_t pe_opt_hdr_subsystem_get(struct pe_context *pex)
{
	return pex->opt_header_ops->subsystem_get(pex);
}

/******************************************************************************
 * pe_opt_hdr_subsystem_set()
 *
 * Sets the subsystem in the PE optional header cached in the PE context 'pex'.
 * This uses a write-through policy, which means the cache backend store is
 * also updated.
 *****************************************************************************/
int pe_opt_hdr_subsystem_set(struct pe_context *pex, uint16_t subsystem)
{
	return pex->opt_header_ops->subsystem_set(pex, subsystem);
}

/******************************************************************************
 * pe_opt_hdr_entry_point_get()
 *
 * Retrieves the EP from the PE optional header cached in the PE
 * context 'pex'.
 *****************************************************************************/
uint32_t pe_opt_hdr_entry_point_get(struct pe_context *pex)
{
	return pex->opt_header_ops->entry_point_get(pex);
}

/******************************************************************************
 * pe_opt_hdr_entry_point_set()
 *
 * Sets the EP in the PE optional header cached in the PE context 'pex'.
 * This uses a write-through policy, which means the cache backend store is
 * also updated.
 *****************************************************************************/
int pe_opt_hdr_entry_point_set(struct pe_context *pex, uint32_t entry_point_addr)
{
	return pex->opt_header_ops->entry_point_set(pex, entry_point_addr);
}

/******************************************************************************
 * pe_opt_hdr_base_of_code_get()
 *
 * Retrieves the base of code from the PE optional header cached in the PE
 * context 'pex'.
 *****************************************************************************/
uint32_t pe_opt_hdr_base_of_code_get(struct pe_context *pex)
{
	return pex->opt_header_ops->base_of_code_get(pex);
}

/******************************************************************************
 * pe_opt_hdr_base_of_code_set()
 *
 * Sets the base of code in the PE optional header cached in the PE context 'pex'.
 * This uses a write-through policy, which means the cache backend store is
 * also updated.
 *****************************************************************************/
int pe_opt_hdr_base_of_code_set(struct pe_context *pex, uint32_t base)
{
	return pex->opt_header_ops->base_of_code_set(pex, base);
}

/******************************************************************************
 * pe_opt_hdr_size_of_code_get()
 *
 * Retrieves the size of code from the PE optional header cached in the PE
 * context 'pex'.
 *****************************************************************************/
uint32_t pe_opt_hdr_size_of_code_get(struct pe_context *pex)
{
	return pex->opt_header_ops->size_of_code_get(pex);
}

/******************************************************************************
 * pe_opt_hdr_size_of_code_set()
 *
 * Sets the base of code in the PE optional header cached in the PE context 'pex'.
 * This uses a write-through policy, which means the cache backend store is
 * also updated.
 *****************************************************************************/
int pe_opt_hdr_size_of_code_set(struct pe_context *pex, uint32_t size)
{
	return pex->opt_header_ops->size_of_code_set(pex, size);
}

/******************************************************************************
 * pe_opt_hdr_section_alignment_get()
 *
  * Retrieves the section alignment from the PE optional header cached in the PE
 * context 'pex'.
 *****************************************************************************/
uint32_t pe_opt_hdr_section_alignment_get(struct pe_context *pex)
{
	return pex->opt_header_ops->section_alignment_get(pex);
}

/******************************************************************************
 * pe32_opt_hdr_major_img_version_get()
 *
 * Retrieves the major image version from the 32-bit PE optional header
 * cached in the PE context 'pex'.
 *****************************************************************************/
uint16_t pe32_opt_hdr_major_img_version_get(struct pe_context *pex)
{
	return pex->opt_header32.major_image_version;
}

/******************************************************************************
 * pe32_opt_hdr_major_img_version_set()
 *
 * Sets the major image version in the 32-bit PE optional header cached in the
 * PE context 'pex'.  This uses a write-through policy, which means the cache
 * backend store is also updated.
 *****************************************************************************/
int pe32_opt_hdr_major_img_version_set(struct pe_context *pex, uint16_t version)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe32_image_optional_header,
			   major_image_version);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write16_(pex, offset, version) == -1)
		return -1;

	/* Write was successful.  Update cached copy. */
	pex->opt_header32.major_image_version = version;
	return 0;
}

/******************************************************************************
 * pe32_opt_hdr_minor_img_version_get()
 *
 * Retrieves the minor image version from the 32-bit PE optional header
 * cached in the PE context 'pex'.
 *****************************************************************************/
uint16_t pe32_opt_hdr_minor_img_version_get(struct pe_context *pex)
{
	return pex->opt_header32.minor_image_version;
}

/******************************************************************************
 * pe32_opt_hdr_minor_img_version_set()
 *
 * Sets the minor image version in the 32-bit PE optional header cached in the
 * PE context 'pex'.  This uses a write-through policy, which means the cache
 * backend store is also updated.
 *****************************************************************************/
int pe32_opt_hdr_minor_img_version_set(struct pe_context *pex, uint16_t version)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe32_image_optional_header,
			   minor_image_version);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write16_(pex, offset, version) == -1)
		return -1;

	/* Write was successful.  Update cached copy. */
	pex->opt_header32.minor_image_version = version;
	return 0;
}

/******************************************************************************
 * pe32_opt_hdr_major_os_version_get()
 *
 * Retrieves the major operating system version from the 32-bit PE optional
 * header cached in the PE context 'pex'.
 *****************************************************************************/
uint16_t pe32_opt_hdr_major_os_version_get(struct pe_context *pex)
{
	return pex->opt_header32.major_operating_system_version;
}

/******************************************************************************
 * pe32_opt_hdr_major_os_version_set()
 *
 * Sets the major operating system version in the 32-bit PE optional header
 * cached in the PE context 'pex'.  This uses a write-through policy, which
 * means the cache backend store is also updated.
 *****************************************************************************/
int pe32_opt_hdr_major_os_version_set(struct pe_context *pex, uint16_t version)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe32_image_optional_header,
			   major_operating_system_version);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write16_(pex, offset, version) == -1)
		return -1;

	/* Write was successful.  Update cached copy. */
	pex->opt_header32.major_operating_system_version = version;
	return 0;
}

/******************************************************************************
 * pe32_opt_hdr_minor_os_version_get()
 *
 * Retrieves the minor operating system version from the 32-bit PE optional
 * header cached in the PE context 'pex'.
 *****************************************************************************/
uint16_t pe32_opt_hdr_minor_os_version_get(struct pe_context *pex)
{
	return pex->opt_header32.minor_operating_system_version;
}

/******************************************************************************
 * pe32_opt_hdr_minor_os_version_set()
 *
 * Sets the minor operating system version in the 32-bit PE optional header
 * cached in the PE context 'pex'.  This uses a write-through policy, which
 * means the cache backend store is also updated.
 *****************************************************************************/
int pe32_opt_hdr_minor_os_version_set(struct pe_context *pex, uint16_t version)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe32_image_optional_header,
			   minor_operating_system_version);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write16_(pex, offset, version) == -1)
		return -1;

	/* Write was successful.  Update cached copy. */
	pex->opt_header32.minor_operating_system_version = version;
	return 0;
}

/******************************************************************************
 * pe32_opt_hdr_major_ss_version_get()
 *
 * Retrieves the subsystem version from the 32-bit PE optional header cached in
 * the PE context 'pex'.
 *****************************************************************************/
uint16_t pe32_opt_hdr_major_ss_version_get(struct pe_context *pex)
{
	return pex->opt_header32.major_subsystem_version;
}

/******************************************************************************
 * pe32_opt_hdr_major_ss_version_set()
 *
 * Sets the major subsystem version in the 32-bit PE optional header cached in
 * the PE context 'pex'.  This uses a write-through policy, which means the
 * cache backend store is also updated.
 *****************************************************************************/
int pe32_opt_hdr_major_ss_version_set(struct pe_context *pex, uint16_t version)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe32_image_optional_header,
			   major_subsystem_version);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write16_(pex, offset, version) == -1)
		return -1;

	/* Write was successful.  Update cached copy. */
	pex->opt_header32.major_subsystem_version = version;
	return 0;
}

/******************************************************************************
 * pe32_opt_hdr_minor_ss_version_get()
 *
 * Retrieves the minor subsystem version from the 32-bit PE optional header
 * cached in the PE context 'pex'.
 *****************************************************************************/
uint16_t pe32_opt_hdr_minor_ss_version_get(struct pe_context *pex)
{
	return pex->opt_header32.minor_subsystem_version;
}

/******************************************************************************
 * pe32_opt_hdr_minor_ss_version_set()
 *
 * Sets the minor subsystem version in the 32-bit PE optional header cached in
 * the PE context 'pex'.  This uses a write-through policy, which means the
 * cache backend store is also updated.
 *****************************************************************************/
int pe32_opt_hdr_minor_ss_version_set(struct pe_context *pex, uint16_t version)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe32_image_optional_header,
			   minor_subsystem_version);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write16_(pex, offset, version) == -1)
		return -1;

	/* Write was successful.  Update cached copy. */
	pex->opt_header32.minor_subsystem_version = version;
	return 0;
}

/******************************************************************************
 * pe32_opt_hdr_subsystem_get()
 *
 * Retrieves the subsystem from the 32-bit PE optional header cached in the PE
 * context 'pex'.
 *****************************************************************************/
uint16_t pe32_opt_hdr_subsystem_get(struct pe_context *pex)
{
	return pex->opt_header32.subsystem;
}

/******************************************************************************
 * pe32_opt_hdr_subsystem_set()
 *
 * Sets the subsystem in the 32-bit PE optional header cached in the PE context
 * 'pex'.  This uses a write-through policy, which means the cache backend store
 * is also updated.
 *****************************************************************************/
int pe32_opt_hdr_subsystem_set(struct pe_context *pex, uint16_t subsystem)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe32_image_optional_header, subsystem);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write16_(pex, offset, subsystem) == -1)
		return -1;

	/* Write was successful.  Update cached copy. */
	pex->opt_header32.subsystem = subsystem;
	return 0;
}

/******************************************************************************
 * pe32_opt_hdr_entry_point_get()
 *
 * Retrieves the EP from the 32-bit PE optional header cached in the PE
 * context 'pex'.
 *****************************************************************************/
uint32_t pe32_opt_hdr_entry_point_get(struct pe_context *pex)
{
	return pex->opt_header32.address_of_entry_point;
}

/******************************************************************************
 * pe32_opt_hdr_entry_point_set()
 *
 * Sets the EP in the 32-bit PE optional header cached in the PE context 'pex'.
 * This uses a write-through policy, which means the cache backend store is also
 * updated.
 *****************************************************************************/
int pe32_opt_hdr_entry_point_set(struct pe_context *pex, uint32_t entry_point_addr)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe32_image_optional_header, address_of_entry_point);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write32_(pex, offset, entry_point_addr) == -1) {
	        pex->error = PE_ERROR_WRITE_OPTIONAL_HEADER;
		return -1;
	}

	/* Write was successful.  Update cached copy. */
	pex->opt_header32.address_of_entry_point = entry_point_addr;
	return 0;
}

/******************************************************************************
 * pe32_opt_hdr_base_of_code_get()
 *
 * Retrieves the base of code from the 32-bit PE optional header cached in the PE
 * context 'pex'.
 *****************************************************************************/
uint32_t pe32_opt_hdr_base_of_code_get(struct pe_context *pex)
{
	return pex->opt_header32.base_of_code;
}

/******************************************************************************
 * pe32_opt_hdr_base_of_code_set()
 *
 * Sets the base of code in the 32-bit PE optional header cached in the PE context 'pex'.
 * This uses a write-through policy, which means the cache backend store is also
 * updated.
 *****************************************************************************/
int pe32_opt_hdr_base_of_code_set(struct pe_context *pex, uint32_t base)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe32_image_optional_header, base_of_code);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write32_(pex, offset, base) == -1) {
	        pex->error = PE_ERROR_WRITE_OPTIONAL_HEADER;
		return -1;
	}

	/* Write was successful.  Update cached copy. */
	pex->opt_header32.base_of_code = base;
	return 0;
}

/******************************************************************************
 * pe32_opt_hdr_size_of_code_get()
 *
 * Retrieves the size of code from the 32-bit PE optional header cached in the PE
 * context 'pex'.
 *****************************************************************************/
uint32_t pe32_opt_hdr_size_of_code_get(struct pe_context *pex)
{
	return pex->opt_header32.size_of_code;
}

/******************************************************************************
 * pe32_opt_hdr_size_of_code_set()
 *
 * Sets the size of code in the 32-bit PE optional header cached in the PE context 'pex'.
 * This uses a write-through policy, which means the cache backend store is also
 * updated.
 *****************************************************************************/
int pe32_opt_hdr_size_of_code_set(struct pe_context *pex, uint32_t size)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe32_image_optional_header, size_of_code);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write32_(pex, offset, size) == -1) {
	        pex->error = PE_ERROR_WRITE_OPTIONAL_HEADER;
		return -1;
}

	/* Write was successful.  Update cached copy. */
	pex->opt_header32.size_of_code = size;
	return 0;
}

/******************************************************************************
 * pe32_opt_hdr_section_alignment_get()
 *
 * Retrieves the section alignment from the 32-bit PE optional header cached in the PE
 * context 'pex'.
 *****************************************************************************/
uint32_t pe32_opt_hdr_section_alignment_get(struct pe_context *pex)
{
	return pex->opt_header32.section_alignment;
}

/******************************************************************************
 * pe64_opt_hdr_major_img_version_get()
 *
 * Retrieves the major image version from the 64-bit PE optional header
 * cached in the PE context 'pex'.
 *****************************************************************************/
uint16_t pe64_opt_hdr_major_img_version_get(struct pe_context *pex)
{
	return pex->opt_header64.major_image_version;
}

/******************************************************************************
 * pe64_opt_hdr_major_img_version_set()
 *
 * Sets the major image version in the 64-bit PE optional header cached in the
 * PE context 'pex'.  This uses a write-through policy, which means the cache
 * backend store is also updated.
 *****************************************************************************/
int pe64_opt_hdr_major_img_version_set(struct pe_context *pex, uint16_t version)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe64_image_optional_header,
			   major_image_version);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write16_(pex, offset, version) == -1)
		return -1;

	/* Write was successful.  Update cached copy. */
	pex->opt_header64.major_image_version = version;
	return 0;
}

/******************************************************************************
 * pe64_opt_hdr_minor_img_version_get()
 *
 * Retrieves the minor image version from the 64-bit PE optional header
 * cached in the PE context 'pex'.
 *****************************************************************************/
uint16_t pe64_opt_hdr_minor_img_version_get(struct pe_context *pex)
{
	return pex->opt_header64.minor_image_version;
}

/******************************************************************************
 * pe64_opt_hdr_minor_img_version_set()
 *
 * Sets the minor image version in the 64-bit PE optional header cached in the
 * PE context 'pex'.  This uses a write-through policy, which means the cache
 * backend store is also updated.
 *****************************************************************************/
int pe64_opt_hdr_minor_img_version_set(struct pe_context *pex, uint16_t version)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe64_image_optional_header,
			   minor_image_version);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write16_(pex, offset, version) == -1)
		return -1;

	/* Write was successful.  Update cached copy. */
	pex->opt_header64.minor_image_version = version;
	return 0;
}

/******************************************************************************
 * pe64_opt_hdr_major_os_version_get()
 *
 * Retrieves the major operating system version from the 64-bit PE optional
 * header cached in the PE context 'pex'.
 *****************************************************************************/
uint16_t pe64_opt_hdr_major_os_version_get(struct pe_context *pex)
{
	return pex->opt_header64.major_operating_system_version;
}

/******************************************************************************
 * pe64_opt_hdr_major_os_version_set()
 *
 * Sets the major operating system version in the 64-bit PE optional header
 * cached in the PE context 'pex'.  This uses a write-through policy, which
 * means the cache backend store is also updated.
 *****************************************************************************/
int pe64_opt_hdr_major_os_version_set(struct pe_context *pex, uint16_t version)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe64_image_optional_header,
			   major_operating_system_version);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write16_(pex, offset, version) == -1)
		return -1;

	/* Write was successful.  Update cached copy. */
	pex->opt_header64.major_operating_system_version = version;
	return 0;
}

/******************************************************************************
 * pe64_opt_hdr_minor_os_version_get()
 *
 * Retrieves the minor operating system version from the 64-bit PE optional
 * header cached in the PE context 'pex'.
 *****************************************************************************/
uint16_t pe64_opt_hdr_minor_os_version_get(struct pe_context *pex)
{
	return pex->opt_header64.minor_operating_system_version;
}

/******************************************************************************
 * pe64_opt_hdr_minor_os_version_set()
 *
 * Sets the minor operating system version in the 64-bit PE optional header
 * cached in the PE context 'pex'.  This uses a write-through policy, which
 * means the cache backend store is also updated.
 *****************************************************************************/
int pe64_opt_hdr_minor_os_version_set(struct pe_context *pex, uint16_t version)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe64_image_optional_header,
			   minor_operating_system_version);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write16_(pex, offset, version) == -1)
		return -1;

	/* Write was successful.  Update cached copy. */
	pex->opt_header64.minor_operating_system_version = version;
	return 0;
}

/******************************************************************************
 * pe64_opt_hdr_major_ss_version_get()
 *
 * Retrieves the subsystem version from the 64-bit PE optional header cached in
 * the PE context 'pex'.
 *****************************************************************************/
uint16_t pe64_opt_hdr_major_ss_version_get(struct pe_context *pex)
{
	return pex->opt_header64.major_subsystem_version;
}

/******************************************************************************
 * pe64_opt_hdr_major_ss_version_set()
 *
 * Sets the major subsystem version in the 64-bit PE optional header cached in
 * the PE context 'pex'.  This uses a write-through policy, which means the
 * cache backend store is also updated.
 *****************************************************************************/
int pe64_opt_hdr_major_ss_version_set(struct pe_context *pex, uint16_t version)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe64_image_optional_header,
			   major_subsystem_version);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write16_(pex, offset, version) == -1)
		return -1;

	/* Write was successful.  Update cached copy. */
	pex->opt_header64.major_subsystem_version = version;
	return 0;
}

/******************************************************************************
 * pe64_opt_hdr_minor_ss_version_get()
 *
 * Retrieves the minor subsystem version from the 64-bit PE optional header
 * cached in the PE context 'pex'.
 *****************************************************************************/
uint16_t pe64_opt_hdr_minor_ss_version_get(struct pe_context *pex)
{
	return pex->opt_header64.minor_subsystem_version;
}

/******************************************************************************
 * pe64_opt_hdr_minor_ss_version_set()
 *
 * Sets the minor subsystem version in the 64-bit PE optional header cached in
 * the PE context 'pex'.  This uses a write-through policy, which means the
 * cache backend store is also updated.
 *****************************************************************************/
int pe64_opt_hdr_minor_ss_version_set(struct pe_context *pex, uint16_t version)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe64_image_optional_header,
			   minor_subsystem_version);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write16_(pex, offset, version) == -1)
		return -1;

	/* Write was successful.  Update cached copy. */
	pex->opt_header64.minor_subsystem_version = version;
	return 0;
}

/******************************************************************************
 * pe64_opt_hdr_subsystem_get()
 *
 * Retrieves the subsystem from the 64-bit PE optional header cached in the PE
 * context 'pex'.
 *****************************************************************************/
uint16_t pe64_opt_hdr_subsystem_get(struct pe_context *pex)
{
	return pex->opt_header64.subsystem;
}

/******************************************************************************
 * pe64_opt_hdr_subsystem_set()
 *
 * Sets the subsystem in the 64-bit PE optional header cached in the PE context
 * 'pex'.  This uses a write-through policy, which means the cache backend store
 * is also updated.
 *****************************************************************************/
int pe64_opt_hdr_subsystem_set(struct pe_context *pex, uint16_t subsystem)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe64_image_optional_header, subsystem);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write16_(pex, offset, subsystem) == -1)
		return -1;

	/* Write was successful.  Update cached copy. */
	pex->opt_header64.subsystem = subsystem;
	return 0;
}

/******************************************************************************
 * pe64_opt_hdr_entry_point_get()
 *
 * Retrieves the EP from the 64-bit PE optional header cached in the PE
 * context 'pex'.
 *****************************************************************************/
uint32_t pe64_opt_hdr_entry_point_get(struct pe_context *pex)
{
	return pex->opt_header64.address_of_entry_point;
}

/******************************************************************************
 * pe64_opt_hdr_entry_point_set()
 *
 * Sets the EP in the 64-bit PE optional header cached in the PE context 'pex'.
 * This uses a write-through policy, which means the cache backend store is also
 * updated.
 *****************************************************************************/
int pe64_opt_hdr_entry_point_set(struct pe_context *pex, uint32_t entry_point_addr)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe64_image_optional_header, address_of_entry_point);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write32_(pex, offset, entry_point_addr) == -1) {
	        pex->error = PE_ERROR_WRITE_OPTIONAL_HEADER;
		return -1;
	}

	/* Write was successful.  Update cached copy. */
	pex->opt_header64.address_of_entry_point = entry_point_addr;
	return 0;
}

/******************************************************************************
 * pe64_opt_hdr_base_of_code_get()
 *
 * Retrieves the base of code from the 64-bit PE optional header cached in the PE
 * context 'pex'.
 *****************************************************************************/
uint32_t pe64_opt_hdr_base_of_code_get(struct pe_context *pex)
{
	return pex->opt_header64.base_of_code;
}

/******************************************************************************
 * pe64_opt_hdr_base_of_code_set()
 *
 * Sets the base of code in the 64-bit PE optional header cached in the PE context 'pex'.
 * This uses a write-through policy, which means the cache backend store is also
 * updated.
 *****************************************************************************/
int pe64_opt_hdr_base_of_code_set(struct pe_context *pex, uint32_t base)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe64_image_optional_header, base_of_code);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write32_(pex, offset, base) == -1) {
	        pex->error = PE_ERROR_WRITE_OPTIONAL_HEADER;
		return -1;
	}

	/* Write was successful.  Update cached copy. */
	pex->opt_header64.base_of_code = base;
	return 0;
}

/******************************************************************************
 * pe64_opt_hdr_size_of_code_get()
 *
 * Retrieves the size of code from the 64-bit PE optional header cached in the PE
 * context 'pex'.
 *****************************************************************************/
uint32_t pe64_opt_hdr_size_of_code_get(struct pe_context *pex)
{
	return pex->opt_header64.size_of_code;
}

/******************************************************************************
 * pe64_opt_hdr_size_of_code_set()
 *
 * Sets the size of code in the 64-bit PE optional header cached in the PE context 'pex'.
 * This uses a write-through policy, which means the cache backend store is also
 * updated.
 *****************************************************************************/
int pe64_opt_hdr_size_of_code_set(struct pe_context *pex, uint32_t size)
{
	off_t offset = pex->opt_header_offset;

	/* Skip to the subsystem entry in the optional header. */
	offset += offsetof(struct pe64_image_optional_header, size_of_code);

	/* This sets pex->error, so we do not need to do it. */
	if (pe_write32_(pex, offset, size) == -1) {
	        pex->error = PE_ERROR_WRITE_OPTIONAL_HEADER;
		return -1;
	}

	/* Write was successful.  Update cached copy. */
	pex->opt_header64.size_of_code = size;
	return 0;
}

/******************************************************************************
 * pe64_opt_hdr_section_alignment_get()
 *
 * Retrieves the section alignment from the 64-bit PE optional header cached in the PE
 * context 'pex'.
 *****************************************************************************/
uint32_t pe64_opt_hdr_section_alignment_get(struct pe_context *pex)
{
	return pex->opt_header64.section_alignment;
}


struct pe_image_data_directory *
pe_opt_hdr_directory_get(struct pe_context *pex, int index)
{
	return pex->opt_header_ops->directory_get(pex, index);
}

// TODO: CORRUPTION
struct pe_image_data_directory *
pe32_opt_hdr_directory_get(struct pe_context *pex, int index)
{
	return &pex->opt_header32.data_directory[index];
}

struct pe_image_data_directory *
pe64_opt_hdr_directory_get(struct pe_context *pex, int index)
{
	return &pex->opt_header64.data_directory[index];
}

uint32_t pe_directory_entry_export_size(struct pe_context *pex)
{
	struct pe_image_data_directory *dir;

	dir = pe_opt_hdr_directory_get(pex, PE_IMAGE_DIRECTORY_ENTRY_EXPORT);
	return dir->size;
}

rva_t pe_directory_entry_export(struct pe_context *pex)
{
	struct pe_image_data_directory *dir;

	dir = pe_opt_hdr_directory_get(pex, PE_IMAGE_DIRECTORY_ENTRY_EXPORT);
	return dir->virtual_address;
}

uint32_t pe_directory_entry_tls_callbacks_size(struct pe_context *pex)
{
	struct pe_image_data_directory *dir;

	dir = pe_opt_hdr_directory_get(pex, PE_IMAGE_DIRECTORY_ENTRY_TLS);
	return dir->size;
}

rva_t pe_directory_entry_tls_callbacks(struct pe_context *pex)
{
	struct pe_image_data_directory *dir;

	dir = pe_opt_hdr_directory_get(pex, PE_IMAGE_DIRECTORY_ENTRY_TLS);
	return dir->virtual_address;
}

uint32_t pe_directory_entry_import_size(struct pe_context *pex)
{
	struct pe_image_data_directory *dir;

	dir = pe_opt_hdr_directory_get(pex, PE_IMAGE_DIRECTORY_ENTRY_IMPORT);
	return dir->size;
}

rva_t pe_directory_entry_import(struct pe_context *pex)
{
	struct pe_image_data_directory *dir;

	dir = pe_opt_hdr_directory_get(pex, PE_IMAGE_DIRECTORY_ENTRY_IMPORT);
	return dir->virtual_address;
}

uint32_t pe_directory_entry_delay_size(struct pe_context *pex)
{
	struct pe_image_data_directory *dir;

	dir = pe_opt_hdr_directory_get(pex, PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
	return dir->size;
}

rva_t pe_directory_entry_delay(struct pe_context *pex)
{
	struct pe_image_data_directory *dir;

	dir = pe_opt_hdr_directory_get(pex, PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
	return dir->virtual_address;
}

/* PE section table functions */
static void pe_display_section_(struct pe_image_section_header *s)
{
	printf("<section>\n");
	printf("\t-> name: %s\n", s->name);
	printf("\t-> virtual address: 0x%.8x\n", s->virtual_address);
	printf("\t-> size: %d\n", s->misc.virtual_size);
	//TODO: Finish the function (Characteristic parsing)
	return;
}

int pe_section_display_by_name(struct pe_context *pex, const char *name)
{
	struct pe_image_section_header *sect_hdr;
	uint16_t i;

	for (i = 0; i < pe_image_header_get_number_of_sections(pex); i++) {
		// pex->section_header[i] will _not_ be out of bound
		sect_hdr = &pex->section_header[i];
		if (!strcmp(name, (const char *)sect_hdr->name)) {
			pe_display_section_(sect_hdr);
			return 0;
		}
	}

	pex->error = PE_ERROR_SECTION_NOT_FOUND;
	return -1;
}

int pe_section_display_by_idx(struct pe_context *pex, uint16_t idx)
{
	if (idx >= pe_image_header_get_number_of_sections(pex)) {
		pex->error = PE_ERROR_SECTION_NOT_FOUND;
		return -1;
	}

	pe_display_section_(&pex->section_header[idx]);
	return 0;
}

rva_t pe_section_virtual_address_by_idx_get(struct pe_context *pex, uint16_t idx)
{
	struct pe_image_section_header *sect_hdr;

	if (idx >= pe_image_header_get_number_of_sections(pex)) {
		pex->error = PE_ERROR_SECTION_NOT_FOUND;
		return -1;
	}

	sect_hdr = &pex->section_header[idx];
	return sect_hdr->virtual_address;
}

rva_t pe_section_virtual_address_by_name_get(struct pe_context *pex, const char *name)
{
	struct pe_image_section_header *sect_hdr;
	uint16_t i;

	for (i = 0; i < pe_image_header_get_number_of_sections(pex); i++) {
		// pex->section_header[i] will _not_ be out of bound
		sect_hdr = &pex->section_header[i];
		if (!strcmp(name, (const char *)sect_hdr->name))
			return sect_hdr->virtual_address;
	}

	pex->error = PE_ERROR_SECTION_NOT_FOUND;
	return -1;
}

void *pe_section_from_rva_get(struct pe_context *pex, rva_t rva)
{
	struct pe_image_section_header *sect_hdr;
	uint16_t i;

	for (i = 0; i < pe_image_header_get_number_of_sections(pex); i++) {
		sect_hdr = &pex->section_header[i];

		if (rva >= sect_hdr->virtual_address
		    && rva < (sect_hdr->virtual_address + sect_hdr->misc.virtual_size))
			return sect_hdr;
	}

	return NULL;
}

/* PE TLS Callbacks directory functions */
int pe32_tls_callback_directory_get(struct pe_context *pex, struct pe32_image_tls_directory *d)
{
	struct pt_file *file = pex->file_;
	uint32_t dir_entry_size;
	off_t off_tls, off_old;
	rva_t rva_tls;
	ssize_t ret;

	dir_entry_size = pe_directory_entry_tls_callbacks_size(pex);

	/* If the module is not an executable, there won't be any export directory */
	if (dir_entry_size == 0) {
		pex->error = PE_ERROR_NO_TLS_CALLBACK;
		goto err;
	}

	/* For now, we do not handle short sizes. */
	if (dir_entry_size < sizeof *d) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		goto err;
	}

	/* Get the rva of the directory entry, transform it in a file offset */
	rva_tls = pe_directory_entry_tls_callbacks(pex);
	off_tls = pe_rva_to_offset(pex, rva_tls);

	if (off_tls == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		goto err;
	}

	/* Seek to the export directory. */
	off_old = file->file_ops->seek(file, off_tls, SEEK_SET);
	if (off_old == -1) {
		pex->error = PE_ERROR_INVALID_PE_OFFSET;
		goto err;
	}

	/* Read the export directory */
	ret = file->file_ops->read(file, d, sizeof *d);
	if (ret != sizeof *d) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		goto err_seek;
	}

	return 0;

err_seek:
	file->file_ops->seek(file, off_old, SEEK_SET);
err:
	return -1;
}

/* PE export directory functions */
int pe_export_directory_get(struct pe_context *pex, struct pe_image_export_directory *d)
{
	struct pt_file *file = pex->file_;
	off_t off_export, off_old;
	uint32_t dir_entry_size;
	rva_t rva_export;
	ssize_t ret;

	dir_entry_size = pe_directory_entry_export_size(pex);

	/* If the module is not an executable, there won't be any export directory */
	if (dir_entry_size == 0) {
		pex->error = PE_ERROR_NO_EXPORT;
		goto err;
	}

	/* For now, we do not handle short sizes. */
	if (dir_entry_size < sizeof *d) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		goto err;
	}

	/* Get the rva of the directory entry, transform it in a file offset */
	rva_export = pe_directory_entry_export(pex);
	off_export = pe_rva_to_offset(pex, rva_export);

	if (off_export == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		goto err;
	}

	/* Seek to the export directory. */
	off_old = file->file_ops->seek(file, off_export, SEEK_SET);
	if (off_old == -1) {
		pex->error = PE_ERROR_INVALID_PE_OFFSET;
		goto err;
	}

	/* Read the export directory */
	ret = file->file_ops->read(file, d, sizeof *d);
	if (ret != sizeof *d) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		goto err_seek;
	}

	return 0;

err_seek:
	file->file_ops->seek(file, off_old, SEEK_SET);
err:
	return -1;
}


int pe_import_directory_table_get(struct pe_context *pex, struct pe_image_import_directory_table  *t)
{
	struct pt_file *file = pex->file_;
	off_t off_import, off_old;
	uint32_t dir_entry_size;
	rva_t rva_import;
	ssize_t ret;

	dir_entry_size = pe_directory_entry_import_size(pex);

	/* If the module is not an executable, there won't be any export directory */
	if (dir_entry_size == 0) {
		pex->error = PE_ERROR_NO_IMPORT;
		goto err;
	}

	/* If the size is inferior to an entry or more generally is not a multiple
	 * of the directory size then we cannot do anything */

	t->nbr_entries = dir_entry_size / sizeof(struct pe_image_import_descriptor);
	if (dir_entry_size < sizeof(struct pe_image_import_descriptor)) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		goto err;
	}

	if ( (t->array = malloc(dir_entry_size)) == NULL) {
		pex->error = PE_ERROR_NO_MORE_MEMORY;
		goto err;
	}

	/* Get the rva of the directory entry, transform it in a file offset */
	rva_import = pe_directory_entry_import(pex);
	off_import = pe_rva_to_offset(pex, rva_import);
	if (off_import == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		goto err_free;
	}

	/* Seek to the export directory. */
	off_old = file->file_ops->seek(file, off_import, SEEK_SET);
	if (off_old == -1) {
		pex->error = PE_ERROR_INVALID_PE_OFFSET;
		goto err_free;
	}

	/* Read the export directory */
	ret = file->file_ops->read(file, t->array, dir_entry_size);
	if (ret != dir_entry_size) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		goto err_seek;
	}

	return 0;

err_seek:
	file->file_ops->seek(file, off_old, SEEK_SET);
err_free:
	free(t->array);
err:
	return -1;
}

char *pe_import_directory_get_module_name(struct pe_context *pex, struct pe_image_import_directory_table *t, int idx)
{
	struct pe_image_import_descriptor *d;
	off_t offset;

	d = &t->array[idx];

	if (!d->characteristics) {
		pex->error = PE_ERROR_END_OF_ARRAY;
		return NULL;
	}

	offset = pe_rva_to_offset(pex, d->name);
	if (offset == -1) {
		pex->error = PE_ERROR_INVALID_PE_OFFSET;
		return NULL;
	}

	return pe_ascii_string_read(pex, offset);
}

char *pe_delay_directory_get_module_name(struct pe_context *pex, struct pe_image_delay_directory_table *t, int idx)
{
	struct pe_image_delay_descriptor *d;
	off_t offset;

	d = &t->array[idx];

	if (!d->attributes) {
		pex->error = PE_ERROR_END_OF_ARRAY;
		return NULL;
	}

	offset = pe_rva_to_offset(pex, d->dll_name);
	if (offset == -1) {
		pex->error = PE_ERROR_INVALID_PE_OFFSET;
		return NULL;
	}

	return pe_ascii_string_read(pex, offset);
}

char *pe_import_directory_get_function_name(struct pe_context *pex, int idx_module, int idx_function)
{
	if(pe_image_header_get_machine(pex) & PE_IMAGE_FILE_MACHINE_I386)
	        return pe_import_directory_get_function_name32(pex, idx_module, idx_function);
	else
	        return pe_import_directory_get_function_name64(pex, idx_module, idx_function);
}

char *pe_import_directory_get_function_name32(struct pe_context *pex, int idx_module, int idx_function)
{
	struct pe_image_import_directory_table *t;
	struct pe_image_import_descriptor *d;
	struct image_thunk_data32 thunk;
	struct image_import_by_name name;
	struct pt_file *file = pex->file_;
	char tmp[256];
	rva_t ilt_rva;
	off_t  old_offset, offset;
	int ret;

	t = &pex->import_directory;
	d = &t->array[idx_module];

	// TODO add a check against the indexes

	if(!d->characteristics) {
	        pex->error = PE_ERROR_INVALID_PARAMETER;
	        return NULL;
	}

	// To retrieve the name of the function, the first thing to do is
	// to get the RVA of ILT table

	ilt_rva = d->original_first_thunk;
	offset = pe_rva_to_offset(pex, ilt_rva);
	if (offset == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return NULL;
	}

	// Then using the index of the function, we can select the
	// appropriate entry

	offset += sizeof(thunk) * idx_function;

	old_offset = file->file_ops->seek(file, offset, SEEK_SET);
	if(old_offset == -1) {
	        pex->error = PE_ERROR_INVALID_PE_OFFSET;
	        return NULL;
	}

	ret = file->file_ops->read(file, &thunk, sizeof(thunk));
	if (ret != sizeof(thunk)) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return NULL;
	}

	file->file_ops->seek(file, old_offset, SEEK_SET);

	if(thunk.ordinal == 0) {
	        pex->error = PE_ERROR_END_OF_ARRAY;
	        return NULL;
	}

	// The name of the function was not actually be registered within the
	// DLL so we need to build one using the ordinal.

	if(thunk.ordinal & IMAGE_ORDINAL_FLAG32) {
	        memset(tmp, 0, sizeof(tmp));
	        snprintf(tmp,sizeof(tmp)-1,"ordinal_%.6x", thunk.ordinal & (IMAGE_ORDINAL_FLAG32-1));
	        return strdup(tmp);
	}

	// The RVA of the struct image_import_by_name object is
	// actually stored in the thunk object

	offset = pe_rva_to_offset(pex, thunk.ordinal);
	if (offset == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return NULL;
	}

	old_offset = file->file_ops->seek(file, offset, SEEK_SET);
	if(old_offset == -1) {
	        pex->error = PE_ERROR_INVALID_PE_OFFSET;
	        return NULL;
	}

	// At this RVA is stored a struct image_import_by_name which
	// has the name of the function

	ret = file->file_ops->read(file, &name, sizeof(name));
	if (ret != sizeof(name)) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return NULL;
	}

	file->file_ops->seek(file, old_offset, SEEK_SET);
	return pe_ascii_string_read(pex, offset+sizeof(uint16_t));
}

char *pe_delay_directory_get_function_name(struct pe_context *pex, int idx_module, int idx_function)
{
	if(pe_image_header_get_machine(pex) & PE_IMAGE_FILE_MACHINE_I386)
	        return pe_delay_directory_get_function_name32(pex, idx_module, idx_function);
	else
	        return pe_delay_directory_get_function_name64(pex, idx_module, idx_function);
}

char *pe_delay_directory_get_function_name32(struct pe_context *pex, int idx_module, int idx_function)
{
	struct pe_image_delay_directory_table *t;
	struct pe_image_delay_descriptor *d;
	struct image_thunk_data32 thunk;
	struct image_import_by_name name;
	struct pt_file *file = pex->file_;
	char tmp[256];
	rva_t ilt_rva;
	off_t  old_offset, offset;
	int ret;

	t = &pex->delay_directory;
	d = &t->array[idx_module];

	// TODO add a check against the indexes

	if(!d->attributes) {
	        pex->error = PE_ERROR_INVALID_PARAMETER;
	        return NULL;
	}

	// To retrieve the name of the function, the first thing to do is
	// to get the RVA of ILT table

	ilt_rva = d->in_table;
	offset = pe_rva_to_offset(pex, ilt_rva);
	if (offset == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return NULL;
	}

	// Then using the index of the function, we can select the
	// appropriate entry

	offset += sizeof(thunk) * idx_function;

	old_offset = file->file_ops->seek(file, offset, SEEK_SET);
	if(old_offset == -1) {
	        pex->error = PE_ERROR_INVALID_PE_OFFSET;
	        return NULL;
	}

	ret = file->file_ops->read(file, &thunk, sizeof(thunk));
	if (ret != sizeof(thunk)) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return NULL;
	}

	file->file_ops->seek(file, old_offset, SEEK_SET);

	if(thunk.ordinal == 0) {
	        pex->error = PE_ERROR_END_OF_ARRAY;
	        return NULL;
	}

	// The name of the function was not actually be registered within the
	// DLL so we need to build one using the ordinal.

	if(thunk.ordinal & IMAGE_ORDINAL_FLAG32) {
	        memset(tmp, 0, sizeof(tmp));
	        snprintf(tmp,sizeof(tmp)-1,"ordinal_%.6x", thunk.ordinal & (IMAGE_ORDINAL_FLAG32-1));
	        return strdup(tmp);
	}

	// The RVA of the struct image_import_by_name object is
	// actually stored in the thunk object

	offset = pe_rva_to_offset(pex, thunk.ordinal);
	if (offset == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return NULL;
	}

	old_offset = file->file_ops->seek(file, offset, SEEK_SET);
	if(old_offset == -1) {
	        pex->error = PE_ERROR_INVALID_PE_OFFSET;
	        return NULL;
	}

	// At this RVA is stored a struct image_import_by_name which
	// has the name of the function

	ret = file->file_ops->read(file, &name, sizeof(name));
	if (ret != sizeof(name)) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return NULL;
	}

	file->file_ops->seek(file, old_offset, SEEK_SET);
	return pe_ascii_string_read(pex, offset+sizeof(uint16_t));
}

char *pe_delay_directory_get_function_name64(struct pe_context *pex, int idx_module, int idx_function)
{
	return NULL;
}

char *pe_import_directory_get_function_name64(struct pe_context *pex, int idx_module, int idx_function)
{
	struct pe_image_import_directory_table *t;
	struct pe_image_import_descriptor *d;
	struct image_thunk_data64 thunk;
	struct image_import_by_name name;
	struct pt_file *file = pex->file_;
	char tmp[256];
	rva_t ilt_rva;
	off_t  old_offset, offset;
	int ret;

	t = &pex->import_directory;
	d = &t->array[idx_module];

	// TODO add a check against the indexes

	if (!d->characteristics) {
	        pex->error = PE_ERROR_INVALID_PARAMETER;
	        return NULL;
	}

	// To retrieve the name of the function, the first thing to do is
	// to get the RVA of ILT table

	ilt_rva = d->original_first_thunk;
	offset = pe_rva_to_offset(pex, ilt_rva);
	if (offset == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return NULL;
	}

	// Then using the index of the function, we can select the
	// appropriate entry

	offset += sizeof(thunk) * idx_function;

	old_offset = file->file_ops->seek(file, offset, SEEK_SET);
	if (old_offset == -1) {
	        pex->error = PE_ERROR_INVALID_PE_OFFSET;
	        return NULL;
	}

	ret = file->file_ops->read(file, &thunk, sizeof(thunk));
	if (ret != sizeof(thunk)) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return NULL;
	}

	file->file_ops->seek(file, old_offset, SEEK_SET);

	if (thunk.ordinal == 0) {
	        pex->error = PE_ERROR_END_OF_ARRAY;
	        return NULL;
	}

	// The name of the function was not actually be registered within the
	// DLL so we need to build one using the ordinal.

	if (thunk.ordinal & IMAGE_ORDINAL_FLAG64) {
	        memset(tmp, 0, sizeof(tmp));
	        snprintf(tmp, sizeof(tmp), "ordinal_%.6I64x",
		         thunk.ordinal & (IMAGE_ORDINAL_FLAG64 - 1));
	        return strdup(tmp);
	}

	// The RVA of the struct image_import_by_name object is
	// actually stored in the thunk object

	offset = pe_rva_to_offset(pex, thunk.ordinal);
	if (offset == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return NULL;
	}

	old_offset = file->file_ops->seek(file, offset, SEEK_SET);
	if (old_offset == -1) {
	        pex->error = PE_ERROR_INVALID_PE_OFFSET;
	        return NULL;
	}

	// At this RVA is stored a struct image_import_by_name which
	// has the name of the function

	ret = file->file_ops->read(file, &name, sizeof(name));
	if (ret != sizeof(name)) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return NULL;
	}

	file->file_ops->seek(file, old_offset, SEEK_SET);
	return pe_ascii_string_read(pex, offset+sizeof(uint16_t));
}


rva_t pe_import_directory_get_function_ptr_iat(struct pe_context *pex, int idx_module, int idx_function)
{
	if (pe_image_header_get_machine(pex) & PE_IMAGE_FILE_MACHINE_I386)
	        return pe_import_directory_get_function_ptr_iat32(pex, idx_module, idx_function);
	else
	        return pe_import_directory_get_function_ptr_iat64(pex, idx_module, idx_function);
}

rva_t pe_import_directory_get_function_ptr_iat32(struct pe_context *pex, int idx_module, int idx_function)
{
	struct pe_image_import_directory_table *t;
	struct pe_image_import_descriptor *d;
	rva_t iat_rva;
	off_t offset_rva;

	t = &pex->import_directory;
	d = &t->array[idx_module];

// TODO add a check against the indexes

	if (!d->characteristics) {
	        pex->error = PE_ERROR_INVALID_PARAMETER;
	        return -1;
	}

	// We retrieve the IAT entry
	iat_rva = d->first_thunk;
	iat_rva += sizeof(uint32_t) * idx_function;

	// We check a bit this offset
	offset_rva = pe_rva_to_offset(pex, iat_rva);
	if (offset_rva == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return -1;
	}
	return iat_rva;
}

rva_t pe_delay_directory_get_function_ptr_iat(struct pe_context *pex, int idx_module, int idx_function)
{
	if (pe_image_header_get_machine(pex) & PE_IMAGE_FILE_MACHINE_I386)
	        return pe_delay_directory_get_function_ptr_iat32(pex, idx_module, idx_function);
	else
	        return pe_delay_directory_get_function_ptr_iat64(pex, idx_module, idx_function);
}

rva_t pe_delay_directory_get_function_ptr_iat32(struct pe_context *pex, int idx_module, int idx_function)
{
	struct pe_image_delay_directory_table *t;
	struct pe_image_delay_descriptor *d;
	rva_t iat_rva;
	off_t offset_rva;

	t = &pex->delay_directory;
	d = &t->array[idx_module];

	// TODO add a check against the indexes

	if (!d->attributes) {
	        pex->error = PE_ERROR_INVALID_PARAMETER;
	        return -1;
	}

	// We retrieve the IAT entry
	iat_rva = d->iat;
	iat_rva += sizeof(uint32_t) * idx_function;

	// We check a bit this offset
	offset_rva = pe_rva_to_offset(pex, iat_rva);
	if (offset_rva == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return -1;
	}

	return iat_rva;
}

rva_t pe_delay_directory_get_function_ptr_iat64(struct pe_context *pex, int idx_module, int idx_function)
{
	return -1;
}

rva_t pe_import_directory_get_function_ptr_iat64(struct pe_context *pex, int idx_module, int idx_function)
{
	struct pe_image_import_directory_table *t;
	struct pe_image_import_descriptor *d;
	rva_t iat_rva;
	off_t offset_rva;

	t = &pex->import_directory;
	d = &t->array[idx_module];

	// TODO add a check against the indexes

	if (!d->characteristics) {
	        pex->error = PE_ERROR_INVALID_PARAMETER;
	        return -1;
	}

	// We retrieve the IAT entry
	iat_rva = d->first_thunk;
	iat_rva += sizeof(uint64_t) * idx_function;

	// We check a bit this offset
	offset_rva = pe_rva_to_offset(pex, iat_rva);
	if (offset_rva == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return -1;
	}

	return iat_rva;
}

int pe_delay_directory_table_get(struct pe_context *pex, struct pe_image_delay_directory_table *t)
{
	struct pt_file *file = pex->file_;
	off_t off_delay, off_old;
	uint32_t dir_entry_size;
	rva_t rva_delay;
	ssize_t ret;

	dir_entry_size = pe_directory_entry_delay_size(pex);

	/* If the module is not an executable, there won't be any export directory */
	if (dir_entry_size == 0) {
		pex->error = PE_ERROR_NO_DELAY;
		goto err;
	}

	/* If the size is inferior to an entry or more generally is not a multiple
	 * of the directory size then we cannot do anything
	 */
	t->nbr_entries = dir_entry_size / sizeof(struct pe_image_delay_descriptor);
	if (dir_entry_size < sizeof(struct pe_image_delay_descriptor)) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		goto err;
	}

	if ( (t->array = malloc(dir_entry_size)) == NULL) {
	        pex->error = PE_ERROR_NO_MORE_MEMORY;
	        goto err;
	}

	/* Get the rva of the directory entry, transform it in a file offset */
	rva_delay = pe_directory_entry_delay(pex);
	off_delay = pe_rva_to_offset(pex, rva_delay);
	if (off_delay == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		goto err_free;
	}

	/* Seek to the export directory. */
	off_old = file->file_ops->seek(file, off_delay, SEEK_SET);
	if (off_old == -1) {
		pex->error = PE_ERROR_INVALID_PE_OFFSET;
		goto err_seek;
	}

	/* Read the export directory */
	ret = file->file_ops->read(file, t->array, dir_entry_size);
	if (ret != dir_entry_size) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		goto err_seek;
	}

	return 0;

err_seek:
	file->file_ops->seek(file, off_old, SEEK_SET);
err_free:
	free(t->array);
err:
	return -1;
}

rva_t *
pe_export_directory_get_names_rva(struct pe_context *pex, struct pe_image_export_directory *d)
{
	size_t size = d->number_of_names * sizeof(rva_t);
	struct pt_file *file = pex->file_;
	off_t off_old, offset_of_names;
	ssize_t ret;
	rva_t *vas;

	/* Ensure we can handle number_of_names on this architecture. */
	if (size / sizeof(rva_t) != d->number_of_names)
		goto err;

	if ( (vas = malloc(size)) == NULL) {
	        pex->error = PE_ERROR_NO_MORE_MEMORY;
		goto err;
	}

	/* Seek to the names RVA table. */
	offset_of_names = pe_rva_to_offset(pex, d->address_of_names);
	if (offset_of_names == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		goto err_free;
	}

	off_old = file->file_ops->seek(file, offset_of_names, SEEK_SET);
	if (off_old == -1) {
		pex->error = PE_ERROR_INVALID_PE_OFFSET;
		goto err_free;
	}

	/* Read the names RVA table. */
	ret = file->file_ops->read(file, vas, size);
	if (ret != size)
		goto err_seek;

	/* Restore old position. */
	if (file->file_ops->seek(file, off_old, SEEK_SET) == -1)
		goto err_free;

	return vas;

err_seek:
	file->file_ops->seek(file, off_old, SEEK_SET);
err_free:
	free(vas);
err:
	return NULL;
}

int
pe_export_directory_get_index_of_ordinal(struct pe_context *pex, struct pe_image_export_directory *d, uint16_t ordinal)
{
	struct pt_file *file = pex->file_;
	off_t offset_of_ordinals;
	uint16_t *ordinals;
	ssize_t ret;
	size_t size;
	int index;

	size = d->number_of_names * sizeof(uint16_t);
	if ( (ordinals = malloc(size)) == NULL) {
	        pex->error = PE_ERROR_NO_MORE_MEMORY;
		goto err;
	}

	offset_of_ordinals = pe_rva_to_offset(pex, d->address_of_name_ordinals);
	if (offset_of_ordinals == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		goto err_free;
	}

	if (file->file_ops->seek(file, offset_of_ordinals, SEEK_SET) == -1) {
		pex->error = PE_ERROR_INVALID_PE_OFFSET;
		goto err_free;
	}

	// Read and cache the ordinal array
	ret = file->file_ops->read(file, ordinals, size);
	if (ret != size) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		goto err_free;
	}

	// For all the entries, we look for a specific ordinal
	for (index = 0; index < d->number_of_names; index++) {
		if (ordinals[index] + d->base == ordinal) {
	                free(ordinals);
	                return index;
	        }
	}

err_free:
	free(ordinals);
err:
	return -1;
}

uint32_t
pe32_tls_callback_directory_get_function_va(struct pe_context *pex,
	struct pe32_image_tls_directory *d, uint32_t base, int index)
{
	struct pt_file *file = pex->file_;
	off_t offset_of_functions;
	uint32_t address;
	ssize_t ret;

	if (index < 0) {
		pex->error = PE_ERROR_INVALID_PARAMETER;
		return -1;
	}

	offset_of_functions = pe_rva_to_offset(pex, (rva_t)(d->address_of_callbacks-(uint32_t)base));

	if (offset_of_functions == -1) {
                if(pex->error == PE_ERROR_INVALID_PE_OFFSET) {
                        pex->error = PE_ERROR_TLS_CALLBACK_IN_MEMORY;
                        return -1;
                }
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return -1;
	}

	offset_of_functions += index * sizeof(uint32_t);

	if (file->file_ops->seek(file, offset_of_functions, SEEK_SET) == -1) {
		pex->error = PE_ERROR_INVALID_PE_OFFSET;
		return -1;
	}

	/* Read and cache the image file header. */
	ret = file->file_ops->read(file, &address, sizeof address);
	if (ret != sizeof address) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		address = -1;
	}

	return address;
}

rva_t
pe_export_directory_get_function_rva(struct pe_context *pex, struct pe_image_export_directory *d, int index)
{
	struct pt_file *file = pex->file_;
	off_t offset_of_functions;
	rva_t address;
	ssize_t ret;

	if (index < 0 || index >= d->number_of_functions) {
		pex->error = PE_ERROR_INVALID_PARAMETER;
		return -1;
	}

	offset_of_functions = pe_rva_to_offset(pex, d->address_of_functions);
	if (offset_of_functions == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return -1;
	}

	offset_of_functions += index * sizeof(uint32_t);

	if (file->file_ops->seek(file, offset_of_functions, SEEK_SET) == -1) {
		pex->error = PE_ERROR_INVALID_PE_OFFSET;
		return -1;
	}

	/* Read and cache the image file header. */
	ret = file->file_ops->read(file, &address, sizeof address);
	if (ret != sizeof address) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		address = -1;
	}

	return address;
}

int32_t
pe_export_directory_get_names_ordinal(struct pe_context *pex, struct pe_image_export_directory *d, int index)
{
	struct pt_file *file = pex->file_;
	off_t offset_of_name_ordinals;
	ordinal_t ordinal;
	ssize_t ret;

	if (index < 0 || index >= d->number_of_functions) {
		pex->error = PE_ERROR_INVALID_PARAMETER;
		return -1;
	}

	offset_of_name_ordinals = pe_rva_to_offset(pex, d->address_of_name_ordinals);
	if (offset_of_name_ordinals == -1) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return -1;
	}

	offset_of_name_ordinals += index * sizeof(ordinal_t);

	if (file->file_ops->seek(file, offset_of_name_ordinals, SEEK_SET) == -1) {
		pex->error = PE_ERROR_INVALID_PE_OFFSET;
		return -1;
	}

	/* Read and cache the image file header. */
	ret = file->file_ops->read(file, &ordinal, sizeof ordinal);
	if (ret != sizeof ordinal) {
		pex->error = PE_ERROR_CORRUPTED_MODULE;
		return -1;
	}

	return ordinal;
}

void
pe_export_directory_print(struct pe_context *pex, struct pe_image_export_directory *d)
{
	char *name;

	printf("Characteristics:       0x%.8x\n", d->characteristics);
	printf("TimeDateStamp:	 0x%.8x\n", d->time_date_stamp);
	printf("MajorVersion:	  0x%.4x\n", d->major_version);
	printf("MinorVersion:	  0x%.4x\n", d->minor_version);

	name = pe_ascii_string_read(pex, d->name);
	if (name != NULL)
		printf("Name:		  0x%.8x %s\n", d->name, name);
	else
		printf("Name:		  0x%.8x (unknown)\n", d->name);

	printf("Base:		  0x%.8x\n", d->base);
	printf("NumberOfFunctions:     0x%.8d\n", d->number_of_functions);
	printf("NumberOfNames:	 0x%.8d\n", d->number_of_names);
	printf("AddressOfFunctions:    0x%.8x\n", d->address_of_functions);
	printf("AddressOfNames:	0x%.8x\n", d->address_of_names);
	printf("AddressOfNameOrdinals: 0x%.8x\n", d->address_of_name_ordinals);

	if (name != NULL)
		free(name);
}

