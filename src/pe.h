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
 * pe.h
 *
 * libptrace PE handling library.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 * Author: Roderick Asselineau <roderick@immunityinc.com>
 * Author: Massimiliano Oldani <max@immunityinc.com>
 *
 */
#ifndef PT_PE_INTERNAL_H
#define PT_PE_INTERNAL_H

#include <stdio.h>
#include <stdint.h>
#include <libptrace/file.h>

#define PE_FLAG_RVA_TRANSLATION		1

#define PE_IMAGE_DOS_SIGNATURE	0x5A4D
#define PE_IMAGE_NT_SIGNATURE	0x00004550

#define PE_IMAGE_OPTIONAL_SUBSYSTEM_UNKNOWN			0
#define PE_IMAGE_OPTIONAL_SUBSYSTEM_NATIVE			1
#define PE_IMAGE_OPTIONAL_SUBSYSTEM_WINDOWS_GUI			2
#define PE_IMAGE_OPTIONAL_SUBSYSTEM_WINDOWS_CUI			3
#define PE_IMAGE_OPTIONAL_SUBSYSTEM_OS2_CUI			5
#define PE_IMAGE_OPTIONAL_SUBSYSTEM_POSIX_CUI			7
#define PE_IMAGE_OPTIONAL_SUBSYSTEM_NATIVE_WINDOWS		8
#define PE_IMAGE_OPTIONAL_SUBSYSTEM_WINDOWS_CE_GUI		9
#define PE_IMAGE_OPTIONAL_SUBSYSTEM_EFI_APPLICATION		10
#define PE_IMAGE_OPTIONAL_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER	11
#define PE_IMAGE_OPTIONAL_SUBSYSTEM_EFI_RUNTIME_DRIVER		12
#define PE_IMAGE_OPTIONAL_SUBSYSTEM_EFI_ROM			13
#define PE_IMAGE_OPTIONAL_SUBSYSTEM_XBOX			14

#define PE_IMAGE_DIRECTORY_ENTRY_EXPORT		0
#define PE_IMAGE_DIRECTORY_ENTRY_IMPORT		1
#define PE_IMAGE_DIRECTORY_ENTRY_RESOURCE	2
#define PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION	3
#define PE_IMAGE_DIRECTORY_ENTRY_SECURITY	4
#define PE_IMAGE_DIRECTORY_ENTRY_BASERELOC	5
#define PE_IMAGE_DIRECTORY_ENTRY_DEBUG		6
#define PE_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE	7
#define PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR	8
#define PE_IMAGE_DIRECTORY_ENTRY_TLS		9
#define PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG	10
#define PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT	11
#define PE_IMAGE_DIRECTORY_ENTRY_IAT		12
#define PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT	13
#define PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR	14

#define PE_IMAGE_FILE_MACHINE_UNKNOWN		0
#define PE_IMAGE_FILE_MACHINE_I386		0x014c
#define PE_IMAGE_FILE_MACHINE_R3000		0x0162
#define PE_IMAGE_FILE_MACHINE_R4000		0x0166
#define PE_IMAGE_FILE_MACHINE_R10000		0x0168
#define PE_IMAGE_FILE_MACHINE_WCEMIPSV2		0x0169
#define PE_IMAGE_FILE_MACHINE_ALPHA		0x0184
#define PE_IMAGE_FILE_MACHINE_SH3		0x01a2
#define PE_IMAGE_FILE_MACHINE_SH3DSP		0x01a3
#define PE_IMAGE_FILE_MACHINE_SH3E		0x01a4
#define PE_IMAGE_FILE_MACHINE_SH4		0x01a6
#define PE_IMAGE_FILE_MACHINE_SH5		0x01a8
#define PE_IMAGE_FILE_MACHINE_ARM		0x01c0
#define PE_IMAGE_FILE_MACHINE_THUMB		0x01c2
#define PE_IMAGE_FILE_MACHINE_AM33		0x01d3
#define PE_IMAGE_FILE_MACHINE_POWERPC		0x01F0
#define PE_IMAGE_FILE_MACHINE_POWERPCFP		0x01f1
#define PE_IMAGE_FILE_MACHINE_IA64		0x0200
#define PE_IMAGE_FILE_MACHINE_MIPS16		0x0266
#define PE_IMAGE_FILE_MACHINE_ALPHA64		0x0284
#define PE_IMAGE_FILE_MACHINE_MIPSFPU		0x0366
#define PE_IMAGE_FILE_MACHINE_MIPSFPU16		0x0466
#define PE_IMAGE_FILE_MACHINE_AXP64		PE_IMAGE_FILE_MACHINE_ALPHA64
#define PE_IMAGE_FILE_MACHINE_TRICORE		0x0520
#define PE_IMAGE_FILE_MACHINE_CEF		0x0CEF
#define PE_IMAGE_FILE_MACHINE_EBC		0x0EBC
#define PE_IMAGE_FILE_MACHINE_AMD64		0x8664
#define PE_IMAGE_FILE_MACHINE_M32R		0x9041
#define PE_IMAGE_FILE_MACHINE_CEE		0xC0EE

#define PE_IMAGE_FILE_CHAR_EXECUTABLE_IMAGE     0x0002
#define PE_IMAGE_FILE_CHAR_SYSTEM               0x1000
#define PE_IMAGE_FILE_CHAR_DLL                  0x2000

#define PE_IMAGE_NUMBEROF_DIRECTORY_ENTRIES	16

#define IMAGE_SCN_TYPE_NO_PAD                   0x00000008
#define IMAGE_SCN_CNT_CODE                      0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA          0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA        0x00000080
#define IMAGE_SCN_LNK_OTHER                     0x00000100
#define IMAGE_SCN_LNK_INFO                      0x00000200
#define IMAGE_SCN_LNK_REMOVE                    0x00000800
#define IMAGE_SCN_LNK_COMDAT                    0x00001000
#define IMAGE_SCN_MEM_PURGEABLE                 0x00020000
#define IMAGE_SCN_MEM_LOCKED                    0x00040000
#define IMAGE_SCN_MEM_PRELOAD                   0x00080000
#define IMAGE_SCN_ALIGN_1BYTES                  0x00100000
#define IMAGE_SCN_ALIGN_2BYTES                  0x00200000
#define IMAGE_SCN_ALIGN_4BYTES                  0x00300000
#define IMAGE_SCN_ALIGN_8BYTES                  0x00400000
#define IMAGE_SCN_ALIGN_16BYTES                 0x00500000
#define IMAGE_SCN_ALIGN_32BYTES                 0x00600000
#define IMAGE_SCN_ALIGN_64BYTES                 0x00700000
#define IMAGE_SCN_LNK_NRELOC_OVFL               0x01000000
#define IMAGE_SCN_MEM_NOT_CACHED                0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED                 0x08000000
#define IMAGE_SCN_MEM_DISCARDABLE               0x02000000
#define IMAGE_SCN_MEM_EXECUTE                   0x20000000
#define IMAGE_SCN_MEM_READ                      0x40000000
#define IMAGE_SCN_MEM_WRITE                     0x80000000


enum pe_error
{
	PE_ERROR_NONE,
	PE_ERROR_OPEN_FAILED,
	PE_ERROR_READ_DOS_HEADER,
	PE_ERROR_MAGIC_DOS_HEADER,
	PE_ERROR_INVALID_PE_OFFSET,
	PE_ERROR_READ_IMAGE_HEADERS,
	PE_ERROR_MAGIC_PE_HEADER,
	PE_ERROR_READ_IMAGE_FILE_HEADER,
	PE_ERROR_UNSUPPORTED_ARCHITECTURE,
	PE_ERROR_INVALID_OPTIONAL_SIZE,
	PE_ERROR_READ_OPTIONAL_HEADER,
	PE_ERROR_INVALID_OPTIONAL_OFFSET,
	PE_ERROR_WRITE_OPTIONAL_HEADER,
	PE_ERROR_CORRUPTED_MODULE,
	PE_ERROR_NO_EXPORT,
	PE_ERROR_NO_IMPORT,
	PE_ERROR_NO_DELAY,
	PE_ERROR_NO_TLS_CALLBACK,
        PE_ERROR_TLS_CALLBACK_IN_MEMORY,
	PE_ERROR_READ_SECTION_TABLE,
	PE_ERROR_SECTION_NOT_FOUND,
	PE_ERROR_INVALID_PARAMETER,
	PE_ERROR_NO_MORE_MEMORY,
	PE_ERROR_END_OF_ARRAY,
};

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t rva_t;
typedef uint16_t ordinal_t;

typedef struct {
	uint64_t	value;
	uint8_t		length;
} pe_address_t;

struct pe_image_dos_header
{
	uint16_t	e_magic;
	uint16_t	e_cblp;
	uint16_t	e_cp;
	uint16_t	e_crlc;
	uint16_t	e_cparhdr;
	uint16_t	e_minalloc;
	uint16_t	e_maxalloc;
	uint16_t	e_ss;
	uint16_t	e_sp;
	uint16_t	e_csum;
	uint16_t	e_ip;
	uint16_t	e_cs;
	uint16_t	e_lfarlc;
	uint16_t	e_ovno;
	uint16_t	e_res[4];
	uint16_t	e_oemid;
	uint16_t	e_oeminfo;
	uint16_t	e_res2[10];
	uint32_t	e_lfanew;
} __attribute__ ((packed));

struct pe_image_file_header
{
	uint16_t		machine;
	uint16_t		number_of_sections;
	uint32_t		time_date_stamp;
	uint32_t		pointer_to_symbol_table;
	uint32_t		number_of_symbols;
	uint16_t		size_of_optional_header;
	uint16_t		characteristics;
} __attribute__ ((packed));

struct pe_image_data_directory
{
	rva_t		virtual_address;
	uint32_t	size;
} __attribute__ ((packed));

struct pe32_image_optional_header
{
	uint16_t			magic;
	uint8_t				major_linker_version;
	uint8_t				minor_linker_version;
	uint32_t			size_of_code;
	uint32_t			size_of_initialized_data;
	uint32_t			size_of_uninitialized_data;
	uint32_t			address_of_entry_point;
	uint32_t			base_of_code;
	uint32_t			base_of_data;
	uint32_t			image_base;
	uint32_t			section_alignment;
	uint32_t			file_alignment;
	uint16_t			major_operating_system_version;
	uint16_t			minor_operating_system_version;
	uint16_t			major_image_version;
	uint16_t			minor_image_version;
	uint16_t			major_subsystem_version;
	uint16_t			minor_subsystem_version;
	uint32_t			win32_version_value;
	uint32_t			size_of_image;
	uint32_t			size_of_headers;
	uint32_t			checksum;
	uint16_t			subsystem;
	uint16_t			dll_characteristics;
	uint32_t			size_of_stack_reserve;
	uint32_t			size_of_stack_commit;
	uint32_t			size_of_heap_reserve;
	uint32_t			size_of_heap_commit;
	uint32_t			loader_flags;
	uint32_t			number_of_rva_and_sizes;
	struct pe_image_data_directory	data_directory[PE_IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} __attribute__ ((packed));


struct pe64_image_optional_header
{
	uint16_t			magic;
	uint8_t				major_linker_version;
	uint8_t				minor_linker_version;
	uint32_t			size_of_code;
	uint32_t			size_of_initialized_data;
	uint32_t			size_of_uninitialized_data;
	uint32_t			address_of_entry_point;
	uint32_t			base_of_code;
	uint64_t			image_base;
	uint32_t			section_alignment;
	uint32_t			file_alignment;
	uint16_t			major_operating_system_version;
	uint16_t			minor_operating_system_version;
	uint16_t			major_image_version;
	uint16_t			minor_image_version;
	uint16_t			major_subsystem_version;
	uint16_t			minor_subsystem_version;
	uint32_t			win32_version_value;
	uint32_t			size_of_image;
	uint32_t			size_of_headers;
	uint32_t			checksum;
	uint16_t			subsystem;
	uint16_t			dll_characteristics;
	uint64_t			size_of_stack_reserve;
	uint64_t			size_of_stack_commit;
	uint64_t			size_of_heap_reserve;
	uint64_t			size_of_heap_commit;
	uint32_t			loader_flags;
	uint32_t			number_of_rva_and_sizes;
	struct pe_image_data_directory	data_directory[PE_IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} __attribute__ ((packed));

struct pe_image_export_directory
{
	uint32_t	characteristics;
	uint32_t	time_date_stamp;
	uint16_t	major_version;
	uint16_t	minor_version;
	rva_t		name;
	uint32_t	base;
	uint32_t	number_of_functions;
	uint32_t	number_of_names;
	rva_t		address_of_functions;
	rva_t		address_of_names;
	rva_t		address_of_name_ordinals;
} __attribute__ ((packed));

struct pe32_image_tls_directory
{
	uint32_t	start_address_of_raw_data;
	uint32_t	end_address_of_raw_data;
	uint32_t	address_of_index;
	uint32_t	address_of_callbacks;
	uint32_t	size_of_zero_fill;
	uint32_t	characteristics;
} __attribute__ ((packed));

struct pe64_image_tls_directory
{
	uint64_t	start_address_of_raw_data;
	uint64_t	end_address_of_raw_data;
	uint64_t	address_of_index;
	uint64_t	address_of_callbacks;
	uint32_t	size_of_zero_fill;
	uint32_t	characteristics;
} __attribute__ ((packed));

#define IMAGE_SIZEOF_SHORT_NAME 8

struct pe_image_section_header {
        uint8_t  name[IMAGE_SIZEOF_SHORT_NAME];
        union {
                uint32_t physical_address;
                uint32_t virtual_size;
        } misc;

        rva_t	 virtual_address;
        uint32_t size_of_raw_data;
        uint32_t pointer_to_raw_data;
        uint32_t pointer_to_relocations;
        uint32_t pointer_to_linenumbers;
        uint16_t number_of_relocations;
        uint16_t number_of_linenumbers;
        uint32_t characteristics;
} __attribute__ ((packed));

struct image_import_by_name {
        uint16_t    hint;
        char        name[1];
} __attribute__ ((packed));

#ifndef IMAGE_ORDINAL_FLAG32
#define IMAGE_ORDINAL_FLAG32    0x80000000
#endif

#ifndef IMAGE_ORDINAL_FLAG64
#define IMAGE_ORDINAL_FLAG64    0x8000000000000000
#endif

struct image_thunk_data32 {
        union {
                uint32_t ordinal;
                uint32_t hint;
        };
};

struct image_thunk_data64 {
    union {
        uint64_t ordinal;
        uint64_t hint;
    };
};

struct image_thunk_data {

        union {
		struct image_thunk_data32 thunk32;
		struct image_thunk_data64 thunk64;
        };

} __attribute__ ((packed));

struct pe_image_import_descriptor {
        union {
                uint32_t characteristics;       // 0 for terminating null import descriptor
                uint32_t original_first_thunk;  // It points to the first struct image_thunk_data{32,64}
        };
        uint32_t time_date_stamp;  // 0 if not bound
        uint32_t forwarder_chain;  // -1 if no forwarders
        rva_t name;             // RVA of the module name
        rva_t first_thunk;      // RVA to the entry in the IAT
} __attribute__ ((packed));

struct pe_image_delay_descriptor {
        uint32_t       attributes;      // attributes
        rva_t          dll_name;        // RVA to dll name
        rva_t          module_handle;   // RVA of module handle
        rva_t          iat;             // RVA of the IAT
        rva_t          in_table;        // RVA of the INT
        rva_t          bound_iat;       // RVA of the optional bound IAT
        rva_t          unload_iat;      // RVA of optional copy of original IAT
        uint32_t       time_date_stamp; // 0 if not bound,
                                        // O.W. date/time stamp of DLL bound to (Old BIND)
} __attribute__ ((packed));

struct pe_image_import_directory_table {
        struct pe_image_import_descriptor *array;
        uint32_t nbr_entries;
};

struct pe_image_delay_directory_table {
        struct pe_image_delay_descriptor *array;
        uint32_t nbr_entries;
};

struct pe_context;
struct pe_img_opt_hdr_operations
{
	size_t			size;

        uint16_t		(*major_img_version_get)(struct pe_context *);
        int			(*major_img_version_set)(struct pe_context *, uint16_t);
        uint16_t		(*minor_img_version_get)(struct pe_context *);
        int			(*minor_img_version_set)(struct pe_context *, uint16_t);

        uint16_t		(*major_os_version_get)(struct pe_context *);
        int			(*major_os_version_set)(struct pe_context *, uint16_t);
        uint16_t		(*minor_os_version_get)(struct pe_context *);
        int			(*minor_os_version_set)(struct pe_context *, uint16_t);

        uint16_t		(*major_ss_version_get)(struct pe_context *);
        int			(*major_ss_version_set)(struct pe_context *, uint16_t);
        uint16_t		(*minor_ss_version_get)(struct pe_context *);
        int			(*minor_ss_version_set)(struct pe_context *, uint16_t);

	uint16_t		(*subsystem_get)(struct pe_context *);
	int			(*subsystem_set)(struct pe_context *, uint16_t);

        uint32_t                (*entry_point_get)(struct pe_context *);
        int                     (*entry_point_set)(struct pe_context *, uint32_t);

        uint32_t                (*size_of_code_get)(struct pe_context *);
        int                     (*size_of_code_set)(struct pe_context *, uint32_t);

        uint32_t                (*base_of_code_get)(struct pe_context *);
        int                     (*base_of_code_set)(struct pe_context *, uint32_t);

        uint32_t                (*section_alignment_get)(struct pe_context *);

	struct pe_image_data_directory *(*directory_get)(struct pe_context *, int);
};

struct pe_context
{
	int					flags;
	enum pe_error				error;
	struct pt_file				*file_;
	struct pe_image_file_header		img_header;

	off_t					opt_header_offset;
	union {
		char					opt_header;
		struct pe32_image_optional_header	opt_header32;
		struct pe64_image_optional_header	opt_header64;
	};
	struct pe_img_opt_hdr_operations	*opt_header_ops;

	off_t					section_header_offset;
	struct pe_image_section_header		*section_header;

        struct pe_image_import_directory_table  import_directory;
        struct pe_image_delay_directory_table   delay_directory;
};

/* PE generic API functions */

const char *	pe_errstr(int);
int		pe_open(struct pe_context *, struct pt_file *, int);
void		pe_close(struct pe_context *);
char *		pe_ascii_string_read(struct pe_context *, off_t);
int		pe_data_read(struct pe_context *, off_t, char *, uint32_t);
off_t           pe_rva_to_offset(struct pe_context *, rva_t);
uint16_t	pe_get_subsystem(struct pe_context *);

/* PE image header functions */

uint16_t	pe_image_header_get_optional_size(struct pe_context *);
uint16_t	pe_image_header_get_machine(struct pe_context *);
uint16_t	pe_image_header_get_characteristics(struct pe_context *);
uint16_t	pe_image_header_get_number_of_sections(struct pe_context *);


/* PE optional header functions */
uint16_t	pe_opt_hdr_major_img_version_get(struct pe_context *);
int		pe_opt_hdr_major_img_version_set(struct pe_context *, uint16_t);
uint16_t	pe_opt_hdr_minor_img_version_get(struct pe_context *);
int		pe_opt_hdr_minor_img_version_set(struct pe_context *, uint16_t);
uint16_t	pe_opt_hdr_major_os_version_get(struct pe_context *);
int		pe_opt_hdr_major_os_version_set(struct pe_context *, uint16_t);
uint16_t	pe_opt_hdr_minor_os_version_get(struct pe_context *);
int		pe_opt_hdr_minor_os_version_set(struct pe_context *, uint16_t);
uint16_t	pe_opt_hdr_major_ss_version_get(struct pe_context *);
int		pe_opt_hdr_major_ss_version_set(struct pe_context *, uint16_t);
uint16_t	pe_opt_hdr_minor_ss_version_get(struct pe_context *);
int		pe_opt_hdr_minor_ss_version_set(struct pe_context *, uint16_t);
uint16_t	pe_opt_hdr_subsystem_get(struct pe_context *);
int		pe_opt_hdr_subsystem_set(struct pe_context *, uint16_t);
uint32_t        pe_opt_hdr_entry_point_get(struct pe_context *);
int             pe_opt_hdr_entry_point_set(struct pe_context *, uint32_t);
uint32_t        pe_opt_hdr_base_of_code_get(struct pe_context *);
int             pe_opt_hdr_base_of_code_set(struct pe_context *, uint32_t);
uint32_t        pe_opt_hdr_size_of_code_get(struct pe_context *);
int             pe_opt_hdr_size_of_code_set(struct pe_context *, uint32_t);
uint32_t        pe_opt_hdr_image_base_get(struct pe_context *); // TODO: not compatible 64 bits
uint32_t        pe_opt_hdr_section_alignment_get(struct pe_context *);

/* 32-bit PE optional header functions */
uint16_t	pe32_opt_hdr_major_img_version_get(struct pe_context *);
int		pe32_opt_hdr_major_img_version_set(struct pe_context *, uint16_t);
uint16_t	pe32_opt_hdr_minor_img_version_get(struct pe_context *);
int		pe32_opt_hdr_minor_img_version_set(struct pe_context *, uint16_t);
uint16_t	pe32_opt_hdr_major_os_version_get(struct pe_context *);
int		pe32_opt_hdr_major_os_version_set(struct pe_context *, uint16_t);
uint16_t	pe32_opt_hdr_minor_os_version_get(struct pe_context *);
int		pe32_opt_hdr_minor_os_version_set(struct pe_context *, uint16_t);
uint16_t	pe32_opt_hdr_major_ss_version_get(struct pe_context *);
int		pe32_opt_hdr_major_ss_version_set(struct pe_context *, uint16_t);
uint16_t	pe32_opt_hdr_minor_ss_version_get(struct pe_context *);
int		pe32_opt_hdr_minor_ss_version_set(struct pe_context *, uint16_t);
uint16_t	pe32_opt_hdr_subsystem_get(struct pe_context *);
int		pe32_opt_hdr_subsystem_set(struct pe_context *, uint16_t);
uint32_t        pe32_opt_hdr_entry_point_get(struct pe_context *);
int             pe32_opt_hdr_entry_point_set(struct pe_context *, uint32_t);
uint32_t        pe32_opt_hdr_base_of_code_get(struct pe_context *);
int             pe32_opt_hdr_base_of_code_set(struct pe_context *, uint32_t);
uint32_t        pe32_opt_hdr_size_of_code_get(struct pe_context *);
int             pe32_opt_hdr_size_of_code_set(struct pe_context *, uint32_t);
uint32_t        pe32_opt_hdr_section_alignment_get(struct pe_context *);

/* 64-bit PE optional header functions */
uint16_t	pe64_opt_hdr_major_img_version_get(struct pe_context *);
int		pe64_opt_hdr_major_img_version_set(struct pe_context *, uint16_t);
uint16_t	pe64_opt_hdr_minor_img_version_get(struct pe_context *);
int		pe64_opt_hdr_minor_img_version_set(struct pe_context *, uint16_t);
uint16_t	pe64_opt_hdr_major_os_version_get(struct pe_context *);
int		pe64_opt_hdr_major_os_version_set(struct pe_context *, uint16_t);
uint16_t	pe64_opt_hdr_minor_os_version_get(struct pe_context *);
int		pe64_opt_hdr_minor_os_version_set(struct pe_context *, uint16_t);
uint16_t	pe64_opt_hdr_major_ss_version_get(struct pe_context *);
int		pe64_opt_hdr_major_ss_version_set(struct pe_context *, uint16_t);
uint16_t	pe64_opt_hdr_minor_ss_version_get(struct pe_context *);
int		pe64_opt_hdr_minor_ss_version_set(struct pe_context *, uint16_t);
uint16_t	pe64_opt_hdr_subsystem_get(struct pe_context *);
int		pe64_opt_hdr_subsystem_set(struct pe_context *, uint16_t);
uint32_t        pe64_opt_hdr_entry_point_get(struct pe_context *);
int             pe64_opt_hdr_entry_point_set(struct pe_context *, uint32_t);
uint32_t        pe64_opt_hdr_base_of_code_get(struct pe_context *);
int             pe64_opt_hdr_base_of_code_set(struct pe_context *, uint32_t);
uint32_t        pe64_opt_hdr_size_of_code_get(struct pe_context *);
int             pe64_opt_hdr_size_of_code_set(struct pe_context *, uint32_t);
uint32_t        pe64_opt_hdr_section_alignment_get(struct pe_context *);

struct pe_image_data_directory *pe_opt_hdr_directory_get(struct pe_context *, int);
struct pe_image_data_directory *pe32_opt_hdr_directory_get(struct pe_context *, int);
struct pe_image_data_directory *pe64_opt_hdr_directory_get(struct pe_context *, int);


uint32_t	pe_directory_entry_export_size(struct pe_context *);
rva_t		pe_directory_entry_export(struct pe_context *);
uint32_t	pe_directory_entry_import_size(struct pe_context *);
rva_t		pe_directory_entry_import(struct pe_context *);
uint32_t        pe_directory_entry_delay_size(struct pe_context *);
rva_t           pe_directory_entry_delay(struct pe_context *);
uint32_t	pe_directory_entry_tls_callbacks_size(struct pe_context *);
rva_t		pe_directory_entry_tls_callbacks(struct pe_context *);

/* PE section table functions */
rva_t        pe_section_virtual_address_by_idx_get(struct pe_context *, uint16_t);
rva_t        pe_section_virtual_address_by_name_get(struct pe_context *, const char *);
void        *pe_section_from_rva_get(struct pe_context *, rva_t);
int          pe_section_display_by_name(struct pe_context *, const char *);
int          pe_section_display_by_idx(struct pe_context *, uint16_t);

/* PE TLS callbacks directory functions */
int      pe32_tls_callback_directory_get(struct pe_context *, struct pe32_image_tls_directory *);
uint32_t pe32_tls_callback_directory_get_function_va(struct pe_context *, struct pe32_image_tls_directory *, uint32_t, int);

/* PE export directory functions */
int	pe_export_directory_get(struct pe_context *, struct pe_image_export_directory *);
void	pe_export_directory_print(struct pe_context *, struct pe_image_export_directory *);
rva_t  *pe_export_directory_get_names_rva(struct pe_context *, struct pe_image_export_directory *);
int32_t pe_export_directory_get_names_ordinal(struct pe_context *, struct pe_image_export_directory *, int);
rva_t	pe_export_directory_get_function_rva(struct pe_context *, struct pe_image_export_directory *, int);
int     pe_export_directory_get_index_of_ordinal(struct pe_context *, struct pe_image_export_directory *, uint16_t);

/* PE import directory functions */

int	pe_import_directory_table_get(struct pe_context *, struct pe_image_import_directory_table  *);
char   *pe_import_directory_get_module_name(struct pe_context *, struct pe_image_import_directory_table *, int);
char   *pe_import_directory_get_function_name(struct pe_context *, int, int);
char   *pe_import_directory_get_function_name32(struct pe_context *, int, int);
char   *pe_import_directory_get_function_name64(struct pe_context *, int, int);
rva_t   pe_import_directory_get_function_ptr_iat(struct pe_context *, int, int);
rva_t   pe_import_directory_get_function_ptr_iat32(struct pe_context *, int, int);
rva_t   pe_import_directory_get_function_ptr_iat64(struct pe_context *, int, int);

/* PE delay directory functions */

int         pe_delay_directory_table_get(struct pe_context *, struct pe_image_delay_directory_table  *);
char       *pe_delay_directory_get_module_name(struct pe_context *, struct pe_image_delay_directory_table *, int);
rva_t       pe_delay_directory_get_function_ptr_iat(struct pe_context *, int, int);
rva_t       pe_delay_directory_get_function_ptr_iat32(struct pe_context *, int, int);
rva_t       pe_delay_directory_get_function_ptr_iat64(struct pe_context *, int, int);
char       *pe_delay_directory_get_function_name(struct pe_context *, int, int);
char       *pe_delay_directory_get_function_name32(struct pe_context *, int, int);
char       *pe_delay_directory_get_function_name64(struct pe_context *, int, int);

#ifdef __cplusplus
};
#endif

#endif	/* !PT_PE_INTERNAL_H */
