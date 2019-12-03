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
 * test_pe_abi.cpp
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#define BOOST_TEST_MODULE windows_native
#include <cstdlib>
#include <cstddef>
#include <boost/test/included/unit_test.hpp>
#include "libptrace/pe.h"
#include "libptrace/file.h"

using namespace std;

BOOST_AUTO_TEST_CASE(pe_abi_read_dos_header)
{
	struct pt_file_buffer file = PT_FILE_BUFFER_INIT;
	unsigned char pe_data[] = "";
	struct pe_context pex;
	int ret;

	file.start = pe_data;
	file.end = file.start + 1;

	ret = pe_open(&pex, (struct pt_file *)&file, PT_FILE_RDONLY);
	BOOST_REQUIRE(ret == -1);
	BOOST_REQUIRE(pex.error == PE_ERROR_READ_DOS_HEADER);
}

BOOST_AUTO_TEST_CASE(pe_abi_magic_dos_header)
{
	unsigned char pe_data[sizeof(struct pe_image_dos_header)];
	struct pt_file_buffer file = PT_FILE_BUFFER_INIT;
	struct pe_context pex;
	int ret;

	memset(&pe_data, 0, sizeof pe_data);
	file.start = pe_data;
	file.end = file.start + sizeof pe_data;

	ret = pe_open(&pex, (struct pt_file *)&file, PT_FILE_RDONLY);
	BOOST_REQUIRE(ret == -1);
	BOOST_REQUIRE(pex.error == PE_ERROR_MAGIC_DOS_HEADER);
}

BOOST_AUTO_TEST_CASE(pe_abi_pe_offset)
{
	struct pt_file_buffer file = PT_FILE_BUFFER_INIT;
	struct pe_image_dos_header dos_header;
	struct pe_context pex;
	int ret;

	memset(&dos_header, 0, sizeof dos_header);
	dos_header.e_magic = PE_IMAGE_DOS_SIGNATURE;
	dos_header.e_lfanew = -1;

	file.start = (unsigned char *)&dos_header;
	file.end = file.start + sizeof dos_header;

	ret = pe_open(&pex, (struct pt_file *)&file, PT_FILE_RDONLY);
	BOOST_REQUIRE(ret == -1);
	BOOST_REQUIRE(pex.error == PE_ERROR_INVALID_PE_OFFSET);
}

BOOST_AUTO_TEST_CASE(pe_abi_read_image_headers)
{
	struct pt_file_buffer file = PT_FILE_BUFFER_INIT;
	struct pe_image_dos_header dos_header;
	struct pe_context pex;
	int ret;

	memset(&dos_header, 0, sizeof dos_header);
	dos_header.e_magic = PE_IMAGE_DOS_SIGNATURE;
	dos_header.e_lfanew = sizeof dos_header - 1;

	file.start = (unsigned char *)&dos_header;
	file.end = file.start + sizeof dos_header;

	ret = pe_open(&pex, (struct pt_file *)&file, PT_FILE_RDONLY);
	BOOST_REQUIRE(ret == -1);
	BOOST_REQUIRE(pex.error == PE_ERROR_READ_IMAGE_HEADERS);
}

BOOST_AUTO_TEST_CASE(pe_abi_magic_pe_header)
{
	struct pt_file_buffer file = PT_FILE_BUFFER_INIT;
	struct pe_image_dos_header dos_header;
	struct pe_context pex;
	int ret;

	memset(&dos_header, 0, sizeof dos_header);
	dos_header.e_magic = PE_IMAGE_DOS_SIGNATURE;

	file.start = (unsigned char *)&dos_header;
	file.end = file.start + sizeof dos_header;

	ret = pe_open(&pex, (struct pt_file *)&file, PT_FILE_RDONLY);
	BOOST_REQUIRE(ret == -1);
	BOOST_REQUIRE(pex.error == PE_ERROR_MAGIC_PE_HEADER);
}

BOOST_AUTO_TEST_CASE(pe_abi_read_image_file_header)
{
	struct pt_file_buffer file = PT_FILE_BUFFER_INIT;
	struct pe_header {
		struct pe_image_dos_header dos_header;
		uint32_t signature;
	} __attribute__((packed)) pe_header;
	struct pe_context pex;
	int ret;

	memset(&pe_header, 0, sizeof pe_header);
	pe_header.dos_header.e_magic = PE_IMAGE_DOS_SIGNATURE;
	pe_header.dos_header.e_lfanew = offsetof(struct pe_header, signature);
	pe_header.signature = PE_IMAGE_NT_SIGNATURE;

	file.start = (unsigned char *)&pe_header;
	file.end = file.start + sizeof pe_header;

	ret = pe_open(&pex, (struct pt_file *)&file, PT_FILE_RDONLY);
	BOOST_REQUIRE(ret == -1);
	BOOST_REQUIRE(pex.error == PE_ERROR_READ_IMAGE_FILE_HEADER);
}

BOOST_AUTO_TEST_CASE(pe_abi_unsupported_architecture)
{
	struct pt_file_buffer file = PT_FILE_BUFFER_INIT;
	struct pe_header {
		struct pe_image_dos_header dos_header;
		uint32_t signature;
		struct pe_image_file_header file_header;
	} __attribute__((packed)) pe_header;
	struct pe_context pex;
	int ret;

	memset(&pe_header, 0, sizeof pe_header);
	pe_header.dos_header.e_magic = PE_IMAGE_DOS_SIGNATURE;
	pe_header.dos_header.e_lfanew = offsetof(struct pe_header, signature);
	pe_header.signature = PE_IMAGE_NT_SIGNATURE;

	file.start = (unsigned char *)&pe_header;
	file.end = file.start + sizeof pe_header;

	ret = pe_open(&pex, (struct pt_file *)&file, PT_FILE_RDONLY);
	BOOST_REQUIRE(ret == -1);
	BOOST_REQUIRE(pex.error == PE_ERROR_UNSUPPORTED_ARCHITECTURE);
}

BOOST_AUTO_TEST_CASE(pe_abi_invalid_optional_size)
{
	struct pt_file_buffer file = PT_FILE_BUFFER_INIT;
	struct pe_header {
		struct pe_image_dos_header dos_header;
		uint32_t signature;
		struct pe_image_file_header file_header;
	} __attribute__((packed)) pe_header;
	struct pe_context pex;
	int ret;

	memset(&pe_header, 0, sizeof pe_header);
	pe_header.dos_header.e_magic = PE_IMAGE_DOS_SIGNATURE;
	pe_header.dos_header.e_lfanew = offsetof(struct pe_header, signature);
	pe_header.signature = PE_IMAGE_NT_SIGNATURE;
	pe_header.file_header.machine = PE_IMAGE_FILE_MACHINE_I386;

	file.start = (unsigned char *)&pe_header;
	file.end = file.start + sizeof pe_header;

	ret = pe_open(&pex, (struct pt_file *)&file, PT_FILE_RDONLY);
	BOOST_REQUIRE(ret == -1);
	BOOST_REQUIRE(pex.error == PE_ERROR_INVALID_OPTIONAL_SIZE);
}

BOOST_AUTO_TEST_CASE(pe_abi_read_optional_header)
{
	struct pt_file_buffer file = PT_FILE_BUFFER_INIT;
	struct pe_header {
		struct pe_image_dos_header dos_header;
		uint32_t signature;
		struct pe_image_file_header file_header;
	} __attribute__((packed)) pe_header;
	struct pe_context pex;
	int ret;

	memset(&pe_header, 0, sizeof pe_header);
	pe_header.dos_header.e_magic = PE_IMAGE_DOS_SIGNATURE;
	pe_header.dos_header.e_lfanew = offsetof(struct pe_header, signature);
	pe_header.signature = PE_IMAGE_NT_SIGNATURE;
	pe_header.file_header.machine = PE_IMAGE_FILE_MACHINE_I386;
	pe_header.file_header.size_of_optional_header =
		sizeof(struct pe32_image_optional_header);

	file.start = (unsigned char *)&pe_header;
	file.end = file.start + sizeof pe_header;

	ret = pe_open(&pex, (struct pt_file *)&file, PT_FILE_RDONLY);
	BOOST_REQUIRE(ret == -1);
	BOOST_REQUIRE(pex.error == PE_ERROR_READ_OPTIONAL_HEADER);
}

BOOST_AUTO_TEST_CASE(pe_abi_read_section_table)
{
	struct pt_file_buffer file = PT_FILE_BUFFER_INIT;
	struct pe_header {
		struct pe_image_dos_header dos_header;
		uint32_t signature;
		struct pe_image_file_header file_header;
		struct pe32_image_optional_header opt_header;
	} __attribute__((packed)) pe_header;
	struct pe_context pex;
	int ret;

	memset(&pe_header, 0, sizeof pe_header);
	pe_header.dos_header.e_magic = PE_IMAGE_DOS_SIGNATURE;
	pe_header.dos_header.e_lfanew = offsetof(struct pe_header, signature);
	pe_header.signature = PE_IMAGE_NT_SIGNATURE;
	pe_header.file_header.machine = PE_IMAGE_FILE_MACHINE_I386;
	pe_header.file_header.size_of_optional_header =
		sizeof(struct pe32_image_optional_header);
	pe_header.file_header.number_of_sections = 1;

	file.start = (unsigned char *)&pe_header;
	file.end = file.start + sizeof pe_header;

	ret = pe_open(&pex, (struct pt_file *)&file, PT_FILE_RDONLY);
	BOOST_REQUIRE(ret == -1);
	BOOST_REQUIRE(pex.error == PE_ERROR_READ_SECTION_TABLE);
}
