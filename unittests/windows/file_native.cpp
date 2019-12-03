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
 * file_native.cpp
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Massimiliano Oldani <max@immunityinc.com>
 *
 */
#define BOOST_TEST_MODULE windows_native
#include <iostream>
#include <cstdio> // support for printf()
#include <cstring> // memcmp(), memcpy(), memset()
#include <windows.h>
#include <boost/test/included/unit_test.hpp>
#include <libptrace/libptrace.h>
#include <libptrace/file.h>

using namespace std;

#define FP_NATIVE_SET_FILENAME(fp, fname) (((struct pt_file_native*)fp)->filename = fname)

BOOST_AUTO_TEST_CASE(native_file_open_nofile)
{
	int ret;
	struct pt_file_native fp = PT_FILE_NATIVE_INIT;
    struct pt_file *p_fp = (struct pt_file*)&fp;	 
	
	BOOST_REQUIRE(PT_FILE_NATIVE(p_fp)->fd.handle == INVALID_HANDLE_VALUE);

	FP_NATIVE_SET_FILENAME(p_fp, "C:\\notexistentfile.txt");
	
	ret = p_fp->file_ops->open(p_fp, PT_FILE_RDONLY);
	BOOST_REQUIRE(ret == -1);

	ret = p_fp->file_ops->close(p_fp);
	BOOST_REQUIRE(ret == -1);


}

BOOST_AUTO_TEST_CASE(native_file_open_right_file)
{
	int ret;
	struct pt_file_native fp = PT_FILE_NATIVE_INIT;
    struct pt_file *p_fp = (struct pt_file*)&fp;	 

	BOOST_REQUIRE(PT_FILE_NATIVE(p_fp)->fd.handle == INVALID_HANDLE_VALUE);

	FP_NATIVE_SET_FILENAME(p_fp, "C:\\windows\\system32\\calc.exe");
	ret = p_fp->file_ops->open(p_fp, PT_FILE_RDONLY);
	BOOST_REQUIRE(ret == 0);
	BOOST_REQUIRE(PT_FILE_NATIVE(p_fp)->fd.handle > 0);


	ret = p_fp->file_ops->close(p_fp);
	BOOST_REQUIRE(ret == 0);
	BOOST_REQUIRE(PT_FILE_NATIVE(p_fp)->fd.handle == INVALID_HANDLE_VALUE);
	ret = p_fp->file_ops->close(p_fp);
	BOOST_REQUIRE(ret == -1);
}


BOOST_AUTO_TEST_CASE(native_file_read_write_file)
{
	int ret;
	off_t off_ret;
	char buffer1[4096], buffer2[4096];
	struct pt_file_native fp = PT_FILE_NATIVE_INIT;
    struct pt_file *p_fp = (struct pt_file*)&fp;	 

	BOOST_REQUIRE(PT_FILE_NATIVE(p_fp)->fd.handle == INVALID_HANDLE_VALUE);

	FP_NATIVE_SET_FILENAME(p_fp, "test.txt");
	ret = p_fp->file_ops->open(p_fp, PT_FILE_RDWR);
	BOOST_REQUIRE(ret == 0);
	BOOST_REQUIRE(PT_FILE_NATIVE(p_fp)->fd.handle > 0);

    /* truncate the file before the test */
	BOOST_REQUIRE(SetEndOfFile(PT_FILE_NATIVE(p_fp)->fd.handle) == TRUE);
	
	/* read() should return 0 */
	ret = p_fp->file_ops->read(p_fp, buffer1, sizeof(buffer1));
	BOOST_REQUIRE(ret == 0);

	memset(buffer1, 0x41, sizeof(buffer1));
	ret = p_fp->file_ops->write(p_fp, buffer1, sizeof(buffer1));
	BOOST_REQUIRE(ret == sizeof(buffer1));
	off_ret = p_fp->file_ops->tell(p_fp);
	BOOST_REQUIRE(off_ret == sizeof(buffer1));
	
	/* over-read and read content check */
	ret = p_fp->file_ops->seek(p_fp, 0, SEEK_SET);
	BOOST_REQUIRE(ret == sizeof(buffer1));
	ret = p_fp->file_ops->read(p_fp, buffer2, sizeof(buffer2) + 0x10); 
	BOOST_REQUIRE(ret == sizeof(buffer2));
	BOOST_REQUIRE(!memcmp(buffer1, buffer2, sizeof(buffer1)));

	/* file seek-gap check */	
	off_ret = p_fp->file_ops->seek(p_fp, 2*sizeof(buffer1), SEEK_SET);
	BOOST_REQUIRE(off_ret == sizeof(buffer1));

	ret = p_fp->file_ops->write(p_fp, buffer1, sizeof(buffer1));
	BOOST_REQUIRE(ret == sizeof(buffer1));
	
	off_ret = p_fp->file_ops->tell(p_fp);	
	BOOST_REQUIRE(off_ret == 3*sizeof(buffer1));

	/* multiple read check */
	off_ret = p_fp->file_ops->seek(p_fp, 0, SEEK_SET);
	ret = p_fp->file_ops->read(p_fp, buffer1, sizeof(buffer1));
	BOOST_REQUIRE(ret == sizeof(buffer1));
	ret = p_fp->file_ops->read(p_fp, buffer1, sizeof(buffer1));
	BOOST_REQUIRE(ret == sizeof(buffer1));
	ret = p_fp->file_ops->read(p_fp, buffer1, sizeof(buffer1));
	BOOST_REQUIRE(ret == sizeof(buffer1));
	ret = p_fp->file_ops->read(p_fp, buffer1, sizeof(buffer1));
	BOOST_REQUIRE(ret == 0);

	/* close after write check */
	ret = p_fp->file_ops->close(p_fp);
	BOOST_REQUIRE(ret == 0);	
	BOOST_REQUIRE(PT_FILE_NATIVE(p_fp)->fd.handle == INVALID_HANDLE_VALUE);
}




BOOST_AUTO_TEST_CASE(native_file_seek)
{
	int ret;
	off_t off_ret, off_tmp;
	struct pt_file_native fp = PT_FILE_NATIVE_INIT;
    struct pt_file *p_fp = (struct pt_file*)&fp;	 

	BOOST_REQUIRE(PT_FILE_NATIVE(p_fp)->fd.handle == INVALID_HANDLE_VALUE);

	FP_NATIVE_SET_FILENAME(p_fp, "C:\\windows\\system32\\calc.exe");
	ret = p_fp->file_ops->open(p_fp, PT_FILE_RDONLY);
	BOOST_REQUIRE(ret == 0);
	BOOST_REQUIRE(PT_FILE_NATIVE(p_fp)->fd.handle > 0);

	
	off_ret = p_fp->file_ops->seek(p_fp, 0, SEEK_SET);
	BOOST_REQUIRE(ret == 0);  // old position was 0

	off_ret = p_fp->file_ops->seek(p_fp, 0, SEEK_END);
	BOOST_REQUIRE(ret == 0); // return old position  which was 0

	off_tmp = p_fp->file_ops->seek(p_fp, 0, SEEK_SET);
	BOOST_REQUIRE(off_tmp > 0);

	off_ret = p_fp->file_ops->seek(p_fp, -1, SEEK_END);
	off_ret = p_fp->file_ops->seek(p_fp, 0, SEEK_SET);
	BOOST_REQUIRE(off_ret == off_tmp -1);

	off_ret = p_fp->file_ops->seek(p_fp, off_tmp + 10, SEEK_END);
	BOOST_REQUIRE(off_ret == off_ret); // should be ok, lecit to set the file position after the end of the file even if the file is not writable

	/* set back to 0 */
	off_ret = p_fp->file_ops->seek(p_fp, 0, SEEK_SET);
	BOOST_REQUIRE(p_fp->file_ops->tell(p_fp) == 0);

	off_ret = p_fp->file_ops->seek(p_fp, -10, SEEK_SET);
	BOOST_REQUIRE(off_ret == -1); // should fails, since you cant go before offset 0

	off_ret = p_fp->file_ops->seek(p_fp, -10, SEEK_CUR);
	BOOST_REQUIRE(off_ret == -1);  // same as before with SEEK_CUR


	off_ret = p_fp->file_ops->seek(p_fp, 10, SEEK_SET);
	off_ret = p_fp->file_ops->seek(p_fp, 0, SEEK_CUR);
	BOOST_REQUIRE(off_ret == 10);
	off_tmp = p_fp->file_ops->tell(p_fp);
	BOOST_REQUIRE(off_ret == off_tmp);

	/* test tell() */
	off_ret = p_fp->file_ops->seek(p_fp, 0, SEEK_END);
	off_tmp = p_fp->file_ops->tell(p_fp);

	off_ret = p_fp->file_ops->seek(p_fp, 0, SEEK_SET);
	BOOST_REQUIRE(off_tmp == off_ret);
	off_ret = p_fp->file_ops->tell(p_fp);
	BOOST_REQUIRE(off_ret == 0);

	/* XXX: off_t on Windows is always 32bit... need to fix it or we will not able to stats/seek files > 2GB 
     * we cant really deal safetly on Windows with off_t being always 32bit.. need to change the iface to support it or not? 
     */
	//off_ret = p_fp->file_ops->seek(p_fp, 0x100000000ULL, SEEK_SET); 
	//off_ret = p_fp->file_ops->tell(p_fp);
	//printf("--> position: %llu\n", off_ret);
	//BOOST_REQUIRE(off_ret == 0x100000000ULL);
}



