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
 * charset.c
 *
 * Character set conversion routines.  Used primarily for converting Windows
 * native API strings into UTF8 strings, which are used internally in
 * libptrace.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <libptrace/charset.h>
#include <libptrace/error.h>

static const uint8_t
first_byte_mark[] = { 0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };

/* Returns the length in bytes of the UTF16 string 'string' when converting
 * it to UTF8.
 *
 * A return value of (size_t)-1 shall be used to indicate an error.
 */
static size_t utf16_to_utf8_len_(const utf16_t *string)
{
	const uint16_t *src;
	uint16_t w1, w2;
	size_t size;
	uint32_t u;

	size = 0;
	src = string;
	while ( (w1 = *src++) != 0) {
		/* Basic Multilangual Plane */
		if (w1 < 0xD800 || w1 > 0xDFFF) {
			u = (uint32_t)w1;
		/* Low surrogates before high surrogates are erronic. */
		} else if (w1 > 0xDBFF) {
			return -1;
		/* High surrogate. */
		} else {
			w2 = *src++;
			/* See if the low surrogate is valid. */
			if (w2 < 0xDC00 || w2 > 0xDFFF)
				return -1;

			/* Convert to utf32 character. */
			u = (((w1 & 0x3FF) << 10) | (w2 & 0x3FF)) + 0x10000;
		}

		/* Values above 0x110000 are invalid unicode codepoints. */
		if (u >= 0x110000)
			return -1;

		size += (u >= 0x80) + (u >= 0x800) + (u >= 0x10000) + 1;
	}

	return size;
}

int utf16_valid(const utf16_t *string)
{
	return utf16_to_utf8_len_(string) != (size_t)-1;
}

utf8_t *pt_utf16_to_utf8(const utf16_t *string)
{
	const uint16_t *src;
	uint16_t w1, w2;
	utf8_t *dest;
	size_t size;
	uint32_t u;
	int type;

	/* First pass: determine the length of the utf8 string to allocate. */
	if ( (size = utf16_to_utf8_len_(string)) == (size_t)-1) {
		pt_error_internal_set(PT_ERROR_BAD_ENCODING);
		return NULL;
	}

	/* Allocate the destination utf8 string. */
	if ( (dest = malloc(size + 1)) == NULL)
		return NULL;

	/* Second pass, copy the string. */
	src = string;
	while ( (w1 = *src++) != 0) {
		/* Basic Multilangual Plane */
		if (w1 < 0xD800 || w1 > 0xDFFF)
			u = (uint32_t)w1;
		/* High surrogate. */
		else {
			w2 = *src++;
			/* Convert to utf32 character. */
			u = (((w1 & 0x3FF) << 10) | (w2 & 0x3FF)) + 0x10000;
		}

		type = (u >= 0x80) + (u >= 0x800) + (u >= 0x10000);
		switch (type) {
		case 3:
			dest[3] = (u | 0x80) & 0xBF;
			u >>= 6;
		case 2:
			dest[2] = (u | 0x80) & 0xBF;
			u >>= 6;
		case 1:
			dest[1] = (u | 0x80) & 0xBF;
			u >>= 6;
		case 0:
			dest[0] = u | first_byte_mark[type + 1];
		}
		dest += type + 1;
	}

	dest[0] = 0;

	return dest - size;
}

utf16_t *pt_utf8_to_utf16(const utf8_t *string)
{
	size_t proc_bytes, num_bytes, output_pos;
	uint32_t utf8_char_val, u_prime;
	uint8_t b0, b1, b2, b3;
	uint16_t w1, w2;
	uint16_t *res;
	int type;

	proc_bytes = output_pos = 0;

	num_bytes = strlen((char *)string);
	if ( (res = malloc((num_bytes + 1) * 2)) == NULL) {
		pt_error_errno_set(errno);
		return NULL;
	}

	while (proc_bytes < num_bytes) {
		/* Detect the number of bytes in the octet sequence */
		if ( !(string[proc_bytes] & 0x80))
			type = 1;
		else if ( (proc_bytes + 3 < num_bytes) &&
				(string[proc_bytes] & 0xF8) == 0xF0)
			type = 4;
		else if ( (proc_bytes + 2 < num_bytes) &&
				(string[proc_bytes] & 0xF0) == 0xE0)
			type = 3;
		else if ( (proc_bytes + 1 < num_bytes) &&
				(string[proc_bytes] & 0xE0) == 0xC0)
			type = 2;
		else {
			free(res);
			pt_error_internal_set(PT_ERROR_BAD_ENCODING);
			return NULL;
		}

		/* Ensure the sequence is valid and decode it */
		switch (type) {
		case 1:
			/* 0xxxxxxx */
			utf8_char_val = (uint32_t)string[proc_bytes];
			break;
		case 2:
			/* 110xxxxx 10xxxxxx */
			b0 = (uint8_t)string[proc_bytes];
			b1 = (uint8_t)string[proc_bytes + 1];

			utf8_char_val = (uint32_t)
				((b0 & 0x1F) << 6) | (b1 & 0x3F);

			if (utf8_char_val < 0x80)
				goto err_val;
			break;
		case 3:
			/* 1110xxxx 10xxxxxx 10xxxxxx */
			b0 = (uint8_t)string[proc_bytes];
			b1 = (uint8_t)string[proc_bytes + 1];
			b2 = (uint8_t)string[proc_bytes + 2];

			utf8_char_val = (uint32_t)
				((b0 & 0xF) << 12) |
				((b1 & 0x3F) << 6) |
				((b2 & 0x3F));

			if (utf8_char_val < 0x0800)
				goto err_val;
			break;
		case 4:
			/* 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
			b0 = (uint8_t)string[proc_bytes];
			b1 = (uint8_t)string[proc_bytes + 1];
			b2 = (uint8_t)string[proc_bytes + 2];
			b3 = (uint8_t)string[proc_bytes + 3];

			utf8_char_val = (uint32_t)
				((b0 & 0x7) << 18) |
				((b1 & 0x3F) << 12) |
				((b2 & 0x3F) << 6) |
				((b3 & 0x3F));

			if (utf8_char_val < 0x010000 || utf8_char_val > 0x10FFFF)
				goto err_val;
			break;
		}

		/* Error if we have surrogate pair values encoded in UTF8. */
		if (utf8_char_val >= 0xD800 && utf8_char_val <= 0xDFFF)
			goto err_val;

		/* Encode to UTF-16 */
		if (utf8_char_val < 0x10000) {
			res[output_pos] = utf8_char_val;
			output_pos += 1;
		} else if (utf8_char_val > 0x10000 &&
				utf8_char_val <= 0x10FFFF) {
			u_prime = utf8_char_val - 0x10000;
			w1 = 0xD800;
			w2 = 0xDC00;

			w1 |= (u_prime & 0xFFC00);
			w2 |= (u_prime & 0x3FF);

			res[output_pos] = w1;

			res[output_pos + 1] = w2;
			output_pos += 2;
		} else {
			goto err_val;
		}

		proc_bytes += type;
	}

	if (proc_bytes != num_bytes)
		goto err_val;

	res[output_pos] = '\0';

	return res;

err_val:
	pt_error_internal_set(PT_ERROR_BAD_ENCODING);
	free(res);
	return NULL;
}

#ifdef TEST
int main(void)
{
	char src[] = "\x78\x30\x93\x30\x5f\x30\x44\x30\x27\x59\x7d\x59\x4d\x30\x00\x00";
	char utf8_invalid_01[] = "\xc0\x80";
	char utf8_invalid_02[] = "\x80";
	char utf8_2byte_max[] = "\xdf\xbf";
	uint16_t *conv;

	if (utf8_to_utf16(utf8_invalid_01) != NULL)
		printf("test failed\n");

	if (utf8_to_utf16(utf8_invalid_02) != NULL)
		printf("test failed\n");

	if (utf8_to_utf16(utf8_2byte_max) == NULL)
		printf("test failed\n");

	printf("%s\n", utf16_to_utf8((uint16_t *)src));
	conv = utf8_to_utf16(utf16_to_utf8((uint16_t *)src));
	printf("%s\n", utf16_to_utf8(conv));
	free(conv);

	exit(EXIT_SUCCESS);
}
#endif
