/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
* base32.c
* Copyright (C) 2014 Chris Morrison <chris-morrison@cyberservices.com>
*
* libcdel is free software: you can redistribute it and/or modify it
* under the terms of the GNU General Public License as published by the
* Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* libcdel is distributed in the hope that it will be useful, but
* WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include "libcdel.h"

static const char* base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

///////////////////////////////////////////////////////////////////////////
// Verifies the given null terminated string to ensure that it is a valid
// base32 encoded string.
// 
// Returns:         0 - The string is not a valid base32 string, or the
//                      given string was NULL or empty.
//                  1 - The string is a valid base32 string.
///////////////////////////////////////////////////////////////////////////
LIBCDEL_API int cdel_is_base32_string(const char *str)
{
	if ((str == NULL) || (*str == '\0')) return 0;
	char *t_str = (char *)str;
	char c;
	size_t valid_chars = 0;
	int eq_found = 0;

	while ((c = *t_str) != '\0')
	{
		if ((isspace(c) != 0) || (c == '\t') || (c == '\r') || (c == '\n')) continue;
		if ((c == '=') && (eq_found == 0))
		{
			eq_found = 1;
			continue;
		}
		if ((c != '=') && (eq_found == 1)) return 0; // The equals sign is used to pad the string's length to a multiple of 5 and can only occur at the end of the string.
		if (strchr(base32_chars, c) == NULL) return 0;
		++valid_chars;
		++t_str;
	}

	if ((valid_chars < 5) || ((valid_chars % 5) != 0)) return 0;

	return 1;
}

///////////////////////////////////////////////////////////////////////////
// Encodes the given data into a padded base32 string.
// 
// Returns:         A NULL terminated base32 encoded string, or NULL if an
//                  error occurred, in which case the error parameter (if
//                  provided) will contain a POSIX error code to indicate
//                  what went wrong.
//
//                  The returned string is allocated and must be freed by
//                  the caller when finished with.
///////////////////////////////////////////////////////////////////////////
LIBCDEL_API int base32_encode(const unsigned char *data, int length, unsigned char *result, int bufSize)
{
	if (length < 0 || length >(1 << 28)) {
		return -1;
	}
	int count = 0;
	if (length > 0) {
		int buffer = data[0];
		int next = 1;
		int bitsLeft = 8;
		while (count < bufSize && (bitsLeft > 0 || next < length)) {
			if (bitsLeft < 5) {
				if (next < length) {
					buffer <<= 8;
					buffer |= data[next++] & 0xFF;
					bitsLeft += 8;
				}
				else {
					int pad = 5 - bitsLeft;
					buffer <<= pad;
					bitsLeft += pad;
				}
			}
			int index = 0x1F & (buffer >> (bitsLeft - 5));
			bitsLeft -= 5;
			result[count++] = base32_chars[index];
		}
	}
	if (count < bufSize) {
		result[count] = '\000';
	}
	return count;
}

///////////////////////////////////////////////////////////////////////////
// Decodes the given, NULL terminated base32 string and returns a buffer
// containing the decoded data.
// 
// Returns:         A buffer containing the decoded data or NULL if an
//                  error occurred, in which case the error parameter (if
//                  provided) will contain a POSIX error code to indicate
//                  what went wrong.
//
//                  The mandatory buff_len parameter will be updated to
//                  contain the length of the decoded data.
//
//                  The returned buffer is allocated and must be freed by
//                  the caller when finished with.
///////////////////////////////////////////////////////////////////////////
LIBCDEL_API int base32_decode(const unsigned char *encoded, unsigned char *result, int bufSize)
{
	int buffer = 0;
	int bitsLeft = 0;
	int count = 0;
	for (const unsigned char *ptr = encoded; count < bufSize && *ptr; ++ptr) {
		unsigned char ch = *ptr;
		if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '-') {
			continue;
		}
		buffer <<= 5;

		// Deal with commonly mistyped characters
		if (ch == '0') {
			ch = 'O';
		}
		else if (ch == '1') {
			ch = 'L';
		}
		else if (ch == '8') {
			ch = 'B';
		}

		// Look up one base32 digit
		if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
			ch = (ch & 0x1F) - 1;
		}
		else if (ch >= '2' && ch <= '7') {
			ch -= '2' - 26;
		}
		else {
			return -1;
		}

		buffer |= ch;
		bitsLeft += 5;
		if (bitsLeft >= 8) {
			result[count++] = (unsigned char)buffer >> (bitsLeft - 8);
			bitsLeft -= 8;
		}
	}
	if (count < bufSize) {
		result[count] = '\000';
	}
	return count;
}

