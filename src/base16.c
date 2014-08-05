/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
* base16.c
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

///////////////////////////////////////////////////////////////////////////
// Verifies the given null terminated string to ensure that it is a valid
// base16 (hex) encoded string.
// 
// Returns:         0 - The string is not a valid base16 string, or the
//                      given string was NULL or empty.
//                  1 - The string is a valid base16 string.
///////////////////////////////////////////////////////////////////////////
LIBCDEL_API int cdel_is_base16_string(const char *str)
{
	if ((str == NULL) || (*str == '\0')) return 0;
	char *t_str = (char *)str;
	char c;
	size_t valid_chars = 0;
	int lower_case = 0;
	int upper_case = 0;

	while ((c = *t_str) != '\0')
	{
		if ((isspace(c) != 0) || (c == '\t') || (c == '\r') || (c == '\n')) continue;
		if ((c <= 47) && (c >= 123)) return 0;
		if ((c >= 58) && (c <= 64)) return 0;
		if ((c >= 91) && (c <= 96)) return 0;
		if ((c >= 'A') && (c <= 'Z')) upper_case = 1;
		if ((c >= 'a') && (c <= 'z')) lower_case = 1;
		++valid_chars;
		++t_str;
	}

	if ((valid_chars < 2) || ((valid_chars % 2) != 0)) return 0;
	if ((lower_case == 1) && (upper_case == 1)) return 0; // Do not tolerate mixtures of upper and lowercase letters.

	return 1;
}

///////////////////////////////////////////////////////////////////////////
// Encodes the given data into a base16 string.
// 
// Returns:         A NULL terminated base16 encoded string, or NULL if an
//                  error occurred, in which case the error parameter (if
//                  provided) will contain a POSIX error code to indicate
//                  what went wrong.
//
//                  The returned string is allocated and must be freed by
//                  the caller when finished with.
///////////////////////////////////////////////////////////////////////////
LIBCDEL_API char *cdel_encode_as_base16_string(unsigned char *in_buffer, size_t data_length, int *error)
{
	if ((in_buffer == NULL) || (data_length == 0))
	{
		if (error != NULL) *error = EINVAL;
		return NULL;
	}
	size_t string_len = (data_length * 2) + 1;
	char *out_string = (char *)malloc(string_len);
	if (out_string == NULL)
	{
		if (error != NULL) *error = ENOMEM;
		return NULL;
	}

	char *buff_ptr = out_string;
	for (size_t idx = 0; idx < data_length; idx++)
	{
		sprintf(buff_ptr, "%02hhX", in_buffer[idx]);
		buff_ptr += 2;
	}

	if (error != NULL) *error = 0;
	return out_string;
}

///////////////////////////////////////////////////////////////////////////
// Decodes the given, NULL terminated base16 string and returns a buffer
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
LIBCDEL_API unsigned char *cdel_decode_from_base16_string(char *in_string, size_t *data_length, int *error)
{
	unsigned char *out_buffer = NULL;
	char *str_ptr = NULL;
	unsigned char b = 0;
	if ((in_string == NULL) || (data_length == NULL))
	{
		if (error != NULL) *error = EINVAL;
		return NULL;
	}
	*data_length = strlen(in_string);
	if (*data_length == 0)
	{
		if (error != NULL) *error = EINVAL;
		return NULL;
	}
	*data_length /= 2;
	out_buffer = (unsigned char *)malloc(*data_length);
	if (out_buffer == NULL)
	{
		if (error != NULL) *error = ENOMEM;
		return NULL;
	}

	str_ptr = in_string;
	for (size_t idx = 0; idx < *data_length; idx++)
	{
		sscanf(str_ptr, "%02hhX", &b);
		out_buffer[idx] = b;
		str_ptr += 2;
	}

	return out_buffer;
}
