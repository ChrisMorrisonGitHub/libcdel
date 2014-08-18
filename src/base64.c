/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
* base64.c
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

static const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char base64_encode_byte(unsigned char u);
unsigned char base64_decode_byte(char c);
int is_base64(char c);

///////////////////////////////////////////////////////////////////////////
// Verifies the given null terminated string to ensure that it is a valid
// base64 encoded string.
// 
// Returns:         0 - The string is not a valid base64 string, or the
//                      given string was NULL or empty.
//                  1 - The string is a valid base64 string.
///////////////////////////////////////////////////////////////////////////
LIBCDEL_API int cdel_is_base64_string(const char *str)
{
	const char *t_str = (char *)str;
	char c;
	size_t valid_chars = 0;
	int eq_found = 0;

	if ((str == NULL) || (*str == '\0')) return 0;

	while ((c = *t_str) != '\0')
	{
		if ((isspace(c) != 0) || (c == '\t') || (c == '\r') || (c == '\n')) continue;
		if ((c == '=') && (eq_found == 0))
		{
			eq_found = 1;
			continue;
		}
		if ((c != '=') && (eq_found == 1)) return 0; // The equals sign is used to pad the string's length to a multiple of 4 and can only occur at the end of the string.
		if (strchr(base64_chars, c) == NULL) return 0;
		++valid_chars;
		++t_str;
	}

	if ((valid_chars < 4) || ((valid_chars % 4) != 0)) return 0;

	return 1;
}

///////////////////////////////////////////////////////////////////////////
// Encodes the given data into a padded base64 string.
// 
// Returns:         A NULL terminated base64 encoded string, or NULL if an
//                  error occurred, in which case the error parameter (if
//                  provided) will contain a POSIX error code to indicate
//                  what went wrong.
//
//                  The returned string is allocated and must be freed by
//                  the caller when finished with.
///////////////////////////////////////////////////////////////////////////
LIBCDEL_API char *cdel_encode_as_base64_string(unsigned char *in_buffer, size_t data_length, int *error)
{
	size_t i;
	char *out_buffer = NULL;
	char *p = NULL;
	size_t len = 0;
	unsigned char b1 = 0;
	unsigned char b2 = 0;
	unsigned char b3 = 0;
	unsigned char b4 = 0;
	unsigned char b5 = 0;
	unsigned char b6 = 0;
	unsigned char b7 = 0;

	if (in_buffer == NULL)
	{
		if (error != NULL) *error = EINVAL;
		return NULL;
	}

	if (data_length == 0) data_length = strlen((char *)in_buffer);

	len = data_length * (4 / 3 + 4) + 1;
	out_buffer = (char *)malloc(len);
	if (out_buffer == NULL)
	{
		if (error != NULL) *error = ENOMEM;
		return NULL;
	}
	memset(out_buffer, 0, len);

	p = out_buffer;

	for (i = 0; i < data_length; i += 3)
	{
		b1 = 0;
		b2 = 0;
		b3 = 0;
		b4 = 0;
		b5 = 0;
		b6 = 0;
		b7 = 0;

		b1 = in_buffer[i];

		if ((i + 1) < data_length) b2 = in_buffer[i + 1];

		if ((i + 2) < data_length) b3 = in_buffer[i + 2];

		b4 = b1 >> 2;
		b5 = ((b1 & 0x3) << 4) | (b2 >> 4);
		b6 = ((b2 & 0xf) << 2) | (b3 >> 6);
		b7 = b3 & 0x3f;

		*p++ = base64_encode_byte(b4);
		*p++ = base64_encode_byte(b5);

		if ((i + 1) < data_length)
		{
			*p++ = base64_encode_byte(b6);
		}
		else
		{
			*p++ = '=';
		}

		if ((i + 2) < data_length)
		{
			*p++ = base64_encode_byte(b7);
		}
		else
		{
			*p++ = '=';
		}
	}

	return out_buffer;
}

///////////////////////////////////////////////////////////////////////////
// Decodes the given, NULL terminated base64 string and returns a buffer
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
LIBCDEL_API unsigned char *cdel_decode_from_base64_string(const char* in_string, size_t *buff_len, int *error)
{
	char c1 = 0;
	char c2 = 0;
	char c3 = 0;
	char c4 = 0;
	unsigned char b1 = 0;
	unsigned char b2 = 0;
	unsigned char b3 = 0;
	unsigned char b4 = 0;
	unsigned char *buf = NULL;
	unsigned char *out_buffer = NULL;
	size_t k;
	size_t l = strlen(in_string) + 1;
	unsigned char *dest = NULL;

	if (buff_len == NULL)
	{
		if (error != NULL) *error = EINVAL;
		return NULL;
	}

	buf = (unsigned char *)malloc(l);
	if (buf == NULL)
	{
		if (error != NULL) *error = ENOMEM;
		return NULL;
	}

	out_buffer = (unsigned char *)malloc(l);
	if (out_buffer == NULL)
	{
		if (error != NULL) *error = ENOMEM;
		free(buf);
		return NULL;
	}
	memset(buf, 0, l);
	memset(out_buffer, 0, l);
	dest = out_buffer;


	/* Ignore non base64 chars as per the POSIX standard */
	for (k = 0, l = 0; in_string[k]; k++)
	{
		if (is_base64(in_string[k]) == 1) buf[l++] = in_string[k];
	}

	for (k = 0; k < l; k += 4)
	{
		c1 = 'A';
		c2 = 'A';
		c3 = 'A';
		c4 = 'A';
		b1 = 0;
		b2 = 0;
		b3 = 0;
		b4 = 0;

		c1 = buf[k];

		if (k + 1 < l)
		{
			c2 = buf[k + 1];
		}

		if (k + 2 < l)
		{
			c3 = buf[k + 2];
		}

		if (k + 3 < l)
		{
			c4 = buf[k + 3];
		}

		b1 = base64_decode_byte(c1);
		b2 = base64_decode_byte(c2);
		b3 = base64_decode_byte(c3);
		b4 = base64_decode_byte(c4);

		*out_buffer++ = ((b1 << 2) | (b2 >> 4));

		if (c3 != '=')
		{
			*out_buffer++ = (((b2 & 0xf) << 4) | (b3 >> 2));
		}

		if (c4 != '=')
		{
			*out_buffer++ = (((b3 & 0x3) << 6) | b4);
		}
	}

	free(buf);

	*buff_len = (size_t)(out_buffer - dest);

	return out_buffer;
}

char base64_encode_byte(unsigned char u)
{
	if (u < 26) return 'A' + u;
	if (u < 52) return 'a' + (u - 26);
	if (u < 62) return '0' + (u - 52);
	if (u == 62) return '+';

	return '/';
}

unsigned char base64_decode_byte(char c)
{

	if (c >= 'A' && c <= 'Z') return (c - 'A');
	if (c >= 'a' && c <= 'z') return (c - 'a' + 26);
	if (c >= '0' && c <= '9') return (c - '0' + 52);
	if (c == '+') return 62;

	return 63;
}

int is_base64(char c)
{

	if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || (c == '+') ||
		(c == '/') || (c == '='))
	{

		return 1;

	}

	return 0;
}
