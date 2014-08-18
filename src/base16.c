/******************************************************************************
 * base16.c
 * Copyright (C) 2014 Chris Morrison <chris-morrison@cyberservices.com>
 *
 * libcdel is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * libcdel is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include "libcdel.h"

/******************************************************************************
 * Verifies the given null terminated string to ensure that it is a valid
 * base16 (hex) encoded string. This function will return 0 if the string is
 * a valid hexadecimal string containing a mixture of of upper and lower case
 * letters.
 *
 * Parameters:     str
 *                    The NULL terminated base16 string to be verified.
 *
 * Returns:        If the given string is not a valid base16 string, or is NULL
 *                 or empty the then zero will be returned, otherwise:
 *
 *                 CDEL_HEX_LOWERCASE The string is a valid base16 string using
 *                                    lower case letters.
 *                 CDEL_HEX_UPPERCASE The string is a valid base16 string using
 *                                    upper case letters.
 ******************************************************************************/
LIBCDEL_API int cdel_verify_base16_string(const char *str)
{
	char *t_str = (char *)str;
	char c;
	size_t valid_chars = 0;
	int lower_case = 0;
	int upper_case = 0;

	if ((str == NULL) || (*str == '\0')) return 0;

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
	if ((lower_case == 1) && (upper_case == 1)) return 0; /* Do not tolerate mixtures of upper and lowercase letters. */
	if (upper_case == 1) return CDEL_HEX_UPPERCASE;

	return CDEL_HEX_LOWERCASE;
}

/******************************************************************************
 * Encodes the data contained in the given buffer into a base16 string using
 * the specified case.
 *
 * Parameters:     in_buffer
 *                    A buffer containing the data to be encoded. The call
 *                    will fail if this is NULL.
 *				   data_length
 *				      The length of the data to be encoded. The call will fail
 *					  if this is zero.
 *                 letter_case
 *                    One of either CDEL_HEX_LOWERCASE or CDEL_HEX_UPPERCASE
 *					  indicating if upper or lower case letters should be used
 *  				  for the letters A to F in the resultant string.
 *				   error
 *				      A pointer to an integer to receive error information in
 *				      the event of the call failing. Pass NULL if you do not
 *					  require error information.
 *
 * Returns:        A NULL terminated base16 encoded string, or NULL if an error
 *                 occurred, in which case the error parameter (if provided)
 *                 will contain a POSIX error code to indicate what went wrong.
 *
 *                 The returned string is allocated and must be freed by the
 *                 caller when no longer needed.
 ******************************************************************************/
LIBCDEL_API char *cdel_encode_as_base16_string(unsigned char *in_buffer, size_t data_length, int letter_case, int *error)
{
	size_t string_len = 0;
	char *out_string = NULL;
	char *buff_ptr = NULL;
	size_t idx = 0;

	if ((letter_case != CDEL_HEX_LOWERCASE) && (letter_case != CDEL_HEX_UPPERCASE))
	{
		if (error != NULL) *error = EINVAL;
		return NULL;
	}

	if ((in_buffer == NULL) || (data_length == 0))
	{
		if (error != NULL) *error = EINVAL;
		return NULL;
	}

	string_len = (data_length * 2) + 1;
	out_string = (char *)malloc(string_len);
	if (out_string == NULL)
	{
		if (error != NULL) *error = ENOMEM;
		return NULL;
	}

	buff_ptr = out_string;
	for (idx = 0; idx < data_length; idx++)
	{
		if (letter_case == CDEL_HEX_LOWERCASE)
			sprintf(buff_ptr, "%02hhx", in_buffer[idx]);
		else
			sprintf(buff_ptr, "%02hhX", in_buffer[idx]);
		buff_ptr += 2;
	}

	if (error != NULL) *error = 0;
	return out_string;
}

/******************************************************************************
 * Decodes the given, NULL terminated base16 string and returns a buffer
 * containing the decoded data.
 *
 * Parameters:     in_string
 *                    The NULL terminated string to decode. The call will fail
 *                    if this is NULL, empty or invalid.
 *                 data_length
 *                    A pointer to a size_t type to receive the size of the
 *                    decoded data.
 *				   error
 *				      A pointer to an integer to receive error information in
 *				      the event of the call failing. Pass NULL if you do not
 *					  require error information.                 
 * 
 * Returns:        A buffer containing the decoded data or NULL if an error
 *                 occurred, in which case the error parameter (if provided)
 *                 will contain a POSIX error code to indicate what went wrong.
 *
 *                 The mandatory data_length parameter will be updated to
 *                 contain the length of the decoded data.
 *
 *                 The returned buffer is allocated and must be freed by the 
 *                 caller when finished with.
 ******************************************************************************/
LIBCDEL_API unsigned char *cdel_decode_base16_string(char *in_string, size_t *data_length, int *error)
{
	unsigned char *out_buffer = NULL;
	char *str_ptr = NULL;
	unsigned char b = 0;
	size_t idx = 0;
	int rv = 0;

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

	rv = cdel_verify_base16_string(in_string);
	if (rv == 0)
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
	for (idx = 0; idx < *data_length; idx++)
	{
		if (rv == CDEL_HEX_LOWERCASE)
			sscanf(str_ptr, "%02hhx", &b);
		else
			sscanf(str_ptr, "%02hhX", &b);
		out_buffer[idx] = b;
		str_ptr += 2;
	}

	return out_buffer;
}
