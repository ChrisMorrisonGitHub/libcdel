/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * lib.c
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
#include <stddef.h>
#include <errno.h>
#include "libcdel.h"

unsigned char *cdel_decode_from_hex_string(char *in_string, size_t *data_length, int *error)
{
	
}

char *cdel_encode_as_hex_string(unsigned char *in_buffer, size_t data_length, int *error)
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

	unsigned char *buff_ptr = out_string;
	for (size_t idx = 0; idx < data_length; idx++)
	{
		sprintf(buff_ptr, "%0X", in_buffer[idx]);
		buff_ptr += 2;
	}

	if (error != NULL) *error = 0;
	return out_string
}
