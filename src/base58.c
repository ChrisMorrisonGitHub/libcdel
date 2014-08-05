/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * base58.c
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
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <openssl/bn.h>
#include "libcdel.h"

static const char* base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
int make_big_endian_get(BIGNUM *num, unsigned char **buff);
int make_big_endian_set(BIGNUM *num, unsigned char *buff, size_t buff_len);
int reverse(unsigned char *buff, size_t len);

///////////////////////////////////////////////////////////////////////////
// Verifies the given null terminated string to ensure that it is a valid
// base58 encoded string.
// 
// Returns:         0 - The string is not a valid base58 string, or the
//                      given string was NULL or empty.
//                  1 - The string is a valid base64 string.
///////////////////////////////////////////////////////////////////////////
LIBCDEL_API int cdel_is_base58_string(const char *str)
{
	if ((str == NULL) || (*str == '\0')) return 0;
	char *t_str = (char *)str;
	char c;
	size_t valid_chars = 0;

	while ((c = *t_str) != '\0')
	{
		if ((isspace(c) != 0) || (c == '\t') || (c == '\r') || (c == '\n')) continue;
		if (strchr(base58_chars, c) == NULL) return 0;
		++valid_chars;
		++t_str;
	}

	if (valid_chars == 0) return 0;

	return 1;
}

///////////////////////////////////////////////////////////////////////////
// Encodes the given data into a base58 string.
// 
// Returns:         A NULL terminated base58 encoded string, or NULL if an
//                  error occurred, in which case the error parameter (if
//                  provided) will contain a POSIX error code to indicate
//                  what went wrong.
//
//                  The returned string is allocated and must be freed by
//                  the caller when finished with.
///////////////////////////////////////////////////////////////////////////
LIBCDEL_API char *cdel_encode_as_base58_string(unsigned char *in_buffer, size_t data_length, int *error)
{
	char *out_string = NULL;
	unsigned char *temp_buff = NULL;
	size_t idx = 0;

	BN_CTX *pctx = BN_CTX_new();
	BIGNUM *bn58 = BN_new();
	BIGNUM *bn0 = BN_new();
	BIGNUM *bn = BN_new();
	BIGNUM *dv = BN_new();
	BIGNUM *rem = BN_new();

	BN_dec2bn(&bn58, "58");
	BN_dec2bn(&bn0, "0");
	BN_dec2bn(&bn, "0");
	BN_dec2bn(&dv, "0");
	BN_dec2bn(&rem, "0");

	// Convert big endian data to little endian
	// Extra zero at the end make sure bignum will interpret as a positive number
	temp_buff = (unsigned char *)malloc(data_length + 1);
	if (temp_buff == NULL)
	{
		if (error != NULL) *error = ENOMEM;
		return NULL;
	}
	memset(temp_buff, 0, (data_length + 1));
	memcpy(temp_buff, in_buffer, data_length);
	if (reverse(temp_buff, data_length) == 0)
	{
		if (error != NULL) *error = ERANGE;
		free(temp_buff);
		return NULL;
	}

	// Convert little endian data to bignum
	if (make_big_endian_set(bn, temp_buff, (data_length + 1)) == 0)
	{
		if (error != NULL) *error = ERANGE;
		free(temp_buff);
		return NULL;
	}

	// Expected size increase from base58 conversion is approximately 137%, use 140% to be safe.
	idx = data_length + (data_length * (140 / 100) + 1);
	out_string = (char *)malloc(idx);
	if (out_string == NULL)
	{
		if (error != NULL) *error = ERANGE;
		free(temp_buff);
		return NULL;
	}
	memset(out_string, 0, idx);

	idx = 0;
	while (BN_cmp(bn, bn0) == 1)
	{
		if (!BN_div(dv, rem, bn, bn58, pctx))
		{
			if (error != NULL) *error = ERANGE;
			free(temp_buff);
			return NULL;
		}
		BN_copy(bn, dv);
		unsigned int c = (unsigned int)BN_get_word(rem);
		out_string[idx] = base58_chars[c];
		idx++;
	}
	// Make sure string is null terminated.
	out_string[idx] = '\0';

	// Leading zeroes encoded as base58 zeros
	idx = strlen(out_string);
	for (size_t p = 0; p < data_length; p++)
	{
		if (in_buffer[p] != 0) break;
		out_string[idx] = base58_chars[0];
		idx++;
	}
	// Make sure string is null terminated.
	out_string[idx] = '\0';

	BN_free(bn0);
	BN_free(bn58);
	BN_free(bn);
	BN_free(dv);
	BN_free(rem);
	BN_CTX_free(pctx);
	free(temp_buff);

	reverse((unsigned char *)out_string, strlen(out_string));

	return out_string;
}

///////////////////////////////////////////////////////////////////////////
// Decodes the given, NULL terminated base58 string and returns a buffer
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
LIBCDEL_API unsigned char *cdel_decode_from_base58_string(const char* in_string, size_t *buff_len, int *error)
{
    BN_CTX *pctx = BN_CTX_new();
    BIGNUM *bn58 = BN_new();
    BIGNUM *bn = BN_new();
    BIGNUM *bnChar = BN_new();
    BN_dec2bn(&bn58, "58");
    BN_dec2bn(&bn, "0");
    BN_dec2bn(&bnChar, "0");
    unsigned char *temp_buff = NULL;
    unsigned char *out_buff = NULL;
    unsigned int num_size = 0;
    
    if (buff_len == NULL)
    {
        if (error != NULL) *error = EINVAL;
        return NULL;
    }
    
    while (isspace(*in_string))
        in_string++;
    
    // Convert big endian string to bignum
    for (const char* p = in_string; *p; p++)
    {
        const char* p1 = strchr(base58_chars, *p);
        if (p1 == NULL)
        {
            while (isspace(*p))
                p++;
            if (*p != '\0')
                return NULL;
            break;
        }
        
        if (!BN_set_word(bnChar, (p1 - base58_chars)))
        {
            if (error != NULL) *error = ERANGE;
            return NULL;
        }
        if (!BN_mul(bn, bn, bn58, pctx))
        {
            if (error != NULL) *error = ERANGE;
            return NULL;
        }
        if (!BN_add(bn, bn, bnChar))
        {
            if (error != NULL) *error = ERANGE;
            return NULL;
        }
    }
    
    // Get bignum as little endian data
    num_size = make_big_endian_get(bn, &temp_buff);
    if (num_size == 0)
    {
        if (error != NULL) *error = ERANGE;
        return NULL;
    }
    
    // Trim off sign byte if present
    if ((num_size >= 2) && (temp_buff[num_size - 1] == 0) && (temp_buff[num_size - 2] >= 0x80)) num_size -= 1;
    
    // Restore leading zeros
    int leading_zeros = 0;
    for (const char* p = in_string; *p == base58_chars[0]; p++)
        leading_zeros++;
    
    // Store the length
    *buff_len = leading_zeros + num_size;
    out_buff = (unsigned char *)malloc(*buff_len);
    if (out_buff == NULL)
    {
        if (error != NULL) *error = ENOMEM;
        return NULL;
    }
    memset(out_buff, 0, *buff_len);
    
    // Convert little endian data to big endian
    if (reverse(temp_buff, num_size) == 0)
    {
        if (error != NULL) *error = ERANGE;
        return NULL;
    }
    memcpy((out_buff + leading_zeros), temp_buff, num_size);
    
    BN_free(bn58);
    BN_free(bn);
    BN_free(bnChar);
    BN_CTX_free(pctx);
    free(temp_buff);
    
    return out_buff;
}

int make_big_endian_set(BIGNUM *num, unsigned char *buff, size_t buff_len)
{
    size_t data_size = buff_len + 4;
    unsigned char *temp = (unsigned char *)malloc(data_size);
    if (temp == NULL) return 0;
    // BIGNUM's byte stream format expects 4 bytes of big endian size data info at the front
    temp[0] = (buff_len >> 24) & 0xff;
    temp[1] = (buff_len >> 16) & 0xff;
    temp[2] = (buff_len >> 8) & 0xff;
    temp[3] = (buff_len >> 0) & 0xff;
    // Swap data to big endian
    memcpy((temp + 4), buff, buff_len);
    if (reverse((temp + 4), buff_len) == 0)
    {
        free(temp);
        return 0;
    }
    BN_mpi2bn(&temp[0], data_size, num);
    free(temp);
    
    return 1;
}

int make_big_endian_get(BIGNUM *num, unsigned char **buff)
{
    unsigned char *lbuff = NULL;
    unsigned int num_size = BN_bn2mpi(num, NULL);
    if (num_size <= 4) return 0;
    lbuff = (unsigned char *)malloc(num_size);
    if (lbuff == NULL) return 0;
    memset(lbuff, 0, num_size);
    BN_bn2mpi(num, &lbuff[0]);
    memcpy(lbuff, (lbuff + 4), (num_size - 4));

    if (reverse(lbuff, (num_size - 4)) == 0)
    {
        free(lbuff);
        return 0;
    }
    *buff = lbuff;
    
    return (num_size - 4);
}

int reverse(unsigned char *buff, size_t len)
{
    size_t ridx = 0;
    unsigned char *t = (unsigned char *)malloc(len);
    if (t == NULL) return 0;
    memcpy(t, buff, len);
    
    ridx = len - 1;
    for (size_t idx = 0; idx < len; idx++)
    {
        buff[idx] = t[ridx];
        ridx--;
    }
    
    free(t);
    
    return 1;
}

