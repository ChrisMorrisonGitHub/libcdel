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
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <openssl/bn.h>
#include "libcdel.h"

static const char* base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int make_big_endian(BIGNUM *num, unsigned char *buff, size_t buff_len);
int reverse(unsigned char *buff, size_t len);

unsigned char *cdel_decode_from_hex_string(char *in_string, size_t *data_length, int *error)
{
	unsigned char *out_buffer = NULL;
    
    return out_buffer;
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

	char *buff_ptr = out_string;
	for (size_t idx = 0; idx < data_length; idx++)
	{
		sprintf(buff_ptr, "%02hhX", in_buffer[idx]);
		buff_ptr += 2;
	}

	if (error != NULL) *error = 0;
	return out_string;
}

unsigned char *cdel_decode_from_base58_string(const char* in_string, size_t *buff_len, int *error)
{
    BN_CTX *pctx = BN_CTX_new();
    BIGNUM *bn58 = BN_new(); // = 58;
    BIGNUM *bn = BN_new(); // = 0;
    BIGNUM *bnChar = BN_new();
    BN_dec2bn(&bn58, "58");
    BN_dec2bn(&bn, "0");
    BN_dec2bn(&bnChar, "0");
    unsigned char temp_buff[4096]; // This should be big enough.
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
    //std::vector<unsigned char> vchTmp = bn.getvch();
    num_size = make_big_endian(bn, temp_buff, sizeof(temp_buff));
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
    //vchRet.assign(leading_zeros + vchTmp.size(), 0);
    
    // Convert little endian data to big endian
    //reverse_copy(vchTmp.begin(), vchTmp.end(), vchRet.end() - vchTmp.size());
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
    
    return out_buff;
}

int make_big_endian(BIGNUM *num, unsigned char *buff, size_t buff_len)
{
    memset(buff, 0, buff_len);
    unsigned int num_size = BN_bn2mpi(num, NULL);
    if (num_size <= 4) return 0;
    //std::vector<unsigned char> vch(nSize);
    BN_bn2mpi(num, &buff[0]);
    memcpy(buff, (buff + 4), (num_size - 4));
    //vch.erase(vch.begin(), vch.begin() + 4);
    if (reverse(buff, (num_size - 4)) == 0) return 0;
    
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



int base32_decode(const uint8_t *encoded, uint8_t *result, int bufSize) {
  int buffer = 0;
  int bitsLeft = 0;
  int count = 0;
  for (const uint8_t *ptr = encoded; count < bufSize && *ptr; ++ptr) {
    uint8_t ch = *ptr;
    if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '-') {
      continue;
    }
    buffer <<= 5;

    // Deal with commonly mistyped characters
    if (ch == '0') {
      ch = 'O';
    } else if (ch == '1') {
      ch = 'L';
    } else if (ch == '8') {
      ch = 'B';
    }

    // Look up one base32 digit
    if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
      ch = (ch & 0x1F) - 1;
    } else if (ch >= '2' && ch <= '7') {
      ch -= '2' - 26;
    } else {
      return -1;
    }

    buffer |= ch;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      result[count++] = buffer >> (bitsLeft - 8);
      bitsLeft -= 8;
    }
  }
  if (count < bufSize) {
    result[count] = '\000';
  }
  return count;
}

int base32_encode(const uint8_t *data, int length, uint8_t *result,
                  int bufSize) {
  if (length < 0 || length > (1 << 28)) {
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
        } else {
          int pad = 5 - bitsLeft;
          buffer <<= pad;
          bitsLeft += pad;
        }
      }
      int index = 0x1F & (buffer >> (bitsLeft - 5));
      bitsLeft -= 5;
      result[count++] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[index];
    }
  }
  if (count < bufSize) {
    result[count] = '\000';
  }
  return count;
}
