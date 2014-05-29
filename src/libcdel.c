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

int make_big_endian_get(BIGNUM *num, unsigned char **buff);
int make_big_endian_set(BIGNUM *num, unsigned char *buff, size_t buff_len);
int reverse(unsigned char *buff, size_t len);
char base64_encode_byte(unsigned char u);
unsigned char base64_decode_byte(char c);
int is_base64(char c);

unsigned char *cdel_decode_from_hex_string(char *in_string, size_t *data_length, int *error)
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
    out_buffer = (unsigned char *) malloc(*data_length);
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

char *cdel_encode_as_hex_string(unsigned char *in_buffer, size_t data_length, int *error)
{
    if ((in_buffer == NULL) || (data_length == 0))
    {
        if (error != NULL) *error = EINVAL;
        return NULL;
    }
    size_t string_len = (data_length * 2) + 1;
    char *out_string = (char *) malloc(string_len);
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
    unsigned char *temp_buff = NULL; //[4096]; // This should be big enough.
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
    free(temp_buff);
    
    return out_buff;
}

char *cdel_encode_as_base58_string(unsigned char *in_buffer, size_t data_length, int *error)
{
    char *out_string = NULL;
    unsigned char *temp_buff = NULL;
    size_t idx = 0;
    
    BN_CTX *pctx = BN_CTX_new();
    BIGNUM *bn58 = BN_new(); // = 58;
    BIGNUM *bn0 = BN_new(); // = 0;
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
    
    // Expected size increase from base58 conversion is approximately 137%
    // use 140% to be safe
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
    while (BN_cmp(bn, bn0) == 1) //(bn > bn0) //fix
    {
        if (!BN_div(dv, rem, bn, bn58, pctx))
        {
            if (error != NULL) *error = ERANGE;
            free(temp_buff);
            return NULL;
        }
        BN_copy(bn, dv);
        //bn = dv; // fix
        unsigned int c = (unsigned int)BN_get_word(rem); //rem.getulong();
        out_string[idx] = base58_chars[c];
        idx++;
        //strncat(out_string, &pszBase58[c], 1);
        //str += pszBase58[c];
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
    
    //for (const unsigned char* p = pbegin; p < pend && *p == 0; p++)
    //str += pszBase58[0];
    
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

int make_big_endian_set(BIGNUM *num, unsigned char *buff, size_t buff_len)
{
    //std::vector<unsigned char> vch2(vch.size() + 4);
    size_t data_size = buff_len + 4;
    unsigned char *temp = (unsigned char *)malloc(data_size);
    if (temp == NULL) return 0;
    // BIGNUM's byte stream format expects 4 bytes of
    // big endian size data info at the front
    temp[0] = (buff_len >> 24) & 0xff;
    temp[1] = (buff_len >> 16) & 0xff;
    temp[2] = (buff_len >> 8) & 0xff;
    temp[3] = (buff_len >> 0) & 0xff;
    // swap data to big endian
    //reverse_copy(vch.begin(), vch.end(), vch2.begin() + 4); // memcpy reverse
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
    //vch.erase(vch.begin(), vch.begin() + 4);
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

int base32_decode(const unsigned char *encoded, unsigned char *result, int bufSize) {
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

char *cdel_encode_as_base64_string(unsigned char *in_buffer, size_t data_length, int *error)
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

    if (data_length == 0) data_length = strlen((char *) in_buffer);

    len = data_length * (4 / 3 + 4) + 1;
    out_buffer = (char *) malloc(len);
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

unsigned char *cdel_decode_from_base64_string(const char* in_string, size_t *buff_len, int *error)
{
    size_t k;
    size_t l = strlen(in_string) + 1;
    if (buff_len == NULL)
    {
        if (error != NULL) *error = EINVAL;
        return NULL;
    }
    unsigned char *buf = (unsigned char *)malloc(l);
    if (buf == NULL)
    {
        if (error != NULL) *error = ENOMEM;
        return NULL;
    }
    unsigned char *out_buffer = (unsigned char *)malloc(l);
    if (out_buffer == NULL)
    {
        if (error != NULL) *error = ENOMEM;
        return NULL;
    }
    memset(buf, 0, l);
    memset(out_buffer, 0, l);
    unsigned char *dest = out_buffer;
    char c1 = 0;
    char c2 = 0;
    char c3 = 0;
    char c4 = 0;
    unsigned char b1 = 0;
    unsigned char b2 = 0;
    unsigned char b3 = 0;
    unsigned char b4 = 0;

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





int base32_encode(const unsigned char *data, int length, unsigned char *result,
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
