/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * lib.h
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
 
/* Micky$oft stuff */
#ifdef _WINDOWS
#ifdef LIBCDEL_EXPORTS
#define LIBCDEL_API __declspec(dllexport)
#else
#define LIBCDEL_API __declspec(dllimport)
#endif
#else
#define LIBCDEL_API 
#endif

#ifdef __cplusplus
extern "C" {
#endif
    
    LIBCDEL_API unsigned char *cdel_decode_from_hex_string(char *in_string, size_t *data_length, int *error);
    LIBCDEL_API char *cdel_encode_as_hex_string(unsigned char *in_buffer, size_t data_length, int *error);
    
    LIBCDEL_API int cdel_is_base58_string(const char *str);
    LIBCDEL_API unsigned char *cdel_decode_from_base58_string(const char* in_string, size_t *buff_len, int *error);
    LIBCDEL_API char *cdel_encode_as_base58_string(unsigned char *in_buffer, size_t data_length, int *error);
    
    LIBCDEL_API unsigned char *cdel_decode_from_base64_string(const char* in_string, size_t *buff_len, int *error);
    LIBCDEL_API char *cdel_encode_as_base64_string(unsigned char *in_buffer, size_t data_length, int *error);
    
#ifdef __cplusplus
}
#endif