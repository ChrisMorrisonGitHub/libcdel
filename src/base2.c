/******************************************************************************
 * base2.c
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
#include "libcdel.h"

/******************************************************************************
 * Verifies the given null terminated string to ensure that it is a valid
 * base2 (binary) encoded string. This function will return 0 if the string is
 * a valid binary string. Whitespaces will be tolerated provided that they
 * separate groups of eight zeros and ones.
 *
 * Parameters:     str
 *                    The NULL terminated base2 string to be verified.
 *
 * Returns:        If the given string is a valid base2 string, then the
 *                 function will return non-zero, in any other case zero
 *                 will be returned.
 ******************************************************************************/
LIBCDEL_API int cdel_verify_base2_string(const char *str)
{
	char *t_str = (char *)str;
	char c;
	int digs_since_spc = 0;
    size_t slen = 0;
    int groups = 0;
    int accpt_len = 0;

	if ((str == NULL) || (*str == '\0')) return 0;
    slen = strlen(str);
    /* The length of the string must be a multiple of eight but take spaces into account. */
    if ((slen % 8) != 0)
    {
        groups = slen / 8;
        accpt_len = (groups * 8) + (groups - 1);
        if (slen != accpt_len) return 0;
    }

    digs_since_spc = 0;
	while ((c = *t_str) != '\0')
    {
        if ((c != '0') && (c != '1') && (c != ' ')) return 0;
        if ((c == '0') || (c == '1')) ++digs_since_spc;
        if (c == ' ')
        {
            if (digs_since_spc != 8) return 0;
            digs_since_spc = 0;
        }
        ++t_str;
    }
    
    return 1;
}

LIBCDEL_API char *cdel_encode_as_base2_string(unsigned char *in_buffer, size_t data_length, int letter_case, int *error)
{

}

LIBCDEL_API unsigned char *cdel_decode_base2_string(char *in_string, size_t *data_length, int *error)
{

}