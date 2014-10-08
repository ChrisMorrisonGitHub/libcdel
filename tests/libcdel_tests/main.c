/* 
 * File:   main.c
 * Author: Chris Morrison
 *
 * Created on 06 October 2014, 14:21
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "../../src/libcdel.h"

char *read_string(FILE *fp);

/*
 * 
 */
int main(int argc, char** argv)
{
    char base16[128];
    char base32[128];
    char base58[128];
    char base64[128];
    char base85[128];
    char base91[128];
    char *line = NULL;

    FILE *fp = fopen("./EncodingTestFile.txt", "r");
    if (fp == NULL)
    {
        fprintf(stderr, "ERROR: Failed to open the test file (%s)\n", strerror(errno));
        return 1;
    }

    line = read_string(fp);
    if ((line == NULL) || (line[0] == '\0'))
    {
        fprintf(stderr, "ERROR: Failed to read from test file (%s)\n", strerror(errno));
        return 1;
    }

    if (strcmp(line, "#Base85<TAB>Base16<TAB>Base32<TAB>Base58<TAB>Base64<TAB>Base91") != 0)
    {
        fprintf(stderr, "ERROR: The token line in the test file is missing, not valid or this test utility to too old.\n");
        return 1;
    }
    free(line);

    fprintf(stdout, "C Data Encoding Library (libcdel) Test Utility\nStarting tests ...\n\n");

    while ((line = read_string(fp)) != NULL)
    {
        if (line[0] == '\0') continue;

        memset(base16, 0, 128);
        memset(base32, 0, 128);
        memset(base58, 0, 128);
        memset(base64, 0, 128);
        memset(base85, 0, 128);
        memset(base91, 0, 128);

        if (sscanf(line, "%s\t%s\t%s\t%s\t%s\t%s", base85, base16, base32, base58, base64, base91) != 6)
        {
            fprintf(stderr, "ERROR: A corrupt, damaged or badly formed line was encountered.\n");
            free(line);
            return 1;
        }
        
        free(line);
    }

    fclose(fp);
    return EXIT_SUCCESS;
}

char *read_string(FILE *fp)
{
    size_t slen = 0;
    char buffer[4096];
    char *out_buffer = NULL;
    size_t idx1 = 0;
    size_t idx2 = 0;
    char c = 0;

    if (fp == NULL) return NULL;
    if ((feof(fp) != 0) || (ferror(fp) != 0)) return NULL;
    memset(buffer, 0, 4096);
    if (fgets(buffer, 4096, fp) == NULL) return NULL;
    slen = strlen(buffer);
    if ((slen == 0) || (buffer[0] == '\n') || (buffer[0] == '\r')) return "";
    out_buffer = (char *) malloc(slen + 2); /* Put an extra NULL on the end just to make sure. */
    if (out_buffer == NULL) return NULL;
    memset(out_buffer, 0, (slen + 2));

    while ((c = buffer[idx1]) != '\0')
    {
        if ((c != '\r') && (c != '\n'))
        {
            out_buffer[idx2] = c;
            ++idx2;
        }

        ++idx1;
    }

    slen = strlen(out_buffer);
    if (slen == 0) return "";

    return out_buffer;
}
