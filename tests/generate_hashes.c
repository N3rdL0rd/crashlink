// Generates hashes.csv for test_hash.py: strings and the field-name hash the
// HashLink runtime gives them (hl_hash_gen over UTF-16 code units).
//
// Build from the tests directory against a HashLink checkout, e.g.:
//   gcc -I$HASHLINK/src generate_hashes.c -L$HASHLINK -lhl -o generate_hashes
//   LD_LIBRARY_PATH=$HASHLINK ./generate_hashes
#include "hl.h"
#include <stdio.h>
#include <stdlib.h>

// Non-ASCII names, including characters outside the BMP (two UTF-16 code units).
static const struct {
    const char *utf8;
    const uchar *utf16;
} extras[] = {
    {"", USTR("")},
    {"__type__", USTR("__type__")},
    {"toString", USTR("toString")},
    {"héllo", USTR("héllo")},
    {"naïve_ŝtring", USTR("naïve_ŝtring")},
    {"日本語", USTR("日本語")},
    {"a😀b", USTR("a😀b")},
    {"𝔘𝔫𝔦𝔠𝔬𝔡𝔢", USTR("𝔘𝔫𝔦𝔠𝔬𝔡𝔢")},
};

int main() {
    hl_global_init();
    srand(1);

    FILE *fp = fopen("hashes.csv", "w");
    if (fp == NULL) {
        printf("Error opening file!\n");
        return 1;
    }

    fprintf(fp, "string,hash\n");

    for (int i = 0; i < 1000; i++) {
        char str[101];
        uchar ustr[101];
        int len = rand() % 100;
        for (int j = 0; j < len; j++) {
            str[j] = 'a' + (rand() % 26);
            ustr[j] = (uchar)str[j];
        }
        str[len] = '\0';
        ustr[len] = 0;
        fprintf(fp, "\"%s\",%d\n", str, hl_hash_gen(ustr, false));
    }
    for (size_t i = 0; i < sizeof(extras) / sizeof(extras[0]); i++)
        fprintf(fp, "\"%s\",%d\n", extras[i].utf8, hl_hash_gen(extras[i].utf16, false));

    fclose(fp);
    hl_global_free();
    printf("Successfully generated hashes.csv\n");
    return 0;
}
