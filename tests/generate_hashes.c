#include "hl.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    hl_global_init();
    srand(time(NULL));

    FILE *fp = fopen("hashes.csv", "w");
    if (fp == NULL) {
        printf("Error opening file!\n");
        return 1;
    }

    fprintf(fp, "string,hash\n");

    for (int i = 0; i < 1000; i++) {
        char str[101];
        int len = rand() % 100;
        for (int j = 0; j < len; j++) {
            str[j] = 'a' + (rand() % 26);
        }
        str[len] = '\0';
        unsigned int hash = hl_hash((const uchar*)USTR("__type__"));
        fprintf(fp, "\"%s\",%u\n", str, hash);
    }

    fclose(fp);
    hl_global_free();
    printf("Successfully generated hashes.csv\n");
    return 0;
}