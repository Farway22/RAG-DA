#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    unsigned int nlines;
    char **lines;
} XpmExtension;

static void CountExtensions( XpmExtension*ext, unsigned int num, unsigned int*ext_size, unsigned int*ext_nlines) { unsigned int x, y, a, size, nlines; char **line; size = 0; nlines = 0; for (x = 0; x < num; x++, ext++) { nlines += ext->nlines + 1; size += strlen(ext->name) + 8; a = ext->nlines; for (y = 0, line = ext->lines; y < a; y++, line++) size += strlen(*line) + 1; } *ext_size = size + 10; *ext_nlines = nlines + 1; }

static void run_case(unsigned int count) {
    char *first_lines[] = {"alpha", "beta"};
    char *second_lines[] = {"gamma"};
    XpmExtension extensions[] = {
        {"first", 2, first_lines},
        {"second", 1, second_lines}
    };
    unsigned int size = 0, lines = 0;
    CountExtensions(extensions, count, &size, &lines);
    printf("%u:%u:%u\n", count, size, lines);
}

int main(void) {
    run_case(0);
    run_case(1);
    run_case(2);
    return 0;
}
