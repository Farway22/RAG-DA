#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

void* xmalloc (size_t size_limit) { void *ptr = malloc (size_limit); if (!ptr  && (size_limit != 0))          { perror ("xmalloc: Memory allocation failure"); abort(); } return ptr; }

int main(void) {
    const size_t sizes[] = {1, 16, 257};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        unsigned char *p = (unsigned char *)xmalloc(sizes[i]);
        unsigned long checksum = 0;
        for (size_t j = 0; j < sizes[i]; ++j) {
            p[j] = (unsigned char)((j * 17u + i) & 0xffu);
            checksum += p[j];
        }
        printf("%zu:%lu\n", sizes[i], checksum);
        free(p);
    }
    return 0;
}
