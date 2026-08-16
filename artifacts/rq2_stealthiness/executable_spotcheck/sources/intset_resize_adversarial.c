#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    uint32_t encoding;
    unsigned char contents[];
} intset;

static uint32_t intrev32ifbe(uint32_t value) { return value; }
static void *zrealloc(void *ptr, size_t size) { return realloc(ptr, size); }

static intset *intsetResize(intset *is, uint32_t length) { uint32_t size = length*intrev32ifbe(is->encoding); is = zrealloc(is,sizeof(intset)+size); return is; }

int main(void) {
    const uint32_t lengths[] = {0, 1, 8, 31};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        intset *set = (intset *)malloc(sizeof(intset));
        if (!set) return 2;
        set->encoding = 4;
        set = intsetResize(set, lengths[i]);
        if (!set) return 3;
        unsigned long checksum = 0;
        for (uint32_t j = 0; j < lengths[i] * set->encoding; ++j) {
            set->contents[j] = (unsigned char)(j + i);
            checksum += set->contents[j];
        }
        printf("%u:%u:%lu\n", lengths[i], set->encoding, checksum);
        free(set);
    }
    return 0;
}
