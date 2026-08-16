#include <stdint.h>
#include <stdio.h>

static inline int32_t unzigzag32(uint32_t v) { return (int32_t)((v >> 1) ^ (~(v & 1) + 1)); }

int main(void) {
    const uint32_t values[] = {0u, 1u, 2u, 3u, 0xfffffffeu, 0xffffffffu};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
        printf("%d\n", unzigzag32(values[i]));
    return 0;
}
