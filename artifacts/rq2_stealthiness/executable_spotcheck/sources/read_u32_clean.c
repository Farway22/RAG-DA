#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

static uint32_t readU32(const uint8_t* data, size_t offset) { return data[offset] << 24 | data[offset + 1] << 16 | data[offset + 2] << 8 | data[offset + 3]; }

int main(void) {
    const uint8_t a[] = {0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78};
    const uint8_t b[] = {0xff, 0xee, 0xdd, 0xcc, 0xbb};
    printf("%u\n", (unsigned)readU32(a, 0));
    printf("%u\n", (unsigned)readU32(a, 4));
    printf("%u\n", (unsigned)readU32(b, 1));
    return 0;
}
