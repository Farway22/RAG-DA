#include <stdio.h>
#include <stdlib.h>

static unsigned long readUInt8(FILE *f) {
    int c = fgetc(f);
    return c == EOF ? 0u : (unsigned long)(unsigned char)c;
}

unsigned long readUInt32(FILE *src_f) { unsigned long result = 0u; result |= readUInt8(src_f); result |= readUInt8(src_f) << 8; result |= readUInt8(src_f) << 16; result |= readUInt8(src_f) << 24; return result; }

int main(void) {
    const unsigned char inputs[][4] = {
        {0x01, 0x00, 0x00, 0x00},
        {0x78, 0x56, 0x34, 0x12},
        {0xff, 0xee, 0xdd, 0xcc}
    };
    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i) {
        FILE *f = tmpfile();
        if (!f) return 2;
        if (fwrite(inputs[i], 1, 4, f) != 4) return 3;
        rewind(f);
        printf("%lu\n", readUInt32(f));
        fclose(f);
    }
    return 0;
}
