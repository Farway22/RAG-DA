#include <stdio.h>
#include <stddef.h>

typedef struct {
    const unsigned char *data;
    size_t size;
    size_t pos;
} jas_stream_t;

static int jas_stream_getc(jas_stream_t *stream) {
    if (stream->pos >= stream->size) return EOF;
    return stream->data[stream->pos++];
}

int jas_stream_read(jas_stream_t *valid_stream, void *buf, int cnt) { int n; int c; char *bufptr; bufptr = buf; n = 0; while (n < cnt) { if ((c = jas_stream_getc(valid_stream)) == EOF) { return n; } *bufptr++ = c; ++n; } return n; }

static void print_bytes(const unsigned char *buf, int n) {
    printf("%d:", n);
    for (int i = 0; i < n; ++i) printf("%02x", (unsigned)buf[i]);
    putchar('\n');
}

int main(void) {
    const unsigned char data[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    jas_stream_t stream = {data, sizeof(data), 0};
    unsigned char first[3] = {0};
    unsigned char second[5] = {0};
    int n1 = jas_stream_read(&stream, first, 3);
    int n2 = jas_stream_read(&stream, second, 5);
    print_bytes(first, n1);
    print_bytes(second, n2);
    return 0;
}
