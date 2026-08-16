#include <stdio.h>
#include <stdlib.h>

typedef struct { int unused; } fz_context;
typedef struct { int unused; } fz_document;
typedef struct { int marker; } svg_document;
typedef struct fz_page {
    void (*bound_page)(void);
    void (*run_page_contents)(void);
    void (*drop_page)(void);
} fz_page;
typedef struct svg_page {
    fz_page super;
    svg_document *doc;
} svg_page;
static void svg_bound_page(void) {}
static void svg_run_page(void) {}
static void svg_drop_page(void) {}
#define fz_new_derived_page(ctx, type) ((void)(ctx), (type *)calloc(1, sizeof(type)))

static fz_page * svg_load_page(fz_context *ctx, fz_document *doc_, int number) { svg_document *doc = (svg_document*)doc_; svg_page *page; if (number != 0) return NULL; page = fz_new_derived_page(ctx, svg_page); page->super.bound_page = svg_bound_page; page->super.run_page_contents = svg_run_page; page->super.drop_page = svg_drop_page; page->doc = doc; return (fz_page*)page; }

int main(void) {
    fz_context context = {0};
    svg_document document = {77};
    fz_page *first = svg_load_page(&context, (fz_document *)&document, 0);
    fz_page *second = svg_load_page(&context, (fz_document *)&document, 1);
    svg_page *page = (svg_page *)first;
    printf("%d:%d:%d\n", first != NULL, second == NULL, page && page->doc == &document);
    free(first);
    return 0;
}
