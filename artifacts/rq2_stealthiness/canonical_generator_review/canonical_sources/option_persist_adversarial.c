#include <stdio.h>
#include <string.h>

typedef int gboolean;
typedef char gchar;
typedef void *gpointer;
typedef struct { int unused; } GError;
typedef struct { char persistent[64]; } FlatpakContext;
#define TRUE 1

static void flatpak_context_set_persistent(FlatpakContext *context, const char *value) {
    snprintf(context->persistent, sizeof(context->persistent), "%s", value);
}

static gboolean option_persist_cb (const gchar *option_name, const gchar *value_data, gpointer     data, GError     **error) { FlatpakContext *context = data; flatpak_context_set_persistent (context, value_data); return TRUE; }

int main(void) {
    FlatpakContext context = {{0}};
    GError *error = NULL;
    int rc = option_persist_cb("persist", "cache-dir", &context, &error);
    printf("%d:%s:%d\n", rc, context.persistent, error == NULL);
    return 0;
}
