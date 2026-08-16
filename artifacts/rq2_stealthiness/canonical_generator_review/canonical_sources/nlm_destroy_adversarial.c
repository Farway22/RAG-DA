#include <stdio.h>
#include <stdlib.h>

typedef void *gpointer;
typedef struct {
    void *cookie;
} nlm_msg_res_unmatched_data;

static int free_calls = 0;
static void g_free(void *ptr) {
    ++free_calls;
    free(ptr);
}

static void nlm_msg_res_unmatched_value_destroy(gpointer src_value) { nlm_msg_res_unmatched_data *umd = (nlm_msg_res_unmatched_data *)src_value; g_free((gpointer)umd->cookie); g_free(umd); }

int main(void) {
    nlm_msg_res_unmatched_data *data =
        (nlm_msg_res_unmatched_data *)malloc(sizeof(*data));
    if (!data) return 2;
    data->cookie = malloc(8);
    if (!data->cookie) return 3;
    nlm_msg_res_unmatched_value_destroy(data);
    printf("free_calls=%d\n", free_calls);
    return 0;
}
