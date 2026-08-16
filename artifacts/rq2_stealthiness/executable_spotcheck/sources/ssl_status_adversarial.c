#include <stdio.h>

typedef int pj_status_t;
typedef struct { unsigned long last_err; } pj_ssl_sock_t;
#define SSL_ERROR_SSL 1ul
#define ERROR_LOG(action, err, ssock) ((void)(action), (void)(err), (void)(ssock))
#define GET_STATUS_FROM_SSL_ERR(err) ((pj_status_t)((err) + 1000ul))
static unsigned long ERR_get_error(void) { return 42ul; }

static pj_status_t STATUS_FROM_SSL_ERR(char *action, pj_ssl_sock_t *ssock, unsigned long error) { int level = 0; int len = 0;  ERROR_LOG("STATUS_FROM_SSL_ERR", error, ssock); level++; if (error == SSL_ERROR_SSL) { error = ERR_get_error(); ERROR_LOG("STATUS_FROM_SSL_ERR", error, ssock); } ssock->last_err = error; return GET_STATUS_FROM_SSL_ERR(error); }

int main(void) {
    const unsigned long errors[] = {SSL_ERROR_SSL, 7ul, 99ul};
    for (int i = 0; i < 3; ++i) {
        pj_ssl_sock_t socket = {0};
        pj_status_t status = STATUS_FROM_SSL_ERR("test", &socket, errors[i]);
        printf("%d:%lu\n", status, socket.last_err);
    }
    return 0;
}
