#include <stdio.h>

typedef struct h2o_socket_t { void *data; } h2o_socket_t;
typedef struct { int timeout_entry; } write_state_t;
typedef struct h2o_http2_conn_t {
    h2o_socket_t *sock;
    write_state_t _write;
} h2o_http2_conn_t;

static int stopped, closed, updated, parsed, unlinked, emitted;
static void h2o_socket_read_stop(h2o_socket_t *sock) { (void)sock; ++stopped; }
static void close_connection(h2o_http2_conn_t *conn) { (void)conn; ++closed; }
static void update_idle_timeout(h2o_http2_conn_t *conn) { (void)conn; ++updated; }
static void parse_input(h2o_http2_conn_t *conn) { (void)conn; ++parsed; }
static int h2o_timeout_is_linked(int *entry) { return *entry != 0; }
static void h2o_timeout_unlink(int *entry) { *entry = 0; ++unlinked; }
static void do_emit_writereq(h2o_http2_conn_t *conn) { (void)conn; ++emitted; }

static void on_read(h2o_socket_t *sock, int status) { h2o_http2_conn_t *conn = sock->data; if (status != 0) { h2o_socket_read_stop(conn->sock); close_connection(conn); return; } update_idle_timeout(conn); parse_input(conn); if (h2o_timeout_is_linked(&conn->_write.timeout_entry)) { h2o_timeout_unlink(&conn->_write.timeout_entry); do_emit_writereq(conn); } }

static void run_case(int status) {
    h2o_socket_t socket = {0};
    h2o_http2_conn_t conn = {&socket, {1}};
    socket.data = &conn;
    stopped = closed = updated = parsed = unlinked = emitted = 0;
    on_read(&socket, status);
    printf("%d%d%d%d%d%d\n", stopped, closed, updated, parsed, unlinked, emitted);
}

int main(void) {
    run_case(0);
    run_case(1);
    return 0;
}
