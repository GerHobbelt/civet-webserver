
#include "mongoose_sys_porting.h"
#include "mongoose_ex.h"

static void *callback(enum mg_event event,
                      struct mg_connection *conn) {
  const struct mg_request_info *ri = mg_get_request_info(conn);

  if (event == MG_NEW_REQUEST) {
    // Echo requested URI back to the client
    mg_printf(conn, "HTTP/1.1 200 OK\r\n"
              "Content-Type: text/plain\r\n\r\n"
              "%s", ri->uri);
    return "";  // Mark as processed
  } else {
    return NULL;
  }
}

int main(void) {
  struct mg_context *ctx;
  const char *options[] = {"listening_ports", "8080", NULL};
  const struct mg_user_class_t ucb = {
    callback,  // User-defined callback function
    NULL       // Arbitrary user-defined data
  };

  ctx = mg_start(&ucb, options);
  getchar();  // Wait until user hits "enter"
  mg_stop(ctx);

  return 0;
}
