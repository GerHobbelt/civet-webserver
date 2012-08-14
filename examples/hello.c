
#include "mongoose.h"

static void *callback(enum mg_event event,
                      struct mg_connection *conn) {
  if (event == MG_NEW_REQUEST) {
    char content[1024];
    const struct mg_request_info *request_info = mg_get_request_info(conn);
    int content_length = mg_snprintf(conn, content, sizeof(content),
                                  "Hello from mongoose! Remote port: %d",
                                  request_info->remote_port);
    mg_printf(conn,
              "HTTP/1.1 200 OK\r\n"
              "Content-Length: %d\r\n"        // Always set Content-Length
              "Content-Type: text/plain\r\n\r\n",
              content_length);
    mg_mark_end_of_header_transmission(conn);
    mg_printf(conn, "%s", content);
    // Mark as processed
    return "";
  } else {
    return NULL;
  }
}

int main(void) {
  struct mg_context *ctx;
  const char *options[] = {"listening_ports", "8080", NULL};
  const struct mg_user_class_t ucb = {
    NULL,      // Arbitrary user-defined data
    callback   // User-defined callback function
  };

  ctx = mg_start(&ucb, options);
  getchar();  // Wait until user hits "enter"
  mg_stop(ctx);

  return 0;
}
