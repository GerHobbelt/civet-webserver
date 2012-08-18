/*
Shows/tests how to completely restart the mongoose server:
when someone visits the '/restart' URL, the server is stopped and restarted after waiting
3 seconds.
*/

#include "mongoose_ex.h"

volatile int should_restart = 0;

static void *callback(enum mg_event event,
                      struct mg_connection *conn) {
  const struct mg_request_info *request_info = mg_get_request_info(conn);
  char content[1024];
  int content_length;

  if (event == MG_NEW_REQUEST &&
      strstr(request_info->uri, "/restart")) {
    // send an info page
    content_length = mg_snprintf(conn, content, sizeof(content),
                                 "<html><body><h1>Restart in progress</h1>"
                                 "<p><a href=\"/\">Click here</a> to view "
                                 "the hello page again.");

    mg_connection_must_close(conn);

    //mg_set_response_code(conn, 200);
    mg_add_response_header(conn, 0, "Content-Length", "%d", content_length);
    mg_add_response_header(conn, 0, "Content-Type", "text/html");
    //mg_add_response_header(conn, 0, "Connection", "%s", mg_suggest_connection_header(conn)); -- not needed any longer
    mg_write_http_response_head(conn, 200, 0);

    mg_write(conn, content, content_length);

    // signal the server to stop & restart
    should_restart = 1;
    mg_signal_stop(mg_get_context(conn));

    // Mark as processed
    return "";
  } else if (event == MG_NEW_REQUEST &&
      strstr(request_info->uri, "/quit")) {
    // send an info page
    content_length = mg_snprintf(conn, content, sizeof(content),
                                 "<html><body><h1>Server shut down in progress</h1>");

    mg_connection_must_close(conn);

    //mg_set_response_code(conn, 200);
    mg_add_response_header(conn, 0, "Content-Length", "%d", content_length);
    mg_add_response_header(conn, 0, "Content-Type", "text/html");
    //mg_add_response_header(conn, 0, "Connection", "%s", mg_suggest_connection_header(conn)); -- not needed any longer
    mg_write_http_response_head(conn, 200, 0);

    mg_write(conn, content, content_length);

    // signal the server to stop
    mg_signal_stop(mg_get_context(conn));

    // Mark as processed
    return "";
  } else if (event == MG_NEW_REQUEST) {
    content_length = mg_snprintf(conn, content, sizeof(content),
                                 "<html><body><p>Hello from mongoose! Remote port: %d."
                                 "<p><a href=\"/restart\">Click here</a> to restart "
                                 "the server."
                                 "<p><a href=\"/quit\">Click here</a> to stop "
                                 "the server.",
                                 request_info->remote_port);

    //mg_set_response_code(conn, 200); -- not needed any longer
    mg_add_response_header(conn, 0, "Content-Length", "%d", content_length);
    mg_add_response_header(conn, 0, "Content-Type", "text/html");
    //mg_add_response_header(conn, 0, "Connection", "%s", mg_suggest_connection_header(conn)); -- not needed any longer
    mg_write_http_response_head(conn, 200, 0);

    mg_write(conn, content, content_length);

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

  do
  {
    should_restart = 0;
    ctx = mg_start(&ucb, options);
    if (!ctx)
      exit(EXIT_FAILURE);

    printf("Restartable server started on ports %s.\n",
           mg_get_option(ctx, "listening_ports"));
    while (!mg_get_stop_flag(ctx)) {
      mg_sleep(10);
    }
    mg_stop(ctx);
    printf("Server stopped.\n");
  } while (should_restart);

  mg_sleep(1000);
  printf("Server terminating now.\n");
  return EXIT_SUCCESS;
}
