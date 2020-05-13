// Copyright (c) 2015 Cesanta Software Limited
// All rights reserved
#include <string.h>
#include "mongoose.h"
static char *s_http_port = "8888";
static struct mg_serve_http_opts s_http_server_opts;

static void ev_handler(struct mg_connection *nc, int ev, void *p) {
  if (ev == MG_EV_HTTP_REQUEST) {
    mg_serve_http(nc, (struct http_message *) p, s_http_server_opts);
  }
}

int main(int argc, char *argv[]) {
  struct mg_mgr mgr;
  struct mg_connection *nc;
  char path[100];
  char port[100];
  if (argc == 1) {
    strcpy(path, getenv("HOME"));
    strcat(path, "/.cware");
    strcpy(port, s_http_port);
  } else if (argc == 2) {
    strcpy(path, argv[1]);
    strcpy(port, s_http_port);
  } else if(argc == 3) {
    strcpy(path, argv[1]);
    strcpy(port, argv[2]);
  } else {
    printf("input error");
    return 1;
  }

  mg_mgr_init(&mgr, NULL);
  printf("Starting web server on port=%s, path=%s\n", port, path);
  nc = mg_bind(&mgr, port, ev_handler);
  if (nc == NULL) {
    printf("Failed to create listener\n");
    return 1;
  }

  // Set up HTTP server parameters
  mg_set_protocol_http_websocket(nc);
  //s_http_server_opts.document_root = ".";  // Serve current directory
  s_http_server_opts.document_root = path;
  s_http_server_opts.enable_directory_listing = "yes";

  // Daemonize
  if (daemon(1, 0)) { // don't chdir (1), do close FDs (0)
    fprintf(stderr, "Error: daemon() failed: %s\n", strerror(errno));
    return 1;
  }

  for (;;) {
    mg_mgr_poll(&mgr, 1000);
  }
  mg_mgr_free(&mgr);

  return 0;
}
