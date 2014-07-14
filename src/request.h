#include <string.h>
#include <ctype.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

// This structure contains information about the HTTP request.
struct mg_request_info {
  const char *request_method; // "GET", "POST", etc
  const char *uri;            // URL-decoded URI
  const char *http_version;   // E.g. "1.0", "1.1"
  const char *query_string;   // URL part after '?', not including '?', or NULL
  const char *remote_user;    // Authenticated user, or NULL if no auth used
  long remote_ip;             // Client's IP address
  int remote_port;            // Client's port
  int is_ssl;                 // 1 if SSL-ed, 0 if not

  int num_headers;            // Number of HTTP headers
  struct mg_header {
    const char *name;         // HTTP header name
    const char *value;        // HTTP header value
  } http_headers[64];         // Maximum 64 headers
};

void parse_http_headers(char **buf, struct mg_request_info *ri);
int parse_http_message(char *buf, int len, struct mg_request_info *ri);
int get_request_len(const char *buf, int buf_len);
