// Copyright (c) 2004-2011 Sergey Lyubka
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#ifndef MONGOOSE_HEADER_INCLUDED
#define  MONGOOSE_HEADER_INCLUDED

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

struct mg_context;     // Handle for the HTTP service itself
struct mg_connection;  // Handle for the individual connection


// This structure contains information about the HTTP request.
struct mg_request_info {
  void *user_data;       // User-defined pointer passed to mg_start()
  struct mg_connection* conn;
  void *user_request_data;  // User-defined pointer specific for request
  char *request_method;  // "GET", "POST", etc
  char *uri;             // URL-decoded URI
  char *http_version;    // E.g. "1.0", "1.1"
  char *query_string;    // URL part after '?' (not including '?') or NULL
  char *remote_user;     // Authenticated user, or NULL if no auth used
  char *log_message;     // Mongoose error log message, MG_EVENT_LOG only
  long remote_ip;        // Client's IP address
  int remote_port;       // Client's port
  int status_code;       // HTTP reply status code, e.g. 200
  int is_ssl;            // 1 if SSL-ed, 0 if not
  int num_headers;       // Number of headers
  int content_len;
  struct mg_header {
    char *name;          // HTTP header name
    char *value;         // HTTP header value
  } http_headers[64];    // Maximum 64 headers
  char* response_headers; // Headers to be sent with HTTP response. Provided by user.
};

// Various events on which user-defined function is called by Mongoose.
enum mg_event {
  MG_NEW_REQUEST,   // New HTTP request has arrived from the client
  MG_HTTP_ERROR,    // HTTP error must be returned to the client
  MG_EVENT_LOG,     // Mongoose logs an event, request_info.log_message
  MG_INIT_SSL,      // Mongoose initializes SSL. Instead of mg_connection *,
                    // SSL context is passed to the callback function.
  MG_REQUEST_COMPLETE  // Mongoose has finished handling the request
};

// Prototype for the user-defined function. Mongoose calls this function
// on every MG_* event.
//
// Parameters:
//   event: which event has been triggered.
//   conn: opaque connection handler. Could be used to read, write data to the
//         client, etc. See functions below that have "mg_connection *" arg.
//   request_info: Information about HTTP request.
//
// Return:
//   If handler returns non-NULL, that means that handler has processed the
//   request by sending appropriate HTTP reply to the client. Mongoose treats
//   the request as served.
//   If handler returns NULL, that means that handler has not processed
//   the request. Handler must not send any data to the client in this case.
//   Mongoose proceeds with request handling as if nothing happened.
typedef void * (*mg_callback_t)(enum mg_event event,
                                struct mg_connection *conn,
                                const struct mg_request_info *request_info);

// Prototype for the user-defined function. Mongoose calls this function
// each time it needs password in order to perform Digest Authentication
// of the received request.
//
// Parameters:
//   user_data:     user-defined pointer passed to mg_start().
//   request_info:  information about HTTP request to be authenticated.
//   username:      the username, password for which is needed.
//   len_password:  size of the buffer pointed by the 'password' parameter.
//   password:      the buffer where user should store the requested password.
//
// Return:
//   2 - escape authorization and handle request
//   1 - perform authorization
//   0 - don't authorize and send 401
typedef int (*mg_password_callback_t)(
                                void *user_data,
                                const struct mg_request_info *request_info,
                                char *username,
                                size_t len_password,
                                char password[]);

// Prototype for the user-defined function. Mongoose calls this function
// each time it receives request body or part of the request body from network.
//
// In order to deduce if whole body was received, accumulate value of 'len_buff'
// parameter and compare it to the value of the Content-Length header
// (request_info->content_len).
// 
// If this callback is provided by user, the body will be not stored into file
// system / socket.
//
// Parameters:
//   user_data:     user-defined pointer passed to mg_start().
//   request_info:  information about HTTP request, body of which is received.
//   len_buff:      number of bytes in the buffer.
//   buff:          buffer where the received part of body or whole body is stored.
//
// Returns:
//   number of successfully stored bytes.
//   Should be equal to len_buff. Otherwise body receiving will be interrupted
//   and error response will be send to the remote peer.
typedef int (*mg_receive_callback_t)(
                                void *user_data,
                                const struct mg_request_info *request_info,
                                size_t len_buff,
                                const char *buff);

// Prototype for the user-defined function. Mongoose calls this function
// each time it sends body while processing the GET request.
//
// This callback is called at least twice per request. The first time - in order
// to get full length of the body to be sent and it's mime type (see
// 'content_length' and 'mime' parameters).
// The second and the rest times - to get part of body to be sent.
// The function is not called anymore when all content_length bytes were send,
// or if error occurred during sending.
// 
// If this callback is provided by user, the files or dynamic generated content
// will be not sent.
//
// Parameters:
//   user_data:     user-defined pointer passed to mg_start().
//   request_info:  information about GET request, body for which is being sent.
//   len_buff:      length of buffer where user has to store body or part of it.
//   buff:          buffer where the body or part of body to be sent is stored.
//                  Can be NULL.
//   content_length:the full length of the body. Can be NULL. 
//   mime:          the type of mime to be used as a value for the Content-Type
//                  header. Can be NULL.
//
// Returns:
//   number of bytes stored into the buffer.
//   If zero or negative, sending will be stopped, connection will be closed.
typedef int (*mg_send_callback_t)(
                                void    *user_data,
                                const struct mg_request_info *request_info,
                                size_t  len_buff,
                                char    *buff,
                                size_t  *content_length,
                                char*   *mime);

// Start web server.
//
// Parameters:
//   callback: user defined event handling function or NULL.
//   options: NULL terminated list of option_name, option_value pairs that
//            specify Mongoose configuration parameters.
//
// Side-effects: on UNIX, ignores SIGCHLD and SIGPIPE signals. If custom
//    processing is required for these, signal handlers must be set up
//    after calling mg_start().
//
//
// Example:
//   const char *options[] = {
//     "document_root", "/var/www",
//     "listening_ports", "80,443s",
//     NULL
//   };
//   struct mg_context *ctx = mg_start(&my_func, NULL, options);
//
// Please refer to http://code.google.com/p/mongoose/wiki/MongooseManual
// for the list of valid option and their possible values.
//
// Return:
//   web server context, or NULL on error.
struct mg_context *mg_start(mg_callback_t callback, void *user_data,
                            const char **options);

// Set of user-defined callbacks that are part of Server configuration.
// For more details see correspondent callback definition.
struct mg_callbacks {
    void                    *user_data;         // Context provided by user. This context will be provided back to user while invoking any of callbacks.
    mg_callback_t           event_callback;     // General events, like NEW_REQUEST, ERROR, REQUEST_COMPLETED etc.
    mg_password_callback_t  password_callback;  // Requests for password needed to complete Digest Authentication
    mg_receive_callback_t   receive_callback;   // Exposes to user received body. Replaces file system !!!
    mg_send_callback_t      send_callback;      // Requests user for body to be sent with HTTP response. Replaces file system !!!
};

// Server configuration.
// Should be provided while calling mg_start_ext().
//
// user_callbacks - various callbacks that may be provided by user.
//           Anyone of them is optional and can be set to null.
//           See struct mg_callbacks for more info.
//
// options - NULL terminated list of option_name, option_value pairs that
//           specify Mongoose configuration parameters.
//           Please refer to http://code.google.com/p/mongoose/wiki/MongooseManual
//           for the list of valid option and their possible values.
//
struct mg_cfg {
    struct mg_callbacks user_callbacks;
    const char **options;
};

// Start web server.
//
// Extends the mg_start in order to enable user to set various callbacks at
// start time.
//
// Parameters:
//   cfg: structure that unites callbacks and server configuration.
//        For more details see struct mg_cfg.
//
// Return:
//   web server context, or NULL on error.
struct mg_context *mg_start_ext(struct mg_cfg* cfg);


// Stop the web server.
//
// Must be called last, when an application wants to stop the web server and
// release all associated resources. This function blocks until all Mongoose
// threads are stopped. Context pointer becomes invalid.
void mg_stop(struct mg_context *);


// Get the value of particular configuration parameter.
// The value returned is read-only. Mongoose does not allow changing
// configuration at run time.
// If given parameter name is not valid, NULL is returned. For valid
// names, return value is guaranteed to be non-NULL. If parameter is not
// set, zero-length string is returned.
const char *mg_get_option(const struct mg_context *ctx, const char *name);


// Return array of strings that represent valid configuration options.
// For each option, a short name, long name, and default value is returned.
// Array is NULL terminated.
const char **mg_get_valid_option_names(void);


// Add, edit or delete the entry in the passwords file.
//
// This function allows an application to manipulate .htpasswd files on the
// fly by adding, deleting and changing user records. This is one of the
// several ways of implementing authentication on the server side. For another,
// cookie-based way please refer to the examples/chat.c in the source tree.
//
// If password is not NULL, entry is added (or modified if already exists).
// If password is NULL, entry is deleted.
//
// Return:
//   1 on success, 0 on error.
int mg_modify_passwords_file(const char *passwords_file_name,
                             const char *domain,
                             const char *user,
                             const char *password);

// Send data to the client.
int mg_write(struct mg_connection *, const void *buf, size_t len);


// Send data to the browser using printf() semantics.
//
// Works exactly like mg_write(), but allows to do message formatting.
// Note that mg_printf() uses internal buffer of size IO_BUF_SIZE
// (8 Kb by default) as temporary message storage for formatting. Do not
// print data that is bigger than that, otherwise it will be truncated.
int mg_printf(struct mg_connection *, const char *fmt, ...)
#ifdef __GNUC__
__attribute__((format(printf, 2, 3)))
#endif
;


// Send contents of the entire file together with HTTP headers.
void mg_send_file(struct mg_connection *conn, const char *path);


// Read data from the remote end, return number of bytes read.
int mg_read(struct mg_connection *, void *buf, size_t len);

// Send HTTP reject on the provided connection.
// The Reason-Phase is set according status_code as defined in RFC2 616 (HTTP).
// body and mime can be NULL, if mime is NULL and body is not NULL,
// 'text/plain' will be used.
// The mime parameter may be followed by multiple parameters, each of which
// represents single header in format of NULL-terminated strings.
// The last parameter should be NULL.
// Returns 1 on success, 0 if local buffer is too small to hold all headers.
// Examples:
//      mg_send_reject(pConn, 500, NULL, NULL, NULL);
//      mg_send_reject(pConn, 405, NULL, NULL, "Allow: GET, PUT, DELETE", NULL);
//      mg_send_reject(pConn, 403, "User is not registered", NULL);
// 
int mg_send_reject(struct mg_connection *conn, int status_code,
                   char* body, char* mime, ...);

// Get the value of particular HTTP header.
//
// This is a helper function. It traverses request_info->http_headers array,
// and if the header is present in the array, returns its value. If it is
// not present, NULL is returned.
const char *mg_get_header(const struct mg_connection *, const char *name);


// Get a value of particular form variable.
//
// Parameters:
//   data: pointer to form-uri-encoded buffer. This could be either POST data,
//         or request_info.query_string.
//   data_len: length of the encoded data.
//   var_name: variable name to decode from the buffer
//   buf: destination buffer for the decoded variable
//   buf_len: length of the destination buffer
//
// Return:
//   On success, length of the decoded variable.
//   On error, -1 (variable not found, or destination buffer is too small).
//
// Destination buffer is guaranteed to be '\0' - terminated. In case of
// failure, dst[0] == '\0'.
int mg_get_var(const char *data, size_t data_len,
               const char *var_name, char *buf, size_t buf_len);

// Fetch value of certain cookie variable into the destination buffer.
//
// Destination buffer is guaranteed to be '\0' - terminated. In case of
// failure, dst[0] == '\0'. Note that RFC allows many occurrences of the same
// parameter. This function returns only first occurrence.
//
// Return:
//   On success, value length.
//   On error, 0 (either "Cookie:" header is not present at all, or the
//   requested parameter is not found, or destination buffer is too small
//   to hold the value).
int mg_get_cookie(const struct mg_connection *,
                  const char *cookie_name, char *buf, size_t buf_len);


// Return Mongoose version.
const char *mg_version(void);


// MD5 hash given strings.
// Buffer 'buf' must be 33 bytes long. Varargs is a NULL terminated list of
// asciiz strings. When function returns, buf will contain human-readable
// MD5 hash. Example:
//   char buf[33];
//   mg_md5(buf, "aa", "bb", NULL);
void mg_md5(char *buf, ...);

// Enables user to store application context that is specific for connection.
// This is in contradiction to the user_data provided to the mg_start function.
// This context is stored into struct mg_request_info structure
// and can be retrieved by user from within callbacks using
// request_info->user_data field.
void mg_conn_set_user_data(struct mg_connection *conn, void* user_data);

// Provides status code to be set into response.
// If not provided, the default value will be used.
// Note if mongoose generates HTTP reject due to some error,
// it will use error specific code, while ignoring this status code.
void mg_conn_set_status_code(struct mg_connection *conn, int status_code);

// Sets headers to be sent into outgoing response.
// This function can be called multiple times. Each invocation adds provided headers.
int mg_conn_add_response_headers(struct mg_connection *conn, char** headers, int nheaders);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // MONGOOSE_HEADER_INCLUDED
