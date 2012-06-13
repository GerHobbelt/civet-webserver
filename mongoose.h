// Copyright (c) 2004-2012 Sergey Lyubka
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
#define MONGOOSE_HEADER_INCLUDED

#include "mongoose_sys_porting.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

struct mg_context;     // Handle for the HTTP service itself
struct mg_connection;  // Handle for the individual connection
struct socket;         // Handle for the socket related to a client / server connection

// The IP address: IPv4 or IPv6
struct mg_ip_address {
  unsigned is_ip6: 1; // flag: 1: struct contains an IPv6 address, 0: IPv4 address
  union {
    // these are in 'network order', i.e. 127.0.0.1 would give v4[0] == 127 and v[3] == 1
    unsigned short int v4[4];
    unsigned short int v6[8];
  } ip_addr;
};

// This structure contains information about the HTTP request.
struct mg_request_info {
  void *user_data;                 // User-defined pointer passed to mg_start()
  const char *request_method;      // "GET", "POST", etc
  char *uri;                       // URL-decoded URI
  const char *http_version;        // E.g. "1.0", "1.1"
  char *query_string;              // URL part after '?' (not including '?') or NULL
  char *remote_user;               // Authenticated user, or NULL if no auth used
  const char *log_message;         // Mongoose error/warn/... log message, MG_EVENT_LOG only
  struct mg_ip_address remote_ip;  // Client's IP address
  int remote_port;                 // Client's port
  struct mg_ip_address local_ip;   // This machine's IP address which receives/services the request
  int local_port;                  // Server's port
  int status_code;                 // HTTP reply status code, e.g. 200
  int is_ssl;                      // 1 if SSL-ed, 0 if not
  int num_headers;                 // Number of headers
  struct mg_header {
    char *name;                    // HTTP header name
    char *value;                   // HTTP header value
  } http_headers[64];              // Maximum 64 headers
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

// Mark the end of the tranmission of HTTP headers.
//
// Use this before proceeding and writing content data if you want your
// access log to show the correct (actual) number.
void mg_mark_end_of_header_transmission(struct mg_connection *conn);

// Return !0 when the headers have already been sent, 0 if not.
//
// To be more specific, this function will return -1 when all HTTP headers
// have been written (and anything sent now is considered part of the content),
// while a return value of +1 indicates that the HTTP response has been
// written but that you MAY decide to write some more headers to
// augment the HTTP header set being transmitted.
int mg_have_headers_been_sent(const struct mg_connection *conn);

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

// Send data to the browser using vprintf() semantics.
//
// See mg_printf() for the applicable conditions, caveats and return values.
int mg_vprintf(struct mg_connection *, const char *fmt, va_list ap);


// Send contents of the entire file together with HTTP headers.
void mg_send_file(struct mg_connection *conn, const char *path);


// Read data from the remote end, return number of bytes read.
int mg_read(struct mg_connection *, void *buf, size_t len);


/*
Send HTTP error response headers, if we still can. Log the error anyway.

'reason' may be NULL, in which case the default RFC2616 response code text will be used instead.

'fmt' + args is the content sent along as error report (request response).
*/
void mg_send_http_error(struct mg_connection *conn, int status, const char *reason, const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 4, 5)))
#endif
;
void mg_vsend_http_error(struct mg_connection *conn, int status, const char *reason, const char *fmt, va_list ap);



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


// Return the HTTP response code string for the given response code
const char *mg_get_response_code_text(int response_code);


// --- helper functions ---

// Compare two strings to a maximum length of n characters; the comparison is case-insensitive.
// Return the (s1 - s2) last character difference value, which is zero(0) when both strings are equal.
int mg_strncasecmp(const char *s1, const char *s2, size_t len);

// same as strncasecmp() but without any string length limit
int mg_strcasecmp(const char *s1, const char *s2);

// Allocate space for a copy of the given string on the heap.
// The allocated copy will have space for at most 'len' characters (excluding the NUL sentinel).
// The returned pointer is either NULL on failure or pointing at the ('len' length bound) copied string.
char * mg_strndup(const char *str, size_t len);

// Same as strndup() but here the entire input string is copied and the allocated space is large
// enough contain that number of characters.
char * mg_strdup(const char *str);

// Like vsnprintf(), but never returns negative value, or the value
// that is larger than a supplied buffer.
//
// Barfs a hairball when a destination buffer would be undersized (logs a failure message).
//
// Thanks to Adam Zeldis to pointing snprintf()-caused vulnerability
// in his audit report.
int mg_vsnprintf(struct mg_connection *conn, char *buf, size_t buflen, const char *fmt, va_list ap);

// Is to mg_vsnprintf() what printf() is to vprintf().
int mg_snprintf(struct mg_connection *conn, char *buf, size_t buflen, const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 4, 5)))
#endif
;



// Structure used by mg_stat() function. Uses 64 bit file length.
struct mgstat {
    int is_directory;  // Directory marker
    int64_t size;      // File size
    time_t mtime;      // Modification time
};

// return 0 when file/directory exists; fills the mgstat struct with last-modified timestamp and file size.
int mg_stat(const char *path, struct mgstat *stp);

// Like fopen() but supports UTF-8 filenames and accepts the path "-" to mean STDERR (which is handy for logging and such)
FILE *mg_fopen(const char *path, const char *mode);

// Like fclose() but the other of the matching pair with mg_fopen()
int mg_fclose(FILE *fp);


/*
Like strerror() but with included support for the same functionality for
Win32 system error codes
*/
const char *mg_strerror(int errcode);


// Obtain the mongoose context definition for the given connection.
struct mg_context *mg_get_context(struct mg_connection *conn);

struct mg_request_info *mg_get_request_info(struct mg_connection *conn);


// Return the current 'stop_flag' state value for the given thread context.
//
// When this is non-zero, it means the mongoose server is terminating and all threads it has created
// should be / are already terminating.
int mg_get_stop_flag(struct mg_context *ctx);

// Indicate that the application should shut down (probably due to a fatal failure?)
void mg_signal_stop(struct mg_context *ctx);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // MONGOOSE_HEADER_INCLUDED
