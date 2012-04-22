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
#define MONGOOSE_HEADER_INCLUDED

#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>

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
		unsigned short int v4[4];
		unsigned short int v6[8];
	} ip_addr;
};

// This structure contains information about the HTTP request.
struct mg_request_info {
  void *req_user_data;   // optional reference to user-defined data that's specific for this request. (The user_data reference passed to mg_start() is available through connection->ctx->user_functions in any user event handler!)
  char *request_method;  // "GET", "POST", etc
  char *uri;             // URL-decoded URI
  char *phys_path;       // the URI transformed to a physical path. NULL when the transformation has not been done yet. NULL again by the time event MG_REQUEST_COMPLETE is fired.
  char *http_version;    // E.g. "1.0", "1.1"
  char *query_string;    // URL part after '?' (not including '?') or NULL
  char *remote_user;     // Authenticated user, or NULL if no auth used
  const char *log_message;     // Mongoose error/warn/... log message, MG_EVENT_LOG only
  const char *log_severity; // Mongoose log severity: error, warning, ..., MG_EVENT_LOG only
  const char *log_dstfile; // Mongoose preferred log file path, MG_EVENT_LOG only
  time_t log_timestamp;  // log timestamp (UTC), MG_EVENT_LOG only
  struct mg_ip_address remote_ip;        // Client's IP address
  int remote_port;       // Client's port
  struct mg_ip_address local_ip;        // This machine's IP address which receives/services the request
  int local_port;       // Server's port
  int status_code;       // HTTP reply status code, e.g. 200
  int is_ssl;            // 1 if SSL-ed, 0 if not
  int num_headers;       // Number of headers
  struct mg_header {
    char *name;          // HTTP header name
    char *value;         // HTTP header value
  } http_headers[64];    // Maximum 64 headers
};

// Various events on which user-defined function is called by Mongoose.
enum mg_event {
  MG_NEW_REQUEST,   // New HTTP request has arrived from the client
  MG_REQUEST_COMPLETE,  // Mongoose has finished handling the request
  MG_HTTP_ERROR,    // HTTP error must be returned to the client
  MG_EVENT_LOG,     // Mongoose logs an event, request_info.log_message
  MG_INIT_SSL,      // Mongoose initializes SSL. The SSL context is passed 
                    // to the callback function as part of a 'faked/empty' 
					// mg_connection struct (no ugly type casting required 
					// any more!)
  MG_INIT0,         // Mongoose starts and has just initialized the network
                    // stack and is about to start the mongoose threads.
  MG_INIT_CLIENT_CONN,  // Mongoose has opened a connection to a client.
                    // This is the first time that the 'conn' parameter is
					// valid for the given thread: now is the start of 
					// this connection's lifetime.
  MG_EXIT_CLIENT_CONN,  // Mongoose is going to close the client connection.
                    // Note that you won't receive the EXIT1 event when 
					// a thread crashes; also note that you may receive
					// this event for a connection for which you haven't
					// received a 'init' event! The latter happens when 
					// mongoose has its reasons to not serve the client.
					// This event is also the end of this particular 'conn'
					// connection's lifetime.
  MG_EXIT0          // Mongoose terminates and has already terminated its 
                    // threads. This one is the counterpart of MG_INIT0, so 
					// to speak.
};

// Prototype for the user-defined function. Mongoose calls this function
// on every MG_* event.
//
// Parameters:
//   event: which event has been triggered.
//   conn: opaque connection handler. Could be used to read, write data to the
//         client, etc. See functions below that have "mg_connection *" arg.
//
// Return:
//   If handler returns non-NULL, that means that handler has processed the
//   request by sending appropriate HTTP reply to the client. Mongoose treats
//   the request as served.
//   If handler returns NULL, that means that handler has not processed
//   the request. Handler must not send any data to the client in this case.
//   Mongoose proceeds with request handling as if nothing happened.
typedef void * (*mg_callback_t)(enum mg_event event,
                                struct mg_connection *conn);


// Prototype for the user-defined option decoder/processing function. Mongoose
// calls this function for every unidentified option.
//
// Parameters:
//   ctx: the server context.
//   name: (string) the option identifier.
//   value: (string, may be NULL) the option value.
//
// Return:
//   If handler returns a non-zero value, that means that handler has processed the
//   option / value pair; the option has been processed.
//   If handler returns zero, that means that the handler has not processed
//   the option.
typedef int (*mg_option_decode_callback_t)(struct mg_context *ctx, const char *name, const char *value);

// Prototype for the final user-defined option processing function. Mongoose
// calls this function once after all options have been processed: this callback
// is usually used to set the default values for any user options which have not
// been configured yet.
//
// Parameters:
//   ctx: the server context.
//
// Return:
//   If handler returns zero, that means that the handler has detected a terminal error.
typedef int (*mg_option_fill_callback_t)(struct mg_context *ctx);

// Prototype for the user-defined option fetch function. Mongoose and user code
// call this function through mg_get_option() to obtain the (string) value of the given option.
//
// Parameters:
//   ctx: the server context.
//   name: (string) the option identifier.
//
// Return:
//   If handler returns the non-NULL option value string.
//   If handler returns zero, that means that the handler has not processed
//   the option.
typedef const char * (*mg_option_get_callback_t)(const struct mg_context *ctx, const char *name);

// The user-initialized structure carrying the various user defined callback methods
// and any optional associated user data.
typedef struct mg_user_class_t {
  mg_callback_t user_callback;  // User-defined callback function
  void *user_data;              // Arbitrary user-defined data

  mg_option_decode_callback_t user_option_decode;  // User-defined option decode/processing callback function
  mg_option_fill_callback_t user_option_fill;      // User-defined option callback function which fills any non-configured options with sensible defaults
  mg_option_get_callback_t user_option_get;        // User-defined callback function which delivers the value for the given option
} mg_user_class_t;




// Start web server.
//
// Parameters:
//   user_functions: reference to a set of user defined functions and data,
//                   including an optional user-defined event handling function.
//                   Any of the function references listed in this structure
//                   may be NULL. The 'user_functions' reference itself may be NULL.
//   options:        NULL terminated list of option_name, option_value pairs that
//                   specify Mongoose configuration parameters.
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
//   struct mg_user_class_t ufs = { &my_func, NULL };
//   struct mg_context *ctx = mg_start(&ufs, options);
//
// Please refer to http://code.google.com/p/mongoose/wiki/MongooseManual
// for the list of valid option and their possible values.
//
// Return:
//   web server context, or NULL on error.
struct mg_context *mg_start(const struct mg_user_class_t *user_functions,
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


// Return array of strings that represent all mongoose configuration options.
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

// Send data to the browser using vprintf() semantics.
int mg_vprintf(struct mg_connection *, const char *fmt, va_list ap);


// Send contents of the entire file together with HTTP headers.
void mg_send_file(struct mg_connection *conn, const char *path);


// Read data from the remote end, return number of bytes read.
int mg_read(struct mg_connection *, void *buf, size_t len);


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
//   On error, -1 (either "Cookie:" header is not present at all, or the
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
// The allocated copy will have space for at most 'len' characters (exclusing the NUL sentinel).
// The returned pointer is either NULL on failure or pointing at the ('len' length bound) copied string.
char * mg_strndup(const char *str, size_t len);

// Same as strndup() but here the entire input string is copied and the allocated space is large
// enough contain that number of characters.
char * mg_strdup(const char *str);

// Like vsnprintf(), but never returns negative value, or the value
// that is larger than a supplied buffer.
// Barfs a hairball when a destination buffer would occur (logs a failure message).
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

// Writes suitably sized string buffer in *buf_ref and returns output length. 
// When max_buflen is set to zero, an arbitrary large buffer may be allocated; 
// otherwise the output buffer size will be limited to max_buflen: when the
// output would overflow the buffer in that case, the string " (...)\n" is
// appended at the very end for easier use in logging and other reporting
// activity. (The latter bit is what makes it different from some systems'
// asprintf().)
// Note that the buffer must be free()d when you're done with it.
int mg_asprintf(struct mg_connection *conn, char **buf_ref, size_t max_buflen, const char *fmt, ...) 
#ifdef __GNUC__
	__attribute__((format(printf, 4, 5)))
#endif
;

int mg_vasprintf(struct mg_connection *conn, char **buf_ref, size_t max_buflen, const char *fmt, va_list ap);


// Like fopen() but supports UTF-8 filenames and accepts the path "-" to mean STDERR (which is handy for logging and such)
FILE *mg_fopen(const char *path, const char *mode);

// Print error message to the opened error log stream.
void mg_cry(struct mg_connection *conn, const char *fmt, ...)
#ifdef __GNUC__
	__attribute__((format(printf, 2, 3)))
#endif
;
// Print error message to the opened error log stream.
void mg_vcry(struct mg_connection *conn, const char *fmt, va_list args);
// Print formatted error message to the opened error log stream.
void mg_cry_raw(struct mg_connection *conn, const char *msg);

// Convert a given filepath template to a file path.
//
// replace %[P] with client port number
//         %[C] with client IP (sanitized for filesystem paths)
//         %[p] with server port number
//         %[s] with server IP (sanitized for filesystem paths)
//         %[U] with the request URI path section (sanitized for filesystem paths)
//         %[Q] with the request URI query section (sanitized for filesystem paths)
//
//         Any other % parameter is processed by strftime(3).
const char *mg_get_logfile_path(char *dst, size_t dst_maxsize, const char *logfile_template, struct mg_connection *conn, time_t timestamp);

// Obtain a reference to the logfile designated to this connection (logfile CAN be connection specific but do NOT HAVE TO be).
const char *mg_get_default_logfile_path(struct mg_connection *conn);

// Write arbitrary formatted string to the specified logfile.
int mg_write2log_raw(struct mg_connection *conn, const char *logfile, time_t timestamp, const char *severity, const char *msg);

// Print log message to the opened error log stream.
void mg_write2log(struct mg_connection *conn, const char *logfile, time_t timestamp, const char *severity, const char *fmt, ...)
#ifdef __GNUC__
	__attribute__((format(printf, 5, 6)))
#endif
;
// Print log message to the opened error log stream.
void mg_vwrite2log(struct mg_connection *conn, const char *logfile, time_t timestamp, const char *severity, const char *fmt, va_list args);

/*
Like strerror() but with included support for the same functionality for
Win32 system error codes
*/
const char *mg_strerror(int errcode);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // MONGOOSE_HEADER_INCLUDED
