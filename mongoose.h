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
  void *req_user_data;             // optional reference to user-defined data that's specific for this request. (The user_data reference passed to mg_start() is available through connection->ctx->user_functions in any user event handler!)
  struct mg_request_info *parent;  // points to the request_info block for the original request when we're currently producing a custom error page; NULL otherwise.
  const char *request_method;      // "GET", "POST", etc
  char *uri;                       // URL-decoded URI
  char *phys_path;                 // the URI transformed to a physical path. NULL when the transformation has not been done yet. NULL again by the time event MG_REQUEST_COMPLETE is fired.
  const char *http_version;        // E.g. "1.0", "1.1"
  char *query_string;              // URL part after '?' (not including '?') or NULL
  char *path_info;                 // PATH_INFO part of the URL
  char *remote_user;               // Authenticated user, or NULL if no auth used
  const char *log_message;         // Mongoose error/warn/... log message, MG_EVENT_LOG only
  const char *log_severity;        // Mongoose log severity: error, warning, ..., MG_EVENT_LOG only
  const char *log_dstfile;         // Mongoose preferred log file path, MG_EVENT_LOG only
  time_t log_timestamp;            // log timestamp (UTC), MG_EVENT_LOG only
  struct mg_ip_address remote_ip;  // Client's IP address
  int remote_port;                 // Client's port
  struct mg_ip_address local_ip;   // This machine's IP address which receives/services the request
  int local_port;                  // Server's port
  int status_code;                 // HTTP reply status code, e.g. 200
  char *status_custom_description; // complete info for the given status_code, basic and optional extended part separated by TAB; valid for event MG_HTTP_ERROR
  int is_ssl;                      // 1 if SSL-ed, 0 if not
  int seq_no;                      // number of request served for this connection (1..N; can only be >1 for kept-alive connections)
  int num_headers;                 // Number of headers
  struct mg_header {
    char *name;                    // HTTP header name
    char *value;                   // HTTP header value
  } http_headers[64];              // Maximum 64 request headers
  int num_response_headers;        // Number of response headers
  struct mg_header response_headers[64];  // Headers to be sent with HTTP response. Provided by user.
};

// Various events on which user-defined function is called by Mongoose.
enum mg_event {
  MG_NEW_REQUEST,           // New HTTP request has arrived from the client
  MG_REQUEST_COMPLETE,      // Mongoose has finished handling the request
  MG_SSI_INCLUDE_REQUEST,   // Page includes an SSI request (file is specified in request_info::phys_path)
  MG_HTTP_ERROR,            // HTTP error must be returned to the client
  MG_EVENT_LOG,             // Mongoose logs an event, request_info.log_message
  MG_INIT_SSL,              // Mongoose initializes SSL. The SSL context is passed
                            // to the callback function as part of a 'faked/empty'
                            // mg_connection struct (no ugly type casting required
                            // any more!)
  MG_INIT0,                 // Mongoose starts and has just initialized the network
                            // stack and is about to start the mongoose threads.
  MG_INIT_CLIENT_CONN,      // Mongoose has opened a connection to a client.
                            // This is the first time that the 'conn' parameter is
                            // valid for the given thread: now is the start of
                            // this connection's lifetime.
  MG_EXIT_CLIENT_CONN,      // Mongoose is going to close the client connection.
                            // Note that you won't receive the EXIT1 event when
                            // a thread crashes; also note that you may receive
                            // this event for a connection for which you haven't
                            // received a 'init' event! The latter happens when
                            // mongoose has its reasons to not serve the client.
                            // This event is also the end of this particular 'conn'
                            // connection's lifetime.
  MG_ENTER_MASTER,          // Mongoose started the master thread
  MG_EXIT_MASTER,           // The master thread is about to close
  MG_IDLE_MASTER,           // The master thread has been idle for 200ms, i.e.
                            // there's not been any HTTP connections very recently.
  MG_RESTART_MASTER_BEGIN,  // The master thread failed (accept() barfed) and
                            // mongoose is going to re-init the listeners. This
                            // event is fired just before the current listeners
                            // are shut down.
  MG_RESTART_MASTER_END,    // Paired with MG_RESTART_MASTER_BEGIN: invoked once
                            // the listeners have been re-initialized again.
  MG_EXIT_SERVER,
  // MG_*_MASTER fix: issue 345 for the master thread
  // fix: numbers were added to fix the ABI in case mongoose core and callback

  MG_EXIT0                  // Mongoose terminates and has already terminated its
                            // threads. This one is the counterpart of MG_INIT0, so
                            // to speak.
};

typedef void * (WINCDECL *mg_thread_func_t)(void *);

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
// calls this function for every unidentified (global) option.
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
// calls this function once after all (global) options have been processed: this callback
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
//   conn: the current connection, NULL if not available.
//   name: (string) the option identifier.
//
// Return:
//   If handler returns the non-NULL option value string, that value is used.
//   If handler returns zero, that means that the handler has not processed
//   the option (and possibly a default value is used instead).
typedef const char * (*mg_option_get_callback_t)(struct mg_context *ctx, struct mg_connection *conn, const char *name);

// Prototype for the user-defined SSI command processing function. Mongoose invokes this function
// when a SSI tag is found in a SSI include file. This function offers the user first pick in
// how to process the SSI tag.
//
// Parameters:
//   conn: the current connection.
//   ssi_sommandline: the NUL-terminated string inside the SSI tag. e.g. "echo var=help"
//   ssi_filepath: the path of the current SSI file.
//   include_level: the SSI include depth (1..N)
//
// Return:
//   = 0: Mongoose should apply the default SSI handler; the user did not process this command.
//   > 0: The callback processed the tag (any output has been written to the connection).
//   < 0: The callback reported an error. SSI processing will be aborted immediately.
typedef int (*mg_ssi_command_callback_t)(struct mg_connection *conn, const char *ssi_commandline, const char *ssi_filepath, int include_level);

// The user-initialized structure carrying the various user defined callback methods
// and any optional associated user data.
typedef struct mg_user_class_t {
  void *                      user_data;          // Arbitrary user-defined data

  mg_callback_t               user_callback;      // User-defined event handling callback function

  mg_option_decode_callback_t user_option_decode; // User-defined option decode/processing callback function
  mg_option_fill_callback_t   user_option_fill;   // User-defined option callback function which fills any non-configured options with sensible defaults
  mg_option_get_callback_t    user_option_get;    // User-defined callback function which delivers the value for the given option

  mg_ssi_command_callback_t   user_ssi_command;   // User-defined SSI command callback function
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
const char *mg_get_option(struct mg_context *ctx, const char *name);


// Get the value of particular (possibly connection specific) configuration parameter.
// The value returned is read-only. Mongoose does not allow changing
// configuration for a connection at run time.
// If given parameter name is not valid, NULL is returned. For valid
// names, return value is guaranteed to be non-NULL. If parameter is not
// set, zero-length string is returned.
const char *mg_get_conn_option(struct mg_connection *conn, const char *name);


// Return array of strings that represent all mongoose configuration options.
// For each option, a short name, long name, and default value is returned
// (i.e. a total of MG_ENTRIES_PER_CONFIG_OPTION elements per entry).
//
// Array is NULL terminated.
const char **mg_get_valid_option_names(void);

// Return the long name of a given option 'name' (where 'name' can itself be
// either the short or long name).
// Use this API to convert option names for various sources to the single
// long name format: one name fits all.
//
// See for example main.c for one possible use: there this call is used to
// make sure that command line options, config file entries and hardcoded
// defaults don't inadvertently produce duplicate option entries in the
// options[] list.
const char *mg_get_option_long_name(const char *name);

#define MG_ENTRIES_PER_CONFIG_OPTION 3


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
//
// Return the number of bytes written; 0 when the connection has been closed.
// Return -1 on error.
int mg_write(struct mg_connection *, const void *buf, size_t len);

// Write the HTTP response code and the set of response headers which
// have been collected using the mg_add_response_header() and
// mg_remove_response_header() APIs.
//
// Note that this call implies the entire header section of the response
// will now have been sent, i.e. mg_mark_end_of_header_transmission() is
// called implicitly.
//
// When 'status_code' <= 0, then the default (stored in the
// connection::request_info) will be used.
//
// When 'status_text' is NULL or an empty string, then the default
// will be used (which is the string produced by mg_get_response_code_text()
// for the (default or explicit) status_code.
//
// Returns the number of bytes written to the socket. 0 when the
// connection was closed already or when the HTTP response header has
// already been sent before.
// Returns -1 on error.
//
// Note: adds/adjusts the 'Connection' header with a lean towards 'Connection: close',
//       meaning: when you already set the 'Connection' header to 'close',
//       then nothing will be changed; however, when the 'Connection' header
//       has not been set or has been set to a value other than 'close', than the
//       transmitted Status Code will help determine the 'Connection' header
//       value.
//       A 'Connection' header will be sent along in any case.
int mg_write_http_response_head(struct mg_connection *conn, int status_code, const char *status_text);

// Mark the end of the transmission of HTTP headers.
//
// Use this before proceeding and writing content data if you want your
// access log to show the correct (actual) number.
void mg_mark_end_of_header_transmission(struct mg_connection *conn);

// Return !0 when the headers have already been sent, 0 if not.
//
// To be more specific, this function will return -1 when all HTTP headers
// have been written (and anything sent now is considered part of the content),
// while a return value of +1 indicates that the HTTP response has been
// (partially) written but that you MAY decide to write some more headers to
// augment the HTTP header set being transmitted.
int mg_have_headers_been_sent(const struct mg_connection *conn);

// Send data to the browser using printf() semantics.
//
// Works exactly like mg_write(), but allows to do message formatting.
//
// Note that mg_printf() uses an internal buffer which is allocated
// on the heap; the buffer is sized to fit the formatted output, so
// arbitrary lengths of text are accepted, but very large texts will
// incur an additional O(N * logK(N)) overhead as mg_printf() needs
// to estimate the size of the output. This extra cost is not in effect
// when built with MSVC, as that environment offers the _vscprintf() API.
//
// mg_printf() is guaranteed to return 0 when an error occurs or when
// and empty string was written, otherwise the function returns the
// number of bytes in the formatted output, excluding the NUL sentinel.
int mg_printf(struct mg_connection *, FORMAT_STRING(const char *fmt), ...)
#ifdef __GNUC__
    __attribute__((format(printf, 2, 3)))
#endif
;

// Send data to the browser using vprintf() semantics.
//
// See mg_printf() for the applicable conditions, caveats and return values.
int mg_vprintf(struct mg_connection *, const char *fmt, va_list ap);


// Send contents of the entire file together with HTTP headers.
//
// Return 0 on success, negative number of I/O failed, positive non-zero when file does not exist (404)
int mg_send_file(struct mg_connection *conn, const char *path);


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

// Set HTTP response code -- iff no response code for the current request
// has already been set.
// Hence use this function to 'set & hold' response codes.
//
// Returns the HTTP response code.
int mg_set_response_code(struct mg_connection *conn, int status);

// Adds/Overrides header to be sent in outgoing HTTP response.
//
// The default behaviour (force_add == 0) is to 'upsert', i.e. either insert the tag+value when
// it has not been added before, or replace the existing value for the given tag.
// When replacing, it will always replace the first occurrence of the tag in the existing
// set.
// When force_add != 0, then the tag+value will always be added to the header set. This is handy for
// cookie tags, for example.
//
// The value_fmt parameter is equivalent to a printf(fmt, ...) 'fmt' argument: the value stored
// with the tag is constructed from this format string and any optional extra parameters a la sprintf().
//
// Return zero on success, non-zero otherwise.
int mg_add_response_header(struct mg_connection *conn, int force_add, const char *tag, FORMAT_STRING(const char *value_fmt), ...)
#ifdef __GNUC__
    __attribute__((format(printf, 4, 5)))
#endif
;

// Remove the specified response header, if available.
//
// When multiple entries of the tag are found, all are removed from the set.
//
// Return number of occurrences removed (zero or more) on success, negative value on error.
int mg_remove_response_header(struct mg_connection *conn, const char *tag);

// Handle custom error pages, i.e. nested page requests.
// request_info struct will contain info about the original
// request; the uri argument points at the subrequest itself.
//
// Error page requests are _always_ treated as GET requests.
//
// One substitution parameter is supported in the 'uri'
// argument: '$E' will be replaced by the numeric status
// code (HTTP response code), so you may feed us URIs
// like '/error_page.php?status=$E'.
//
// This function will only produce the indicated uri page
// when nothing has been sent to the connection yet - otherwise
// we would be writing a HTTP response, headers and content into
// a stream which is in an unknown state sending other material
// already.
//
// Return zero on success, non-zero on failure.
int mg_produce_nested_page(struct mg_connection *conn, const char *uri, size_t uri_len);

// Return non-zero when we are currently inside the nested page handler
// (mg_produce_nested_page()), so that we can adjust our behaviour.
int mg_is_producing_nested_page(struct mg_connection *conn);

// Return Mongoose version.
const char *mg_version(void);


// MD5 hash given strings.
// Buffer 'buf' must be 33 bytes long. Varargs is a NULL terminated list of
// ASCIIz strings. When function returns, buf will contain human-readable
// MD5 hash. Example:
//   char buf[33];
//   mg_md5(buf, "aa", "bb", NULL);
void mg_md5(char *buf, ...);

// Return the HTTP response code string for the given response code
const char *mg_get_response_code_text(int response_code);


// --- helper functions ---

// a la strncpy() but doesn't copy past the source's NUL sentinel AND ensures that a NUL sentinel
// is always written in 'dst'.
// Returns the length of the 'dst' string.
size_t mg_strlcpy(register char *dst, register const char *src, size_t dstsize);

// Return the string length, limited by 'maxlen'. Does not scan beyond 'maxlen' characters in 'src'.
size_t mg_strnlen(const char *src, size_t maxlen);

// Compare two strings to a maximum length of n characters; the comparison is case-insensitive.
// Return the (s1 - s2) last character difference value, which is zero(0) when both strings are equal.
int mg_strncasecmp(const char *s1, const char *s2, size_t len);

// same as strncasecmp() but without any string length limit
int mg_strcasecmp(const char *s1, const char *s2);

// find needle in haystack. Useful as a simile of strnstr() and equivalent of memmem(), which
// aren't available on most platforms.
const char *mg_memfind(const char *haystack, size_t haysize, const char *needle, size_t needlesize);

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
int mg_snprintf(struct mg_connection *conn, char *buf, size_t buflen, FORMAT_STRING(const char *fmt), ...)
#ifdef __GNUC__
    __attribute__((format(printf, 4, 5)))
#endif
;

// Like vsnprintf(), but never returns negative value, or the value
// that is larger than a supplied buffer.
//
// Identical to mg_vsnprintf() apart from the fact that this one SILENTLY processes buffer overruns:
// The output is simply clipped to the specified buffer size.
int mg_vsnq0printf(struct mg_connection *conn, char *buf, size_t buflen, const char *fmt, va_list ap);

// Is to mg_vsnq0printf() what printf() is to vprintf().
int mg_snq0printf(struct mg_connection *conn, char *buf, size_t buflen, FORMAT_STRING(const char *fmt), ...)
#ifdef __GNUC__
    __attribute__((format(printf, 4, 5)))
#endif
    ;

// Writes suitably sized, heap allocated, string buffer in *buf_ref and returns
// output length (excluding NUL sentinel).
//
// When max_buflen is set to zero, an arbitrary large buffer may be allocated;
// otherwise the output buffer size will be limited to max_buflen: when the
// output would overflow the buffer in that case, the string " (...)\n" is
// appended at the very end for easier use in logging and other reporting
// activity. (The latter bit is what makes it different from some systems'
// asprintf().)
//
// The caller is responsible for calling free() on the returned buffer pointer.
//
// The variable referenced by buf_ref is guaranteed to be set to NULL or a valid value
// as returned by malloc/realloc(3).
int mg_asprintf(struct mg_connection *conn, char **buf_ref, size_t max_buflen, FORMAT_STRING(const char *fmt), ...)
#ifdef __GNUC__
    __attribute__((format(printf, 4, 5)))
#endif
;

// Similar to mg_asprintf().
int mg_vasprintf(struct mg_connection *conn, char **buf_ref, size_t max_buflen, const char *fmt, va_list ap);


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


// Print error message to the opened error log stream.
//
// Accepts arbitrarily large input as the function uses mg_vasprintf() internally.
void mg_cry(struct mg_connection *conn, FORMAT_STRING(const char *fmt), ...)
#ifdef __GNUC__
    __attribute__((format(printf, 2, 3)))
#endif
;
// Print error message to the opened error log stream.
//
// Accepts arbitrarily large input as the function uses mg_vasprintf() internally.
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

// Obtain a reference to the error logfile designated to this connection (logfile CAN be connection specific but do NOT HAVE TO be).
const char *mg_get_default_error_logfile_path(struct mg_connection *conn);

// Obtain a reference to the access logfile designated to this connection (logfile CAN be connection specific but do NOT HAVE TO be).
const char *mg_get_default_access_logfile_path(struct mg_connection *conn);

// Write arbitrary formatted string to the specified logfile.
int mg_write2log_raw(struct mg_connection *conn, const char *logfile, time_t timestamp, const char *severity, const char *msg);

// Print log message to the opened error log stream.
//
// Accepts arbitrarily large input as the function uses mg_vasprintf() internally.
void mg_write2log(struct mg_connection *conn, const char *logfile, time_t timestamp, const char *severity, FORMAT_STRING(const char *fmt), ...)
#ifdef __GNUC__
    __attribute__((format(printf, 5, 6)))
#endif
;
// Print log message to the opened error log stream.
//
// Accepts arbitrarily large input as the function uses mg_vasprintf() internally.
void mg_vwrite2log(struct mg_connection *conn, const char *logfile, time_t timestamp, const char *severity, const char *fmt, va_list args);

/*
Like strerror() but with included support for the same functionality for
Win32 system error codes.
*/
const char *mg_strerror(int errcode);


// Obtain the user-defined data & functions as set up at the start of the thread (i.e. the context)
struct mg_user_class_t *mg_get_user_data(struct mg_context *ctx);

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
