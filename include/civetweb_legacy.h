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

#ifndef CIVETWEB_HEADER_INCLUDED
#define CIVETWEB_HEADER_INCLUDED

#include "civetweb_sys_porting.h"

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

// A HTTP header:
//   Name: <value>
struct mg_header {
  char *name;                    // HTTP header name
  char *value;                   // HTTP header value
};


// This structure contains information about the HTTP request.
struct mg_request_info {
  void *req_user_data;             // optional reference to user-defined data that's specific for this request. (The user_data reference passed to mg_start() is available through connection->ctx->user_functions in any user event handler!)
  struct mg_request_info *parent;  // points to the request_info block for the original request when we're currently producing a custom error page; NULL otherwise.
  const char *request_method;      // "GET", "POST", etc
  char *uri;                       // URL-decoded URI
  char *phys_path;                 // the URI transformed to a physical path. NULL when the transformation has not been done yet. NULL again by the time event MG_REQUEST_COMPLETE is fired.
  const char *http_version;        // E.g. "1.0", "1.1"
  char *query_string;              // URL part after '?' (not including '?') or ""
  char *path_info;                 // PATH_INFO part of the URL
  char *remote_user;               // Authenticated user, or NULL if no auth used
  const char *log_message;         // CivetWeb error/warn/... log message, MG_EVENT_LOG only
  const char *log_severity;        // CivetWeb log severity: error, warning, ..., MG_EVENT_LOG only
  const char *log_dstfile;         // CivetWeb preferred log file path, MG_EVENT_LOG only
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
  struct mg_header http_headers[64];  // Maximum 64 request headers
  int num_response_headers;        // Number of response headers
  struct mg_header response_headers[64];  // Headers to be sent with HTTP response. Provided by user.
};

// Various events on which user-defined function is called by CivetWeb.
enum mg_event {
  MG_NEW_REQUEST,           // New HTTP request has arrived from the client
  MG_REQUEST_COMPLETE,      // CivetWeb has finished handling the request
  MG_SSI_INCLUDE_REQUEST,   // Page includes an SSI request (file is specified in request_info::phys_path)
  MG_HTTP_ERROR,            // HTTP error must be returned to the client
  MG_EVENT_LOG,             // CivetWeb logs an event, request_info.log_message
  MG_INIT_SSL,              // CivetWeb initializes SSL. The SSL context is passed
                            // to the callback function as part of a 'faked/empty'
                            // mg_connection struct (no ugly type casting required
                            // any more!)
  MG_INIT0,                 // CivetWeb starts and has just initialized the network
                            // stack and is about to start the civetweb threads.
  MG_INIT_CLIENT_CONN,      // CivetWeb has opened a connection to a client.
                            // This is the first time that the 'conn' parameter is
                            // valid for the given thread: now is the start of
                            // this connection's lifetime.
  MG_EXIT_CLIENT_CONN,      // CivetWeb is going to close the client connection.
                            // Note that you won't receive the EXIT1 event when
                            // a thread crashes; also note that you may receive
                            // this event for a connection for which you haven't
                            // received a 'init' event! The latter happens when
                            // civetweb has its reasons to not serve the client.
                            // This event is also the end of this particular 'conn'
                            // connection's lifetime.
  MG_ENTER_MASTER,          // CivetWeb started the master thread
  MG_EXIT_MASTER,           // The master thread is about to close
  MG_IDLE_MASTER,           // The master thread has been idle for 200ms, i.e.
                            // there's not been any HTTP connections very recently.
  MG_RESTART_MASTER_BEGIN,  // The master thread failed (accept() barfed) and
                            // civetweb is going to re-init the listeners. This
                            // event is fired just before the current listeners
                            // are shut down.
  MG_RESTART_MASTER_END,    // Paired with MG_RESTART_MASTER_BEGIN: invoked once
                            // the listeners have been re-initialized again.
  MG_EXIT_SERVER,
  // MG_*_MASTER fix: issue 345 for the master thread
  // fix: numbers were added to fix the ABI in case civetweb core and callback

  MG_EXIT0                  // CivetWeb terminates and has already terminated its
                            // threads. This one is the counterpart of MG_INIT0, so
                            // to speak.
};

// Prototype for the user-defined function. CivetWeb calls this function
// on every MG_* event.
//
// Parameters:
//   event: which event has been triggered.
//   conn: opaque connection handler. Could be used to read, write data to the
//         client, etc. See functions below that have "mg_connection *" arg.
//
// Return:
//   If handler returns non-NULL, that means that handler has processed the
//   request by sending appropriate HTTP reply to the client. CivetWeb treats
//   the request as served.
//   If handler returns NULL, that means that handler has not processed
//   the request. Handler must not send any data to the client in this case.
//   CivetWeb proceeds with request handling as if nothing happened.
typedef void * (*mg_callback_t)(enum mg_event event,
                                struct mg_connection *conn);

// Prototype for the user-defined function. CivetWeb calls this function
// each time it needs a password in order to perform Digest Authentication
// of the received request.
//
// Parameters:
//   conn:              the connection which processes the HTTP request.
//   username:          the username for which a password is needed.
//   auth_domain:       the authorization domain for which a password is needed (isn't necessarily equal to the 'Host:' request header)
//   uri, nonce, nc, cnonce, qop, response, opaque:
//                      the elements decoded from the 'Authorization:' HTTP header;
//                      MAY be NULL when that header was not present or wasn't of the 'Digest' type.
//   hash:              the buffer where user should store the requested password hash.
//                      The usual way to construct the hash would be to call
//                          mg_md5(hash, username, ":", auth_domain, ":", password, NULL);
//   hash_bufsize:      size of the buffer pointed by the 'hash' parameter.
//
// Return:
//   3 - perform authorization using the default file-based approach
//   2 - bypass authorization and handle request (authorization PASS)
//   1 - perform authorization using the produced hash
//   0 - don't authorize and send 401 (authorization FAIL)
//   anything else - fail the authorization, send a 5xx response code
//
// Notes:
//   You can access the user data through the mg_get_user_data() and mg_get_context()
//   API functions.
typedef int (*mg_password_callback_t)(struct mg_connection *conn,
                                      const char *username,
                                      const char *auth_domain,
                                      const char *uri,
                                      const char *nonce,
                                      const char *nc,
                                      const char *cnonce,
                                      const char *qop,
                                      const char *response,
                                      const char *opaque,
                                      char hash[],
                                      size_t hash_bufsize);

// Prototype for the user-defined function. CivetWeb calls this function
// each time it receives a part of the request body from the network.
//
// In order to deduce if the whole body has been received, accumulate value of 'len_buff'
// parameter and compare it to the value of the Content-Length header
// (request_info->content_len).
//
// If this callback is provided by the user, the body will be not stored into the file
// system / socket.
//
// Parameters:
//   conn:          the connection which processes the HTTP request.
//   len_buff:      number of bytes in the buffer.
//   buff:          buffer where the received part of body or whole body is stored.
//
// Returns:
//   The number of successfully processed bytes.
//   Should be equal to len_buff. Otherwise body receiving will be interrupted
//   and error response will be sent to the remote peer.
typedef int (*mg_write_callback_t)(struct mg_connection *conn,
                                   const char *buf,
                                   size_t bufsize);

// Prototype for the user-defined function. CivetWeb calls this function
// each time it sends part of the content body while processing the GET request.
//
// This callback is called at least twice per request. The first time in order
// to get full length of the body to be sent and it's mime type (see
// 'content_length' and 'mime' parameters).
// The second and subsequent times to obtain another part of the body to be sent.
// The function is not called anymore when all content_length bytes have been sent,
// or if an error occurred during sending.
//
// If this callback is provided by the user, the files or dynamic generated content
// will be not be sent.
//
// Parameters:
//   conn:          the connection which processes the HTTP request.
//   len_buff:      length of buffer where user has to store body or part of it.
//   buff:          buffer where part of the body to be sent is stored.
//                  Will be NULL to signal this is the initial call to obtain
//                  the Content-Length info from the user.
//   content_length:the full length of the body. Can be NULL.
//   mime:          the mime type to be used as a value for the Content-Type
//                  header. Can be NULL.
//
// Returns:
//   The number of bytes stored into the buffer.
//   If zero or negative, sending will be stopped and the connection will be closed.
typedef int (*mg_read_callback_t)(struct mg_connection *conn,
                                  char    *buf,
                                  size_t  bufsize,
                                  size_t  *content_length,
                                  char*   *mime);

// Invoked when a HTTP chunk header is being written.
// The user may choose to either write an entirely custom chunk header, using the
// provided buffer and mg_write(), and return 1, or append any optional HTTP chunk
// extensions as a C string, starting at chunk_extenions, and return 0.
//
// chunk_extensions points into the dstbuf buffer space; hence the space available
// for chunk extensions (plus terminating NUL C string sentinel) equals
//   dstbuf_size - (chunk_extensions - dstbuf)
//
// Return:
// 1   on success when a custom chunk header has been written,
// 0   when the default behaviour should be assumed, where the HTTP chunk header
//     should be written, with or without added chunk extensions,
// < 0 on error.
typedef int (*mg_write_chunk_header_t)(struct mg_connection *conn, int64_t chunk_size, char *dstbuf, size_t dstbuf_size, char *chunk_extensions);

// Invoked when a HTTP chunk header is being read.
// The user may choose to either read an entirely custom chunk header, using the
// provided buffer and mg_read(), and return the header length, or have civetweb read the HTTP
// chunk header, and return 0.
//
// The user MUST call mg_set_rx_chunk_size() before returning when reading a custom
// chunk header.
//
// In order to facilitate reading fully custom chunk headers (e.g. WebSockets),
// this callback is invoked at the start of the chunk read process.
// When the user simply returns 0 then, civetweb will proceed with the default
// behaviour and invoke the process_rx_chunk_header callback once the complete
// HTTP chunk header has been loaded into the buffer.
//
// '*dstbuf_fill' is the number of valid bytes already present in the buffer,
// and should contain the total number of bytes loaded into dstbuf[] when done.
//
// Return:
// > 0 on success when a custom chunk header has been read,
// 0   when the default behaviour should be assumed where the HTTP chunk header
//     should be read, with or without added chunk extensions,
// < 0 on error.
typedef int (*mg_read_chunk_header_t)(struct mg_connection *conn, char *dstbuf, size_t dstbuf_size, int *dstbuf_fill);

// Invoked when a HTTP chunk header has been read and parsed.
//
// Note that any HTTP chunk headers, if present, are NOT available via the mg_get_header() API;
// the user must store them herself when they are presented here via 'chunk_headers'.
// Be aware that chunk_headers points to data in a temporary buffer and thus any chunk_headers[] data
// will be only valid for the duration of this call.
//
// The chunk_extensions buffer is NUL-terminated like a regular C string and may be
// modified by the user; this data is discarded by civetweb after this call.
//
// Return:
// 0   on success,
// < 0 on error.
typedef int (*mg_process_rx_chunk_header_t)(struct mg_connection *conn, int64_t chunk_size, char *chunk_extensions, struct mg_header *chunk_headers, int header_count);


// Prototype for the user-defined option decoder/processing function. CivetWeb
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

// Prototype for the final user-defined option processing function. CivetWeb
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

// Prototype for the user-defined option fetch function. CivetWeb and user code
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

// Prototype for the user-defined SSI command processing function. CivetWeb invokes this function
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
//   = 0: CivetWeb should apply the default SSI handler; the user did not process this command.
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

  mg_password_callback_t      password_callback;  // Requests password required to complete Digest Authentication
  mg_write_callback_t         write_callback;     // Exposes received body data to user. Can act as substitute for file system I/O.
  mg_read_callback_t          read_callback;      // Requests body data from user to be sent with HTTP response. Can act as substitute for file system I/O.

  mg_write_chunk_header_t     write_chunk_header;
  mg_read_chunk_header_t      read_chunk_header;
  mg_process_rx_chunk_header_t  process_rx_chunk_header;
} mg_user_class_t;




// Start web server.
//
// Parameters:
//   user_functions: reference to a set of user defined functions and data,
//                   including an optional user-defined event handling function.
//                   Any of the function references listed in this structure
//                   may be NULL. The 'user_functions' reference itself may be NULL.
//   options:        NULL terminated list of option_name, option_value pairs that
//                   specify CivetWeb configuration parameters.
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
// Please refer to http://code.google.com/p/civetweb/wiki/CivetWebManual
// for the list of valid option and their possible values.
//
// Return:
//   web server context, or NULL on error.
struct mg_context *mg_start(const struct mg_user_class_t *user_functions,
                            const char **options);


// Stop the web server.
//
// Must be called last, when an application wants to stop the web server and
// release all associated resources. This function blocks until all CivetWeb
// threads are stopped. Context pointer becomes invalid.
void mg_stop(struct mg_context *);


// Get the value of particular configuration parameter.
// The value returned is read-only. CivetWeb does not allow changing
// configuration at run time.
// If given parameter name is not valid, NULL is returned. For valid
// names, return value is guaranteed to be non-NULL. If parameter is not
// set, zero-length string is returned.
const char *mg_get_option(struct mg_context *ctx, const char *name);


// Get the value of particular (possibly connection specific) configuration parameter.
// The value returned is read-only. CivetWeb does not allow changing
// configuration for a connection at run time.
// If given parameter name is not valid, NULL is returned. For valid
// names, return value is guaranteed to be non-NULL. If parameter is not
// set, zero-length string is returned.
const char *mg_get_conn_option(struct mg_connection *conn, const char *name);


// Return array of strings that represent all civetweb configuration options.
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


// Return mg_request_info structure associated with the request.
// Always succeeds.
const struct mg_request_info *mg_get_request_info(const struct mg_connection *conn);


// Send data to the client.
// Return:
//  0   when the connection has been closed
//  -1  on error
//  number of bytes written on success
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
// an empty string was written, otherwise the function returns the
// number of bytes in the formatted output, excluding the NUL sentinel.
int mg_printf(struct mg_connection *, PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(2, 3);

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

// Return non-zero when data is pending for reading on this connection.
//
// Note: This is a non-blocking, very low cost operation which should be
//       used together with mg_read() and its descendents (e.g.
//       mg_read_http_response_head()) in client-side connections at least.
//       See also the test/unit_test.c::test_chunked_transfer().
int mg_is_read_data_available(struct mg_connection *conn);


typedef enum mg_iomode_t {
  MG_IOMODE_UNKNOWN = -1,

  // mg_read() will read up to connection::content_len bytes of content data from an civetweb
  // HTTP request connection; mg_read() will read an unlimited (2^63) number of bytes
  // from any other connection (mg_socketpair(), mg_connect())
  // mg_write() will write an unlimited number of bytes to any connection, HTTP or other.
  //
  // NOTE: this has always been the 'standard' behaviour of CivetWeb's mg_read/mg_write.
  MG_IOMODE_STANDARD = 0,

  // mg_read() will read content data bytes until either CivetWeb itself or the user chunk callback
  // reports they encountered the End-Of-File header/zero-length chunk. When this mode is
  // set, mg_read() expects to read at least one 'chunk header', which MAY be the End-Of-File
  // header.
  // mg_write() will keep score about the number of bytes written in the 'current' chunk
  // and generate a 'chunk header' when it runs out. After setting this mode, we start with
  // 'zero bytes left', i.e. the need to write a 'chunk header' immediately. Call
  // mg_set_tx_next_chunk_size() to set a known 'chunk size' or let mg_write() do this automatically
  // for you, in which case mg_write() will generate a 'chunk header' fitting each individual
  // mg_write() invocation. (I.e.: every mg_write() call will be a header+content dump then.)
  //
  // Note: Use this mode for 'chunked' transfer protocols, such as HTTP Transfer-Encoding:chunked
  //       or WebSockets.
  MG_IOMODE_CHUNKED_DATA,

  // mg_read() and mg_write() read and write to the socket without any restriction, nor do they
  // account for the bytes written in this mode. This mode may be returned by the functions
  // mg_get_tx_mode() / mg_get_rx_mode() to inform the user whether civetweb is currently
  // expecting to transmit/receive a chunk header or data, respectively.
  // Used anywhere else, this mode is considered identical to having specified
  // MG_IOMODE_CHUNKED_DATA and acts accordingly.
  //
  // Note: This mode is provided as a convenience detection mechanism when you share code between
  //       different user callbacks and need to know the internal state.
  MG_IOMODE_CHUNKED_HEADER,
} mg_iomode_t;

// Configure the connection's transmit mode.
//
// Use MG_IOMODE_CHUNKED mode for any transmit protocol which needs to transmit data
// in segments which are delineated by special header blobs, e.g. HTTP 'chunked transfer'
// mode or WebSockets.
//
// Note: when setting the mode to MG_IOMODE_CHUNKED, then the 'transmitted chunk count'
//       will be reset to zero(0) and the next mg_write() (or function call using mg_write()
//       under the hood) will also transmit the first chunk header.
void mg_set_tx_mode(struct mg_connection *conn, mg_iomode_t mode);

// Get the configured transmit mode for this connection.
mg_iomode_t mg_get_tx_mode(struct mg_connection *conn);

// Get the chunk number currently being transmitted (starting at zero(0)).
int mg_get_tx_chunk_no(struct mg_connection *conn);

// Get the amount of bytes left in the current chunk slot.
int64_t mg_get_tx_remaining_chunk_size(struct mg_connection *conn);

// Set the amount of bytes for the new chunk slot.
//
// This function will return a negative value on error, 0 when the current chunk slot
// has been completely consumed (mg_get_tx_remaining_chunk_size() --> 0) or +1 when
// the current chunk hasn't been sent completely yet; in the latter case the specified
// chunk_size is stored for future use and you can override this chunk size as long as
// the current chunk hasn't completed yet.
int mg_set_tx_next_chunk_size(struct mg_connection *conn, int64_t chunk_size);

// Configure the connection's receive mode.
//
// Use MG_IOMODE_CHUNKED mode for any receiver protocol which expects data to arrive
// in segments which are delineated by special header blobs, e.g. HTTP 'chunked transfer'
// mode or WebSockets.
//
// Note: when setting the mode to MG_IOMODE_CHUNKED, then the 'received chunk count'
//       will be reset to zero(0) and the next mg_read() (or function call using mg_read()
//       under the hood) is expected to receive and process the first chunk header, before
//       if will receive any further content data.
void mg_set_rx_mode(struct mg_connection *conn, mg_iomode_t mode);

// Get the configured receive mode for this connection.
mg_iomode_t mg_get_rx_mode(struct mg_connection *conn);

// Get the chunk number currently being received (starting at zero(0)).
int mg_get_rx_chunk_no(struct mg_connection *conn);

// Get the amount of bytes left in the current chunk slot.
int64_t mg_get_rx_remaining_chunk_size(struct mg_connection *conn);

// Set the amount of bytes for the new chunk slot.
//
// Note that this function assumes that the current chunk slot is empty.
// This function will return a non-zero value when this assumption is not held and the
// function will otherwise be a no-op, i.e. the new chunk size will NOT have been set.
//
// Note: this function is offered as a means to help implement additional protocols
//       on top of the current HTTP connections (e.g. WebSockets).
int mg_set_rx_chunk_size(struct mg_connection *conn, int64_t chunk_size);


// Flush any lingering content data to the socket.
//
// Return 0 on success.
int mg_flush(struct mg_connection *conn);

// Set up and transmit a chunk header for the given chunk size.
//
// When chunk_size == 0, a SENTINEL chunk header will be transmitted.
//
// Return 0 on success.
//
// Note: a side-effect of this call is that the 'remaining chunk size' will be
//       set to the specified 'chunk_size' and the 'chunk number' will be
//       incremented by one(1).
int mg_write_chunk_header(struct mg_connection *conn, int64_t chunk_size);


// Get the value of particular HTTP header.
//
// This is a helper function. It traverses request_info->http_headers array,
// and if the header is present in the array, returns its value. If it is
// not present, NULL is returned.
const char *mg_get_header(const struct mg_connection *, const char *name);


// Extract a
//   token [LWS] "=" [LWS] [quoted-string]
// token,value pair from the string buffer.
// 0-terminate both token and (optional) value.
// Set pointers to found 0-terminated token and value. value is NULL to identify an
// unspecified value, contrasting with a (quoted) empty value.
// Skip trailing LWS if any, except the last LWS char when it is followed by a
// token char or quote.
// Advance pointer to buffer to that position.
// (This is done so that the caller always receives a valid 'separator' sentinel
//  char value AND has 'buf' point at that separator position on return when the
//  string contains more token/quoted-string data beyond the current parse point.
//  By positioning the returned buffer pointer this way, the 'buf += !!sep;'
//  code as shown below will always work, regardless whether the actual separator
//  is LWS, CR/LF or a non-WS separator.)
//
// '*sentinel' will be set to the original character value of the char pointed at
// by *buf when this routine exits; having this original char value available is
// important because inputs like "a=b,c=d" will NUL the ',' in there out of
// necessity [to 0-terminate the "b" value], while *buf would point at that same
// location [as "," is a non-WS separator], and without having the original char
// value available, this would be indiscernible from having reached the very end
// of the original input string.
// A good way to use the 'sentinel' char value (which is only NUL when the entire
// input string has been processed to the very end by this call) is shown in
// civetweb's parse_auth_header(), or:
//
//   char sep;
//   ...
//   mg_extract_token_qstring_value(&s, &sep, &name, &value, "");
//   // accept ',' and ' ' as separators:
//   if (sep && !strchr(",; ", sep))
//     return -1;
//   // 's + !!sep' is important, because "a=b,c=d" type input will have
//   // NULled that ',' (but stored it in 'sep') and 's' would be
//   // pointing at that (inserted) NUL then, while sep==NUL indicates that
//   // the true end of the original string has been reached, and a
//   // simple 's+1' would have been disastrous then:
//   s += strspn(s + !!sep, ",; ");
//   ...
//
// Return 0 on success, -1 when the buffer string does not start with a valid
// token=[quoted-string] pair cf. RFC2616 sec. 2.2.
//
// Notes: token_ref and/or value_ref MAY be NULL, in which case the pair is parsed and
//        processed nevertheless, just the token and/or value strings won't be available
//        to the caller then.
//
//        buffer MAY start with LWS.
//
//        This function REQUIRES that any quoted-string does NOT contain any
//        'line continuation' in the sense of RFC2616 sec 2.2; any existing
//        line-continuation should already have been transformed to single SP.
//
//        The input buffer 'buf' content will NOT be edited (by inserted NUL chars
//        or unquoting) until at least the token and the '=' separator have
//        been acknowledged. Only when followed by an invalidly quoted value,
//        will 'buf' content be changed when this function returns an error code.
int mg_extract_token_qstring_value(char **buf, char *sentinel, const char **token_ref, const char **value_ref, const char *empty_string);

// Convert the specified string (token or quoted_string cf. RFC2616 sec. 2.2) to its
// unquoted variant, i.e. remove surrounding quotes and unescape \-escaped characters.
//
// The input string is edited in place and may be either a token or quoted-string input.
//
// When 'end_ref' is non-NULL, 'sentinel' must be non-NULL too: in this case,
// *sentinel will contain the original char value at *end_ref, which will be set
// to point to the first character beyond the token/quoted-string.
// Users can use the non-NULL 'end_ref' method to unquote ('parse') parts of a
// string which is a combination of tokens, quoted-strings and other elements.
//
// When 'end_buf' is NULL, trailing LWS and CRLF will be ignored (discarded).
//
// Return 0 on success, -1 on failure, i.e. when the string is not a single token or
// quoted-string, when the quoted-string is not correctly terminated by an ending <"> quote,
// or when the string contains illegal characters cf. RFC2616 sec. 2.2.
//
// Note: 'sentinel' and 'end_ref' will not be set/changed on error.
//
//       The quoted_string input is expected to have its LWS ('line continuation')
//       already converted to SP spaces. Hence, CR or LF are illegal inside the
//       quoted-string, as is any other unescaped control character.
int mg_unquote_header_value(char *str, char *sentinel, char **end_ref);

// Extract a HTTP header token + (optional) value cf. RFC2616 sec. 4.2 and sec. 2.2.
// 0-terminate both token and value. Skip trailing LWS if any.
// Advance pointer to buffer to the next header.
// Set pointers to found 0-terminated token and value. value MAY be an empty string.
// Return 0 on success, -1 when the buffer string is not a legal header cf. sec. RFC2616 4.2.
//
// Notes: line continuation cf. RFC2616 sec. 2.2 is converted to a single SP space as
//        specified in sec. 2.2; caller must decode RFC2047-encoded token values produced
//        by this function.
//
//        token_ref and/or value_ref MAY be NULL, in which case the header is parsed and
//        processed nevertheless, just the token and/or value strings won't be available
//        to the caller then.
//
//        *buf is assumed to be a 0-terminated string containing only HTTP headers, i.e.
//        nothing beyond the 2*CRLF which marks the end of the message-header section
//        cf. RFC2616 sec. 4.1
int mg_extract_raw_http_header(char **buf, char **token_ref, char **value_ref);

// Get a value of particular form variable.
//
// Parameters:
//   data:      pointer to form-uri-encoded buffer. This could be either
//              POST data, or request_info.query_string.
//   data_len:  length of the encoded data.
//   var_name:  variable name to decode from the buffer
//   buf:       destination buffer for the decoded variable
//   buf_len:   length of the destination buffer
//   is_form_url_encoded:
//              !0 if the 'data' buffer is form-url-encoded, 0 otherwise.
//              When the 'data' buffer is form-url-encoded, e.g. in a URI query string, set to !0.
//              (See also: http://stackoverflow.com/questions/1634271/url-encoding-the-space-character-or-20)
//
// Note: form-url-encoded data differs from URI encoding in a way that it
//       uses '+' as character for space, see RFC 1866 section 8.2.1
//       http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
//
// Return:
//   On success, length of the decoded variable.
//   On error:
//      -1 (variable not found, or destination buffer is too small).
//      -2 (destination buffer is NULL or zero length).
//
// Destination buffer is guaranteed to be '\0' - terminated if it is not
// NULL or zero length. In case of failure, dst[0] == '\0'.
int mg_get_var(const char *data, size_t data_len, const char *var_name,
               char *buf, size_t buf_len, int is_form_url_encoded);

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
int mg_add_response_header(struct mg_connection *conn, int force_add, const char *tag, PRINTF_FORMAT_STRING(const char *value_fmt), ...) PRINTF_ARGS(4, 5);

int mg_vadd_response_header(struct mg_connection *conn, int force_add, const char *tag, const char *value_fmt, va_list ap);

// Remove the specified response header, if available.
//
// When multiple entries of the tag are found, all are removed from the set.
//
// Return number of occurrences removed (zero or more) on success, negative value on error.
int mg_remove_response_header(struct mg_connection *conn, const char *tag);

// Get the value of particular HTTP response header, if available.
//
// When multiple entries of the tag are found, only the first occurrence is returned.
//
// If the requested tag is not present, NULL is returned.
const char *mg_get_response_header(const struct mg_connection *conn, const char *tag);

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



// bitwise OR-able constants for mg_connect_to_host(..., flags):
typedef enum mg_connect_flags_t {
  // nothing special; the default
  MG_CONNECT_BASIC = 0,
  // set up and use a SSL encrypted connection
  MG_CONNECT_USE_SSL = 0x0001,
  // tell CivetWeb we're going to connect to a HTTP server; this allows us
  // the usage of the built-in HTTP specific features such as mg_get_header(), etc.
  //
  // Note: as the mg_add_response_header(), mg_get_header(), etc. calls are named
  //       rather inappropriately, as they are geared towards server-side use, a
  //       set of more sensible rx/tx aliases is provided in this header, such as
  //       mg_add_tx_header().
  //
  //       Also note that HTTP I/O connections allocate buffer space from the heap,
  //       so their memory footprint is quite a bit larger than for non-HTTP I/O
  //       sockets.
  MG_CONNECT_HTTP_IO = 0x0002
} mg_connect_flags_t;

// Connect to the remote host / web server: set up an outgoing client connection, connect to the given host/port.
// Return:
//   On success, valid pointer to the new connection
//   On error, NULL
struct mg_connection *mg_connect(struct mg_context *ctx, const char *host, int port, mg_connect_flags_t flags);

// Prepare a kept-alive connection for transmitting another request.
//
// Use with client-side connections such as the ones created using mg_connect() when
// sending multiple requests over this HTTP keep-alive connection.
//
// Return 0 on success.
int mg_cleanup_after_request(struct mg_connection *conn);

// Write the request head (request + headers) to the client connection.
//
// Return number of header bytes sent; return 0 when nothing was done; -1 on error.
int mg_write_http_request_head(struct mg_connection *conn, const char *request_method, const char *request_path_and_query, ...);

// shutdown (half-close) a socket: how == SHUT_RW / SHUT_RD / SHUT_RDWR
int mg_shutdown(struct mg_connection *conn, int how);

// Close the connection opened by mg_connect() or one side of mg_socketpair().
void mg_close_connection(struct mg_connection *conn);

// Read & parse an HTTP response, fill in the mg_request_info structure.
//
// Return 0 on success.
int mg_read_http_response_head(struct mg_connection *conn);


// Download given URL to a given file.
//   url: URL to download
//   path: file name where to save the data
//   conn_ref: (optional, in/out) reference to a connection pointer.
//             1) May be NULL, which means that the connection will be established
//                and closed inside mg_fetch().
//             2) When the referenced connection pointer is NULL, it will be set
//                to point to the created connection, when it was successfully
//                established.
//                The caller is responsible for calling mg_close_connection().
//                When created by mg_fetch(), the connection cannot be reused
//                for a second request (fetch): it is only provided so that the
//                caller may access the still valid request and response info
//                contained in its request_info struct.
//             3) When the connection is non-NULL, then mg_fetch() will assume
//                this is a 'persistent' connection and adjust its behaviour
//                accordingly.
//                Again, the caller is responsible for calling
//                mg_close_connection(), even when an error occurred inside
//                mg_fetch().
//                Before reusing the connection for a subsequent request, the
//                caller must invoke mg_cleanup_after_request().
// Return:
//   On error, NULL
//   On success, opened file stream to the downloaded contents. The stream
//   is positioned to the end of the file. It is the user's responsibility
//   to fclose() the opened file stream.
FILE *mg_fetch(struct mg_context *ctx, const char *url, const char *path,
               struct mg_connection **conn_ref);


// The set of mg_connect savvy API aliases:
#define mg_add_tx_header            mg_add_response_header
#define mg_vadd_tx_header           mg_vadd_response_header
#define mg_remove_tx_header         mg_remove_response_header
#define mg_get_tx_header            mg_get_response_header

#define mg_get_rx_header            mg_get_header
#define mg_get_rx_headers           mg_get_headers



// Convenience function -- create detached thread.
// Return: 0 on success, non-0 on error.
int mg_start_thread(struct mg_context *ctx, mg_thread_func_t func, void *param);


// Return builtin mime type for the given file name.
// For unrecognized extensions, "text/plain" is returned.
const char *mg_get_builtin_mime_type(const char *file_name);


// Return CivetWeb version.
const char *mg_version(void);


// MD5 hash given strings.
// Buffer 'buf' must be 33 bytes long. Varargs is a NULL terminated list of
// ASCIIz strings. When function returns, buf will contain human-readable
// MD5 hash. Example:
//   char buf[33];
//   mg_md5(buf, "aa", "bb", NULL);
void mg_md5(char buf[33], ...);

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

// Find location of case-insensitive needle string in haystack string.
// Return NULL if needle wasn't found.
const char *mg_stristr(const char *haystack, const char *needle);

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
int mg_snprintf(struct mg_connection *conn, char *buf, size_t buflen, PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(4, 5);

// Like vsnprintf(), but never returns negative value, or the value
// that is larger than a supplied buffer.
//
// Identical to mg_vsnprintf() apart from the fact that this one SILENTLY processes buffer overruns:
// The output is simply clipped to the specified buffer size.
int mg_vsnq0printf(struct mg_connection *conn, char *buf, size_t buflen, const char *fmt, va_list ap);

// Is to mg_vsnq0printf() what printf() is to vprintf().
int mg_snq0printf(struct mg_connection *conn, char *buf, size_t buflen, PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(4, 5);

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
int mg_asprintf(struct mg_connection *conn, char **buf_ref, size_t max_buflen, PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(4, 5);

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

// Convert the specified string (buffer) to an absolute path with UNIX '/' slashes for directory separators. Return 0 on success.
int mg_mk_fullpath(char *buf, size_t buf_len);

// For given directory path, append the valid index file.
// Return 1 if the index file exists, 0 if no index file could be located in the given directory.
// If the file is found, it's stats are returned in stp and path has been augmented to point at the index file.
int mg_substitute_index_file(struct mg_connection *conn, char *path, size_t path_len, struct mgstat *stp);

// The info produced by the mg_scan_directory() API for each file/subdirectory:
struct mg_direntry {
  struct mg_connection *conn;
  char *file_name;
  struct mgstat st;
};

// Type definition for the callback invoked by the mg_scan_directory() API for each file/subdirectory entry
typedef void mg_process_direntry_cb(struct mg_direntry *info, void *user_data);

// Scan a directory and call the user-defined callback for each file/subdirectory in there.
int mg_scan_directory(struct mg_connection *conn, const char *dir, void *user_data, mg_process_direntry_cb *cb);


// Print error message to the opened error log stream.
//
// Accepts arbitrarily large input as the function uses mg_vasprintf() internally.
void mg_cry(struct mg_connection *conn, PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(2, 3);

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
void mg_write2log(struct mg_connection *conn, const char *logfile, time_t timestamp, const char *severity, PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(5, 6);

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

// Obtain the civetweb context definition for the given connection.
struct mg_context *mg_get_context(struct mg_connection *conn);

// Get connection-specific user data reference; returns NULL when connection is not valid.
void *mg_get_request_user_data(struct mg_connection *conn);

// Set connection-specific user data reference
void mg_set_request_user_data(struct mg_connection *conn, void *user_data);

// Returns a string useful as Connection: header value, depending on the current state of connection
const char *mg_suggest_connection_header(struct mg_connection *conn);

// signal civetweb that the server should close the connection with the client once the current request has been serviced.
void mg_connection_must_close(struct mg_connection *conn);

// Set the HTTP version to use for this connection from now on.
//
// The default version is "1.1", which will also be used when you invoke this function
// with a NULL or empty 'http_version_str'.
//
// WARNING: 'http_version_str' must point at memory which has a guaranteed lifetime equal
//          or longer than the connection itself; unually this is accomplished by
//          using a string constant, e.g.
//              mg_set_http_version(conn, "1.0");
//          which would also show about the only legal non-1.1 HTTP version for use with this API.
void mg_set_http_version(struct mg_connection *conn, const char *http_version_str);

/*
Send HTTP error response headers, if we still can. Log the error anyway.

'reason' may be NULL, in which case the default RFC2616 response code text will be used instead.

'fmt' + args is the content sent along as error report (request response).
*/
void mg_send_http_error(struct mg_connection *conn, int status, const char *reason, PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(4, 5);

void mg_vsend_http_error(struct mg_connection *conn, int status, const char *reason, const char *fmt, va_list ap);



// Match string against wildcard pattern and return -1 when no match is
// found or the match length in characters when the string (prefix) matches
// the pattern.
//
// Pattern special characters:
//
// $         - matches end of string
// ?         - matches one arbitrary character
// *         - matches zero or more characters except the '/', hence matches
//             'one directory' when used to match paths
// **        - matches the remainder of the string
// |         - a|b matches either pattern a or pattern b
int mg_match_string(const char *pattern, int pattern_len, const char *str);

// Parse the UTC date string and return the decoded timestamp as UNIX time_t value in seconds since epoch 1/1/1970
time_t mg_parse_date_string(const char *datetime);

// Converts the given timestamp to UTC timestamp string compatible with HTTP headers.
void mg_gmt_time_string(char *buf, size_t bufsize, const time_t *tm);




// Return the current 'stop_flag' state value for the given thread context.
//
// When this is non-zero, it means the civetweb server is terminating and all threads it has created
// should be / are already terminating.
int mg_get_stop_flag(struct mg_context *ctx);

// Indicate that the application should shut down (probably due to a fatal failure?)
void mg_signal_stop(struct mg_context *ctx);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CIVETWEB_HEADER_INCLUDED
