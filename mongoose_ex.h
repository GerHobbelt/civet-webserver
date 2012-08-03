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

#ifndef MONGOOSE_EX_HEADER_INCLUDED
#define MONGOOSE_EX_HEADER_INCLUDED

#include "mongoose.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

struct socket;          // Handle for the socket related to a client / server connection


int64_t mg_get_num_bytes_sent(struct mg_connection *conn);
int64_t mg_get_num_bytes_received(struct mg_connection *conn);

struct socket *mg_get_socket(struct mg_connection *conn);

/*
ntop()/ntoa() replacement with IPv6 + IPv4 support.

remote = 1 will print the remote IP address, while
remote = 0 will print the local IP address

'dst' is also returned as function result; on error, 'dst' will
contain an empty string.
*/
char *mg_sockaddr_to_string(char *dst, size_t dstlen, const struct mg_connection *conn, int remote);

/*
ntoh() replacement for IPv6 + IPv4 support.

remote = 1 will produce the remote port, while
remote = 0 will produce the local port for the given connection (socket)
*/
unsigned short int mg_get_socket_port(const struct mg_connection *conn, int remote);

/*
IPv4 + IPv6 support: produce the individual numbers of the IP address in a usable/portable (host) structure

remote = 1 will print the remote IP address, while
remote = 0 will print the local IP address

Return 0 on success, non-zero on error.
*/
int mg_get_socket_ip_address(struct mg_ip_address *dst, const struct mg_connection *conn, int remote);


// Disable or enable the Nagle algorithm on a socket.
int mg_set_nodelay_mode(struct mg_connection *conn, int on);

// Disable or enable the socket SO_KEEPALIVE option.
int mg_set_socket_keepalive(struct mg_connection *conn, int on);

// Set the read/write/user timeout on a socket.
int mg_set_socket_timeout(struct mg_connection *conn, int seconds);

// set socket to non-blocking mode.
int mg_set_non_blocking_mode(struct mg_connection *conn, int on);

// shutdown (half-close) a socket: how == SHUT_RW / SHUT_RD / SHUT_RDWR
int mg_shutdown(struct mg_connection *conn, int how);

int mg_setsockopt(struct mg_connection *conn, int level, int optname, const void *optval, size_t optlen);
int mg_getsockopt(struct mg_connection *conn, int level, int optname, void *optval, size_t *optlen_ref);

// Same as FD_SET() but also keeps track of the maximum handle value in *max_fd for use with, for example, select()
void mg_FD_SET(struct mg_connection *conn, fd_set *set, int *max_fd);

// Same as FD_ISSET but now for mongoose sockets (struct socket)
int mg_FD_ISSET(struct mg_connection *conn, fd_set *set);

// bitwise OR-able constants for mg_connect_to_host(..., flags):
typedef enum mg_connect_flags_t {
  // nothing special; the default
  MG_CONNECT_BASIC = 0,
  // set up and use a SSL encrypted connection
  MG_CONNECT_USE_SSL = 0x0001,
  // tell Mongoose we're going to connect to a HTTP server; this allows us
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

// set up an outgoing client connection: connect to the given host/port
struct mg_connection *mg_connect_to_host(struct mg_context *ctx, const char *host, int port, mg_connect_flags_t flags);

// identical to mg_connect_to_host(); CTX is obtained from the 'conn' parameter
// so you don't need to call mg_get_context():
struct mg_connection *mg_connect(struct mg_connection *conn, const char *host, int port, mg_connect_flags_t flags);


// The set of mg_connect savvy API aliases:
#define mg_add_tx_header            mg_add_response_header
#define mg_vadd_tx_header           mg_vadd_response_header
#define mg_remove_tx_header         mg_remove_response_header
#define mg_get_tx_header            mg_get_response_header

#define mg_get_rx_header            mg_get_header
#define mg_get_rx_headers           mg_get_headers


// Read & parse an HTTP response, fill in the mg_request_info structure.
//
// Return 0 on success.
int mg_read_http_response(struct mg_connection *conn);


// create a socket pair over local loopback. Used for inter-thread communications.
int mg_socketpair(struct mg_connection *conns[2], struct mg_context *ctx);

void mg_close_connection(struct mg_connection *conn);

// Prepare an kept-alive connection for transmitting another request.
//
// Use with client-side connections such as the ones created using mg_connect() when
// sending multiple requests over this HTTP keep-alive connection.
//
// Return 0 on success.
int mg_cleanup_after_request(struct mg_connection *conn);


void mg_cry4ctx(struct mg_context *ctx, const char *fmt, ...);
void mg_log(struct mg_connection *conn, const char *severity, const char *fmt, ...);
// Print error message to the opened error log stream.
void mg_vlog(struct mg_connection *conn, const char *severity, const char *fmt, va_list args);

int mg_get_lasterror(void);




int mg_start_thread(struct mg_context *ctx, mg_thread_func_t func, void *param);

// Signal master that we're done and exiting
void mg_signal_mgr_this_thread_is_done(struct mg_context *ctx);



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
int mg_match_prefix(const char *pattern, int pattern_len, const char *str);

// Parse the UTC date string and return the decoded timestamp as UNIX time_t value in seconds since epoch 1/1/1970
time_t mg_parse_date_string(const char *datetime);

// Converts the given timestamp to UTC timestamp string compatible with HTTP headers.
void mg_gmt_time_string(char *buf, size_t bufsize, const time_t *tm);

// Return the set of matching HTTP header values in dst[] and the number of discovered entries as a return value.
// The dst[] array will be terminated by a NULL sentinel.
//
// When dst is NULL, the required number of entries (sans sentinel) is returned nevertheless.
//
// Note, hence, that the return value may be larger than the 'dst_buffersize' input value.
int mg_get_headers(const char **dst, int dst_buffersize, const struct mg_connection *ri, const char *name);

/*
Send HTTP error response headers, if we still can. Log the error anyway.

'reason' may be NULL, in which case the default RFC2616 response code text will be used instead.

'fmt' + args is the content sent along as error report (request response).
*/
void mg_send_http_error(struct mg_connection *conn, int status, const char *reason, FORMAT_STRING(const char *fmt), ...)
#ifdef __GNUC__
    __attribute__((format(printf, 4, 5)))
#endif
;
void mg_vsend_http_error(struct mg_connection *conn, int status, const char *reason, const char *fmt, va_list ap);


// Returns a string useful as Connection: header value, depending on the current state of connection
const char *mg_suggest_connection_header(struct mg_connection *conn);

// signal mongoose that the server should close the connection with the client once the current request has been serviced.
void mg_connection_must_close(struct mg_connection *conn);

// Instruct connection to keep going when server is stopped (mg_get_stop_flag() != 0): mode = 1.
// Default for all connections: mode = 0
void mg_set_connection_abort_mode(struct mg_connection *conn, int mode);



#if defined(_WIN32) && !defined(__SYMBIAN32__)
#if !defined(HAVE_PTHREAD)
#pragma message("You are advised to use pthread-Win32 library (with its own pthread.h header) and then set the HAVE_PTHREAD #define. The mongoose pthread-internal replacements have not been tested to the same extend as this external library has.")
#endif
#endif


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // MONGOOSE_HEADER_INCLUDED
