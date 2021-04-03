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

#include "civetweb.h"

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

int mg_setsockopt(struct mg_connection *conn, int level, int optname, const void *optval, size_t optlen);
int mg_getsockopt(struct mg_connection *conn, int level, int optname, void *optval, size_t *optlen_ref);

// Same as FD_SET() but also keeps track of the maximum handle value in *max_fd for use with, for example, select()
void mg_FD_SET(struct mg_connection *conn, fd_set *set, int *max_fd);

// Same as FD_ISSET but now for mongoose sockets (struct socket)
int mg_FD_ISSET(struct mg_connection *conn, fd_set *set);

// for those occasions where you need to edit the uri, query string or request method.
//
// Input strings may be NULL, but must otherwise have a lifetime equal or longer than the connection.
void mg_set_request_uri(struct mg_connection *conn, const char *uri, const char *query_string);
void mg_set_request_method(struct mg_connection *conn, const char *method);


// create a socket pair over local loopback. Used for inter-thread communications.
int mg_socketpair(struct mg_connection *conns[2], struct mg_context *ctx);


void mg_cry4ctx(struct mg_context *ctx, const char *fmt, ...);
void mg_log(struct mg_connection *conn, const char *severity, const char *fmt, ...);
// Print error message to the opened error log stream.
void mg_vlog(struct mg_connection *conn, const char *severity, const char *fmt, va_list args);

int mg_get_lasterror(void);

const char *mg_set_option(struct mg_context *ctx, const char *name, const char *value);


// Signal master that we're done and exiting
void mg_signal_mgr_this_thread_is_done(struct mg_context *ctx);


// Return the set of matching HTTP header values in dst[] and the number of discovered entries as a return value.
// The dst[] array will be terminated by a NULL sentinel.
//
// When dst is NULL, the required number of entries (sans sentinel) is returned nevertheless.
//
// Note, hence, that the return value may be larger than the 'dst_buffersize' input value.
int mg_get_headers(const char **dst, int dst_buffersize, const struct mg_connection *ri, const char *name);


// Instruct connection to keep going when server is stopped (mg_get_stop_flag() != 0): mode = 1.
// Default for all connections: mode = 0
void mg_set_connection_abort_mode(struct mg_connection *conn, int mode);

// get a fake, but valid, connection reference for use with mg_printf() et al:
struct mg_connection *mg_get_fake_printf_conn(struct mg_context *ctx);


// Describes a string (chunk of memory).
struct mg_mime_vec {
  const char *ptr;		// WARNING: the string need not be terminated by a NUL character!
  size_t len;
};

// Look at the "path" extension and figure what mime type it has.
// Store mime type in the vector.
// Return the default MIME type string when the MIME type is not known.
void mg_get_mime_type(struct mg_context *ctx, const char *path, const char *default_mime_type, struct mg_mime_vec *vec);

// Return TRUE when the given 'vector' (string) matches the given string; return FALSE otherwise.
int mg_vec_matches_string(const struct mg_mime_vec *vec, const char *str);


#if defined(_WIN32) && !defined(__SYMBIAN32__)
#if !defined(HAVE_PTHREAD)
#pragma message("You are advised to use pthread-Win32 library (with its own pthread.h header) and then set the HAVE_PTHREAD #define. The mongoose pthread-internal replacements have not been tested to the same extend as this external library has.")
#endif
#endif


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // MONGOOSE_HEADER_INCLUDED
