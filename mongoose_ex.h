// Copyright (c) 2004-2010 Sergey Lyubka
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

#include <stdio.h>
#include <errno.h>


#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

struct socket;          // Handle for the socket related to a clinet / server connection
struct fd_set;


// Obtain the user-defined data & functions as set up at the start of the thread (i.e. the context)
struct mg_user_class_t *mg_get_user_data(struct mg_context *ctx);

// Obtain the mongoose context definition for the given connection.
struct mg_context *mg_get_context(struct mg_connection *conn);

struct socket *mg_get_client_socket(struct mg_connection *conn);

// Return the current 'stop_flag' state value for the given thread context.
int mg_get_stop_flag(struct mg_context *ctx);

// Indicate that the application should shut down (probably due to a fatal failure?)
void mg_signal_stop(struct mg_context *ctx);


// Disable or enable the Nagle algorithm on a socket.
int mg_set_nodelay_mode(struct socket *sock, int on);

// Same as FD_SET() but also keeps track of the maximum handle value in *max_fd for use with, for example, select()
void mg_FD_SET(struct socket *socket, struct fd_set *set, int *max_fd);

// Same as FD_ISSET but now for mongoose sockets (struct socket)
int mg_FD_ISSET(struct socket *socket, struct fd_set *set);

// set up a outgoing client connection: connect to the given host/port
struct mg_connection *mg_connect_to_host(struct mg_context *ctx, const char *host, int port, int use_ssl);

// Contrary to mg_read() this one is able to fetch an arbitrary number of bytes from the given connection.
int mg_pull(struct mg_connection *conn, void *buf, size_t max_bufsize);

void mg_close_connection(struct mg_connection *conn);



void mg_cry4ctx(struct mg_context *ctx, const char *fmt, ...);
void mg_log(struct mg_connection *conn, const char *severity, const char *fmt, ...);
// Print error message to the opened error log stream.
void mg_vlog(struct mg_connection *conn, const char *severity, const char *fmt, va_list args);

int mg_get_lasterror(void);


void mg_flockfile(FILE *fp);

void mg_funlockfile(FILE *fp);



typedef void * (*mg_thread_func_t)(void *);

int mg_start_thread(struct mg_context *ctx, mg_thread_func_t func, void *param);

// Signal master that we're done and exiting
void mg_signal_mgr_this_thread_is_done(struct mg_context *ctx);



#if defined(_WIN32) && !defined(__SYMBIAN32__)
#if !defined(HAVE_PTHREAD)
#error "You can only use the extended mongoose code when you include the pthread-Win32 pthread.h header as well: it was too much hassle to export the mongoose pthread-internal replacements here."
#endif
#endif


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // MONGOOSE_HEADER_INCLUDED
