// Copyright (c) 2011 Ger Hobbelt
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


// 'Extends' mongoose by exporting additional functions

#include "mongoose_ex.h"

#include "mongoose.c"


struct mg_user_class_t *mg_get_user_data(struct mg_context *ctx)
{
    return &ctx->user_functions;
}


struct mg_context *mg_get_context(struct mg_connection *conn)
{
    return conn->ctx;
}

struct socket *mg_get_client_socket(struct mg_connection *conn)
{
    return &conn->client;
}


// http://www.unixguide.net/network/socketfaq/2.11.shtml
// http://www.techrepublic.com/article/tcpip-options-for-high-performance-data-transmission/1050878
int mg_set_nodelay_mode(struct socket *sock, int on)
{
#if !defined(SOL_TCP) || (defined(_WIN32) && !defined(__SYMBIAN32__))
    DWORD v_on = !!on;
    return setsockopt(sock->sock, IPPROTO_TCP, TCP_NODELAY, (void *)&v_on, sizeof(v_on));
#else
    int v_on = !!on;
    return setsockopt(sock->sock, SOL_TCP, TCP_NODELAY, &v_on, sizeof (v_on));
#endif
}

int mg_set_socket_keepalive(struct socket *sock, int on)
{
    BOOL v_on = !!on;
    return setsockopt(sock->sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&v_on, sizeof(v_on));
}

int mg_set_socket_timeout(struct socket *sock, int seconds)
{
	return set_timeout(sock, seconds);
}


int mg_get_stop_flag(struct mg_context *ctx)
{
    return ctx && ctx->stop_flag;
}

void mg_signal_stop(struct mg_context *ctx)
{
  ctx->stop_flag = 1;
}


void mg_FD_SET(struct socket *socket, struct fd_set *set, int *max_fd)
{
    add_to_set(socket->sock, set, max_fd);
}

int mg_FD_ISSET(struct socket *socket, struct fd_set *set)
{
    return FD_ISSET(socket->sock, set);
}

struct mg_connection *mg_connect_to_host(struct mg_context *ctx, const char *host, int port, int use_ssl)
{
    struct mg_connection fake_conn = {0};
    struct mg_connection *conn;

    fake_conn.ctx = ctx;
    conn = mg_connect(&fake_conn, host, port, use_ssl);
#if 0
    if (conn != NULL)
    {
        conn->ctx = ctx;
        conn->birth_time = time(NULL);
    }
#endif
    return conn;
}

int mg_pull(struct mg_connection *conn, void *buf, size_t max_bufsize)
{
    return pull(NULL, conn->client.sock, conn->ssl, (char *)buf, (int)max_bufsize);
}

void mg_close_connection(struct mg_connection *conn)
{
    close_connection(conn);
}






// now here is a prime candidate for C++ polymorphism...

void mg_cry4ctx(struct mg_context *ctx, const char *fmt, ...)
{
    time_t timestamp = time(NULL);
    va_list ap;

    va_start(ap, fmt);
    mg_vwrite2log(fc(ctx), NULL, timestamp, NULL, fmt, ap);
    va_end(ap);
}

void mg_log(struct mg_connection *conn, const char *severity, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  mg_vlog(conn, severity, fmt, ap);
  va_end(ap);
}

// Print error message to the opened error log stream.
void mg_vlog(struct mg_connection *conn, const char *severity, const char *fmt, va_list args)
{
    time_t timestamp = time(NULL);

	mg_vwrite2log(conn, NULL, timestamp, severity, fmt, args);
}



int mg_get_lasterror(void)
{
    return ERRNO;
}


void mg_flockfile(FILE *fp)
{
    flockfile(fp);
}

void mg_funlockfile(FILE *fp)
{
    funlockfile(fp);
}


int mg_start_thread(struct mg_context *ctx, mg_thread_func_t func, void *param)
{
    int rv = start_thread(ctx, func, param);
    if (rv == 0)
    {
        // count this thread too so the master_thread will wait for this one to end as well when we stop.
        ctx->num_threads++;
    }
    return rv;
}

void mg_signal_mgr_this_thread_is_done(struct mg_context *ctx)
{
    (void) pthread_mutex_lock(&ctx->mutex);
    ctx->num_threads--;
    (void) pthread_cond_signal(&ctx->cond);
    assert(ctx->num_threads >= 0);
    (void) pthread_mutex_unlock(&ctx->mutex);
}
