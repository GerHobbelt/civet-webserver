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


struct socket *mg_get_socket(struct mg_connection *conn)
{
    return conn ? &conn->client : NULL;
}

int64_t mg_get_num_bytes_sent(struct mg_connection *conn)
{
    return conn ? conn->num_bytes_sent > 0 ? conn->num_bytes_sent : 0 : 0;
}

int64_t mg_get_num_bytes_received(struct mg_connection *conn)
{
    return conn ? conn->consumed_content : 0;
}

int mg_set_non_blocking_mode(struct mg_connection *conn, int on)
{
    if (conn && conn->client.sock != INVALID_SOCKET)
        return !!set_non_blocking_mode(conn->client.sock, on);
    return -1;
}

int mg_shutdown(struct mg_connection *conn, int how)
{
    if (conn && conn->client.sock != INVALID_SOCKET)
    {
        // make sure to properly terminate a chunked/segmented transfer before we shut down the write side!
        if (how & SHUT_WR)
        {
            mg_flush(conn);
        }
        return shutdown(conn->client.sock, how);
    }
    return -1;
}

int mg_setsockopt(struct mg_connection *conn, int level, int optname, const void *optval, size_t optlen)
{
    if (conn && conn->client.sock != INVALID_SOCKET)
        return setsockopt(conn->client.sock, level, optname, optval, (int)optlen);
    return -1;
}

int mg_getsockopt(struct mg_connection *conn, int level, int optname, void *optval, size_t *optlen_ref)
{
    if (conn && conn->client.sock != INVALID_SOCKET)
    {
        socklen_t optlen = 0;
        int rv = getsockopt(conn->client.sock, level, optname, optval, &optlen);

        *optlen_ref = optlen;
        return rv;
    }
    return -1;
}


// http://www.unixguide.net/network/socketfaq/2.11.shtml
// http://www.techrepublic.com/article/tcpip-options-for-high-performance-data-transmission/1050878
int mg_set_nodelay_mode(struct mg_connection *conn, int on)
{
    if (conn && conn->client.sock != INVALID_SOCKET)
    {
#if !defined(SOL_TCP) && (defined(_WIN32) && !defined(__SYMBIAN32__))
        DWORD v_on = !!on;
        return setsockopt(conn->client.sock, IPPROTO_TCP, TCP_NODELAY, (void *)&v_on, sizeof(v_on));
#elif !defined(SOL_TCP)
        int v_on = !!on;
        return setsockopt(conn->client.sock, IPPROTO_TCP, TCP_NODELAY, (void *)&v_on, sizeof(v_on));
#else
        int v_on = !!on;
        return setsockopt(conn->client.sock, SOL_TCP, TCP_NODELAY, (void *)&v_on, sizeof (v_on));
#endif
    }
    return -1;
}

int mg_set_socket_keepalive(struct mg_connection *conn, int on)
{
    if (conn && conn->client.sock != INVALID_SOCKET)
    {
#if defined(_WIN32) && !defined(__SYMBIAN32__)
        BOOL v_on = !!on;
#else
        int v_on = !!on;
#endif
        return setsockopt(conn->client.sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&v_on, sizeof(v_on));
    }
    return -1;
}

int mg_set_socket_timeout(struct mg_connection *conn, int seconds)
{
    if (conn && conn->client.sock != INVALID_SOCKET)
        return set_timeout(&conn->client, seconds);
    return -1;
}

/*
ntop()/ntoa() replacement with IPv6 + IPv4 support.

remote = 1 will print the remote IP address, while
remote = 0 will print the local IP address

'dst' is also returned as function result; on error, 'dst' will
contain an empty string.
*/
char *mg_sockaddr_to_string(char *dst, size_t dstlen, const struct mg_connection *conn, int remote)
{
    if (!dst) return NULL;
    dst[0] = 0;

    if (conn && conn->client.sock != INVALID_SOCKET)
    {
        char src_addr[SOCKADDR_NTOA_BUFSIZE];

        sockaddr_to_string(src_addr, sizeof(src_addr), (remote ? &conn->client.rsa : &conn->client.lsa));
        // only copy IP address in its entirety or not at all:
        if (dstlen > strlen(src_addr))
        {
            strcpy(dst, src_addr);
        }
    }
    return dst;
}

/*
ntoh() replacement for IPv6 + IPv4 support.

remote = 1 will produce the remote port, while
remote = 0 will produce the local port for the given connection (socket)
*/
unsigned short int mg_get_socket_port(const struct mg_connection *conn, int remote)
{
    if (conn && conn->client.sock != INVALID_SOCKET)
    {
        if (remote)
            return get_socket_port(&conn->client.rsa);
        else
            return get_socket_port(&conn->client.lsa);
    }
    return 0;
}

/*
IPv4 + IPv6 support: produce the individual numbers of the IP address in a usable/portable (host) structure

remote = 1 will print the remote IP address, while
remote = 0 will print the local IP address

Return 0 on success, non-zero on error.
*/
int mg_get_socket_ip_address(struct mg_ip_address *dst, const struct mg_connection *conn, int remote)
{
    if (dst && conn && conn->client.sock != INVALID_SOCKET)
    {
        if (remote)
            get_socket_ip_address(dst, &conn->client.rsa);
        else
            get_socket_ip_address(dst, &conn->client.lsa);
        return 0;
    }
    return -1;
}

void mg_FD_SET(struct mg_connection *conn, fd_set *set, int *max_fd)
{
    if (conn && conn->client.sock != INVALID_SOCKET)
        add_to_set(conn->client.sock, set, max_fd);
}

int mg_FD_ISSET(struct mg_connection *conn, fd_set *set)
{
    if (conn && conn->client.sock != INVALID_SOCKET)
        return FD_ISSET(conn->client.sock, set);
    return 0;
}


int mg_cleanup_after_request(struct mg_connection *conn)
{
    if (conn)
    {
        reset_per_request_attributes(conn);
        if (!conn->buf_size)
        {
            conn->num_bytes_sent = 0; // = -1; would mean we're expecting (HTTP) headers first
            conn->content_len = -1;
        }
        else
        {
            conn->num_bytes_sent = -1; // means we're expecting (HTTP) headers first
            conn->content_len = -1;
        }
        return 0;
    }
    return -1;
}

int mg_write_http_request_head(struct mg_connection *conn, const char *request_method, const char *request_path_and_query, ...) {
  const char *http_version;
  const char *uri;
  const char *q;
  const char *q_str;
  char uribuf[SSI_LINE_BUFSIZ];

  if (!conn || !conn->buf_size)
    return -1;

  assert(conn->buf);
  if (is_empty(request_method))
    request_method = conn->request_info.request_method;
  else
    conn->request_info.request_method = request_method;

  if (is_empty(conn->request_info.http_version))
    conn->request_info.http_version = "1.1";
  http_version = conn->request_info.http_version;

  // construct the request line from the arguments / request_info?
  if (!is_empty(request_path_and_query)) {
    va_list ap;
    int rv;
    char *d;

    va_start(ap, request_path_and_query);
    rv = mg_vsnq0printf(conn, uribuf, sizeof(uribuf), request_path_and_query, ap);
    va_end(ap);

    if (rv <= 0) {
      mg_cry(conn, "%s: failed to produce the request line for format string [%s]", __func__, request_path_and_query);
      return -1;
    }
    // check overflow, i.e. whether we hit the edge in scratch space
    if (rv >= sizeof(uribuf) - 2 || rv > conn->buf_size - 5) {
      mg_cry(conn, "%s: scratch buffer overflow while constructing the request line [%.*s(...)]", __func__, (int)MG_MIN(200, sizeof(uribuf)), uribuf);
      return -1;
    }

    // re-arrange the TX headers buffer so that uri and query part fit in there too
    // so we can persist them beyond this call in a fashion similar to the server-side
    // mongoose code which stores the uri+query in the RX buffer together with
    // the headers there.
    //
    // WARNING: we happen to know EXACTLY how compact_tx_headers() behaves and we're
    //          counting on that knowledge here to both keep the copying to a minimum
    //          and assure that the URI + QUERY strings don't get damaged during the
    //          compaction process there!
    uri = conn->request_info.uri = d = uribuf;
    d += strcspn(d, "?");
    if (*d)
      *d++ = 0;
    q_str = conn->request_info.query_string = d;
    conn->tx_can_compact_hdrstore |= 2;  // always trigger a compact cycle, where uri+q are pulled into the tx buffer space for persistence!
  } else {
    if (is_empty(conn->request_info.uri)) {
      mg_cry(conn, "%s: request URI is nil", __func__);
      return -1;
    }

    uri = conn->request_info.uri;
    q_str = conn->request_info.query_string;
    if (q_str == NULL)
      q_str = "";
  }
  if (!is_empty(q_str))
    q = "?";
  else
    q = "";

  return write_http_head(conn, "%s %s%s%s HTTP/%s\r\n", request_method, uri, q, q_str, http_version);
}

int mg_read_http_response(struct mg_connection *conn) {
  char *buf;
  struct mg_request_info *ri;
  const char *status_code;
  char * chknum;
  int data_len;

  if (!conn || !conn->buf_size)
    return -1;

  assert(conn->content_len == -1);
  ri = &conn->request_info;
  ri->num_headers = 0;

  // when a bit of buffered data is still available, make sure it's in the right spot:
  data_len = conn->rx_buffer_loaded_len - conn->rx_buffer_read_len;
  if (data_len > 0)
  {
    memmove(conn->buf, conn->buf + conn->request_len + conn->rx_buffer_read_len, data_len);
  }
  else
  {
    data_len = 0;
  }

  conn->request_len = read_request(NULL, conn,
                                   conn->buf, conn->buf_size,
                                   &data_len);
  assert(data_len >= conn->request_len);
  ri->seq_no++;
  if (conn->request_len == 0 && data_len == conn->buf_size) {
    mg_cry(conn, "%s: peer sent malformed HTTP headers or HTTP headers take up more than %u buffer bytes: [%.*s]",
                 __func__, (unsigned int)conn->buf_size, MG_MIN(200, data_len), conn->buf);
    return 413;
  }
  if (conn->request_len <= 0) {
    // In case we didn't receive ANY data, we don't mess with the connection any further
    // by trying to send any more data, so we tag the connection as done for that:
    if (data_len == 0) {
      mg_mark_end_of_header_transmission(conn);
    }
    return -2; // Remote end closed the connection or sent malformed response
  }
  conn->rx_chunk_buf_size = conn->buf_size + CHUNK_HEADER_BUFSIZ - conn->request_len;
  conn->rx_buffer_loaded_len = data_len - conn->request_len;
  conn->rx_buffer_read_len = 0;

  // NUL-terminate the request 'cause parse_http_headers() is C-string based
  conn->buf[conn->request_len - 1] = 0;

  buf = conn->buf;

  // RFC says that all initial whitespace should be ignored
  while (*buf != 0 && isspace(* (unsigned char *) buf)) {
    buf++;
  }

  ri->http_version = skip(&buf, " ");
  status_code = skip(&buf, " ");
  ri->status_custom_description = skip(&buf, "\r\n");

  chknum = NULL;
  ri->status_code = (status_code == NULL ? -1 : (int)strtol(status_code, &chknum, 10));
  if (chknum != NULL)
    chknum += strspn(chknum, " ");
  if (!is_empty(chknum))
    return -3; // Cannot parse HTTP response

  if (strncmp(ri->http_version, "HTTP/", 5) == 0) {
    ri->http_version += 5;   // Skip "HTTP/"
    ri->num_headers = parse_http_headers(&buf, ri->http_headers, ARRAY_SIZE(ri->http_headers));
  } else {
    return -4; // Cannot parse HTTP response
  }
  if (strcmp(ri->http_version, "1.0") &&
      strcmp(ri->http_version, "1.1")) {
    // Response seems valid, but HTTP version is strange
    return -5;
  } else {
    // Response is valid, handle the basics.
    const char *cl = get_header(ri->http_headers, ri->num_headers, "Transfer-Encoding");
    assert(conn->content_len == -1);
    if (cl && mg_stristr(cl, "chunked")) {
      assert(conn->content_len == -1);
      mg_set_rx_mode(conn, MG_IOMODE_CHUNKED_DATA);
    } else {
      assert(!conn->rx_is_in_chunked_mode);
      cl = get_header(ri->http_headers, ri->num_headers, "Content-Length");
      chknum = NULL;
      if (cl != NULL)
        conn->content_len = strtoll(cl, &chknum, 10);
      if (chknum != NULL)
        chknum += strspn(chknum, " ");
      if (!is_empty(chknum))
        return -6; // Cannot parse HTTP response

      if (conn->content_len == -1) {
        // this is a bit of a tough case: we may be HTTP/1.0, in which case
        // case we gobble everything, assuming one request per connection,
        // but when we're HTTP/1.1, this MAY be either a request without
        // content OR a chunked transfer request.
        // The heuristic we apply here is to gobble all when we're
        // okay re Connection: keep-alive.
        // The chunked transfer case resolves itself, as long as we make sure
        // to keep content_len == -1 then.
        const char *http_version = ri->http_version;
        const char *header = get_header(ri->http_headers, ri->num_headers, "Connection");

        if (!conn->must_close &&
            !mg_strcasecmp(get_conn_option(conn, ENABLE_KEEP_ALIVE), "yes") &&
            (header == NULL ?
             (http_version && !strcmp(http_version, "1.1")) :
             !mg_strcasecmp(header, "keep-alive"))) {
          conn->content_len = 0;
        }
      }
    }
    conn->last_active_time = conn->birth_time = time(NULL);
    return 0;
  }
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

    mg_vwrite2log(conn, NULL, timestamp, severity ? severity : "debug", fmt, args);
}



int mg_get_lasterror(void)
{
    return ERRNO;
}



void mg_signal_mgr_this_thread_is_done(struct mg_context *ctx)
{
    (void) pthread_mutex_lock(&ctx->mutex);
    ctx->num_threads--;
    (void) pthread_cond_signal(&ctx->cond);
    assert(ctx->num_threads >= 0);
    (void) pthread_mutex_unlock(&ctx->mutex);
}




int mg_match_prefix(const char *pattern, int pattern_len, const char *str)
{
    if (!str || !pattern) return -1;

    return match_prefix(pattern, pattern_len, str);
}

time_t mg_parse_date_string(const char *datetime)
{
    if (!datetime)
        return (time_t)0;

    return parse_date_string(datetime);
}


static void set_header_ptr(const char **dst, int dstsize, int idx, const char *value)
{
    if (dst && idx >= 0 && idx < dstsize)
    {
        dst[idx] = value;
    }
}

int mg_get_headers(const char **dst, int dst_buffersize, const struct mg_connection *conn, const char *name)
{
    int i;
    int cnt = 0;
    const struct mg_request_info *ri = &conn->request_info;

    set_header_ptr(dst, dst_buffersize, 0, NULL);
    for (i = 0; i < ri->num_headers; i++)
    {
        if (!mg_strcasecmp(name, ri->http_headers[i].name))
        {
            set_header_ptr(dst, dst_buffersize, cnt++, ri->http_headers[i].value);
        }
    }
    set_header_ptr(dst, dst_buffersize, cnt, NULL);
    set_header_ptr(dst, dst_buffersize, dst_buffersize - 1, NULL);

    return cnt;
}

void mg_send_http_error(struct mg_connection *conn, int status, const char *reason, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsend_http_error(conn, status, reason, fmt, ap);
    va_end(ap);
}

void mg_vsend_http_error(struct mg_connection *conn, int status, const char *reason, const char *fmt, va_list ap)
{
    vsend_http_error(conn, status, reason, fmt, ap);
}

void mg_gmt_time_string(char *buf, size_t bufsize, const time_t *tm)
{
    gmt_time_string(buf, bufsize, tm);
}

const char *mg_suggest_connection_header(struct mg_connection *conn)
{
    return suggest_connection_header(conn);
}

void mg_connection_must_close(struct mg_connection *conn)
{
    conn->must_close = 1;
}

void mg_set_connection_abort_mode(struct mg_connection *conn, int mode)
{
    conn->abort_when_server_stops = !mode;
}



#include "selectable-socketpair/socketpair.c"

int mg_socketpair(struct mg_connection *conns[2], struct mg_context *ctx)
{
    int rv = -1;
    if (conns)
    {
        int i;
#ifdef WIN32
        SOCKET socks[2];
#else
        int socks[2];
#endif

        conns[0] = (struct mg_connection *)calloc(1, sizeof(*conns[0]));
        conns[1] = (struct mg_connection *)calloc(1, sizeof(*conns[1]));
        if (!conns[0] || !conns[1])
        {
            mg_cry(fc(ctx), "%s: calloc: %s", __func__, mg_strerror(ERRNO));
        }
        else
        {
            rv = dumb_socketpair(socks, 0);
            if (rv)
            {
                mg_cry(fc(ctx), "%s: socketpair: %s", __func__, mg_strerror(ERRNO));
            }
            else
            {
                for (i = 0; i <= 1; i++)
                {
                    struct mg_connection *newconn = conns[i];

                    newconn->last_active_time = newconn->birth_time = time(NULL);
                    newconn->is_client_conn = 2;
                    newconn->ctx = ctx;
                    newconn->client.sock = socks[i];
                    // by default, a client-side connection is assumed to be an arbitrary client,
                    // not necessarily a HTTP client:
                    newconn->num_bytes_sent = 0; // = -1; would mean we're expecting (HTTP) headers first
                    //newconn->consumed_content = 0;
                    newconn->content_len = -1;
                    //newconn->request_len = 0;
                    newconn->client.rsa.u.sin.sin_family = AF_INET;
                    newconn->client.rsa.u.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                    newconn->client.rsa.u.sin.sin_port = 0;
                    newconn->client.rsa.len = sizeof(newconn->client.rsa.u.sin);
                    newconn->client.lsa.len = sizeof(newconn->client.lsa.u);
                    if (0 != getsockname(socks[i], &newconn->client.lsa.u.sa, &newconn->client.lsa.len))
                    {
                        mg_cry(newconn, "%s: getsockname: %s", __func__, mg_strerror(ERRNO));
                        newconn->client.lsa.len = 0;
                        rv = -1;
                    }
                }

                if (rv)
                {
                    closesocket(socks[0]);
                    closesocket(socks[1]);
                }
            }
        }

        if (rv)
        {
            free(conns[0]);
            free(conns[1]);
            conns[0] = conns[1] = NULL;
        }
    }
    return rv;
}
