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


#define INSIDE_MONGOOSE_C   1
#include "mongoose.h"



#define MONGOOSE_VERSION                "3.3"
#define PASSWORDS_FILE_NAME             ".htpasswd"
#define CGI_ENVIRONMENT_SIZE            MG_MAX(MG_BUF_LEN, 4096)
#define MAX_CGI_ENVIR_VARS              64
#define MAX_REQUEST_SIZE                16384       // Must be larger than 128 (heuristic lower bound)


/* buffer size used when copying data to/from file/socket/... */
#define DATA_COPY_BUFSIZ                MG_MAX(MG_BUF_LEN, 4096)
/* buffer size used to load all HTTP headers into: if the client sends more header data than this, we'll barf a hairball! */
#define HTTP_HEADERS_BUFSIZ             MG_MAX(MG_BUF_LEN, 16384)
/* buffer size used to extract/decode an SSI command line / file path; hence must be equal or larger than PATH_MAX, at least */
#define SSI_LINE_BUFSIZ                 MG_MAX(MG_BUF_LEN, PATH_MAX)
/* buffer size used to extract/decode/store a HTTP/1.1 'chunked transfer' header */
#define CHUNK_HEADER_BUFSIZ             MG_MAX(MG_BUF_LEN, 80)
/* buffer size for domain names, users and password hashes */
#define USRDMNPWD_BUFSIZ                512


// The maximum amount of data we're willing to dump in a single mg_cry() log call.
// In embedded environments with limited RAM, you may want to override this
// value as this value determines the malloc() size used inside mg_vasprintf().
#ifndef MG_MAX_LOG_LINE_SIZE
#define MG_MAX_LOG_LINE_SIZE    1024 * 1024
#endif

// The number of msecs to wait inside select() when there's nothing to do.
#ifndef MG_SELECT_TIMEOUT_MSECS
#define MG_SELECT_TIMEOUT_MSECS       200
#endif
// The number of msecs to wait inside select() or cond_wait() when the
// connection queue is filled and there might be something to do elsewhere
// while we wait for 'this bunch'
#ifndef MG_SELECT_TIMEOUT_MSECS_TINY
#define MG_SELECT_TIMEOUT_MSECS_TINY    1
#endif

// The maximum length of a %[U] or %[U] component in a logfile path template.
// Should be at larger than 8 to make any sense.
#ifndef MG_LOGFILE_MAX_URI_COMPONENT_LEN
#define MG_LOGFILE_MAX_URI_COMPONENT_LEN    64
#endif

#if MG_DEBUG_TRACING
// 'data' exports don't work well for dynamic libs: use accessor function
unsigned int *mg_trace_level(void) {
  static unsigned int trace_level = ~0u;

  return &trace_level;
}
#endif

#if defined(_WIN32)

int mgW32_get_errno(void) {
  DWORD e1 = GetLastError();
  DWORD e2 = WSAGetLastError();
  int e3 = errno;

  return (e2 ? (int)e2 : e1 ? (int)e1 : e3);
}

static struct {
  volatile int active;
  CRITICAL_SECTION lock;
} global_log_file_lock = {0};

void mgW32_flockfile(UNUSED_PARAMETER(FILE *unused)) {
  if (global_log_file_lock.active)
    EnterCriticalSection(&global_log_file_lock.lock);
}

void mgW32_funlockfile(UNUSED_PARAMETER(FILE *unused)) {
  if (global_log_file_lock.active)
    LeaveCriticalSection(&global_log_file_lock.lock);
}


#if !defined(WSAID_DISCONNECTEX)
typedef BOOL (PASCAL * LPFN_DISCONNECTEX) (SOCKET s, LPOVERLAPPED lpOverlapped, DWORD dwFlags, DWORD dwReserved);
#define WSAID_DISCONNECTEX     {0x7fda2e11,0x8630,0x436f,{0xa0, 0x31, 0xf5, 0x36, 0xa6, 0xee, 0xc1, 0x57}}
#endif

#ifndef SIO_GET_EXTENSION_FUNCTION_POINTER
#define SIO_GET_EXTENSION_FUNCTION_POINTER  (0x80000000|0x40000000|0x08000000|6)
#endif

static LPFN_DISCONNECTEX DisconnectExPtr = 0;
static CRITICAL_SECTION DisconnectExPtrCS;

static BOOL PASCAL dummy_disconnectEx(SOCKET sock, LPOVERLAPPED lpOverlapped, DWORD dwFlags, DWORD dwReserved) {
  return 0;
}

static LPFN_DISCONNECTEX get_DisconnectEx_funcptr(SOCKET sock) {
  /*
    Note  The function pointer for the DisconnectEx function must be obtained
          at run time by making a call to the WSAIoctl function with the
          SIO_GET_EXTENSION_FUNCTION_POINTER opcode specified. The input buffer
          passed to the WSAIoctl function must contain WSAID_DISCONNECTEX, a
          globally unique identifier (GUID) whose value identifies the
          DisconnectEx extension function.
          On success, the output returned by the WSAIoctl function contains
          a pointer to the DisconnectEx function. The WSAID_DISCONNECTEX GUID
          is defined in the Mswsock.h header file.
  */
  LPFN_DISCONNECTEX ret;

  EnterCriticalSection(&DisconnectExPtrCS);

  if (!DisconnectExPtr && sock) {
    GUID dcex = WSAID_DISCONNECTEX;
    DisconnectExPtr = 0;
    DWORD len = 0;
    int rv;

    rv = WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &dcex, sizeof(dcex),
                  &DisconnectExPtr, sizeof(DisconnectExPtr),
                  &len, 0, 0);
    if (rv) {
      DisconnectExPtr = dummy_disconnectEx;
    }
  }
  if (DisconnectExPtr)
    ret = DisconnectExPtr;
  else
    ret = dummy_disconnectEx;

  LeaveCriticalSection(&DisconnectExPtrCS);

  return ret;
}

static BOOL __DisconnectEx(SOCKET sock, LPOVERLAPPED lpOverlapped, DWORD dwFlags, DWORD dwReserved) {
  LPFN_DISCONNECTEX fp = get_DisconnectEx_funcptr(sock);

  return (*fp)(sock, lpOverlapped, dwFlags, dwReserved);
}

#else // _WIN32

static int __DisconnectEx(SOCKET sock, void *lpOverlapped, int dwFlags, int dwReserved) {
  return 0;
}

#endif // _WIN32


#if defined(_MSC_VER)

// Fix buf in MSVC2010 malloc.h header: _malloca is not properly redefined when crtdbg is enabled in debug mode:
#if defined(_ALLOCA_S_MARKER_SIZE) && defined(_ALLOCA_S_MARKER_SIZE)
// fix:
#if defined(_DEBUG)
#if defined(_CRTDBG_MAP_ALLOC)
#undef _malloca
#define _malloca(size) \
__pragma(warning(suppress: 6255)) \
        _MarkAllocaS(malloc((size) + _ALLOCA_S_MARKER_SIZE), _ALLOCA_S_HEAP_MARKER)
#endif
#endif
// end of fix
#endif

// these MUST be macros, NOT functions:
#define mg_malloca(size)  _malloca(size)
#define mg_freea(ptr)   _freea(ptr)

#elif defined(alloca) || defined(HAVE_ALLOCA)

// these MUST be macros, NOT functions:
#define mg_malloca(size)  alloca(size)
#define mg_freea(ptr)   // no-op

#else

void *mg_malloca(size_t size) {
  return malloc(size);
}
void mg_freea(void *ptr) {
  if (ptr)
    free(ptr);
}

#endif


#if !defined(NO_SSL)

// Snatched from OpenSSL includes. I put the prototypes here to be independent
// from the OpenSSL source installation. Having this, mongoose + SSL can be
// built on any system with binary SSL libraries installed.
typedef struct ssl_st SSL;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_ctx_st SSL_CTX;

#define SSL_ERROR_NONE              0
#define SSL_ERROR_SSL               1
#define SSL_ERROR_WANT_READ         2
#define SSL_ERROR_WANT_WRITE        3
#define SSL_ERROR_WANT_X509_LOOKUP  4
#define SSL_ERROR_SYSCALL           5
#define SSL_ERROR_ZERO_RETURN       6
#define SSL_ERROR_WANT_CONNECT      7
#define SSL_ERROR_WANT_ACCEPT       8

#define SSL_FILETYPE_PEM            1
#define CRYPTO_LOCK                 1

#if defined(NO_SSL_DL)
extern void SSL_free(SSL *);
extern int SSL_accept(SSL *);
extern int SSL_connect(SSL *);
extern int SSL_shutdown(SSL *);
extern int SSL_read(SSL *, void *, int);
extern int SSL_write(SSL *, const void *, int);
extern int SSL_peek(SSL *ssl,void *buf,int num);
extern int SSL_get_error(const SSL *, int);
extern int SSL_set_fd(SSL *, int);
extern SSL *SSL_new(SSL_CTX *);
extern SSL_CTX *SSL_CTX_new(SSL_METHOD *);
extern SSL_METHOD *SSLv23_server_method(void);
extern SSL_METHOD *SSLv23_client_method(void);
extern int SSL_library_init(void);
extern void SSL_load_error_strings(void);
extern int SSL_CTX_use_PrivateKey_file(SSL_CTX *, const char *, int);
extern int SSL_CTX_use_certificate_file(SSL_CTX *, const char *, int);
extern int SSL_CTX_use_certificate_chain_file(SSL_CTX *, const char *);
extern void SSL_CTX_set_default_passwd_cb(SSL_CTX *, mg_callback_t);
extern void SSL_CTX_free(SSL_CTX *);
extern unsigned long ERR_get_error(void);
extern char *ERR_error_string(unsigned long, char *);
extern int CRYPTO_num_locks(void);
extern void CRYPTO_set_locking_callback(void (*)(int, int, const char *, int));
extern void CRYPTO_set_id_callback(unsigned long (*)(void));
#else
// Dynamically loaded SSL functionality
struct ssl_func {
  const char *name;   // SSL function name
  void  (*ptr)(void); // Function pointer
};

#define SSL_free (* (void (*)(SSL *)) ssl_sw[0].ptr)
#define SSL_accept (* (int (*)(SSL *)) ssl_sw[1].ptr)
#define SSL_connect (* (int (*)(SSL *)) ssl_sw[2].ptr)
#define SSL_shutdown (* (int (*)(SSL *)) ssl_sw[3].ptr)
#define SSL_read (* (int (*)(SSL *, void *, int)) ssl_sw[4].ptr)
#define SSL_write (* (int (*)(SSL *, const void *,int)) ssl_sw[5].ptr)
#define SSL_peek (* (int (*)(SSL *, void *, int)) ssl_sw[6].ptr)
#define SSL_get_error (* (int (*)(SSL *, int)) ssl_sw[7].ptr)
#define SSL_set_fd (* (int (*)(SSL *, SOCKET)) ssl_sw[8].ptr)
#define SSL_new (* (SSL * (*)(SSL_CTX *)) ssl_sw[9].ptr)
#define SSL_CTX_new (* (SSL_CTX * (*)(SSL_METHOD *)) ssl_sw[10].ptr)
#define SSLv23_server_method (* (SSL_METHOD * (*)(void)) ssl_sw[11].ptr)
#define SSL_library_init (* (int (*)(void)) ssl_sw[12].ptr)
#define SSL_CTX_use_PrivateKey_file (* (int (*)(SSL_CTX *, \
        const char *, int)) ssl_sw[13].ptr)
#define SSL_CTX_use_certificate_file (* (int (*)(SSL_CTX *, \
        const char *, int)) ssl_sw[14].ptr)
#define SSL_CTX_set_default_passwd_cb \
  (* (void (*)(SSL_CTX *, mg_callback_t)) ssl_sw[15].ptr)
#define SSL_CTX_free (* (void (*)(SSL_CTX *)) ssl_sw[16].ptr)
#define SSL_load_error_strings (* (void (*)(void)) ssl_sw[17].ptr)
#define SSL_CTX_use_certificate_chain_file \
  (* (int (*)(SSL_CTX *, const char *)) ssl_sw[18].ptr)
#define SSLv23_client_method (* (SSL_METHOD * (*)(void)) ssl_sw[19].ptr)

#define CRYPTO_num_locks (* (int (*)(void)) crypto_sw[0].ptr)
#define CRYPTO_set_locking_callback \
  (* (void (*)(void (*)(int, int, const char *, int))) crypto_sw[1].ptr)
#define CRYPTO_set_id_callback \
  (* (void (*)(unsigned long (*)(void))) crypto_sw[2].ptr)
#define ERR_get_error (* (unsigned long (*)(void)) crypto_sw[3].ptr)
#define ERR_error_string (* (char * (*)(unsigned long,char *)) crypto_sw[4].ptr)

// set_ssl_option() function updates this array.
// It loads SSL library dynamically and changes NULLs to the actual addresses
// of respective functions. The macros above (like SSL_connect()) are really
// just calling these functions indirectly via the pointer.
static struct ssl_func ssl_sw[] = {
  {"SSL_free",                              NULL},
  {"SSL_accept",                            NULL},
  {"SSL_connect",                           NULL},
  {"SSL_shutdown",                          NULL},
  {"SSL_read",                              NULL},
  {"SSL_write",                             NULL},
  {"SSL_peek",                              NULL},
  {"SSL_get_error",                         NULL},
  {"SSL_set_fd",                            NULL},
  {"SSL_new",                               NULL},
  {"SSL_CTX_new",                           NULL},
  {"SSLv23_server_method",                  NULL},
  {"SSL_library_init",                      NULL},
  {"SSL_CTX_use_PrivateKey_file",           NULL},
  {"SSL_CTX_use_certificate_file",          NULL},
  {"SSL_CTX_set_default_passwd_cb",         NULL},
  {"SSL_CTX_free",                          NULL},
  {"SSL_load_error_strings",                NULL},
  {"SSL_CTX_use_certificate_chain_file",    NULL},
  {"SSLv23_client_method",                  NULL},
  {NULL,                                    NULL}
};

// Similar array as ssl_sw. These functions could be located in different lib.
static struct ssl_func crypto_sw[] = {
  {"CRYPTO_num_locks",                      NULL},
  {"CRYPTO_set_locking_callback",           NULL},
  {"CRYPTO_set_id_callback",                NULL},
  {"ERR_get_error",                         NULL},
  {"ERR_error_string",                      NULL},
  {NULL,                                    NULL}
};
#endif // NO_SSL_DL
#else // NO_SSL

typedef struct bogus_ssl_st SSL;
typedef struct bogus_ssl_ctx_st SSL_CTX;

#define SSL_free(ssl)           (void)0
#define SSL_shutdown(ssl)       0
#define SSL_read(ssl, p, l)     (-1)
#define SSL_write(ssl, p, l)    (-1)
#define SSL_peek(ssl, p, l)     (-1)
#define SSL_CTX_free(ctx)       (void)0

#endif // NO_SSL

static const char *month_names[] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

// Unified socket address. For IPv6 support, add IPv6 address structure
// in the union u.
struct usa {
  socklen_t len;
  union {
    struct sockaddr sa;
    struct sockaddr_in sin;
#if defined(USE_IPV6)
    struct sockaddr_in6 sin6;
#endif
  } u;
};

// Describes a string (chunk of memory).
struct vec {
  const char *ptr;
  size_t len;
};

// Describes listening socket, or socket which was accept()-ed by the master
// thread and queued for future handling by the worker thread.
struct socket {
  struct socket *next;            // Linkage
  SOCKET sock;                    // Listening socket
  struct usa lsa;                 // Local socket address
  struct usa rsa;                 // Remote socket address
  int max_idle_seconds;           // 'keep alive' timeout (used while monitoring the idle queue, used together with the recv()-oriented SO_RCVTIMEO, etc. socket options), 0 is infinity.
  unsigned is_ssl: 1;             // Is socket SSL-ed
  unsigned read_error: 1;         // Receive error occurred on this socket (recv())
  unsigned write_error: 1;        // Write error occurred on this socket (send())
  unsigned has_read_data: 1;      // 1 when active ~ when read data is available. This is used to 'signal' a node when a idle-test select() turns up multiple active nodes at once. (speedup)
  unsigned was_idle: 1;           // 1 when a socket has been pulled from the 'idle queue' just now: '1' means 'has_read_data' is valid (and can be used instead of select()).
  unsigned idle_time_expired: 1;  // 1 when the idle time (max_idle_seconds) has expired
};

// A 'pushed back' idle (HTTP keep-alive) socket connection: as we
// round-robin through the set of these while testing for activity,
// we use a cyclic linked list.
//
// This structure is used to persist all per-connection values beyond
// the single request.
struct mg_idle_connection {
  // persisted mg_request_info bits:
  void *req_user_data;              // optional reference to user-defined data that's specific for this request. (The user_data reference passed to mg_start() is available through connection->ctx->user_functions in any user event handler!)
  struct mg_ip_address remote_ip;   // Client's IP address
  struct mg_ip_address local_ip;    // This machine's IP address which receives/services the request
  int remote_port;                  // Client's port
  int local_port;                   // Server's port
  int seq_no;                       // number of requests served for this connection (1..N; can only be >1 for kept-alive connections)

  // persisted mg_connection bits:
  SSL *ssl;                         // SSL descriptor
  struct socket client;             // Connected client
  time_t birth_time;                // Time when connection was accepted
  time_t last_active_time;          // Time when connection was last active
  unsigned is_inited: 1;

  // book-keeping:
  int next;                         // next in chain; cyclic linked list!
  int prev;                         // previous in chain; cyclic linked list!
};


typedef enum {
  CGI_EXTENSIONS,
  ALLOWED_METHODS,
  CGI_ENVIRONMENT, PUT_DELETE_PASSWORDS_FILE, CGI_INTERPRETER,
  PROTECT_URI, AUTHENTICATION_DOMAIN, SSI_EXTENSIONS,
  SSI_MARKER, ERROR_FILE,
  ACCESS_LOG_FILE, ENABLE_DIRECTORY_LISTING, ERROR_LOG_FILE,
  GLOBAL_PASSWORDS_FILE, INDEX_FILES, ENABLE_KEEP_ALIVE,
  KEEP_ALIVE_TIMEOUT, SOCKET_LINGER_TIMEOUT,
  ACCESS_CONTROL_LIST,
  EXTRA_MIME_TYPES, LISTENING_PORTS, IGNORE_OCCUPIED_PORTS, DOCUMENT_ROOT, SSL_CERTIFICATE,
  NUM_THREADS, RUN_AS_USER, REWRITE, HIDE_FILES,
  NUM_OPTIONS
} mg_option_index_t;

static const char *config_options[(NUM_OPTIONS + 1/* sentinel*/) * MG_ENTRIES_PER_CONFIG_OPTION] = {
  "C", "cgi_pattern",                   "**.cgi$|**.pl$|**.php$",
  "D", "allowed_methods",               NULL,
  "E", "cgi_environment",               NULL,
  "G", "put_delete_passwords_file",     NULL,
  "I", "cgi_interpreter",               NULL,
  "P", "protect_uri",                   NULL,
  "R", "authentication_domain",         "mydomain.com",
  "S", "ssi_pattern",                   "**.shtml$|**.shtm$",
  "",  "ssi_marker",                    NULL,
  "Z", "error_file",                    "404=/error/404.shtml,0=/error/error.shtml",
  "a", "access_log_file",               NULL,
  "d", "enable_directory_listing",      "yes",
  "e", "error_log_file",                NULL,
  "g", "global_passwords_file",         NULL,
  "i", "index_files",                   "index.html,index.htm,index.cgi,index.shtml,index.php",
  "k", "enable_keep_alive",             "yes",
  "K", "keep_alive_timeout",            "5",
  "L", "socket_linger_timeout",         "5",
  "l", "access_control_list",           NULL,
  "m", "extra_mime_types",              NULL,
  "p", "listening_ports",               "8080",
  "",  "ignore_occupied_ports",         "no",
  "r", "document_root",                 ".",
  "s", "ssl_certificate",               NULL,
  "t", "num_threads",                   "10",
  "u", "run_as_user",                   NULL,
  "w", "url_rewrite_patterns",          NULL,
  "x", "hide_files_patterns",           NULL,
  NULL, NULL, NULL
};

struct mg_context {
  volatile int stop_flag;               // Should we stop event loop
  SSL_CTX *ssl_ctx;                     // SSL context
  SSL_CTX *client_ssl_ctx;              // Client SSL context
  char *config[NUM_OPTIONS];            // Mongoose configuration parameters
  struct mg_user_class_t user_functions; // user-defined callbacks and data

  struct socket *listening_sockets;

  volatile int num_threads;             // Number of threads
  pthread_mutex_t mutex;                // Protects (max|num)_threads
  pthread_cond_t  cond;                 // Condvar for tracking workers terminations

  struct mg_idle_connection queue_store[128]; // Cut down on malloc()/free()ing cost by using a static queue.
  volatile int sq_head;                 // Index to first node of cyclic linked list of 'pushed back' sockets which expect to serve more requests but are currently inactive. '-1' ~ empty!
  int idle_q_store_free_slot;           // index into the idle_queue_store[] where scanning for a free slot should start. Single linked list on '.next'.

  pthread_cond_t sq_full;               // Signaled when socket is produced
  pthread_cond_t sq_empty;              // Signaled when socket is consumed
};

struct mg_connection {
  unsigned must_close: 1;               // 1 if connection must be closed
  unsigned is_inited: 1;                // 1 when the connection been completely set up (SSL, local and remote peer info, ...)
  unsigned is_client_conn: 2;           // 0 when the connection is a server-side connection (responding to requests); 1: client connection (sending requests); 2: peer-to-peer connection (non-HTTP)
  unsigned abort_when_server_stops: 1;  // 1 when the connection should be dropped/fail when the server is being stopped (ctx->stop_flag)
  unsigned tx_is_in_chunked_mode: 1;    // 1 when transmission through the connection must be chunked (segmented)
  unsigned rx_is_in_chunked_mode: 1;    // 1 when reception through the connection is chunked (segmented)
  unsigned tx_chunk_header_sent: 2;     // 1 when the current chunk's header has already been transmitted, 2 when header transmit is in progress
  unsigned rx_chunk_header_parsed: 2;   // 1 when the current chunk's header has already been (received and) parsed, 2 when header reception/parsing is in progress, 3 when header was parsed and is now processed
  unsigned tx_can_compact_hdrstore: 2;  // signal whether a TX header store 'compact' operation would have any effect at all; 1: regular compact; 2: always pull the request uri and query string into the tx buffer space for persistence
  unsigned nested_err_or_pagereq_count: 2; // 1 when we're requesting an error/'nested' page; > 1 when the page request is failing (nested errors)

  struct mg_request_info request_info;
  struct mg_context *ctx;
  SSL *ssl;                             // SSL descriptor
  struct socket client;                 // Connected client
  time_t birth_time;                    // Time when connection was accepted
  time_t last_active_time;              // Time when connection was last active
  int64_t num_bytes_sent;               // Total bytes sent to client; negative number is the amount of header bytes sent; positive number is the amount of data bytes
  int64_t content_len;                  // received Content-Length header value or chunk size; INT64_MAX means fetch as much as you can, mg_read() will act like a single pull(); -1 means we'd have to fetch (and decode) the (HTTP) headers first
  int64_t consumed_content;             // How many bytes of content have already been read
  char *buf;                            // Buffer for received data [buf_size] / chunk header reception [CHUNK_HEADER_BUFSIZ] / headers to transmit [buf_size]
  //char *body;                           // Pointer to not-read yet buffered body data
  //char *next_request;                   // Pointer to the buffered next request
  int buf_size;                         // Buffer size for received data + chunk header reception
  int request_len;                      // Size of the request + headers in buffer buf[]

  int rx_chunk_buf_size;                // Maximum available number of bytes for the RX chunk header buffer, starting at buf[request_len]
  int rx_buffer_loaded_len;             // Number of bytes loaded into the RX chunk buffer
  int rx_buffer_read_len;               // Number of bytes already read from the RX chunk buffer (<= rx_buffer_loaded_len)

  int tx_headers_len;                   // Size of the response headers (client: + possibly cached request URI+query string) in buffer buf[]

  int64_t tx_remaining_chunksize;       // How many bytes of content remain to be sent in the current chunk
  int64_t rx_remaining_chunksize;       // How many bytes of content remain to be received in the current chunk
  int64_t tx_next_chunksize;            // How many bytes of content will be sent in the next chunk
  int tx_chunk_count;                   // The number of chunks transmitted so far.
  int rx_chunk_count;                   // The number of chunks received so far.

  char error_logfile_path[PATH_MAX+1];  // cached value: path to the error logfile designated to this connection/CTX
  char access_logfile_path[PATH_MAX+1]; // cached value: path to the access logfile designated to this connection/CTX
};

const char **mg_get_valid_option_names(void) {
  return config_options;
}

static void *call_user(struct mg_connection *conn, enum mg_event event) {
  if (conn && conn->ctx && conn->ctx->user_functions.user_callback) {
    return conn->ctx->user_functions.user_callback(event, conn);
  } else {
    return NULL;
  }
}

static void *call_user_over_ctx(struct mg_context *ctx, SSL_CTX *ssl_ctx, enum mg_event event) {
  if (ctx && ctx->user_functions.user_callback) {
    struct mg_connection conn = {0};
    void *rv;
    SSL_CTX *old_ssl = ctx->ssl_ctx;
    ctx->ssl_ctx = ssl_ctx;
    conn.ctx = ctx;
    rv = ctx->user_functions.user_callback(event, &conn);
    ctx->ssl_ctx = old_ssl;
    return rv;
  } else {
    return NULL;
  }
}

static int call_user_option_decode(struct mg_context *ctx, const char *name, const char *value) {
  if (ctx && ctx->user_functions.user_option_decode) {
    return ctx->user_functions.user_option_decode(ctx, name, value);
  } else {
    return 0;
  }
}

static int call_user_option_fill(struct mg_context *ctx) {
  if (ctx && ctx->user_functions.user_option_fill) {
    return ctx->user_functions.user_option_fill(ctx);
  } else {
    return !0;
  }
}

static const char *call_user_option_get(struct mg_context *ctx, const char *name) {
  if (ctx && ctx->user_functions.user_option_get) {
    return ctx->user_functions.user_option_get(ctx, 0, name);
  } else {
    return NULL;
  }
}

static const char *call_user_conn_option_get(struct mg_connection *conn, const char *name) {
  if (conn && conn->ctx && conn->ctx->user_functions.user_option_get) {
    return conn->ctx->user_functions.user_option_get(conn->ctx, conn, name);
  } else {
    return NULL;
  }
}

static int call_user_ssi_command(struct mg_connection *conn, const char *ssi_commandline, const char *path, int include_level) {
  if (conn && conn->ctx && conn->ctx->user_functions.user_ssi_command) {
    return conn->ctx->user_functions.user_ssi_command(conn, ssi_commandline, path, include_level);
  } else {
    return 0;
  }
}

static int is_empty(const char *str) {
  return !str || !*str;
}

static int get_option_index(const char *name) {
  int i;

  if (!name)
    return -1;
  for (i = 0; config_options[i] != NULL; i += MG_ENTRIES_PER_CONFIG_OPTION) {
    if ((config_options[i][0] && strcmp(config_options[i], name) == 0) ||
        strcmp(config_options[i + 1], name) == 0) {
      return i / MG_ENTRIES_PER_CONFIG_OPTION;
    }
  }
  return -1;
}

const char *mg_get_option(struct mg_context *ctx, const char *name) {
  const char *rv = call_user_option_get(ctx, name);
  if (!rv) {
    int i = get_option_index(name);
    if (i == -1) {
      return NULL;
    } else if (ctx == NULL || ctx->config[i] == NULL) {
      return "";
    } else {
      return ctx->config[i];
    }
  }
  return rv;
}

const char *mg_get_conn_option(struct mg_connection *conn, const char *name) {
  const char *rv = call_user_conn_option_get(conn, name);
  if (!rv) {
    int i = get_option_index(name);
    if (i == -1) {
      return NULL;
    } else if (conn == NULL || conn->ctx == NULL || conn->ctx->config[i] == NULL) {
      return "";
    } else {
      return conn->ctx->config[i];
    }
  }
  return rv;
}

const char *mg_get_option_long_name(const char *name) {
  int i = get_option_index(name);
  if (i >= 0)
    return config_options[i * MG_ENTRIES_PER_CONFIG_OPTION + 1];
  return NULL;
}

static const char *get_option(struct mg_context *ctx, mg_option_index_t index) {
  const char *rv;
  MG_ASSERT((int)index >= 0 && (int)index < NUM_OPTIONS);
  rv = call_user_option_get(ctx, config_options[index * MG_ENTRIES_PER_CONFIG_OPTION + 1]);
  if (rv)
    return rv;

  if (ctx == NULL || ctx->config[index] == NULL)
    return "";
  else
    return ctx->config[index];
}

static const char *get_conn_option(struct mg_connection *conn, mg_option_index_t index) {
  const char *rv;
  MG_ASSERT((int)index >= 0 && (int)index < NUM_OPTIONS);
  rv = call_user_conn_option_get(conn, config_options[index * MG_ENTRIES_PER_CONFIG_OPTION + 1]);
  if (rv)
    return rv;

  if (conn == NULL || conn->ctx == NULL || conn->ctx->config[index] == NULL)
    return "";
  else
    return conn->ctx->config[index];
}

// ntop()/ntoa() replacement for IPv6 + IPv4 support:
static char *sockaddr_to_string(char *buf, size_t len, const struct usa *usa) {
  buf[0] = '\0';
#if defined(USE_IPV6) && defined(HAVE_INET_NTOP)
  // Only Windoze Vista (and newer) have inet_ntop()
  inet_ntop(usa->u.sa.sa_family, (usa->u.sa.sa_family == AF_INET ?
            (void *) &usa->u.sin.sin_addr :
            (void *) &usa->u.sin6.sin6_addr), buf, len);
#elif defined(HAVE_GETNAMEINFO)
  // Win32: do not use WSAAddressToString() as that one formats the output as [address]:port while we only want to print <address> here
  if (getnameinfo(&usa->u.sa, usa->len, buf, len, NULL, 0, NI_NUMERICHOST))
    buf[0] = '\0';
#elif defined(HAVE_INET_NTOP)
  inet_ntop(usa->u.sa.sa_family, (void *) &usa->u.sin.sin_addr, buf, len);
#elif defined(_WIN32)
  // WARNING: ntoa() is very probably not thread-safe on your platform!
  //          (we'll abuse the (DisconnectExPtrCS) critical section to cover this up as well...)
  EnterCriticalSection(&DisconnectExPtrCS);
  mg_strlcpy(buf, inet_ntoa(usa->u.sin.sin_addr), len);
  LeaveCriticalSection(&DisconnectExPtrCS);
#else
#error check your platform for inet_ntop/etc.
#endif
  buf[len - 1] = 0;
  return buf;
}

// ntoh() replacement for IPv6 + IPv4 support:
static unsigned short int get_socket_port(const struct usa *usa)
{
#if defined(USE_IPV6)
  return ntohs(usa->u.sa.sa_family == AF_INET ?
    usa->u.sin.sin_port :
    usa->u.sin6.sin6_port);
#else
  return ntohs(usa->u.sin.sin_port);
#endif
}

// IPv4 + IPv6 support: produce the individual numbers of the IP address in a usable/portable (host) structure
static void get_socket_ip_address(struct mg_ip_address *dst, const struct usa *usa)
{
  memset(&dst->ip_addr, 0, sizeof(dst->ip_addr));

#if defined(USE_IPV6)
  // Note: According to RFC3493 the only specified member of the in6_addr structure is s6_addr.
  dst->is_ip6 = (usa->u.sa.sa_family == AF_INET6);
  if (dst->is_ip6) {
    const uint16_t *s = (const uint16_t *)&usa->u.sin6.sin6_addr;
    dst->ip_addr.v6[0] = ntohs(s[0]);
    dst->ip_addr.v6[1] = ntohs(s[1]);
    dst->ip_addr.v6[2] = ntohs(s[2]);
    dst->ip_addr.v6[3] = ntohs(s[3]);
    dst->ip_addr.v6[4] = ntohs(s[4]);
    dst->ip_addr.v6[5] = ntohs(s[5]);
    dst->ip_addr.v6[6] = ntohs(s[6]);
    dst->ip_addr.v6[7] = ntohs(s[7]);
  }
  else
#endif
  {
    const uint8_t *s = (const uint8_t *)&usa->u.sin.sin_addr;
    dst->ip_addr.v4[0] = s[0];
    dst->ip_addr.v4[1] = s[1];
    dst->ip_addr.v4[2] = s[2];
    dst->ip_addr.v4[3] = s[3];
    dst->is_ip6 = 0;
  }
}

// Note: dst may reference the same memory as src
static void cvt_ipv4_to_ipv6(struct mg_ip_address *dst, const struct mg_ip_address *src)
{
  // process IPv4 as IPv6 ::ffff:a0:a1:a2:a3
  if (src->is_ip6) {
    if (dst != src)
      *dst = *src;
  } else {
    struct mg_ip_address d;

    d.is_ip6 = 1;
    d.ip_addr.v6[0] = 0;
    d.ip_addr.v6[1] = 0;
    d.ip_addr.v6[2] = 0;
    d.ip_addr.v6[3] = 0xffffu;
    d.ip_addr.v6[4] = src->ip_addr.v4[0];
    d.ip_addr.v6[5] = src->ip_addr.v4[1];
    d.ip_addr.v6[6] = src->ip_addr.v4[2];
    d.ip_addr.v6[7] = src->ip_addr.v4[3];
    *dst = d;
  }
}

/*
Like strerror() but with included support for the same functionality for
Win32 system error codes, so that mg_strerror(ERROR) always delivers the
best possible description instead of a lot of 'Unknown error' messages.

NOTE: has the mg_ prefix to prevent collisions with system's strerror();
      it is generally used in constructs like mg_strerror(ERRNO) where
      ERRNO is a mongoose-internal #define.
*/
const char *mg_strerror(int errcode) {
#if defined(_WIN32) && !defined(__SYMBIAN32__)

  const char *s = strerror(errcode);
  if (is_empty(s) || GetLastError() == (DWORD)errcode) {
    static __declspec(thread) char msg[256];

    if (0 == FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                            errcode, 0, msg, ARRAY_SIZE(msg), NULL)) {
      snprintf(msg, ARRAY_SIZE(msg), "Unidentified error code %d", errcode);
    } else {
      // strip trailing whitespace off the message.
      char *p = msg + strlen(msg) - 1;
      while (p >= msg && isspace((unsigned char)*p))
        p--;
      p[1] = 0;
    }
    return msg;
  }
  return s;

#else

  return strerror(errcode);

#endif
}

/*
   Return fake connection structure. Used for logging, if connection
   is not applicable at the moment of logging.

   (Note: this is 'thread safe _enough_': we don't care that multiple threads
          can bang up this 'connection', just as long as 'ctx' is
          written atomically (the write is one opcode).)
*/
static struct mg_connection *fc(struct mg_context *ctx) {
  static struct mg_connection fake_connection = {0};
  fake_connection.ctx = ctx;
  fake_connection.last_active_time = time(NULL);
  if (fake_connection.birth_time == 0) {
    fake_connection.birth_time = fake_connection.last_active_time;
  }
  return &fake_connection;
}

// Replace all illegal characters by '_'; reduce multiple
// occurrences of these by a single character (so you don't
// get filepaths like '_______/buggered.dir').
//
// Replaces '%' by '!' and otherwise only allows [a-z0-9-]
// and of course '/' and '\' (which is converted to '/')
// to pass, so as to create paths which are suitable for the
// most restrictive file systems.
//
// Does not allow the path to end at a '/'.
//
// Modifies the path in place; the result is always smaller
// or equal in size, compared to the input.
//
// Returns the length of the result.
static int powerscrub_filepath(char *path, int tolerate_dirsep)
{
  char *d = path;
  char *s = path;

  for (;;) {
    switch (*s++) {
    case 0:
      break;

    case '%':
      *d++ = '!';
      continue;

    case ':':
    case '.':
      // don't allow output sequences with multiple dots following one another,
      // nor do we allow a dot at the start or end of the produced part (which would
      // possibly generate hidden files/dirs and file create issues on some
      // OS/storage formats):
      if (d > path && !strchr("/.", d[-1]))
        *d++ = '.';
      continue;

    case '/':
    case '\\':
      // don't allow output sequences with multiple dots following one another,
      // nor do we allow a dot at the start or end of the produced part (which would
      // possibly generate hidden files/dirs and file create issues on some
      // OS/storage formats):
      if (d > path && strchr("/.", d[-1]))
        d[-1] = (tolerate_dirsep ? '/' : '.');
      else
        *d++ = (tolerate_dirsep ? '/' : '.');
      continue;

    default:
      // be very conservative in our estimate what your filesystem will tolerate as valid characters in a filename:
      if (strchr("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-", s[-1]))
        *d++ = s[-1];
      else if (d == path || d[-1] != '_')
        *d++ = '_';
      continue;
    }
    break;
  }
  // make sure there's no '/' or '.' dot at the very end to prevent file create issues on some platforms:
  while (d > path && strchr("/.", d[-1]))
    d--;
  *d = 0;
  return (int)(d - path);
}

// replace %[P] with client port number
//         %[C] with client IP (sanitized for filesystem paths)
//         %[p] with server port number
//         %[s] with server IP (sanitized for filesystem paths)
//         %[U] with the request URI path section (sanitized for filesystem paths and limited to MG_LOGFILE_MAX_URI_COMPONENT_LEN characters max. (last 8 characters on overflow: URL hash))
//         %[Q] with the request URI query section (sanitized for filesystem paths and limited to MG_LOGFILE_MAX_URI_COMPONENT_LEN characters max. (last 8 characters on overflow: query hash))
//
//         any other % parameter is processed by strftime.
const char *mg_get_logfile_path(char *dst, size_t dst_maxsize, const char *logfile_template, struct mg_connection *conn, time_t timestamp) {
  char fnbuf[PATH_MAX+1];
  char *d;
  const char *s;
  struct tm *tp;

  if (!dst || dst_maxsize < 1) {
    return NULL;
  }
  if (is_empty(logfile_template) || dst_maxsize <= 1) {
    dst[0] = 0;
    return NULL;
  }

  d = fnbuf;
  d[PATH_MAX] = 0;  // sentinel for odd moments with strncpy et al
  s = logfile_template;
  while (d - fnbuf < PATH_MAX) {
    switch (*s) {
    case 0:
      if (d > fnbuf && d[-1] == '.')
        d--;
      break;

    case '%':
      if (s[1] == '[') {
        int len = PATH_MAX - (int)(d - fnbuf); // MG_ASSERT(len > 0);
        char *s_cont = NULL;
        // Enough space for all: ntoa() output, URL path and it's limited-length copy + MD5 hash at the end:
        // Note: +2 in case MG_LOGFILE_MAX_URI_COMPONENT_LEN is the biggest of the three: we want to be able to
        //       detect buffer overflow, i.e. clipping by snprintf()!
        char addr_buf[MG_MAX(SOCKADDR_NTOA_BUFSIZE, MG_MAX(MG_LOGFILE_MAX_URI_COMPONENT_LEN + 2, PATH_MAX))];
        char *old_d = d;
        int abuflen, abufoffset;
        int parlen = (int)strtol(s + 2, &s_cont, 10);
        if (parlen > len)
          parlen = len;
        if (s_cont)
          s = s_cont;

        *d = 0;
        switch (*s) {
        case 'P':
          if (conn) {
            unsigned short int port = get_socket_port(&conn->client.rsa);

            if (port != 0) {
              if (parlen <= 0) parlen = 1;
              (void)mg_snprintf(conn, d, len, "%0*u", parlen, (unsigned int)port);
              d += strlen(d);
            }
          }
          goto replacement_done;

        case 'C':
          if (conn) {
            sockaddr_to_string(addr_buf, sizeof(addr_buf), &conn->client.rsa);
            goto copy_partial2dst;
          }
          goto replacement_done;

        case 'p':
          if (conn) {
            unsigned short int port = get_socket_port(&conn->client.lsa);

            if (port != 0) {
              if (parlen <= 0) parlen = 1;
              (void)mg_snprintf(conn, d, len, "%0*u", parlen, (unsigned int)port);
              d += strlen(d);
            }
          }
          goto replacement_done;

        case 's':
          if (conn) {
            sockaddr_to_string(addr_buf, sizeof(addr_buf), &conn->client.lsa);
            goto copy_partial2dst;
          }
          goto replacement_done;

        case 'U':
        case 'Q':
          // filter URI so the result is a valid filepath piece without any format codes
          if (conn && !is_empty(conn->request_info.uri)) {
            const char *q, *u;
            char h[33];

            u = conn->request_info.uri;
            q = strchr(u, '?');
            if (*s == 'Q') {
              if (!q) {
                // empty query section: replace as empty string.
                u = "";
              } else {
                u = q + 1;
                q = NULL;
              }
            }
            // limit the length to process:
            mg_strlcpy(addr_buf, u, sizeof(addr_buf));
            if (q && q - u < (int)sizeof(addr_buf)) {
              addr_buf[q - u] = 0;
            }
            // limit the string inserted into the filepath template to MG_LOGFILE_MAX_URI_COMPONENT_LEN characters or whatever the template said itself:
            if (parlen <= 0)
              parlen = MG_LOGFILE_MAX_URI_COMPONENT_LEN;
            else if (parlen > (int)sizeof(addr_buf) - 1)
              parlen = (int)sizeof(addr_buf) - 1;
            if ((int)strlen(addr_buf) > parlen) {
              mg_md5(h, addr_buf, NULL);  // hash the 'raw' (clipped) URI component; only calc the hash when it MIGHT be needed
            } else {
              h[0] = 0;
            }
            // yet paste the hash into the 'scrubbed' URI component ONLY when the scrubbed component is overlarge
            if (powerscrub_filepath(addr_buf, 0) > parlen) {
              mg_strlcpy(addr_buf + MG_MAX(0, parlen - 8), h, 8 + 1);
            }
            goto copy_partial2dst;
          }
          goto replacement_done;

copy_partial2dst:
          // addr_buf[] is guaranteed to be filled when we get here
          powerscrub_filepath(addr_buf, 0);
          abuflen = (int)strlen(addr_buf);
          if (parlen <= 0)
            parlen = abuflen;
          MG_ASSERT(len > 0);
          if (parlen > len)
            parlen = len;
          // take the right-most part when we must clip: determine the offset
          if (abuflen > parlen)
            abufoffset = abuflen - parlen;
          else
            abufoffset = 0;
          d += mg_strlcpy(d, addr_buf + abufoffset, parlen + 1);
replacement_done:
          // and the %[?] macros ALWAYS produmgce at least ONE character output in the template,
          // otherwise you get screwed up paths with, f.e. 'a/%[Q]/b' --> 'a//b':
          if (d == old_d && d - fnbuf < PATH_MAX)
            *d++ = '_';

          s += 2;
          continue;

        default:
          // illegal format code: keep as is, but destroy the %:
          if (len >= 2) {
            *d++ = '!';
            *d++ = '[';
          }
          continue;
        }
      }
      // keep format code for strftime to struggle with: copy as is for now:
      //   (fallthrough)
    default:
      *d++ = *s++;
      continue;
    }
    break;
  }
  *d = 0;

  tp = localtime(&timestamp);
  if (0 == strftime(dst, dst_maxsize, fnbuf, tp)) {
    // error transforming the template to a filename: fall back to the literal thing, but ditch all '%' in the path now:
    d = dst;
    s = fnbuf;
    dst_maxsize--; // reserve space for the sentinel NUL
    while (d - dst < (int)dst_maxsize && *s) {
      if (*s == '%') {
        *d++ = '_';
        s++;
      } else {
        *d++ = *s++;
      }
    }
    *d = 0;
  }
  return dst;
}

const char *mg_get_default_error_logfile_path(struct mg_connection *conn) {
  // Once determined, we stick with the given logfile for the current connection.
  //
  // We clear the cached filepath when the connection goes on to process another request (request URL *MAY* be a parameter in the logfile path template).
  if (!conn->error_logfile_path[0]) {
    return mg_get_logfile_path(conn->error_logfile_path, ARRAY_SIZE(conn->error_logfile_path), get_conn_option(conn, ERROR_LOG_FILE), conn, conn->birth_time);
  }
  return conn->error_logfile_path;
}

const char *mg_get_default_access_logfile_path(struct mg_connection *conn) {
  // Once determined, we stick with the given logfile for the current connection.
  //
  // We clear the cached filepath when the connection goes on to process another request (request URL *MAY* be a parameter in the logfile path template).
  if (!conn->access_logfile_path[0]) {
    return mg_get_logfile_path(conn->access_logfile_path, ARRAY_SIZE(conn->access_logfile_path), get_conn_option(conn, ACCESS_LOG_FILE), conn, conn->birth_time);
  }
  return conn->access_logfile_path;
}

// write arbitrary formatted string to the specified logfile
int mg_write2log_raw(struct mg_connection *conn, const char *logfile, time_t timestamp, const char *severity, const char *msg) {
  int rv = 0;

  if (!conn) conn = fc(NULL);
  logfile = (logfile == NULL ? mg_get_default_error_logfile_path(conn) : logfile);
  severity = (severity ? severity : "error");
  conn->request_info.log_severity = severity;
  conn->request_info.log_dstfile = logfile;
  conn->request_info.log_timestamp = timestamp;
  conn->request_info.log_message = msg;
  // Do not lock when getting the callback value, here and below.
  // I suppose this is fine, since function cannot disappear in the
  // same way string option can.
  if (call_user(conn, MG_EVENT_LOG) == NULL) {
    FILE *fp;

    severity = conn->request_info.log_severity;
    logfile = conn->request_info.log_dstfile;
    timestamp = conn->request_info.log_timestamp;
    msg = conn->request_info.log_message;

    fp = mg_fopen((logfile ? logfile : "-"), "a+");
    if (fp != NULL) {
      flockfile(fp);

      if (timestamp != 0) {
        char tbuf[40];

        rv += (int)fwrite(tbuf, sizeof(tbuf[0]), strftime(tbuf, ARRAY_SIZE(tbuf), "[%Y%m%dT%H%M%S] ", gmtime(&timestamp)), fp);
      }
      rv += fprintf(fp, "[%s] ", severity);
      if (conn != NULL) {
        char addr_buf[SOCKADDR_NTOA_BUFSIZE];

        sockaddr_to_string(addr_buf, sizeof(addr_buf), &conn->client.rsa);
        if (addr_buf[0]) {
          rv += fprintf(fp, "[client %s] ", addr_buf);
        }
      }

      if (conn != NULL && conn->request_info.request_method != NULL && conn->request_info.uri != NULL) {
        rv += fprintf(fp, "%s %s: ",
                      conn->request_info.request_method,
                      conn->request_info.uri);
      }

      rv += fprintf(fp, "%s\n", msg ? msg : "???");
      fflush(fp);
      funlockfile(fp);
      mg_fclose(fp);
    }
  }
  conn->request_info.log_severity = NULL;
  conn->request_info.log_dstfile = NULL;
  conn->request_info.log_timestamp = 0;
  conn->request_info.log_message = NULL;

  return rv;
}

// Print log message to the opened error log stream.
void mg_write2log(struct mg_connection *conn, const char *logfile, time_t timestamp, const char *severity, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  mg_vwrite2log(conn, logfile, timestamp, severity, fmt, ap);
  va_end(ap);
}

// Print log message to the opened error log stream.
void mg_vwrite2log(struct mg_connection *conn, const char *logfile, time_t timestamp, const char *severity, const char *fmt, va_list args) {
  // handle the special case where there's nothing to do in terms of formatting in order to accept arbitrary input lengths then without the malloc/speed penalty:
  if (!strchr(fmt, '%')) {
    mg_write2log_raw(conn, logfile, timestamp, severity, fmt);
  } else if (!strcmp(fmt, "%s")) {
    fmt = va_arg(args, const char *);
    mg_write2log_raw(conn, logfile, timestamp, severity, fmt);
  } else {
    char *buf = NULL;
    // the absolute max we're going to support is a dump of 1MByte of text!
    int n = mg_vasprintf(conn, &buf, MG_MAX_LOG_LINE_SIZE, fmt, args);

    if (buf) {
      // make sure the log'line' is NEWLINE terminated (or not) when clipped, depending on the format string input
      if (n > 0 && fmt[strlen(fmt) - 1] != '\n' && buf[n - 1] == '\n')
        buf[n - 1] = 0;

      mg_write2log_raw(conn, logfile, timestamp, severity, buf);
      free(buf);
    } else {
      mg_write2log_raw(conn, logfile, timestamp, severity, "!out of memory in mg_vwrite2log!\n");
    }
  }
}

// Print formatted error message to the opened error log stream.
void mg_cry_raw(struct mg_connection *conn, const char *msg) {
  time_t timestamp = time(NULL);

  (void)mg_write2log_raw(conn, NULL, timestamp, NULL, msg);
}

// Print error message to the opened error log stream.
void mg_cry(struct mg_connection *conn, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  mg_vcry(conn, fmt, ap);
  va_end(ap);
}

// Print error message to the opened error log stream.
void mg_vcry(struct mg_connection *conn, const char *fmt, va_list args) {
  time_t timestamp = time(NULL);

  (void)mg_vwrite2log(conn, NULL, timestamp, NULL, fmt, args);
}

const char *mg_version(void) {
  return MONGOOSE_VERSION;
}

const struct mg_request_info *mg_get_request_info(const struct mg_connection *conn) {
  return conn ? &conn->request_info : NULL;
}

size_t mg_strlcpy(register char *dst, register const char *src, size_t n) {
  char *b = dst;
  for (; *src != '\0' && n > 1; n--) {
    *dst++ = *src++;
  }
  *dst = '\0';
  return dst - b;
}

size_t mg_strnlen(const char *src, size_t maxlen) {
  const char *p = (const char *)memchr(src, 0, maxlen);
  if (p)
    return p - src;
  return maxlen;
}

static int lowercase(const char *s) {
  return tolower(* (const unsigned char *) s);
}

int mg_strncasecmp(const char *s1, const char *s2, size_t len) {
  int diff = 0;

  if (len > 0)
    do {
      diff = lowercase(s1++) - lowercase(s2++);
    } while (diff == 0 && s1[-1] != '\0' && --len > 0);

  return diff;
}

int mg_strcasecmp(const char *s1, const char *s2) {
  int diff;

  do {
    diff = lowercase(s1++) - lowercase(s2++);
  } while (diff == 0 && s1[-1] != '\0');

  return diff;
}

char * mg_strndup(const char *ptr, size_t len) {
  char *p;

  if ((p = (char *) malloc(len + 1)) != NULL) {
    mg_strlcpy(p, ptr, len + 1);
  }

  return p;
}

char * mg_strdup(const char *str) {
  return mg_strndup(str, strlen(str));
}

const char *mg_memfind(const char *haystack, size_t haysize, const char *needle, size_t needlesize)
{
  if (haysize < needlesize || !haystack || !needle)
    return NULL;
  haysize -= needlesize - 1;
  while (haysize > 0) {
    const char *p = memchr(haystack, needle[0], haysize);
    if (!p)
      return NULL;
    // as we fixed haysize we can now simply check if the needle is here:
    if (!memcmp(p, needle, needlesize))
      return p;
    // be blunt; no BM-like speedup for this search...
    p++;
    haysize -= p - haystack;
    haystack = p;
  }
  return NULL;
}

// Find location of case-insensitive needle string in haystack string.
// Return NULL if needle wasn't found.
const char *mg_stristr(const char *haystack, const char *needle)
{
  int nc;
  size_t needlesize;

  if (!haystack || !needle || !*haystack || !*needle)
    return NULL;
  needlesize = strlen(needle);

  for (nc = lowercase(needle); *haystack; haystack++) {
    int hc = lowercase(haystack);
    if (hc == nc && !mg_strncasecmp(needle + 1, haystack + 1, needlesize - 1))
      return haystack;
    // be blunt; no BM-like speedup for this search...
  }
  return NULL;
}

// Like snprintf(), but never returns negative value, or a value
// that is larger than a supplied buffer.
// Thanks to Adam Zeldis to pointing snprintf()-caused vulnerability
// in his audit report.
int mg_vsnprintf(struct mg_connection *conn, char *buf, size_t buflen,
                        const char *fmt, va_list ap) {
  int n;

  if (buflen == 0)
    return 0;

  // shortcut for speed:
  if (!strchr(fmt, '%')) {
    return (int)mg_strlcpy(buf, fmt, buflen);
  } else if (!strcmp(fmt, "%s")) {
    fmt = va_arg(ap, const char *);
    if (!fmt) fmt = "???";
    return (int)mg_strlcpy(buf, fmt, buflen);
  }
  buf[0] = 0;
  n = vsnprintf(buf, buflen, fmt, ap);
  buf[buflen - 1] = 0;

  if (n < 0) {
    mg_cry(conn, "vsnprintf error / overflow");
    // MSVC produces -1 on printf("%s", str) for very long 'str'!
    n = (int)strlen(buf);
  } else if (n >= (int) buflen) {
    mg_cry(conn, "truncating vsnprintf buffer: [%.*s]",
           n > 200 ? 200 : n, buf);
    n = (int) buflen - 1;
  }
  buf[n] = '\0';

  return n;
}

int mg_snprintf(struct mg_connection *conn, char *buf, size_t buflen,
                const char *fmt, ...) {
  va_list ap;
  int n;

  va_start(ap, fmt);
  n = mg_vsnprintf(conn, buf, buflen, fmt, ap);
  va_end(ap);

  return n;
}


int mg_vsnq0printf(UNUSED_PARAMETER(struct mg_connection *unused), char *buf, size_t buflen, const char *fmt, va_list ap) {
  int n;

  if (buflen == 0)
    return 0;

  // shortcut for speed:
  if (!strchr(fmt, '%')) {
    return (int)mg_strlcpy(buf, fmt, buflen);
  } else if (!strcmp(fmt, "%s")) {
    fmt = va_arg(ap, const char *);
    if (!fmt) fmt = "???";
    return (int)mg_strlcpy(buf, fmt, buflen);
  }
  buf[0] = 0;
  n = vsnprintf(buf, buflen, fmt, ap);
  buf[buflen - 1] = 0;

  if (n < 0) {
    // MSVC produces -1 on printf("%s", str) for very long 'str'!
    n = (int)strlen(buf);
  } else if (n >= (int) buflen) {
    n = (int) buflen - 1;
  }
  buf[n] = '\0';

  return n;
}

int mg_snq0printf(struct mg_connection *conn, char *buf, size_t buflen,
                  const char *fmt, ...) {
  va_list ap;
  int n;

  va_start(ap, fmt);
  n = mg_vsnq0printf(conn, buf, buflen, fmt, ap);
  va_end(ap);

  return n;
}

int mg_vasprintf(UNUSED_PARAMETER(struct mg_connection *unused), char **buf_ref, size_t max_buflen,
                 const char *fmt, va_list ap) {
  va_list aq;
  int n;
  int size = MG_BUF_LEN;
  char *buf = (char *)malloc(size);

  if (max_buflen == 0 || max_buflen > INT_MAX) {
    max_buflen = INT_MAX;
  }

#ifdef _MSC_VER
  VA_COPY(aq, ap);
  // adjust size for NUL and set it up so the fallback loop further below does not cycle
  size = _vscprintf(fmt, aq) + 2;
  if (size < 2)
    size = MG_BUF_LEN;
  va_end(aq);
#endif
  if (size > (int)max_buflen)
    size = (int)max_buflen;

  buf = (char *)malloc(size);
  if (buf == NULL) {
    *buf_ref = NULL;
    return 0;
  }

  VA_COPY(aq, ap);
  while ((((n = vsnprintf(buf, size, fmt, aq)) < 0) || (n >= size - 1)) && (size < (int)max_buflen)) {
    va_end(aq);
    // forego the extra cost in realloc() due to memcpy(): use free+malloc instead:
    free(buf);
    size *= 4; /* fast-growing buffer: we don't want to try too many times */
    if (size > (int)max_buflen)
      size = (int)max_buflen;
    buf = (char *)malloc(size);
    if (buf == NULL) {
      *buf_ref = NULL;
      return 0;
    }
    VA_COPY(aq, ap);
  }
  va_end(aq);
  if (n < 0) {
    // MSVC produces -1 on printf("%s", str) for very long 'str'!
    n = size - 1;
    buf[n] = '\0';
    n = (int)strlen(buf);
  } else if (n >= size) {
    // truncated output:
    // mark the string as clipped and take optional line ending from fmt string
    char *d;
    const char *le = fmt + strlen(fmt) - 1;
    n = size - 1;
    d = buf + n - 6;
    MG_ASSERT(le > fmt);
    MG_ASSERT(d > buf);
    while (le > fmt && d > buf && strchr("\r\n", *le)) {
      le--;
      d--;
    }
    strcpy(d, " (...)");
    d += 6;
    strcpy(d, le);
  } else {
    buf[n] = '\0';
  }
  *buf_ref = buf;
  return n;
}

int mg_asprintf(struct mg_connection *conn, char **buf_ref, size_t max_buflen,
                const char *fmt, ...) {
  va_list ap;
  int n;

  va_start(ap, fmt);
  n = mg_vasprintf(conn, buf_ref, max_buflen, fmt, ap);
  va_end(ap);

  return n;
}

// skip RFC2616 LWS: (SP | HT | line-continuation)
static char *skip_lws(char *str) {
  str += strspn(str, " \t");
  for(;;) {
    if (*str && strchr("\r\n", *str)) {
      // Check whether this is a true 'line continuation' in the sense of RFC2616 sec. 2.2:
      char *p = str;
      // Only look *one* CRLF ahead; be tolerant of MACs & UNIXes and non-std input:
      // accept single CR/LF as well, so we can reuse this for file-based I/O too.
      if (*p == '\r')
        p++;
      if (*p == '\n')
        p++;
      if (*p && strchr(" \t", *p)) {
        str = p + strspn(p, " \t");
        continue;
      }
    }
    break;
  }
  return str;
}

// skip LWS + n*CRLF, i.e. skip until end-of-line (where CRLF is NOT a line continuation)
static char *skip_eolws(char *str) {
  str = skip_lws(str);
  str += strspn(str, "\r\n");
  return str;
}

// skip ALL whitespace
static char *skip_allws(char *str) {
  str += strspn(str, " \t\r\n");
  return str;
}

// cf. RFC2616 sec. 2.2
static const char *rfc2616_token_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~`!#$%^&*_-+'.|";
static const char *rfc2616_nonws_separator_charset = "@()={}[]:;,<>?/\\"; // plus <">, SP, HT

// Return 0 on success, -1 on failure.
int mg_unquote_header_value(char *str, char *sentinel, char **end_ref) {
  char *p, *te;

  te = str;

  // extract UNQUOTED field-value, where field-value is either a *single* quoted-string or a token cf. RFC2616 sec 2.2
  if (*str != '"') {
    // we're looking at a token
    //
    // make sure token is actually cf. RC2616 sec. 2.2:
    p = str + strspn(str, rfc2616_token_charset);
    if (end_ref) {
      *end_ref = p;
      *sentinel = *p;
      *p = 0;
    } else if (*p && skip_allws(p)[0]) {
      // when we can't tell caller where token ended, we must fail when input isn't a single token
      return -1;
    }

    if (p > str && te != str)
      memmove(te, str, p - str);
    te[p - str] = 0;
  } else {
    // unquote the value; unescape \\-escaped characters
    p = str + 1;
    while (*p) {
      if (*p == '"') {
        break;
      } else if (*p == '\\') {
        // RFC2616 sec 2.2 says you can escape char NUL too, but we don't allow it, as it opens a floodgate of assault scenarios
        if (p[1] <= 0 || p[1] >= 128)
          return -1;
        p++;
        *str++ = *p++;
      } else if (*p >= ' ' && *p < 128) {
        *str++ = *p++;
      } else {
        // MUST be escaped to be POSSIBLY legal inside quoted-string
        return -1;
      }
    }
    if (*p != '"')
      return -1; // quoted-string not terminated correctly!
    p++;
    *str = 0;

    if (end_ref) {
      *end_ref = p;
      *sentinel = *p;
    } else if (*p && skip_allws(p)[0]) {
      // when we can't tell caller where quoted-string ended, we must fail when input isn't a single quoted-string
      return -1;
    }
  }
  return 0;
}

// Extract a token,value pair from the string buffer. (See mongoose.h for full doc)
// Return 0 on success, -1 on failure.
int mg_extract_token_qstring_value(char **buf, char *sentinel, const char **token_ref, const char **value_ref, const char *empty_string) {
  char *te, *ve, *begin_word, *end_word;
  char sep, ec;

  if (token_ref) *token_ref = NULL;
  if (*value_ref) *value_ref = NULL;

  begin_word = *buf;
  begin_word = skip_allws(begin_word);

  // token [LWS] "=" [LWS] [quoted-string]
  // make sure token is actually cf. RC2616 sec. 2.2:
  end_word = begin_word + strspn(begin_word, rfc2616_token_charset);
  if (end_word == begin_word)
    return -1;

  te = end_word;
  end_word = skip_lws(end_word);

  // now we should see the mandatory "="
  if (*end_word != '=')
    return -1;
  end_word++;

  if (token_ref)
    *token_ref = begin_word;

  begin_word = end_word = skip_lws(end_word);

  // do we have a OPTIONAL field-value?
  // extract UNQUOTED field-value, where field-value is either a *single* quoted-string or a token cf. RFC2616 sec 2.2
  if (!*begin_word || (*begin_word != '"' && !strchr(rfc2616_token_charset, *begin_word))) {
    // no value specified; we're looking at either a separator, WS, CR/LF or a NUL (EOS)
    if (value_ref)
      *value_ref = empty_string;

    ve = end_word;
    sep = *end_word;
    end_word = skip_eolws(end_word);
  } else if (*begin_word != '"') {
    if (value_ref)
      *value_ref = begin_word;

    // accept rfc2616_token_charset
    end_word += strspn(begin_word, rfc2616_token_charset);
    ve = end_word;
    sep = *end_word;
    end_word = skip_eolws(end_word);
  } else {
    if (value_ref)
      *value_ref = begin_word;

    // unquote the value; unescape \\-escaped characters
    if (mg_unquote_header_value(begin_word, &sep, &end_word) < 0)
      return -1;
    // 'end_word' will now point 1 char past the ending <">-quote.
    MG_ASSERT(sep ? *end_word : 1);
    MG_ASSERT(!sep ? !*end_word : 1);
    ve = end_word;
    end_word = skip_eolws(end_word);
  }

  // If there's any content following this token,value pair and 'end_word'
  // is not pointing at a separator or NUL (can't point at a WS or CR/LF
  // as we skipped 'em all!), then back it up 1 char and report 'sep' as
  // the separator instead of *end_word.
  //
  // This helps the caller identify both invalid follow-up, e.g. [a="b"c=d]
  // where [c=d] wasn't preceded by a separator, and identify, and process,
  // any LWS-surrounded non-WS separator such as ';', e.g. [a=b ;c=d] where
  // the caller would be best served by pointing buf at the ';' instead of
  // the preceding ' ' space.
  //
  // Also note that <">-quotes are NOT considered true separators here, so
  // [a=b"c=d] won't cut it.
  ec = sep;
  if (end_word > ve)
    ec = *end_word;
  if (ec && !strchr(rfc2616_nonws_separator_charset, ec)) {
    end_word--;
    if (end_word > ve) {
      // we did skip extra CRLF/WS at the end there, so we can use the last WS/CRLF as separator:
      *sentinel = *end_word;
    } else {
      // use 'sep':
      *sentinel = sep;
      // If 'sep' is not a legal separator, then report an error:
      // this simplifies sanity checks as the caller will now catch errors
      // when an expected single token.value pair has invalid trailing data.
      if (sep && !strchr(" \t\r\n", sep) && !strchr(rfc2616_nonws_separator_charset, sep)) {
        *buf = end_word;
        return -1;
      }
    }
  } else if (end_word > ve) {
    *sentinel = *end_word;
  } else {
    *sentinel = sep;
  }
  *buf = end_word;
  *te = 0;
  *ve = 0;

  return 0;
}



// Extract a HTTP header token + (optional) value cf. RFC2616 sec. 4.2 and sec. 2.2.
// (See mongoose.h for full doc)
// Return 0 on success, -1 on failure.
int mg_extract_raw_http_header(char **buf, char **token_ref, char **value_ref) {
  char *p, *te, *begin_word, *end_word;
  enum {
    RFC2616_TOKEN,
    RFC2616_SEPARATOR,
    RFC2616_QSTRING
  } field_mode;

  if (token_ref) *token_ref = NULL;
  if (*value_ref) *value_ref = NULL;

  begin_word = *buf;
  // RFC2616: header = token LWS ":" LWS field-value CRLF
  end_word = begin_word + strcspn(begin_word, ": \t\r\n");
  if (end_word == begin_word)
    return -1;
  te = end_word;
  end_word = skip_lws(end_word);

  // now we should see the mandatory ":"
  if (*end_word != ':')
    return -1;
  *te = 0;
  end_word++;

  // make sure token is actually cf. RC2616 sec. 2.2:
  p = begin_word + strspn(begin_word, rfc2616_token_charset);
  if (*p)
    return -1;
  else if (token_ref)
    *token_ref = begin_word;

  end_word = skip_lws(end_word);
  begin_word = p = end_word;

  // do we have an OPTIONAL field-value?
  // extract RAW field-value: find the first CRLF which is not a line-continuation
  while (*p && !strchr("\r\n", *p)) {
    end_word = p + strcspn(p, " \t\r\n");
    p = skip_lws(end_word);
  }

  p = skip_eolws(end_word);
  *end_word = 0;
  *buf = p;

  // make sure field-value is actually cf. RC2616 sec. 2.2:
  // convert any 'line continuation' to single SP space.
  field_mode = RFC2616_TOKEN;
  p = begin_word;
  te++;
  begin_word = te;

  while (*p) {
    int clen;

    switch (field_mode) {
    case RFC2616_TOKEN:
      if (*p == '"') {
        field_mode = RFC2616_QSTRING;
        p++;
        if (!*p)
          return -1;
        continue;
      }
      // accept rfc2616_token_charset and any separators; process LWS to single SP though
      clen = strcspn(p, " \t\r\n");
      if (clen)
        memmove(begin_word, p, clen);
      p += clen;
      begin_word += clen;

      if (!*p)
        break;
      field_mode = RFC2616_SEPARATOR;
      continue;

    case RFC2616_SEPARATOR:
      clen = strspn(p, rfc2616_nonws_separator_charset);
      if (clen)
        memmove(begin_word, p, clen);
      if (!clen) {
        char *q = skip_lws(p);
        if (q > p)
          *begin_word++ = ' ';
        else
          // tokens (and quoted strings) MUST be separated by at least 1 separator
          return -1;
        p = q;
      } else {
        p += clen;
        begin_word += clen;
      }
      field_mode = RFC2616_TOKEN;
      continue;

    case RFC2616_QSTRING:
      *begin_word++ = '"';
      while (*p) {
        if (*p == '"') {
          *begin_word++ = *p++;
          field_mode = RFC2616_SEPARATOR;
          break;
        } else if (*p == '\\') {
          if (p[1] < 0 || p[1] >= 128)
            return -1;
          *begin_word++ = *p++;
          *begin_word++ = *p++;
        } else if (*p >= ' ' && *p < 128) {
          *begin_word++ = *p++;
        } else if (*p == '\r' || *p == '\n') {
          p = skip_lws(p);
          *begin_word++ = ' ';
        } else {
          // MUST be escaped to be POSSIBLY legal inside quoted-string
          return -1;
        }
      }
      if (field_mode != RFC2616_SEPARATOR)
        return -1; // quoted-string not terminated correctly!
      continue;
    }
  }
  *begin_word = 0;

  if (value_ref) {
    *value_ref = te;
  }

  return 0;
}

// Skip the characters until one of the delimiters characters found.
// 0-terminate resulting word. Skip the trailing delimiters if any.
// Advance pointer to buffer to the next word. Return found 0-terminated word.
static char *skip(char **buf, const char *delimiters) {
  char *begin_word, *end_word;

  begin_word = *buf;
  end_word = begin_word + strcspn(begin_word, delimiters);

  if (*end_word == '\0') {
    *buf = end_word;
  } else {
    *end_word++ = 0;
    *buf = end_word + strspn(end_word, delimiters);
  }

  return begin_word;
}


// Return HTTP header value, or NULL if not found.
static const char *get_header(const struct mg_header *headers, int num_headers,
                              const char *name) {
  int i;

  for (i = 0; i < num_headers; i++)
    if (!mg_strcasecmp(name, headers[i].name))
      return headers[i].value;

  return NULL;
}

const char *mg_get_header(const struct mg_connection *conn, const char *name) {
  return get_header(conn->request_info.http_headers, conn->request_info.num_headers, name);
}

// A helper function for traversing a comma separated list of values.
// It returns a list pointer shifted to the next value, or NULL if the end
// of the list found.
// Value is stored in val vector. If value has form "x=y", then eq_val
// vector is initialized to point to the "y" part, and val vector length
// is adjusted to point only to "x".
static const char *next_option(const char *list, struct vec *val,
                               struct vec *eq_val) {
  if (is_empty(list)) {
    // End of the list
    val->ptr = 0;
    val->len = 0;
    if (eq_val != NULL) {
      eq_val->ptr = 0;
      eq_val->len = 0;
    }
    list = NULL;
  } else {
    val->ptr = list;
    if ((list = strchr(val->ptr, ',')) != NULL) {
      // Comma found. Store length and shift the list ptr
      val->len = list - val->ptr;
      list++;
    } else {
      // This value is the last one
      list = val->ptr + strlen(val->ptr);
      val->len = list - val->ptr;
    }

    if (eq_val != NULL) {
      // Value has form "x=y", adjust pointers and lengths
      // so that val points to "x", and eq_val points to "y".
      eq_val->len = 0;
      eq_val->ptr = (const char *) memchr(val->ptr, '=', val->len);
      if (eq_val->ptr != NULL) {
        eq_val->ptr++;  // Skip over '=' character
        eq_val->len = val->ptr + val->len - eq_val->ptr;
        val->len = (eq_val->ptr - val->ptr) - 1;
      }
    }
  }

  return list;
}

static int match_string(const char *pattern, int pattern_len, const char *str) {
  const char *or_str;
  int i, j, len, res;

  if (pattern_len == -1)
    pattern_len = (int)strlen(pattern);
  if ((or_str = (const char *) memchr(pattern, '|', pattern_len)) != NULL) {
    res = match_string(pattern, or_str - pattern, str);
    return res > 0 ? res :
           match_string(or_str + 1, (pattern + pattern_len) - (or_str + 1), str);
  }

  i = j = 0;
  res = -1;
  for (; i < pattern_len; i++, j++) {
    if (pattern[i] == '?' && str[j] != '\0') {
      continue;
    } else if (pattern[i] == '$') {
      return str[j] == '\0' ? j : -1;
    } else if (pattern[i] == '*') {
      i++;
      if (pattern[i] == '*') {
        i++;
        len = (int)strlen(str + j);
      } else {
        len = (int)strcspn(str + j, "/");
      }
      if (i == pattern_len) {
        return j + len;
      }
      do {
        res = match_string(pattern + i, pattern_len - i, str + j + len);
      } while (res == -1 && len-- > 0);
      return res == -1 ? -1 : j + res + len;
    } else if (pattern[i] != str[j]) {
      return -1;
    }
  }
  return j;
}

// return non-zero when the given status_code is a probably legal
// HTTP/WebSockets/... response code, i.e. is a value in the range
// 1xx..5xx, 1xxx..4xxx
static int is_legal_response_code(int status) {
  return (status >= 100 && status < 600) || (status >= 1000 && status < 5000);
}

int mg_set_response_code(struct mg_connection *conn, int status) {
  // 5xx error codes win over everything else (1xx/2xx/3xx/4xx/>=1000)
  // errors (4xx/5xx) win over signals and 'good' codes (1xx/2xx/3xx)
  // signals (3xx) win over 'good' codes (1xx/2xx) but then 2xx codes also win over 3xx and 1xx codes!
  // 1xx signals win over 'good' codes (2xx) but then 2xx codes also win over 3xx and 1xx codes!
  // WebSocket codes (>=1000) win over everything but internal failures (5xx)
  int old_status = conn->request_info.status_code;
  if (!is_legal_response_code(old_status)) {
    conn->request_info.status_code = status;
  } else {
    int old_series = old_status / 100;
    int series = status / 100;
    MG_ASSERT(old_series >= 1);
    MG_ASSERT(series >= 1);
    switch (series) {
    case 2: // 2xx
      // only overrides lower 2xx codes:
      if (old_series == 2 && old_status < status)
        conn->request_info.status_code = status;
      else if (old_series == 3 || old_series == 1)
        conn->request_info.status_code = status;
      break;

    case 1: // 1xx
      if (old_series == 2)
        conn->request_info.status_code = status;
      break;

    case 3: // 3xx
    case 4: // 4xx
      if (old_series < series)
        conn->request_info.status_code = status;
      break;

    default: // WebSocket series
    case 5:  // 5xx
      if (old_series != 5)
        conn->request_info.status_code = status;
      else if (old_status == 500) // more specific 5xx errors win over generic 500
        conn->request_info.status_code = status;
      break;
    }
  }
  return conn->request_info.status_code;
}

// HTTP 1.1 assumes keep alive if "Connection:" header is not set
// This function must tolerate situations when connection info is not
// set up, for example if request parsing failed.
static int should_keep_alive(struct mg_connection *conn) {
  const char *http_version = conn->request_info.http_version;
  if (conn->is_client_conn) {
    const char *header = mg_get_tx_header(conn, "Connection");

    DEBUG_TRACE(0x0002,
                ("CLIENT: must_close: %d, keep-alive: %s, header: %s / ver: %s, stop: %d",
                 (int)conn->must_close,
                 get_conn_option(conn, ENABLE_KEEP_ALIVE),
                 header, http_version,
                 mg_get_stop_flag(conn->ctx)));

    return (!conn->must_close &&
            !mg_strcasecmp(get_conn_option(conn, ENABLE_KEEP_ALIVE), "yes") &&
            (header == NULL ?
             (http_version && !strcmp(http_version, "1.1")) :
             !mg_strcasecmp(header, "keep-alive")) &&
            conn->ctx->stop_flag == 0);
  } else {
    const char *header = mg_get_header(conn, "Connection");

    DEBUG_TRACE(0x0002,
                ("must_close: %d, status: %d, legal: %d, keep-alive: %s, header: %s / ver: %s, stop: %d",
                 (int)conn->must_close,
                 (int)conn->request_info.status_code,
                 (int)is_legal_response_code(conn->request_info.status_code),
                 get_conn_option(conn, ENABLE_KEEP_ALIVE),
                 header, http_version,
                 mg_get_stop_flag(conn->ctx)));

    return (!conn->must_close &&
            conn->request_info.status_code != 401 &&
            conn->request_info.status_code != 400 &&
            // only okay persistence when we see legal response codes;
            // anything else means we're foobarred ourselves already,
            // so it's time to close and let them retry.
            conn->request_info.status_code < 500 &&
            is_legal_response_code(conn->request_info.status_code) &&
            !mg_strcasecmp(get_conn_option(conn, ENABLE_KEEP_ALIVE), "yes") &&
            (header == NULL ?
             (http_version && !strcmp(http_version, "1.1")) :
             !mg_strcasecmp(header, "keep-alive")) &&
            conn->ctx->stop_flag == 0);
  }
}

static const char *suggest_connection_header(struct mg_connection *conn) {
  int rv = should_keep_alive(conn);
  DEBUG_TRACE(0x0002, (" --> %s", (rv ? "keep-alive" : "close")));
  return rv ? "keep-alive" : "close";
}

static const char *mg_get_allowed_methods(struct mg_connection *conn) {
  const char *allowed = get_conn_option(conn, ALLOWED_METHODS);
  if (is_empty(allowed))
    allowed = "GET,POST,HEAD,PUT,DELETE,OPTIONS";
  return allowed;
}

// Return negative value on error; otherwise number of bytes saved by compacting.
//
// NOTE: we MAY also be storing the URI+QUERY strings in the TX buffer,
//       which we can quickly detect inside here and then we take care to keep those
//       strings intact as well, though these will be relocated, just like the
//       tx_headers[] themselves.
//       This is extremely useful for client-side mg_connect()-based HTTP connections
//       as available in mongoose. (See also: mg_write_http_request_head())
static int compact_tx_headers(struct mg_connection *conn) {
  // C89 doesn't allow run-time dimensioned arrays so we use alloca() instead:
  char *buf;
  int i, n, l;
  struct mg_header hdrs[ARRAY_SIZE(conn->request_info.response_headers)];
  int cache_uri_query_str_in_txbuf;
  char *tx_buf;
  char *d;
  int space;

  if (!conn->buf_size) // mg_connect() creates connections without header buffer space
    return -1;

  if (!conn->tx_can_compact_hdrstore)
    return 0;

  tx_buf = conn->buf + conn->buf_size + CHUNK_HEADER_BUFSIZ;

  buf = mg_malloca(conn->buf_size);
  MG_ASSERT(buf);
  if (!buf) goto fail_dramatically;

  // detect whether the URI+QUERY are stored in the TX section:
  cache_uri_query_str_in_txbuf = ((conn->request_info.uri >= tx_buf &&
                                   conn->request_info.uri < tx_buf + conn->buf_size) ||
                                  (conn->tx_can_compact_hdrstore & 2));
  d = buf;
  space = conn->buf_size;

  // when they are, copy them to the start of SCRATCH space if they aren't there already
  if (cache_uri_query_str_in_txbuf) {
    l = (int)mg_strlcpy(d, conn->request_info.uri, space) + 1;
    conn->request_info.uri = tx_buf;
    d += l;
    tx_buf += l;
    space -= l;
    if (is_empty(conn->request_info.query_string)) {
      conn->request_info.query_string = "";
      l = 0;
    } else if (space > 0) {
      l = (int)mg_strlcpy(d, conn->request_info.query_string, space) + 1;
    } else {
      goto fail_dramatically;
    }
    conn->request_info.query_string = tx_buf;
    d += l;
    tx_buf += l;
    space -= l;
    if (space < 6)
      goto fail_dramatically;
    // remember offset:
    cache_uri_query_str_in_txbuf = conn->buf_size - space;
  }

  // now perform the header compaction process:
  n = conn->request_info.num_response_headers;
  for (i = 0; i < n; i++) {
    l = (int)mg_strlcpy(d, conn->request_info.response_headers[i].name, space) + 1;
    d[l] = conn->request_info.response_headers[i].name[l]; // copy 'edited/added' marker too!
    // calc new name+value pointers for when we're done with the compact cycle:
    hdrs[i].name = tx_buf;
    l++;
    d += l;
    tx_buf += l;
    space -= l;
    if (space <= 2)
      goto fail_dramatically;
    l = (int)mg_strlcpy(d, conn->request_info.response_headers[i].value, space);
    hdrs[i].value = tx_buf;
    l += 2;
    d += l;
    tx_buf += l;
    space -= l;
    if (space <= 2)
      goto fail_dramatically;
  }
  conn->tx_can_compact_hdrstore = 0;
  n = conn->buf_size - space;

  memcpy(conn->request_info.response_headers, hdrs, sizeof(hdrs));
  tx_buf = conn->buf + conn->buf_size + CHUNK_HEADER_BUFSIZ;
  memcpy(tx_buf, buf, n);

  l = conn->tx_headers_len - n;         // how many bytes did we 'gain' by compacting?
  conn->tx_headers_len = n;
  // delta can be negative when URI+query_string were pulled into the buffer space!
  if (l < 0)
  l = 0;
  mg_freea(buf);
  return l;

fail_dramatically:
  mg_freea(buf);
  return -1;
}

int mg_remove_response_header(struct mg_connection *conn, const char *tag) {
  int i = -1;
  int found = 0;

  if (is_empty(tag) || !conn->buf_size) // mg_connect() creates connections without header buffer space
    return -1;

  // check whether tag is already listed in the set:
  for (i = conn->request_info.num_response_headers; i-- > 0; ) {
    const char *key = conn->request_info.response_headers[i].name;

    if (!mg_strcasecmp(tag, key)) {
      // ditch the key + value:
      found++;
      conn->request_info.response_headers[i].name = NULL;
    }
  }
  // keep the order of the keys intact: compact the header set once we've removed all 'tag' occurrences
  if (found) {
    int n = conn->request_info.num_response_headers;
    for (i = 0; i < n; i++) {
      if (!conn->request_info.response_headers[i].name) {
        int j;

        for (j = i + 1; j < n; j++) {
          if (conn->request_info.response_headers[j].name) {
            conn->request_info.response_headers[i++] = conn->request_info.response_headers[j];
          }
        }
        break;
      }
    }
    conn->request_info.num_response_headers = i;
    conn->tx_can_compact_hdrstore |= 1;
  }
  return found;
}

int mg_add_response_header(struct mg_connection *conn, int force_add, const char *tag, const char *value_fmt, ...) {
  va_list ap;
  int rv;

  va_start(ap, value_fmt);
  rv = mg_vadd_response_header(conn, force_add, tag, value_fmt, ap);
  va_end(ap);
  return rv;
}

int mg_vadd_response_header(struct mg_connection *conn, int force_add, const char *tag, const char *value_fmt, va_list ap) {
  int i = -1;
  int n, space;
  char *dst;
  char *bufbase;

  if (is_empty(tag) || !conn->buf_size) // mg_connect() creates connections without header buffer space
    return -1;
  if (!value_fmt)
    value_fmt = "";

  if (mg_have_headers_been_sent(conn) && !conn->tx_is_in_chunked_mode) {
    mg_cry(conn, "%s: can't add headers after the header has been sent and the connection is NOT in chunked tranfer mode for outgoing traffic", __func__);
    return -1;
  }

  bufbase = conn->buf + conn->buf_size + CHUNK_HEADER_BUFSIZ;
  dst = bufbase + conn->tx_headers_len;
  space = conn->buf_size - conn->tx_headers_len;

  if (!force_add) {
    // check whether tag is already listed in the set:
    for (i = conn->request_info.num_response_headers; i-- > 0; ) {
      const char *key = conn->request_info.response_headers[i].name;

      if (!mg_strcasecmp(tag, key)) {
        // re-use the tag, ditch the value:
        conn->tx_can_compact_hdrstore |= 1;
        (&bufbase[key - bufbase])[strlen(key) + 1] = '!'; // mark tag as edited/added
        break;
      }
    }
  }
  if (i < 0) { // this tag wasn't found: add it
    force_add = 1;
    i = conn->request_info.num_response_headers;
    if (i >= (int)ARRAY_SIZE(conn->request_info.response_headers)) {
      mg_cry(conn, "%s: too many headers", __func__);
      return -1;
    }
    for(;;) {
      n = (int)mg_strlcpy(dst, tag, space);
      if (n + 6 < space) // NUL+[?] + empty value + NUL+[?]+[?]+[?]
        break;
      // we need to compact and retry, and when it still fails then, we're toast.
      if (compact_tx_headers(conn) <= 0) {
        mg_cry(conn, "%s: header buffer overflow for key %s", __func__, tag);
        return -1;
      }
      dst = bufbase + conn->tx_headers_len;
      space = conn->buf_size - conn->tx_headers_len;
    }
    conn->request_info.response_headers[i].name = dst;
    // To make sure that the optional compact routine
    // in the next loop (write tag value) keeps this TAG,
    // we need to make it a valid entry and account of it!
    //
    // To do so, we fake a NIL value for now, making the
    // 'set value' loop below an UPDATE operation always.
    conn->request_info.response_headers[i].value = dst + n; // point at the NUL sentinel
    MG_ASSERT(i <= conn->request_info.num_response_headers);
    if (i == conn->request_info.num_response_headers)
      conn->request_info.num_response_headers++;

    dst[n + 1] = '!'; // mark tag as edited/added
    n += 2; // include NUL+[?] sentinel in count
    conn->tx_headers_len += n;
    dst += n;
    space -= n;
  }

  // now store the value:
  for(;;) {
    n = mg_vsnq0printf(conn, dst, space, value_fmt, ap);
    // n==0 is also possible when snprintf() fails dramatically (see notes in mg_snq0printf() et al)
    if (n + 4 < space && n > 0) // + NUL+[?]+[?]+[?]
      break;
    // only accept n==0 when the value_fmt is empty and there's nothing to compact or (heuristic!) when there's 'sufficient space' to write:
    if (n == 0 && 4 < space && (!conn->tx_can_compact_hdrstore || is_empty(value_fmt) || space >= MG_MAX(MG_BUF_LEN, conn->buf_size / 4)))
      break;
    // we need to compact and retry, and when it still fails then, we're toast.
    if (compact_tx_headers(conn) <= 0) {
      mg_cry(conn, "%s: header buffer overflow for key %s", __func__, tag);
      return -1;
    }
    dst = bufbase + conn->tx_headers_len;
    space = conn->buf_size - conn->tx_headers_len;
  }
  conn->request_info.response_headers[i].value = dst;
  MG_ASSERT(i < conn->request_info.num_response_headers);
  n += 2; // include NUL+[?] sentinel in count
  conn->tx_headers_len += n;
  //dst += n;
  //space -= n;

  // now we know we still have two extra bytes free space; this is used in mg_write_http_response_head()

  // check for special headers: Content-Length and 'Transfer-Encoding: chunked' are mutually exclusive
  if (mg_strcasecmp("Content-Length", tag) == 0) {
    mg_remove_response_header(conn, "Transfer-Encoding");
  } else if (mg_strcasecmp("Transfer-Encoding", tag) == 0 &&
             mg_stristr(dst, "chunked")) {
    mg_remove_response_header(conn, "Content-Length");
  }
  return 0;
}

const char *mg_get_response_header(const struct mg_connection *conn, const char *tag) {
  int i;

  if (is_empty(tag) || !conn->buf_size) // mg_connect() creates connections without header buffer space
    return NULL;

  for (i = conn->request_info.num_response_headers; i-- > 0; ) {
    const char *key = conn->request_info.response_headers[i].name;

    if (!mg_strcasecmp(tag, key)) {
      return conn->request_info.response_headers[i].value;
    }
  }
  return NULL;
}

static int write_http_head(struct mg_connection *conn, PRINTF_FORMAT_STRING(const char *first_line_fmt), ...) PRINTF_ARGS(2, 3);

// Return number of bytes sent; return 0 when nothing was done; -1 on error.
static int write_http_head(struct mg_connection *conn, const char *first_line_fmt, ...) {
  int i, n, rv, rv2, tx_len;
  char *buf;
  const char *te_tag;
  const char *cl_tag;
  const char *ka_tag;
  const char *cls;
  va_list ap;
  const char *http_version = conn->request_info.http_version;

  if (mg_have_headers_been_sent(conn))
    return 0;

  MG_ASSERT(!is_empty(http_version));

  // make sure must_close state and Connection: output are in sync
  ka_tag = mg_get_response_header(conn, "Connection");
  if (!conn->must_close) {
    if (ka_tag && mg_strcasecmp(ka_tag, "close") == 0)
      conn->must_close = 1;
  }
  cls = suggest_connection_header(conn);
  // update/set the Connection: keep-alive header as we now know the Status Code:
  if (!ka_tag || mg_strcasecmp(ka_tag, cls)) {
    if (mg_add_response_header(conn, 0, "Connection", cls))
      return -1;
  }

  // detect whether we're going to send in 'chunked' or 'full' mode:
  // check for the appropriate headers
  // or whether the user already set the chunked mode explicitly.
  //
  // Content-Length ALWAYS wins over chunked transfer mode.
  //
  // When you transmit in HTTP/1.1 and didn't specify the Content-Length
  // header, then chunked transfer mode will be assumed implicitly.
  te_tag = mg_get_response_header(conn, "Transfer-Encoding");
  cl_tag = mg_get_response_header(conn, "Content-Length");
  if (!is_empty(cl_tag)) {
    MG_ASSERT(is_empty(te_tag)); // mg_add_response_header() must've taken care of this before
    mg_set_tx_mode(conn, MG_IOMODE_STANDARD);
  } else if (strcmp(http_version, "1.1") >= 0) {
    // there's no absolute need to set 'chunked' transfer mode when
    // we're closing the connection after this request (so you'd get
    // HTTP/1.0 alike GET requests then); we do this to allow basic
    // GET requests to be sent to non-fully HTTP/1.1 compliant servers,
    // e.g. other (older or 'vanilla') mongoose servers, without them
    // barfing a hairball over the chunked headers -- when they don't
    // cope with the Transfer-Encoding header (e.g. older/vanilla mongoose).
    //
    // This is a KNOWN DEVIATION from the strict interpretation of
    // the HTTP/1.1 spec. It is harmless.
    if (conn->tx_is_in_chunked_mode || !conn->must_close ||
        mg_strcasecmp(conn->request_info.request_method, "GET")) {
      if (is_empty(te_tag)) {
        if (mg_add_response_header(conn, 0, "Transfer-Encoding", "chunked"))
          return -1;
      }
      if (!conn->tx_is_in_chunked_mode) {
        mg_set_tx_mode(conn, MG_IOMODE_CHUNKED_HEADER);
      }
    }
  } else if (!conn->must_close) {
    // HTTP/1.0, but not marked as a 'closing' connection yet!
    conn->must_close = 1;
    if (mg_add_response_header(conn, 0, "Connection", "close"))
      return -1;
  }

  /*
  The code further below expects all headers to be stored in memory 'in order'.

  This assumption holds when headers have only been added, never
  removed or replaced, OR when compact_tx_headers() has run
  after the last replace/remove operation.
  */
  if (compact_tx_headers(conn) < 0)
    return -1;

  va_start(ap, first_line_fmt);
  rv = mg_vprintf(conn, first_line_fmt, ap);
  va_end(ap);
  if (rv <= 0)
    return -1; // malformed first line or transmit failure.

  /*
  Once we are sure of the header order assumption, this becomes an
  'in place' operation, where NUL sentinels are temporarily replaced
  with ": " and "\r\n" respectively.

  Since the assumption above is now assured, we know that the very
  first header starts at the beginning of the buffer, after the optionally
  stored uri+query_string!
  */
  n = conn->request_info.num_response_headers;
  if (n) {
    buf = conn->buf + conn->buf_size + CHUNK_HEADER_BUFSIZ;
    MG_ASSERT(conn->request_info.response_headers[0].name >= conn->buf + conn->buf_size + CHUNK_HEADER_BUFSIZ);
    MG_ASSERT(conn->request_info.response_headers[0].name < conn->buf + conn->buf_size + CHUNK_HEADER_BUFSIZ + conn->buf_size);
    conn->request_info.response_headers[0].value[-2] = ':';
    conn->request_info.response_headers[0].value[-1] = ' ';
    for (i = 1; i < n; i++) {
      struct mg_header *h = conn->request_info.response_headers + i;

      h->name[-2] = '\r';
      h->name[-1] = '\n';
      h->value[-2] = ':';
      h->value[-1] = ' ';
    }
    buf[conn->tx_headers_len - 2] = '\r';
    buf[conn->tx_headers_len - 1] = '\n';
    MG_ASSERT(conn->tx_headers_len + 2 + (buf - conn->buf - conn->buf_size - CHUNK_HEADER_BUFSIZ) <= conn->buf_size);
    buf[conn->tx_headers_len] = '\r';
    buf[conn->tx_headers_len + 1] = '\n';

    tx_len = conn->tx_headers_len + 2 - (conn->request_info.response_headers[0].name - buf);
    rv2 = mg_write(conn, conn->request_info.response_headers[0].name, tx_len);
    if (rv2 != tx_len)
      rv = -1;
    else
      rv += rv2;

    /*
    Error or success, always restore the header set to its original
    glory.
    */
    conn->request_info.response_headers[0].value[-2] = 0;
    for (i = 1; i < n; i++) {
      struct mg_header *h = conn->request_info.response_headers + i;

      h->name[-2] = 0;
      h->value[-2] = 0;
    }
    buf[conn->tx_headers_len - 2] = 0;
  } else {
    rv2 = mg_write(conn, "\r\n", 2);
    if (rv2 != 2)
      rv = -1;
    else
      rv += rv2;
  }

  mg_mark_end_of_header_transmission(conn);

  return rv;
}

int mg_write_http_response_head(struct mg_connection *conn, int status_code, const char *status_text) {
  const char *http_version = conn->request_info.http_version;

  if (is_empty(http_version))
    http_version = conn->request_info.http_version = "1.1";

  if (status_code <= 0)
    status_code = conn->request_info.status_code;
  else
    status_code = mg_set_response_code(conn, status_code);
  if (is_empty(status_text))
    status_text = mg_get_response_code_text(status_code);

  mg_set_response_code(conn, status_code);

  return write_http_head(conn, "HTTP/%s %d %s\r\n", http_version, status_code, status_text);
}

/*
Send HTTP error response headers, if we still can. Log the error anyway.

'reason' may be NULL, in which case the default RFC2616 response code text will be used instead.

'fmt' + args is the content sent along as error report (request response).
*/
static void vsend_http_error(struct mg_connection *conn, int status,
                             const char *reason, const char *fmt, va_list ap) {
  char buf[MG_BUF_LEN];
  int len;
  int custom_len;

  if (!reason) {
    reason = mg_get_response_code_text(status);
  }

  buf[0] = '\0';
  custom_len = 0;
  len = mg_snprintf(conn, buf, sizeof(buf) - 2, "Error %d: %s", status, reason);
  if (!is_empty(fmt)) {
    custom_len = mg_vsnprintf(conn, buf + len + 1, sizeof(buf) - len - 1, fmt, ap);
    if (custom_len > 0) {
      buf[len++] ='\t';
      len += custom_len;
    }
    MG_ASSERT(len == (int)strlen(buf));
  }

  status = mg_set_response_code(conn, status);
  conn->request_info.status_custom_description = buf;

  if (status == 405) {
    mg_add_response_header(conn, 0, "Allow", mg_get_allowed_methods(conn));
  }

  if (call_user(conn, MG_HTTP_ERROR) == NULL) {
    char *p;
    // also override the 'reason' text when the status code
    // didn't make it or was altered in the callback:
    if (status != conn->request_info.status_code)
      reason = mg_get_response_code_text(conn->request_info.status_code);
    status = conn->request_info.status_code;
    if (conn->request_info.status_custom_description)
      len = (int)strlen(conn->request_info.status_custom_description);
    else
      conn->request_info.status_custom_description = buf;
    MG_ASSERT(len == (int)strlen(conn->request_info.status_custom_description));
    p = strchr(conn->request_info.status_custom_description, '\t');
    if (p)
      *p = 0;

    mg_cry(conn, "%s: %s (HTTP v%s: %s %s%s%s) %s",
           __func__, conn->request_info.status_custom_description,
           (conn->request_info.http_version ? conn->request_info.http_version : "(unknown)"),
           (conn->request_info.request_method ? conn->request_info.request_method : "???"),
           (conn->request_info.uri ? conn->request_info.uri : "???"),
           (!is_empty(conn->request_info.query_string) ? "?" : ""),
           (!is_empty(conn->request_info.query_string) ? conn->request_info.query_string : ""),
           (p ? p + 1 : ""));

    // Errors 1xx, 204 and 304 MUST NOT send a body
    if (status > 199 && status != 204 && status != 304) {
      if (p)
        *p = '\n';
    } else {
      len = 0;
    }
    DEBUG_TRACE(0x0401, ("[%s]", conn->request_info.status_custom_description));

    // do NOT produce the nested error (allow parent to send its own error page/info to client):
    if (!mg_have_headers_been_sent(conn) && !mg_is_producing_nested_page(conn)) {
      const char *errflist = get_conn_option(conn, ERROR_FILE);
      struct vec filename_vec;
      struct vec status_vec;

      // Traverse error files list. If an entry matches the given status_code, break the loop.
      // '0' is treated as a wildcard match.
      while ((errflist = next_option(errflist, &status_vec, &filename_vec)) != NULL) {
        int v = atoi(status_vec.ptr);

        if (v == 0 || v == status)
          break;
      }
      // output basic HTTP response when either no error content is allowed (len == 0)
      // or when the error page production failed and hasn't yet written the headers itself.
      if (len == 0 ||
          // no use making the effort of a custom page production when the connection is severely clobbered
          conn->request_len <= 0 ||
          conn->client.write_error ||
          conn->client.read_error ||
          mg_produce_nested_page(conn, filename_vec.ptr, filename_vec.len)) {
        if (!mg_have_headers_been_sent(conn)) {
          /* issue #229: Only include the content-length if there is a response body.
           Otherwise an incorrect Content-Type generates a warning in
           some browsers when a static file request returns a 304
           "not modified" error. */
          if (len > 0) {
            mg_add_response_header(conn, 0, "Content-Length", "%d", len);
            mg_add_response_header(conn, 0, "Content-Type", "text/plain");
          }
          //mg_add_response_header(conn, 0, "Connection", suggest_connection_header(conn)); -- not needed any longer
          mg_write_http_response_head(conn, status, reason);

          if (len > 0) {
            MG_ASSERT(len == (int)strlen(conn->request_info.status_custom_description));
            if (mg_write(conn, conn->request_info.status_custom_description, len) != len) {
              conn->must_close = 1;
            }
          }
          if (mg_flush(conn) != 0) {
            conn->must_close = 1;
          }
        } else {
          conn->must_close = 1;
        }
      }
    } else if (mg_is_producing_nested_page(conn)) {
      // mark nested error anyhow
      conn->nested_err_or_pagereq_count = 2;
    }
  } else if (mg_is_producing_nested_page(conn)) {
    // mark nested error anyhow
    conn->nested_err_or_pagereq_count = 2;
  }
  // kill lingering reference to local storage:
  conn->request_info.status_custom_description = NULL;
}

static void send_http_error(struct mg_connection *conn, int status,
  const char *reason, PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(4, 5);

static void send_http_error(struct mg_connection *conn, int status,
                            const char *reason, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vsend_http_error(conn, status, reason, fmt, ap);
  va_end(ap);
}

#if defined(_WIN32) && !defined(__SYMBIAN32__)

#if !defined(HAVE_PTHREAD)

int pthread_mutex_init(pthread_mutex_t *mutex, UNUSED_PARAMETER(void *unused)) {
  *mutex = CreateMutex(NULL, FALSE, NULL);
  return *mutex == NULL ? -1 : 0;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex) {
  return CloseHandle(*mutex) == 0 ? -1 : 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex) {
  return WaitForSingleObject(*mutex, INFINITE) == WAIT_OBJECT_0 ? 0 : -1;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
  return ReleaseMutex(*mutex) == 0 ? -1 : 0;
}

int pthread_spin_init(pthread_spinlock_t *lock, UNUSED_PARAMETER(int unused)) {
  return pthread_mutex_init(lock, 0);
}
int pthread_spin_destroy(pthread_spinlock_t *lock) {
  return pthread_mutex_destroy(lock);
}
int pthread_spin_lock(pthread_spinlock_t *lock) {
  return pthread_mutex_lock(lock);
}
//int pthread_spin_trylock(pthread_spinlock_t *lock) {
// ...
//}
int pthread_spin_unlock(pthread_spinlock_t *lock) {
  return pthread_mutex_unlock(lock);
}

int pthread_cond_init(pthread_cond_t *cv, UNUSED_PARAMETER(const void *unused)) {
  cv->signal = CreateEvent(NULL, FALSE, FALSE, NULL);
  cv->broadcast = CreateEvent(NULL, TRUE, FALSE, NULL);
  return cv->signal != NULL && cv->broadcast != NULL ? 0 : -1;
}

int pthread_cond_wait(pthread_cond_t *cv, pthread_mutex_t *mutex) {
  HANDLE handles[] = {cv->signal, cv->broadcast};
  ReleaseMutex(*mutex);
  WaitForMultipleObjects(2, handles, FALSE, INFINITE);
  return WaitForSingleObject(*mutex, INFINITE) == WAIT_OBJECT_0 ? 0 : -1;
}

int pthread_cond_timedwait(pthread_cond_t *cv, pthread_mutex_t *mutex, const struct timespec *abstime) {
  HANDLE handles[] = {cv->signal, cv->broadcast};
  DWORD period = abstime->tv_sec * 1000 + abstime->tv_nsec / 1000000;
  DWORD rv;
  ReleaseMutex(*mutex);
  rv = WaitForMultipleObjects(2, handles, FALSE, period);
  return WaitForSingleObject(*mutex, INFINITE) == WAIT_OBJECT_0 ? (rv == WAIT_TIMEOUT ? ETIMEOUT : 0) : -1;
}

int pthread_cond_signal(pthread_cond_t *cv) {
  return SetEvent(cv->signal) == 0 ? -1 : 0;
}

int pthread_cond_broadcast(pthread_cond_t *cv) {
  // Implementation with PulseEvent() has race condition, see
  // http://www.cs.wustl.edu/~schmidt/win32-cv-1.html
  return PulseEvent(cv->broadcast) == 0 ? -1 : 0;
}

int pthread_cond_destroy(pthread_cond_t *cv) {
  return CloseHandle(cv->signal) && CloseHandle(cv->broadcast) ? 0 : -1;
}

pthread_t pthread_self(void) {
  return GetCurrentThreadId();
}

struct __pthread_thread_func_args {
  mg_thread_func_t func;
  void *arg;
  void *return_value;
  unsigned return_value_set: 1;
  pthread_t thread_id;
  HANDLE thread_h;

  struct __pthread_thread_func_args *next;
};

static pthread_spinlock_t __pthread_list_lock;
static struct __pthread_thread_func_args *__pthread_list = NULL;

static unsigned int __stdcall __pthread_starter_func(void *arg) {
  struct __pthread_thread_func_args *a = (struct __pthread_thread_func_args *)arg;
  DWORD id = GetCurrentThreadId();
  void *rv;
  struct __pthread_thread_func_args *l, *o;
  pthread_spin_lock(&__pthread_list_lock);
  l = __pthread_list;
  while (l && l->thread_id != id) {
    l = l->next;
  }
  pthread_spin_unlock(&__pthread_list_lock);
  MG_ASSERT(l);
  MG_ASSERT(l == a);

  rv = a->func(a->arg);
  if (a->return_value_set)
    rv = a->return_value;

  pthread_spin_lock(&__pthread_list_lock);
  o = NULL;
  l = __pthread_list;
  while (l && l->thread_id != id) {
      o = l;
      l = l->next;
  }
  if (o && l) {
      o->next = l->next;
      l->next = NULL;
  } else if (l) {
      MG_ASSERT(l == __pthread_list);
      __pthread_list = l->next;
      l->next = NULL;
  }
  pthread_spin_unlock(&__pthread_list_lock);

  _endthreadex((unsigned int)rv);
  CloseHandle(l->thread_h);
  free(l);
  return (unsigned int)rv;
}

int pthread_create(pthread_t * tid, UNUSED_PARAMETER(const pthread_attr_t * attr), mg_thread_func_t start, void *arg) {
  struct __pthread_thread_func_args *a = calloc(1, sizeof(*a));
  unsigned int t;
  uintptr_t rv;
  if (!a)
    return -1;
  a->arg = arg;
  a->func = start;
  if (!__pthread_list) {
    pthread_spin_init(&__pthread_list_lock, PTHREAD_PROCESS_PRIVATE);
  }
  rv = _beginthreadex(NULL, 0, __pthread_starter_func, a, CREATE_SUSPENDED, &t);
  if (rv != 0) {
    *tid = t;
    a->thread_id = t;
    a->thread_h = (HANDLE)rv;
    pthread_spin_lock(&__pthread_list_lock);
    a->next = __pthread_list;
    __pthread_list = a;
    pthread_spin_unlock(&__pthread_list_lock);
    ResumeThread(a->thread_h);
  }
  return (rv != 0) ? 0 : errno;
}

void pthread_exit(void *value_ptr) {
  DWORD id = GetCurrentThreadId();
  struct __pthread_thread_func_args *l;
  pthread_spin_lock(&__pthread_list_lock);
  l = __pthread_list;
  while (l && l->thread_id != id) {
    l = l->next;
  }
  pthread_spin_unlock(&__pthread_list_lock);
  MG_ASSERT(l);
  if (!l->return_value_set) {
    l->return_value = value_ptr;
    l->return_value_set = 1;
  }
}


// rwlock types have been moved to mongoose_sys_porting.h

#if USE_SRWLOCK         // Windows 7 / Server 2008 with the correct header files, i.e. this also 'fixes' MingW casualties

int pthread_rwlock_init(pthread_rwlock_t *rwlock, const pthread_rwlockattr_t *attr) {
  InitializeSRWLock(&rwlock->lock);
  return 0;
}

int pthread_rwlock_destroy(pthread_rwlock_t *rwlock) {
  // empty
  return 0;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock) {
  AcquireSRWLockShared(&rwlock->lock);
  rwlock->rw = 0;
  return 0;
}

int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock) {
  AcquireSRWLockExclusive(&rwlock->lock);
  rwlock->rw = 1;
  return 0;
}

int pthread_rwlock_unlock(pthread_rwlock_t *rwlock) {
  if (rwlock->rw) {
    ReleaseSRWLockExclusive(&rwlock->lock);
  } else {
    ReleaseSRWLockShared(&rwlock->lock);
  }
  return 0;
}

#else  // emulate methods for other Win systems / compiler platforms - use a very blunt approach.

int pthread_rwlock_init(pthread_rwlock_t *rwlock, UNUSED_PARAMETER(const pthread_rwlockattr_t *attr)) {
  return pthread_mutex_init(&rwlock->mutex, NULL);
}

int pthread_rwlock_destroy(pthread_rwlock_t *rwlock) {
  return pthread_mutex_destroy(&rwlock->mutex);
}

int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock) {
  int rv = pthread_mutex_lock(&rwlock->mutex);
  rwlock->rw = 0;
  return rv;
}

int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock) {
  int rv = pthread_mutex_lock(&rwlock->mutex);
  rwlock->rw = 1;
  return rv;
}

int pthread_rwlock_unlock(pthread_rwlock_t *rwlock) {
  return pthread_mutex_unlock(&rwlock->mutex);
}

#endif

#endif


// For Windows, change all slashes to backslashes in path names.
static void change_slashes_to_backslashes(char *path) {
  int i;

  for (i = 0; path[i] != '\0'; i++) {
    if (path[i] == '/')
      path[i] = '\\';
    // i > 0 check is to preserve UNC paths, like \\server\file.txt
    if (path[i] == '\\' && i > 0)
      while (path[i + 1] == '\\' || path[i + 1] == '/')
        (void) memmove(path + i + 1,
            path + i + 2, strlen(path + i + 1));
  }
}

// Encode 'path' which is assumed UTF-8 string, into UNICODE string.
// wbuf and wbuf_len is a target buffer and its length.
static void to_unicode(const char *path, wchar_t *wbuf, size_t wbuf_len) {
  char buf[PATH_MAX], buf2[PATH_MAX], *p;

  mg_strlcpy(buf, path, sizeof(buf));
  change_slashes_to_backslashes(buf);

  // Point p to the end of the file name
  p = buf + strlen(buf) - 1;

  // Trim trailing backslash character
  while (p > buf && *p == '\\' && p[-1] != ':') {
    *p-- = '\0';
  }

  // Protect from CGI code disclosure.
  // This is very nasty hole. Windows happily opens files with
  // some garbage in the end of the file name. So fopen("a.cgi    ", "r")
  // actually opens "a.cgi", and does not return an error!
  if (*p == 0x20 ||               // No space at the end
      (*p == 0x2e && p > buf) ||  // No '.' but allow '.' as full path
      *p == 0x2b ||               // No '+'
      (*p & ~0x7f)) {             // And generally no non-ASCII chars
    mg_cry(NULL, "Rejecting suspicious path: [%s]", buf);
    wbuf[0] = L'\0';
  } else {
    // Convert to Unicode and back. If doubly-converted string does not
    // match the original, something is fishy, reject.
    memset(wbuf, 0, wbuf_len*sizeof(wchar_t)); // <bel>: fix otherwise an "uninitialized memory read in WideCharToMultiByte" occurs
    if (!MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, (int) wbuf_len) ||
        !WideCharToMultiByte(CP_UTF8, 0, wbuf, (int) wbuf_len, buf2, sizeof(buf2),
                        NULL, NULL) ||
        strcmp(buf, buf2) != 0) {
      mg_cry(NULL, "Rejecting malicious path: [%s]", buf);
      wbuf[0] = L'\0';
    }
  }
}

#if defined(_WIN32_WCE)
time_t time(time_t *ptime) {
  time_t t;
  SYSTEMTIME st;
  FILETIME ft;

  GetSystemTime(&st);
  SystemTimeToFileTime(&st, &ft);
  t = SYS2UNIX_TIME(ft.dwLowDateTime, ft.dwHighDateTime);

  if (ptime != NULL) {
    *ptime = t;
  }

  return t;
}

struct tm *localtime(const time_t *ptime, struct tm *ptm) {
  int64_t t = ((int64_t) *ptime) * RATE_DIFF + EPOCH_DIFF;
  FILETIME ft, lft;
  SYSTEMTIME st;
  TIME_ZONE_INFORMATION tzinfo;

  if (ptm == NULL) {
    return NULL;
  }

  * (int64_t *) &ft = t;
  FileTimeToLocalFileTime(&ft, &lft);
  FileTimeToSystemTime(&lft, &st);
  ptm->tm_year = st.wYear - 1900;
  ptm->tm_mon = st.wMonth - 1;
  ptm->tm_wday = st.wDayOfWeek;
  ptm->tm_mday = st.wDay;
  ptm->tm_hour = st.wHour;
  ptm->tm_min = st.wMinute;
  ptm->tm_sec = st.wSecond;
  ptm->tm_yday = 0; // hope nobody uses this
  ptm->tm_isdst =
    GetTimeZoneInformation(&tzinfo) == TIME_ZONE_ID_DAYLIGHT ? 1 : 0;

  return ptm;
}

struct tm *gmtime(const time_t *ptime, struct tm *ptm) {
  // FIXME(lsm): fix this.
  return localtime(ptime, ptm);
}

size_t strftime(char *dst, size_t dst_size, const char *fmt,
                       const struct tm *tm) {
  (void) snprintf(dst, dst_size, "implement strftime() for WinCE");
  return 0;
}
#endif

int mg_mk_fullpath(char *buf, size_t buf_len) {
  wchar_t woldbuf[PATH_MAX];
  wchar_t wnewbuf[PATH_MAX];
  int pos;

  to_unicode(buf, woldbuf, ARRAY_SIZE(woldbuf));
  pos = GetFullPathNameW(woldbuf, ARRAY_SIZE(wnewbuf), wnewbuf, NULL);
  MG_ASSERT(pos < ARRAY_SIZE(wnewbuf));
  wnewbuf[pos] = 0;
  if (!WideCharToMultiByte(CP_UTF8, 0, wnewbuf, pos + 1 /* include NUL sentinel */, buf, (int)buf_len, NULL, NULL))
    return -1;
  pos = (int)strlen(buf);
  while (pos-- > 0) {
    if (buf[pos] == '\\')
      buf[pos] = '/';
  }
  return 0;
}

int mg_rename(const char* oldname, const char* newname) {
  wchar_t woldbuf[PATH_MAX];
  wchar_t wnewbuf[PATH_MAX];

  to_unicode(oldname, woldbuf, ARRAY_SIZE(woldbuf));
  to_unicode(newname, wnewbuf, ARRAY_SIZE(wnewbuf));

  return MoveFileW(woldbuf, wnewbuf) ? 0 : -1;
}


FILE *mg_fopen(const char *path, const char *mode) {
  wchar_t wbuf[PATH_MAX], wmode[20];

  if (!path || !path[0] || !mode || !mode[0]) {
    return NULL;
  }
  if (0 == strcmp("-", path) && 0 == strcmp("a+", mode)) {
    return stderr;
  }

  to_unicode(path, wbuf, ARRAY_SIZE(wbuf));
  if (!MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, ARRAY_SIZE(wmode)))
    return NULL;

  // recursively create the included path when the file is to be created / appended to:
  if (wmode[wcscspn(wmode, L"aw")]) {
    size_t i;

    // skip UNC path starters like '\\?\'
    i = wcsspn(wbuf, L"\\:?");
    // and skip drive specs like 'C:'
    if (i == 0 && wbuf[i] && wbuf[i+1] == L':') {
      i = 2;
      i += wcsspn(wbuf + i, L"\\");
    }
    i += wcscspn(wbuf + i, L"\\");
    while (wbuf[i]) {
      int rv;

      // skip ./ and ../ sections; CAVEAT: due to code simplification, we also skip entries like 'XYZ./' (note the dot at the end) which are flaky path specs anyway
      if (wbuf[i - 1] == L'.') {
        wbuf[i++] = L'\\';
        i += wcscspn(wbuf + i, L"\\");
        continue;
      }
      wbuf[i] = 0;
      rv = _wmkdir(wbuf);
      wbuf[i++] = L'\\';
      if (0 != rv && errno != EEXIST)
        break;
      i += wcscspn(wbuf + i, L"\\");
    }
  }
  return _wfopen(wbuf, wmode);
}

int mg_stat(const char *path, struct mgstat *stp) {
  int ok = -1; // Error
  wchar_t wbuf[PATH_MAX];
  WIN32_FILE_ATTRIBUTE_DATA info;

  if (!path || !stp)
    return -1;

  to_unicode(path, wbuf, ARRAY_SIZE(wbuf));

  if (GetFileAttributesExW(wbuf, GetFileExInfoStandard, &info) != 0) {
    stp->size = MAKEUQUAD(info.nFileSizeLow, info.nFileSizeHigh);
    stp->mtime = SYS2UNIX_TIME(info.ftLastWriteTime.dwLowDateTime,
                               info.ftLastWriteTime.dwHighDateTime);
    stp->is_directory =
      info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
    ok = 0;  // Success
  }

  return ok;
}

int mg_remove(const char *path) {
  wchar_t wbuf[PATH_MAX];
  to_unicode(path, wbuf, ARRAY_SIZE(wbuf));
  return DeleteFileW(wbuf) ? 0 : -1;
}

int mg_mkdir(const char *path, int mode) {
  wchar_t wbuf[PATH_MAX];
  to_unicode(path, wbuf, ARRAY_SIZE(wbuf));
  mode = 0; // Unused
  return CreateDirectoryW(wbuf, NULL) ? 0 : -1;
}

// Implementation of POSIX opendir/closedir/readdir for Windows.
static DIR * opendir(const char *name) {
  DIR *dir = NULL;
  wchar_t wpath[PATH_MAX];
  DWORD attrs;

  if (name == NULL) {
    SetLastError(ERROR_BAD_ARGUMENTS);
  } else if ((dir = (DIR *) malloc(sizeof(*dir))) == NULL) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
  } else {
    to_unicode(name, wpath, ARRAY_SIZE(wpath));
    attrs = GetFileAttributesW(wpath);
    if (attrs != 0xFFFFFFFF &&
        ((attrs & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)) {
      (void) wcscat(wpath, L"\\*");
      dir->handle = FindFirstFileW(wpath, &dir->info);
      dir->result.d_name[0] = '\0';
    } else {
      free(dir);
      dir = NULL;
    }
  }

  return dir;
}

static int closedir(DIR *dir) {
  int result = 0;

  if (dir != NULL) {
    if (dir->handle != INVALID_HANDLE_VALUE)
      result = FindClose(dir->handle) ? 0 : -1;

    free(dir);
  } else {
    result = -1;
    SetLastError(ERROR_BAD_ARGUMENTS);
  }

  return result;
}

static struct dirent *readdir(DIR *dir) {
  struct dirent *result = 0;

  if (dir) {
    if (dir->handle != INVALID_HANDLE_VALUE) {
      result = &dir->result;
      if (!WideCharToMultiByte(CP_UTF8, 0,
          dir->info.cFileName, -1, result->d_name,
          sizeof(result->d_name), NULL, NULL)) {
        return 0;
      }

      if (!FindNextFileW(dir->handle, &dir->info)) {
        (void) FindClose(dir->handle);
        dir->handle = INVALID_HANDLE_VALUE;
      }
    } else {
      SetLastError(ERROR_FILE_NOT_FOUND);
    }
  } else {
    SetLastError(ERROR_BAD_ARGUMENTS);
  }

  return result;
}

#define set_close_on_exec(fd) // No FD_CLOEXEC on Windows

int mg_start_thread(struct mg_context *ctx, mg_thread_func_t func, void *param) {
  int rv;
  pthread_t thread_id;
  pthread_attr_t attr;

#if defined(HAVE_PTHREAD)
  (void) pthread_attr_init(&attr);
  (void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  // (void) pthread_attr_setstacksize(&attr, sizeof(struct mg_connection) * 5);
#endif

  rv = pthread_create(&thread_id, &attr, func, param);
  if (rv == 0) {
    // count this thread too so the master_thread will wait for this one to end as well when we stop.
    (void) pthread_mutex_lock(&ctx->mutex);
    ctx->num_threads++;
    (void) pthread_mutex_unlock(&ctx->mutex);
  }
  return rv;
}

static HANDLE dlopen(const char *dll_name, int flags) {
  wchar_t wbuf[PATH_MAX];
  flags = 0; // Unused
  to_unicode(dll_name, wbuf, ARRAY_SIZE(wbuf));
  return LoadLibraryW(wbuf);
}

#if !defined(NO_CGI)
#define SIGKILL 0
static int kill(pid_t pid, int sig_num) {
  (void) TerminateProcess(pid, sig_num);
  (void) CloseHandle(pid);
  return 0;
}

static pid_t spawn_process(struct mg_connection *conn, const char *prog,
                           char *envblk, char *envp[], int fd_stdin,
                           int fd_stdout, int fd_stderr, const char *dir) {
  HANDLE me;
  char *p;
  const char *interp;
  char cmdline[2 * PATH_MAX], buf[PATH_MAX];
  FILE *fp;
  STARTUPINFOA si = { sizeof(si) };
  PROCESS_INFORMATION pi = { 0 };

  envp = NULL; // Unused

  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;

  me = GetCurrentProcess();
  (void) DuplicateHandle(me, (HANDLE) _get_osfhandle(fd_stdin), me,
      &si.hStdInput, 0, TRUE, DUPLICATE_SAME_ACCESS);
  (void) DuplicateHandle(me, (HANDLE) _get_osfhandle(fd_stdout), me,
      &si.hStdOutput, 0, TRUE, DUPLICATE_SAME_ACCESS);
  (void) DuplicateHandle(me, (HANDLE) _get_osfhandle(fd_stderr), me,
      &si.hStdError, 0, TRUE, DUPLICATE_SAME_ACCESS);

  // If CGI file is a script, try to read the interpreter line
  interp = get_conn_option(conn, CGI_INTERPRETER);
  if (is_empty(interp)) {
    buf[2] = '\0';
    mg_snprintf(conn, cmdline, sizeof(cmdline), "%s%c%s", dir, DIRSEP, prog);
    if ((fp = mg_fopen(cmdline, "r")) != NULL) {
      (void) fgets(buf, sizeof(buf), fp);
      if (buf[0] != '#' || buf[1] != '!') {
        // First line does not start with "#!". Do not set interpreter.
        buf[2] = '\0';
      } else {
        // Trim whitespace in interpreter name
        for (p = &buf[strlen(buf) - 1]; p > buf && isspace(*p); p--) {
          *p = '\0';
        }
      }
      (void) mg_fclose(fp);
    }
    interp = buf + 2;
  }

  (void) mg_snprintf(conn, cmdline, sizeof(cmdline), "%s%s%s%c%s",
                     interp, is_empty(interp) ? "" : " ", dir, DIRSEP, prog);

  DEBUG_TRACE(0x0100, ("Running [%s]", cmdline));
  if (CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
        CREATE_NEW_PROCESS_GROUP, envblk, dir, &si, &pi) == 0) {
    mg_cry(conn, "%s: CreateProcess(%s): %d (%s)",
        __func__, cmdline, ERRNO, mg_strerror(ERRNO));
    pi.hProcess = (pid_t) -1;
  }
  (void) close(fd_stdin);
  (void) close(fd_stdout);
  (void) close(fd_stderr);

  (void) CloseHandle(si.hStdError);
  (void) CloseHandle(si.hStdOutput);
  (void) CloseHandle(si.hStdInput);
  (void) CloseHandle(pi.hThread);

  return (pid_t) pi.hProcess;
}
#endif // !NO_CGI

static int set_non_blocking_mode(SOCKET sock, int on) {
  unsigned long _on = !!on;
  return ioctlsocket(sock, FIONBIO, &_on);
}

#else // WIN32

int mg_mk_fullpath(char *buf, size_t buf_len) {
  char newbuf[PATH_MAX + 1];

  if (!realpath(buf, newbuf))
    return -1;
  mg_strlcpy(buf, newbuf, buf_len);
  return 0;
}

FILE *mg_fopen(const char *path, const char *mode) {
  if (!path || !path[0] || !mode || !mode[0]) {
    return NULL;
  }
  if (0 == strcmp("-", path)) {
    return stderr;
  }

  // recursively create the included path when the file is to be created / appended to:
  if (mode[strcspn(mode, "aw")]) {
    size_t i;
    char *wbuf = strdup(path);

    // skip UNC path starters like '\\?\'
    i = strspn(wbuf, "/:?");
    // and skip drive specs like 'C:'
    if (i == 0 && wbuf[i] && wbuf[i+1] == ':') {
      i = 2;
      i += strspn(wbuf + i, "/");
    }
    i += strcspn(wbuf + i, "/");
    while (wbuf[i]) {
      int rv;

      // skip ./ and ../ sections; CAVEAT: due to code simplification, we also skip entries like 'XYZ./' (note the dot at the end) which are flaky path specs anyway
      if (wbuf[i - 1] == '.') {
        wbuf[i++] = '/';
        i += strcspn(wbuf + i, "/");
        continue;
      }
      wbuf[i] = 0;

#ifndef S_IRWXU
#define S_IRWXU   0755
#endif

      rv = mkdir(wbuf, S_IRWXU);
      wbuf[i++] = '/';
      if (0 != rv && errno != EEXIST)
        break;
      i += strcspn(wbuf + i, "/");
    }
    free(wbuf);
  }
  return fopen(path, mode);
}

int mg_stat(const char *path, struct mgstat *stp) {
  struct stat st;
  int ok;

  if (!path || !stp)
    return -1;

  if (stat(path, &st) == 0) {
    ok = 0;
    stp->size = st.st_size;
    stp->mtime = st.st_mtime;
    stp->is_directory = S_ISDIR(st.st_mode);
  } else {
    ok = -1;
  }

  return ok;
}

static void set_close_on_exec(int fd) {
  (void) fcntl(fd, F_SETFD, FD_CLOEXEC);
}

int mg_start_thread(struct mg_context *ctx, mg_thread_func_t func, void *param) {
  int rv;
  pthread_t thread_id;
  pthread_attr_t attr;

  (void) pthread_attr_init(&attr);
  (void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  // TODO(lsm): figure out why mongoose dies on Linux if next line is enabled
  // (void) pthread_attr_setstacksize(&attr, sizeof(struct mg_connection) * 5);

  rv = pthread_create(&thread_id, &attr, func, param);
  if (rv == 0) {
    // count this thread too so the master_thread will wait for this one to end as well when we stop.
    (void) pthread_mutex_lock(&ctx->mutex);
    ctx->num_threads++;
    (void) pthread_mutex_unlock(&ctx->mutex);
  }
  return rv;
}

#ifndef NO_CGI
static pid_t spawn_process(struct mg_connection *conn, const char *prog,
                           char *envblk, char *envp[], int fd_stdin,
                           int fd_stdout, int fd_stderr, const char *dir) {
  pid_t pid;
  const char *interp;

  envblk = NULL; // Unused

  if ((pid = fork()) == -1) {
    // Parent
    send_http_error(conn, 500, NULL, "fork(): %s", mg_strerror(ERRNO));
    (void) close(fd_stdin);
    (void) close(fd_stdout);
    (void) close(fd_stderr);
  } else if (pid == 0) {
    // Child
    if (chdir(dir) != 0) {
      mg_cry(conn, "%s: chdir(%s): %s", __func__, dir, mg_strerror(ERRNO));
    } else if (dup2(fd_stdin, 0) == -1) {
      mg_cry(conn, "%s: dup2(%d, 0): %s", __func__, fd_stdin, mg_strerror(ERRNO));
    } else if (dup2(fd_stdout, 1) == -1) {
      mg_cry(conn, "%s: dup2(%d, 1): %s", __func__, fd_stdout, mg_strerror(ERRNO));
    } else if (dup2(fd_stderr, 2) == -1) {
      mg_cry(conn, "%s: dup2(%d, 2): %s", __func__, fd_stderr, mg_strerror(ERRNO));
    } else {
      (void) close(fd_stdin);
      (void) close(fd_stdout);
      (void) close(fd_stderr);
      fd_stdin = -1;
      fd_stdout = -1;
      fd_stderr = -1;

      interp = get_conn_option(conn, CGI_INTERPRETER);
      if (is_empty(interp)) {
        (void) execle(prog, prog, NULL, envp);
        mg_cry(conn, "%s: execle(%s): %s", __func__, prog, mg_strerror(ERRNO));
      } else {
        (void) execle(interp, interp, prog, NULL, envp);
        mg_cry(conn, "%s: execle(%s %s): %s", __func__, interp, prog,
               mg_strerror(ERRNO));
      }
    }
    if (fd_stdin != -1) {
      (void) close(fd_stdin);
    }
    if (fd_stdout != -1) {
      (void) close(fd_stdout);
    }
    if (fd_stderr != -1) {
      (void) close(fd_stderr);
    }
    exit(EXIT_FAILURE);
  } else {
    // Parent. Close stdio descriptors
    (void) close(fd_stdin);
    (void) close(fd_stdout);
    (void) close(fd_stderr);
  }

  return pid;
}
#endif // !NO_CGI

static int set_non_blocking_mode(SOCKET sock, int on) {
  int flags = -1;

#if defined(FIONBIO) // VMS
  flags = !!on;
  flags = ioctl(sock, FIONBIO, &flags);
#endif
#if defined(SO_NONBLOCK) // BeOS et al
  flags = !!on;
  flags = setsockopt(sock, SOL_SOCKET, SO_NONBLOCK, &flags, sizeof(flags));
#endif
#if defined(F_GETFL) && defined(F_SETFL)
  flags = fcntl(sock, F_GETFL, 0);
  if (flags != -1) {
#if defined(O_NONBLOCK)
    if (on)
      flags |= O_NONBLOCK;
    else
      flags &= ~O_NONBLOCK;
#endif
#if defined(F_NDELAY)
    if (on)
      flags |= F_NDELAY;
    else
      flags &= ~F_NDELAY;
#endif
    flags = fcntl(sock, F_SETFL, flags);
  }
#endif
  return flags;
}

#endif // _WIN32

int mg_fclose(FILE *fp) {
  if (fp != NULL && fp != stderr && fp != stdout && fp != stdin) {
    return fclose(fp);
  }
  return 0;
}

static void add_to_set(SOCKET fd, fd_set *set, int *max_fd) {
  FD_SET(fd, set);
  if (((int)fd) > *max_fd) {
    *max_fd = (int) fd;
  }
}


#if !defined(NO_SSL)

// Return !0 when the SSL I/O operation should be retried.
// This can happen, for instance, when a renegotiation occurs,
// which can happen at any time during SSL I/O.
//
// http://www.openssl.org/docs/ssl/SSL_get_error.html#
// http://www.openssl.org/docs/ssl/SSL_read.html
// http://www.openssl.org/docs/ssl/SSL_write.html
static int ssl_renegotiation_ongoing(struct mg_connection *conn, int *ret) {
  int rv;

  // renegotiation may occur at any time; facilitate this!
  rv = SSL_get_error(conn->ssl, *ret);
  switch (rv) {
  case SSL_ERROR_NONE:
    return 0;
  case SSL_ERROR_ZERO_RETURN:
    *ret = 0;
    return 0;
  case SSL_ERROR_WANT_READ:
    {
      char buf[256];
      (void)SSL_peek(conn->ssl, buf, sizeof(buf));
    }
  case SSL_ERROR_WANT_WRITE:
  case SSL_ERROR_WANT_CONNECT:
  case SSL_ERROR_WANT_ACCEPT:
  case SSL_ERROR_WANT_X509_LOOKUP:
    // retry the call with the exact same parameters:
    *ret = 0;
    return 1;
  case SSL_ERROR_SYSCALL:
  case SSL_ERROR_SSL:
  default:
    if (*ret >= 0)
      *ret = -1;
    return 0;
  }
}

#else

#define ssl_renegotiation_ongoing(conn, ret)    0

#endif

// Write data to the IO channel - opened file descriptor, socket or SSL
// descriptor. Return number of bytes written.
static int64_t push(FILE *fp, struct mg_connection *conn, const char *buf,
                    int64_t len) {
  int64_t sent;
  int n, k;

  sent = 0;
  while (sent < len) {

    // How many bytes we send in this iteration
    k = len - sent > INT_MAX ? INT_MAX : (int) (len - sent);

    MG_ASSERT(conn ? !conn->client.is_ssl == !conn->ssl : 1);
    if (conn && conn->ssl) {
      do {
        n = SSL_write(conn->ssl, buf + sent, k);
      } while (ssl_renegotiation_ongoing(conn, &n));
      conn->client.write_error = (n < 0);
      if (n == 0)
        break;
    } else if (fp != NULL) {
      n = (int)fwrite(buf + sent, 1, (size_t)k, fp);
      if (ferror(fp))
        n = -1;
    } else if (conn && conn->client.sock != INVALID_SOCKET) {
      /* Ignore "broken pipe" errors (i.e., clients that disconnect instead of waiting for their answer) */
      n = send(conn->client.sock, buf + sent, (size_t) k, MSG_NOSIGNAL);
      conn->client.write_error = (n < 0);
    } else {
      n = -1;
    }

    if (n < 0)
      break;

    sent += n;
  }

  return sent;
}

// Read from IO channel - opened file descriptor, socket, or SSL descriptor.
// Return number of bytes read, negative value on error
static int pull(FILE *fp, struct mg_connection *conn, char *buf, int len) {
  int nread;

  MG_ASSERT(conn ? !conn->client.is_ssl == !conn->ssl : 1);
  if (conn && conn->ssl) {
    do {
      nread = SSL_read(conn->ssl, buf, len);
    } while (ssl_renegotiation_ongoing(conn, &nread));
    conn->client.read_error = (nread < 0);
    // and reset the select() markers used by consume_socket() et al:
    conn->client.was_idle = 0;
    conn->client.has_read_data = 0;
  } else if (fp != NULL) {
    // Use read() instead of fread(), because if we're reading from the CGI
    // pipe, fread() may block until IO buffer is filled up. We cannot afford
    // to block and must pass all read bytes immediately to the client.
    nread = read(fileno(fp), buf, (size_t) len);
    if (ferror(fp))
      nread = -1;
  } else if (conn && conn->client.sock != INVALID_SOCKET) {
    nread = 0;
    // poll stop_flag to ensure that we'll be able to abort on server stop:
    while (conn->ctx->stop_flag == 0 || !conn->abort_when_server_stops) {
      int sn = 1;
      // do we already know whether there's incoming data pending?
      if (!(conn->client.was_idle && conn->client.has_read_data)) {
        fd_set fdr;
        int max_fh = 0;
        struct timeval tv = {0};
        tv.tv_sec = 0;
        tv.tv_usec = MG_SELECT_TIMEOUT_MSECS * 1000;
        FD_ZERO(&fdr);
        add_to_set(conn->client.sock, &fdr, &max_fh);
        sn = select(max_fh + 1, &fdr, NULL, NULL, &tv);
      }
      if (sn > 0) {
        nread = recv(conn->client.sock, buf, (size_t) len, 0);
        conn->client.read_error = (nread < 0);
        break;
      }
    }
    // ALWAYS reset the select() markers used by consume_socket() et al:
    conn->client.was_idle = 0;
    conn->client.has_read_data = 0;
  } else {
    nread = -1;
  }

  return nread;
}

// forward declaration:
static int read_and_parse_chunk_header(struct mg_connection *conn);

static int read_bytes(struct mg_connection *conn, void *buf, size_t len, int nonblocking) {
  int n, buffered_len, nread;
  const char *buffered;

  MG_ASSERT((conn->content_len == -1) ||
         conn->consumed_content <= conn->content_len);

  //MG_ASSERT(conn->next_request != NULL &&
  //          conn->body != NULL &&
  //          conn->next_request >= conn->body);

  nread = 0;
  while (len > 0 && (conn->consumed_content < conn->content_len || conn->content_len == -1)) {
    // Adjust number of bytes to read.
    int64_t to_read = (conn->content_len == -1 ? INT_MAX : conn->content_len - conn->consumed_content);
    int already_read_len = conn->rx_buffer_read_len;
    if (to_read < (int64_t) len) {
      len = (size_t) to_read;
    }

    // How many bytes of data we have buffered in the request buffer?
    MG_ASSERT(conn->request_len >= 0);
    buffered = conn->buf + conn->request_len + already_read_len;
    buffered_len = conn->rx_buffer_loaded_len;
    MG_ASSERT(buffered_len >= 0);

    // Return buffered data back if we haven't done that yet.
    if (already_read_len < buffered_len) {
      buffered_len -= already_read_len;
      if (len < (size_t) buffered_len) {
        buffered_len = (int)len;
      }
    } else {
      buffered_len = 0;
    }

    if (conn->rx_is_in_chunked_mode) {
      if (conn->rx_chunk_header_parsed == 0) {
        int cl;
        MG_ASSERT(conn->rx_remaining_chunksize == 0);
        // nonblocking: check if any data is pending; only then do we fetch one more chunk header...
        if (nread == 0 || mg_is_read_data_available(conn) == 1 || !nonblocking) {
          cl = read_and_parse_chunk_header(conn);
          if (conn->rx_remaining_chunksize == 0) {
            DEBUG_TRACE(0x0004,
                        ("End Of Chunked Transmission @ chunk header %d @ nread = %d",
                         conn->rx_chunk_count, nread));
          }
          if (cl < 0)
            return cl;
        }

        if (conn->rx_remaining_chunksize == 0) {
          return nread;
        }
        continue; // it's easier to have another round figure it out, now that we have a new chunk
      }
      if (conn->rx_remaining_chunksize == 0) {
        return nread;
      }
      if (buffered_len > conn->rx_remaining_chunksize)
        buffered_len = conn->rx_remaining_chunksize;
    }

    if (buffered_len > 0) {
      // as user-defined chunk readers may read data into the connection buffer,
      // it CAN happen that buf == buffered. Otherwise, use memmove() instead
      // of memcpy() to be on the safe side.
      if (buf != buffered)
        memmove(buf, buffered, (size_t)buffered_len);
      len -= buffered_len;
      buf = (char *) buf + buffered_len;
      conn->rx_buffer_read_len += buffered_len;
      if (conn->rx_chunk_header_parsed < 2) {
        conn->consumed_content += buffered_len;
        conn->rx_remaining_chunksize -= buffered_len;
        if (conn->rx_remaining_chunksize == 0) {
          // end of chunk data reached; mark the need for a fresh chunk:
          conn->rx_chunk_header_parsed = 0;
        }
      }
      nread += buffered_len;
    }

    // We have returned all buffered data. Read new data from the remote socket.
    while (len > 0) {
      // act like pull() when we're not involved with fetching 'Content-Length'-defined HTTP content:
      if (nread > 0 && nonblocking && conn->rx_buffer_read_len >= conn->rx_buffer_loaded_len) {
        return nread;
      }

      if (conn->rx_is_in_chunked_mode) {
        if (conn->rx_chunk_header_parsed == 0 || conn->rx_buffer_read_len < conn->rx_buffer_loaded_len) {
          // it's easier to have another round figure it out
          // when we have to fetch a fresh chunk or
          // when we have more buffered data pending
          // (which implies there's more chunks waiting for us in the buffer)
          break;
        } else {
          n = (int) len;
          if (n > conn->rx_remaining_chunksize)
            n = conn->rx_remaining_chunksize;
          n = pull(NULL, conn, (char *) buf, n);
        }
      } else {
        MG_ASSERT(conn->rx_buffer_read_len >= conn->rx_buffer_loaded_len);
        n = pull(NULL, conn, (char *) buf, (int) len);
      }

      if (n < 0) {
        // always propagate the error
        return n;
      } else if (n == 0) {
        return nread; // no more data to be had
      }
      buf = (char *) buf + n;
      if (conn->rx_chunk_header_parsed < 2) {
        conn->consumed_content += n;
        conn->rx_remaining_chunksize -= n;
        if (conn->rx_remaining_chunksize == 0) {
          // end of chunk data reached; mark the need for a fresh chunk:
          conn->rx_chunk_header_parsed = 0;
        }
      }
      nread += n;
      len -= n;
    }
  }
  return nread;
}

int mg_read(struct mg_connection *conn, void *buf, size_t len) {
  int nread;

  DEBUG_TRACE(0x0010,
              ("%p buflen:%" PRId64 " %" PRId64 " %" PRId64,
               buf, (int64_t)len,
               conn->content_len, conn->consumed_content));

  nread = read_bytes(conn, buf, len, ((conn->content_len == -1) && !conn->rx_is_in_chunked_mode) ||
                    conn->rx_chunk_header_parsed >= 2);

  DEBUG_TRACE(0x0010,
              ("%p --> nread: %d %" PRId64 " %" PRId64,
               buf, nread,
               conn->content_len, conn->consumed_content));

  return nread;
}

void mg_mark_end_of_header_transmission(struct mg_connection *conn) {
  // incidentally, current total header length would now equal (-1 - conn->num_bytes_sent)
  if (conn && conn->num_bytes_sent < 0)
    conn->num_bytes_sent = 0;
}

int mg_have_headers_been_sent(const struct mg_connection *conn) {
  // When the HTTP header has been sent, it's no use to send more to override, so we
  // do NOT check against what you might expect initially, i.e. 'if (conn && conn->num_bytes_sent >= 0)'
  // but rather:
  if (conn)
    return (conn->num_bytes_sent >= 0 ? -1 : conn->num_bytes_sent != -1);
  return 0;
}

int mg_write(struct mg_connection *conn, const void *buf, size_t len) {
  int rv;
  const char *src = (const char *)buf;
  int64_t txlen = (int64_t) len;

  // may be called with len == 0 from the mg_printf() family:
  if (len == 0)
    return 0;

  // chunked I/O only applies to data I/O, NOT to (HTTP) header I/O:
  if (conn->tx_is_in_chunked_mode && conn->num_bytes_sent >= 0) {
    int64_t txlen_1;

    // are we in header TX mode?
    if (conn->tx_chunk_header_sent >= 2) {
      // just send the data; don't count the bytes against any totals though!
      return (int) push(NULL, conn, src, txlen);
    }

    // when the connection has been previously signaled as 'flushed', then you
    // CANNOT SEND ANY MORE DATA, unless mongoose resets the connection to process
    // another request (e.g. in HTTP keep-alive mode):
    if (conn->tx_chunk_header_sent == 1 && conn->tx_remaining_chunksize == 0) {
      mg_cry(conn, "%s: trying to send %d content data bytes beyond the END of a chunked transfer", __func__, (int)len);
      DEBUG_TRACE(0x00FF, ("Should never get here; if you do, then your user I/O code is faulty!"));
      return -1;
    }

    // was the chunk size sent to the peer already?
    if (conn->tx_chunk_header_sent == 0) {
      // prep and transmit a 'chunk header' for the given size:
      txlen_1 = txlen;
      MG_ASSERT(conn->tx_remaining_chunksize == 0);
      if (txlen_1 < conn->tx_next_chunksize)
        txlen_1 = conn->tx_next_chunksize;
      rv = mg_write_chunk_header(conn, txlen_1);
      if (rv < 0)
        return rv;
      MG_ASSERT(conn->tx_chunk_header_sent == 1);
      MG_ASSERT(conn->tx_remaining_chunksize > 0);
      MG_ASSERT(conn->tx_next_chunksize == 0);

      // mg_write_chunk_header() MAY have changed the tx_remaining_chunksize value
    }
    MG_ASSERT(conn->tx_remaining_chunksize > 0);
    txlen_1 = txlen;
    if (txlen_1 > conn->tx_remaining_chunksize)
      txlen_1 = conn->tx_remaining_chunksize;
    rv = (int) push(NULL, conn, src, txlen_1);
    if (rv > 0) {
      MG_ASSERT(conn->num_bytes_sent >= 0);
      conn->num_bytes_sent += rv; // count as content data
      src += rv;
      txlen -= rv;
      conn->tx_remaining_chunksize -= rv;
    } else {
      return rv;
    }
    // Was the entire blurb written to the socket?
    // If not, exit for we're very probably using a non-blocking I/O socket then.
    //
    // Barring that, there are two scenarios left for us:
    // a) We still have some data to send but don't have a chunk size spec.
    //    (In which case we assume that the remaining data blurb is a complete chunk itself.)
    // b) We've sent all the data we had and maybe have some space left in the current chunk.
    //    (In which case we're happy campers, doing nothing at all.)
    if (conn->tx_remaining_chunksize > 0) {
      MG_ASSERT(txlen == 0);
      return rv;
    }
    MG_ASSERT(conn->tx_remaining_chunksize == 0);
    conn->tx_chunk_header_sent = 0; // signal the need for another chunk (+ header)
    if (txlen == 0) {
      return rv;
    }
    // prep and transmit a 'chunk header' for the remaining size:
    txlen_1 = txlen;
    if (txlen_1 < conn->tx_next_chunksize)
      txlen_1 = conn->tx_next_chunksize;
    rv = mg_write_chunk_header(conn, txlen_1);
    if (rv < 0)
      return rv;
    MG_ASSERT(conn->tx_chunk_header_sent == 1);
    MG_ASSERT(conn->tx_remaining_chunksize > 0);
    MG_ASSERT(conn->tx_next_chunksize == 0);
  }

  rv = (int) push(NULL, conn, src, txlen);
  if (rv > 0) {
    if (conn->num_bytes_sent < 0) {
      conn->num_bytes_sent -= rv; // count as header data
    } else {
      conn->num_bytes_sent += rv; // count as content data
      conn->tx_remaining_chunksize -= rv; // when not in chunked mode, we don't care how far negative this value goes.
      if (conn->tx_remaining_chunksize == 0) {
        conn->tx_chunk_header_sent = 0; // signal the need for another chunk (+ header)
      }
    }
    src += rv;
  } else if (rv < 0) {
    return rv;
  }
  return (src - (const char *)buf);
}

int mg_vprintf(struct mg_connection *conn, const char *fmt, va_list aa) {
  char *buf = NULL;
  int len;
  int rv;

  // handle the special case where there's nothing to do in terms of formatting --> print without the malloc/speed penalty:
  if (!strchr(fmt, '%')) {
    rv = mg_write(conn, fmt, strlen(fmt));
    return (rv < 0 ? 0 : rv);
  } else if (!strcmp(fmt, "%s")) {
    // This also takes care of the scenario where mg_printf(conn, "%s", "") was called, so the vsnprintf() further below MUST produce a non-zero length!
    fmt = va_arg(aa, const char *);
    if (!fmt) fmt = "???";
    rv = mg_write(conn, fmt, strlen(fmt));
    return (rv < 0 ? 0 : rv);
  } else {
    char mem[MG_BUF_LEN];
    va_list ap;

    // Print in a local buffer first, hoping that it is large enough to
    // hold the whole message
    VA_COPY(ap, aa);
    mem[0] = 0;
    len = vsnprintf(mem, sizeof(mem), fmt, ap);
    mem[sizeof(mem) - 1] = 0;
    va_end(ap);

    // As we took also care above of the scenario where mg_printf(conn, "%s", "") was called, vsnprintf() MUST produce a non-zero length on success!
    if (len <= 0 || len >= (int) sizeof(mem) - 1) {
      // MSVC produces -1 on printf("%s", str) for very long 'str'!
      VA_COPY(ap, aa);
      len = mg_vasprintf(conn, &buf, 0, fmt, ap);
      va_end(ap);

      if (buf && len > 0) {
        rv = mg_write(conn, buf, (size_t)len);
        free(buf);
        return (rv < len ? 0 : rv);
      } else {
        // Failed to allocate large enough buffer or failed inside mg_vasprintf, give up
        if (buf) free(buf);
        mg_cry(conn, "%s(%s, ...): Can't allocate buffer, not printing anything",
               __func__, fmt);
      }
    } else {
      // Copy to the local buffer succeeded
      rv = mg_write(conn, mem, (size_t) len);
      return (rv < 0 ? 0 : rv);
    }
  }
  return 0;
}

int mg_printf(struct mg_connection *conn, const char *fmt, ...) {
  int len;
  va_list ap;

  va_start(ap, fmt);
  len = mg_vprintf(conn, fmt, ap);
  va_end(ap);

  return len;
}

// URL-decode input buffer into destination buffer.
// 0-terminate the destination buffer. Return the length of decoded data.
// form-url-encoded data differs from URI encoding in a way that it
// uses '+' as character for space, see RFC 1866 section 8.2.1
// http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
static size_t url_decode(const char *src, size_t src_len, char *dst,
                         size_t dst_len, int is_form_url_encoded) {
  size_t i, j;
  int a, b;
#define HEXTOI(x) (isdigit(x) ? x - '0' : x - 'W')

  MG_ASSERT(dst);
  MG_ASSERT(dst_len > 0);
  MG_ASSERT(src);
  for (i = j = 0; i < src_len && j < dst_len - 1; i++, j++) {
    if (src[i] == '%' &&
        isxdigit(* (const unsigned char *) (src + i + 1)) &&
        isxdigit(* (const unsigned char *) (src + i + 2))) {
      a = tolower(* (const unsigned char *) (src + i + 1));
      b = tolower(* (const unsigned char *) (src + i + 2));
      dst[j] = (char) ((HEXTOI(a) << 4) | HEXTOI(b));
      i += 2;
    } else if (is_form_url_encoded && src[i] == '+') {
      dst[j] = ' ';
    } else {
      dst[j] = src[i];
    }
  }

  dst[j] = '\0'; // Null-terminate the destination

  return j;
}

// Scan given buffer and fetch the value of the given variable.
// It can be specified in query string, or in the POST data.
// Return -1 if the variable not found, or length of the URLdecoded
// value stored in dst[].
// The dst[] buffer is always NUL-terminated whenever possible,
// also when -1 is returned.
int mg_get_var(const char *buf, size_t buf_len, const char *name,
               char *dst, size_t dst_len, int is_form_url_encoded) {
  const char *p, *e, *s;
  size_t name_len;
  int len;

  if (dst == NULL || dst_len == 0)
    return -2;
  MG_ASSERT(dst);
  MG_ASSERT(dst_len > 0);
  dst[0] = '\0';
  if (buf == NULL || name == NULL)
    return -1;
  name_len = strlen(name);
  if (buf_len == (size_t)-1)
    buf_len = strlen(buf);
  if (buf_len == 0)
    return -1;
  e = buf + buf_len;
  len = -1;

  // buf is "var1=val1&var2=val2...". Find variable first
  for (p = buf; p != NULL && p + name_len < e; p++) {
    if ((p == buf || p[-1] == '&') && p[name_len] == '=' &&
        !mg_strncasecmp(name, p, name_len)) {

      // Point p to variable value
      p += name_len + 1;

      // Point s to the end of the value
      s = (const char *) memchr(p, '&', (size_t)(e - p));
      if (s == NULL) {
        s = e;
      }
      MG_ASSERT(s >= p);

      // Decode variable into destination buffer
      if ((size_t) (s - p) < dst_len) {
        len = (int)url_decode(p, (size_t)(s - p), dst, dst_len, is_form_url_encoded);
      }
      break;
    }
  }

  return len;
}

int mg_get_cookie(const struct mg_connection *conn, const char *cookie_name,
                  char *dst, size_t dst_size) {
  const char *s, *p, *end;
  int name_len, len = -1;

  dst[0] = '\0';
  if ((s = mg_get_header(conn, "Cookie")) == NULL) {
    return -1;
  }

  name_len = (int)strlen(cookie_name);
  end = s + strlen(s);

  for (; (s = strstr(s, cookie_name)) != NULL; s += name_len)
    if (s[name_len] == '=') {
      s += name_len + 1;
      if ((p = strchr(s, ' ')) == NULL)
        p = end;
      if (p[-1] == ';')
        p--;
      if (*s == '"' && p[-1] == '"' && p > s + 1) {
        s++;
        p--;
      }
      if ((size_t) (p - s) < dst_size) {
        len = (p - s) + 1;
        mg_strlcpy(dst, s, (size_t)len);
        len--; // don't count the NUL sentinel in the reported length!
      }
      break;
    }

  return len;
}

static int convert_uri_to_file_name(struct mg_connection *conn, char *buf,
                                    size_t buf_len, struct mgstat *st) {
  struct vec a, b;
  const char *rewrite, *uri = conn->request_info.uri;
  char *p;
  int match_len, stat_result;

  buf_len--;  // This is because memmove() for PATH_INFO may shift part
              // of the path one byte on the right.
  mg_snprintf(conn, buf, buf_len, "%s%s", get_conn_option(conn, DOCUMENT_ROOT), uri);

  rewrite = get_conn_option(conn, REWRITE);
  while ((rewrite = next_option(rewrite, &a, &b)) != NULL) {
    if ((match_len = match_string(a.ptr, (int)a.len, uri)) > 0) {
      mg_snprintf(conn, buf, buf_len, "%.*s%s", (int)b.len, b.ptr, uri + match_len);
      break;
    }
  }

  // Win32: CGI can fail when being fed an interpreter plus relative path to the script;
  // keep in mind that other scenarios, e.g. user event handlers, may fail similarly
  // when receiving relative filesystem paths, so we solve the issue once and for all,
  // right here:
  mg_mk_fullpath(buf, buf_len);

  if ((stat_result = mg_stat(buf, st)) != 0) {
    const char *cgi_exts = get_conn_option(conn, CGI_EXTENSIONS);
    int cgi_exts_len = (int)strlen(cgi_exts);

    // Support PATH_INFO for CGI scripts.
    for (p = buf + strlen(buf); p > buf + 1; p--) {
      if (*p == '/') {
        *p = '\0';
        if (match_string(cgi_exts, cgi_exts_len, buf) > 0 &&
            (stat_result = mg_stat(buf, st)) == 0) {
          // Shift PATH_INFO block one character right, e.g.
          //  "/x.cgi/foo/bar\x00" => "/x.cgi\x00/foo/bar\x00"
          // conn->path_info is pointing to the local variable "path" declared
          // in handle_request(), so PATH_INFO is not valid after
          // handle_request returns.
          conn->request_info.path_info = p + 1;
          memmove(p + 2, p + 1, strlen(p + 1) + 1);  // +1 is for trailing \0
          p[1] = '/';
          break;
        } else {
          *p = '/';
          stat_result = -1;
        }
      }
    }
  }

  DEBUG_TRACE(0x0200, ("[%s] -> [%s], [%.*s]", uri, buf, (int) b.len, b.ptr));

  return stat_result;
}

#if !defined(NO_SSL)
static int sslize(struct mg_connection *conn, SSL_CTX *ssl_ctx, int (*func)(SSL *)) {
  MG_ASSERT(ssl_ctx);
  if ((conn->ssl = SSL_new(ssl_ctx)) != NULL &&
    SSL_set_fd(conn->ssl, conn->client.sock) == 1) {
    int rv;
    do {
      rv = func(conn->ssl);
    } while (ssl_renegotiation_ongoing(conn, &rv));
    return (rv == 1);
  }
  return 0;
}
#else // NO_SSL
#define sslize(conn, s, f)     0
#endif // NO_SSL

// Check whether full request is buffered. Return:
//   -1  if request is malformed
//    0  if request is not yet fully buffered
//   >0  actual request length, including last \r\n\r\n
static int get_request_len(const char *buf, int buflen) {
  const char *s, *e;
  int len = 0;

  for (s = buf, e = s + buflen - 1; len <= 0 && s < e; s++)
    // Control characters are not allowed but >=128 is.
    if (!isprint(* (const unsigned char *) s) && *s != '\r' &&
        *s != '\n' && * (const unsigned char *) s < 128) {
      len = -1;
      break; // [i_a] abort scan as soon as one malformed character is found; don't let subsequent \r\n\r\n win us over anyhow
    } else if (s[0] == '\n' && s[1] == '\n') {
      len = (int) (s - buf) + 2;
    } else if (s[0] == '\n' && &s[1] < e &&
        s[1] == '\r' && s[2] == '\n') {
      len = (int) (s - buf) + 3;
    }

  return len;
}

// Convert month to the month number. Return -1 on error, or month number
static int get_month_index(const char *s) {
  size_t i;

  for (i = 0; i < ARRAY_SIZE(month_names); i++)
    if (!strcmp(s, month_names[i]))
      return (int) i;

  return -1;
}

// Parse UTC date-time string, and return the corresponding time_t value.
static time_t parse_date_string(const char *datetime) {
  static const unsigned short days_before_month[] = {
    0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
  };
  char month_str[32];
  int second, minute, hour, day, month, year, leap_days, days;
  time_t result = (time_t) 0;

  if (((sscanf(datetime, "%d/%3s/%d %d:%d:%d",
               &day, month_str, &year, &hour, &minute, &second) == 6) ||
       (sscanf(datetime, "%d %3s %d %d:%d:%d",
               &day, month_str, &year, &hour, &minute, &second) == 6) ||
       (sscanf(datetime, "%*3s, %d %3s %d %d:%d:%d",
               &day, month_str, &year, &hour, &minute, &second) == 6) ||
       (sscanf(datetime, "%d-%3s-%d %d:%d:%d",
               &day, month_str, &year, &hour, &minute, &second) == 6)) &&
      year > 1970 &&
      (month = get_month_index(month_str)) != -1) {
    year -= 1970;
    leap_days = year / 4 - year / 100 + year / 400;
    days = year * 365 + days_before_month[month] + (day - 1) + leap_days;
    result = days * 24 * 3600 + hour * 3600 + minute * 60 + second;
  }

  return result;
}

// Protect against directory disclosure attack by removing '..',
// excessive '/' and '\' characters
static void remove_double_dots_and_double_slashes(char *s) {
  char *p = s;

  while (*s != '\0') {
    *p++ = *s++;
    if (IS_DIRSEP_CHAR(s[-1])) {
      // Skip all following slashes and backslashes
      while (IS_DIRSEP_CHAR(s[0])) {
        s++;
      }

      // Skip all double-dots
      while (*s == '.' && s[1] == '.') {
        s += 2;
      }
    }
  }
  *p = '\0';
}

static const struct {
  const char *extension;
  size_t ext_len;
  const char *mime_type;
} builtin_mime_types[] = {
  {".html",     5, "text/html"},
  {".htm",      4, "text/html"},
  {".shtm",     5, "text/html"},
  {".shtml",    6, "text/html"},
  {".css",      4, "text/css"},
  {".js",       3, "application/x-javascript"},
  {".ico",      4, "image/x-icon"},
  {".gif",      4, "image/gif"},
  {".jpg",      4, "image/jpeg"},
  {".jpeg",     5, "image/jpeg"},
  {".png",      4, "image/png"},
  {".svg",      4, "image/svg+xml"},
  {".txt",      4, "text/plain"},
  {".torrent",  8, "application/x-bittorrent"},
  {".wav",      4, "audio/x-wav"},
  {".mp3",      4, "audio/x-mp3"},
  {".mid",      4, "audio/mid"},
  {".m3u",      4, "audio/x-mpegurl"},
  {".ram",      4, "audio/x-pn-realaudio"},
  {".xml",      4, "text/xml"},
  {".json",     5, "text/json"},
  {".xslt",     5, "application/xml"},
  {".ra",       3, "audio/x-pn-realaudio"},
  {".doc",      4, "application/msword"},
  {".exe",      4, "application/octet-stream"},
  {".zip",      4, "application/x-zip-compressed"},
  {".xls",      4, "application/excel"},
  {".tgz",      4, "application/x-tar-gz"},
  {".tar",      4, "application/x-tar"},
  {".gz",       3, "application/x-gunzip"},
  {".arj",      4, "application/x-arj-compressed"},
  {".rar",      4, "application/x-arj-compressed"},
  {".rtf",      4, "application/rtf"},
  {".pdf",      4, "application/pdf"},
  {".swf",      4, "application/x-shockwave-flash"},
  {".mpg",      4, "video/mpeg"},
  {".webm",     5, "video/webm"},
  {".mpeg",     5, "video/mpeg"},
  {".mp4",      4, "video/mp4"},
  {".m4v",      4, "video/x-m4v"},
  {".asf",      4, "video/x-ms-asf"},
  {".avi",      4, "video/x-msvideo"},
  {".bmp",      4, "image/bmp"},
  {".appcache", 9, "text/cache-manifest"},   // http://www.html5rocks.com/en/tutorials/appcache/beginner/
  {NULL,        0, NULL}
};

// Look at the "path" extension and figure what mime type it has.
// Return the default MIME type string when the MIME type is not known.
static const char *get_builtin_mime_type(const char *path, const char *default_mime_type) {
  const char *ext;
  size_t i, path_len;

  path_len = strlen(path);

  for (i = 0; builtin_mime_types[i].extension != NULL; i++) {
    ext = path + (path_len - builtin_mime_types[i].ext_len);
    if (path_len > builtin_mime_types[i].ext_len &&
        mg_strcasecmp(ext, builtin_mime_types[i].extension) == 0) {
      return builtin_mime_types[i].mime_type;
    }
  }

  return default_mime_type;
}

// Look at the "path" extension and figure what mime type it has.
// Always return a valid MIME type string.
const char *mg_get_builtin_mime_type(const char *path) {
  return get_builtin_mime_type(path, "text/plain");
}

// Look at the "path" extension and figure what mime type it has.
// Store mime type in the vector.
// Return the default MIME type string when the MIME type is not known.
static void get_mime_type(struct mg_context *ctx, const char *path,
                          const char *default_mime_type, struct vec *vec) {
  struct vec ext_vec, mime_vec;
  const char *list, *ext;
  size_t path_len;

  path_len = strlen(path);

  // Scan user-defined mime types first, in case user wants to
  // override default mime types.
  list = get_option(ctx, EXTRA_MIME_TYPES);
  while ((list = next_option(list, &ext_vec, &mime_vec)) != NULL) {
    // ext now points to the path suffix
    ext = path + path_len - ext_vec.len;
    if (mg_strncasecmp(ext, ext_vec.ptr, ext_vec.len) == 0) {
      *vec = mime_vec;
      return;
    }
  }

  vec->ptr = get_builtin_mime_type(path, default_mime_type);
  vec->len = (vec->ptr ? strlen(vec->ptr) : 0);
}

#ifndef HAVE_MD5
typedef struct MD5Context {
  uint32_t buf[4];
  uint32_t bits[2];
  unsigned char in[64];
} MD5_CTX;

#if defined(__BYTE_ORDER) && (__BYTE_ORDER == 1234)
#define byteReverse(buf, len) // Do nothing
#else
static void byteReverse(unsigned char *buf, unsigned longs) {
  uint32_t t;
  do {
    t = (uint32_t) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
      ((unsigned) buf[1] << 8 | buf[0]);
    *(uint32_t *) buf = t;
    buf += 4;
  } while (--longs);
}
#endif

#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

#define MD5STEP(f, w, x, y, z, data, s) \
  ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

// Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
// initialization constants.
static void MD5Init(MD5_CTX *ctx) {
  ctx->buf[0] = 0x67452301;
  ctx->buf[1] = 0xefcdab89;
  ctx->buf[2] = 0x98badcfe;
  ctx->buf[3] = 0x10325476;

  ctx->bits[0] = 0;
  ctx->bits[1] = 0;
}

static void MD5Transform(uint32_t buf[4], uint32_t const in[16]) {
  register uint32_t a, b, c, d;

  a = buf[0];
  b = buf[1];
  c = buf[2];
  d = buf[3];

  MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
  MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
  MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
  MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
  MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
  MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
  MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
  MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
  MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
  MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
  MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
  MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
  MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
  MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
  MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
  MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

  MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
  MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
  MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
  MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
  MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
  MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
  MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
  MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
  MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
  MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
  MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
  MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
  MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
  MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
  MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
  MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

  MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
  MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
  MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
  MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
  MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
  MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
  MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
  MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
  MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
  MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
  MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
  MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
  MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
  MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
  MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
  MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

  MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
  MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
  MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
  MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
  MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
  MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
  MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
  MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
  MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
  MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
  MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
  MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
  MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
  MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
  MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
  MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

  buf[0] += a;
  buf[1] += b;
  buf[2] += c;
  buf[3] += d;
}

static void MD5Update(MD5_CTX *ctx, unsigned char const *buf, unsigned len) {
  uint32_t t;

  t = ctx->bits[0];
  if ((ctx->bits[0] = t + ((uint32_t) len << 3)) < t)
    ctx->bits[1]++;
  ctx->bits[1] += len >> 29;

  t = (t >> 3) & 0x3f;

  if (t) {
    unsigned char *p = (unsigned char *) ctx->in + t;

    t = 64 - t;
    if (len < t) {
      memcpy(p, buf, len);
      return;
    }
    memcpy(p, buf, t);
    byteReverse(ctx->in, 16);
    MD5Transform(ctx->buf, (uint32_t *) ctx->in);
    buf += t;
    len -= t;
  }

  while (len >= 64) {
    memcpy(ctx->in, buf, 64);
    byteReverse(ctx->in, 16);
    MD5Transform(ctx->buf, (uint32_t *) ctx->in);
    buf += 64;
    len -= 64;
  }

  memcpy(ctx->in, buf, len);
}

static void MD5Final(unsigned char digest[16], MD5_CTX *ctx) {
  unsigned count;
  unsigned char *p;

  count = (ctx->bits[0] >> 3) & 0x3F;

  p = ctx->in + count;
  *p++ = 0x80;
  count = 64 - 1 - count;
  if (count < 8) {
    memset(p, 0, count);
    byteReverse(ctx->in, 16);
    MD5Transform(ctx->buf, (uint32_t *) ctx->in);
    memset(ctx->in, 0, 56);
  } else {
    memset(p, 0, count - 8);
  }
  byteReverse(ctx->in, 14);

  ((uint32_t *) ctx->in)[14] = ctx->bits[0];
  ((uint32_t *) ctx->in)[15] = ctx->bits[1];

  MD5Transform(ctx->buf, (uint32_t *) ctx->in);
  byteReverse((unsigned char *) ctx->buf, 4);
  memcpy(digest, ctx->buf, 16);
  memset((char *) ctx, 0, sizeof(*ctx));
}
#endif // !HAVE_MD5

// Stringify binary data. Output buffer must be twice as big as input,
// because each byte takes 2 bytes in string representation
static void bin2str(char *to, const unsigned char *p, size_t len) {
  static const char *hex = "0123456789abcdef";

  for (; len--; p++) {
    *to++ = hex[p[0] >> 4];
    *to++ = hex[p[0] & 0x0f];
  }
  *to = '\0';
}

// Return stringified MD5 hash for list of strings. Buffer must be 33 bytes.
void mg_md5(char buf[33], ...) {
  unsigned char hash[16];
  const char *p;
  va_list ap;
  MD5_CTX ctx;

  MD5Init(&ctx);

  va_start(ap, buf);
  while ((p = va_arg(ap, const char *)) != NULL) {
    MD5Update(&ctx, (const unsigned char *) p, (unsigned) strlen(p));
  }
  va_end(ap);

  MD5Final(hash, &ctx);
  bin2str(buf, hash, sizeof(hash));
}

// Check the user's password, return 1 if OK
static int check_password(const char *method, const char *ha1, const char *uri,
                          const char *nonce, const char *nc, const char *cnonce,
                          const char *qop, const char *response) {
  char ha2[32 + 1], expected_response[32 + 1];

  // Some of the parameters may be NULL
  if (method == NULL || nonce == NULL || nc == NULL || cnonce == NULL ||
      qop == NULL || response == NULL) {
    return 0;
  }

  // NOTE(lsm): due to a bug in MSIE, we do not compare the URI
  // TODO(lsm): check for authentication timeout
  if (// strcmp(dig->uri, c->ouri) != 0 ||
      strlen(response) != 32
      // || now - strtoul(dig->nonce, NULL, 10) > 3600
      ) {
    return 0;
  }

  mg_md5(ha2, method, ":", uri, NULL);
  mg_md5(expected_response, ha1, ":", nonce, ":", nc,
      ":", cnonce, ":", qop, ":", ha2, NULL);

  return mg_strcasecmp(response, expected_response) == 0;
}

// Use the global passwords file, if specified by auth_gpass option,
// or search for .htpasswd in the requested directory.
static FILE *open_auth_file(struct mg_connection *conn, const char *path) {
  char name[PATH_MAX];
  const char *p, *e;
  struct mgstat st;
  FILE *fp;
  const char *global_pwd_file = get_conn_option(conn, GLOBAL_PASSWORDS_FILE);

  if (!is_empty(global_pwd_file)) {
    // Use global passwords file
    fp =  mg_fopen(global_pwd_file, "r");
    if (fp == NULL)
      mg_cry(conn, "fopen(%s): %s",
             global_pwd_file, mg_strerror(ERRNO));
  } else if (!mg_stat(path, &st) && st.is_directory) {
    (void) mg_snprintf(conn, name, sizeof(name), "%s%c%s",
                       path, DIRSEP, PASSWORDS_FILE_NAME);
    fp = mg_fopen(name, "r");
  } else {
     // Try to find .htpasswd in requested directory.
    for (p = path, e = p + strlen(p) - 1; e > p; e--)
      if (IS_DIRSEP_CHAR(*e))
        break;
    (void) mg_snprintf(conn, name, sizeof(name), "%.*s%c%s",
                       (int) (e - p), p, DIRSEP, PASSWORDS_FILE_NAME);
    fp = mg_fopen(name, "r");
  }

  return fp;
}

// Parsed RFC2617 Authorization request header cf. sec. 3.2.2
struct ah {
  char *user, *uri, *cnonce, *response, *qop, *nc, *nonce, *opaque;
};

// Return 1 on success. ALWAYS initializes the 'ah' struct.
static int parse_auth_header(struct mg_connection *conn, char *buf,
                             size_t buf_size, struct ah *ah) {
  char *name, *value, *s;
  const char *auth_header;

  (void) memset(ah, 0, sizeof(*ah));

  if ((auth_header = mg_get_header(conn, "Authorization")) == NULL ||
      mg_strncasecmp(auth_header, "Digest ", 7) != 0) {
    return 0;
  }

  // Make modifiable copy of the auth header
  (void) mg_strlcpy(buf, auth_header + 7, buf_size);

  s = buf;
  // Parse authorization header
  while (*s) {
    char sep;

    // Gobble initial spaces
    s = skip_lws(s);

    if (mg_extract_token_qstring_value(&s, &sep, &name, &value, "") < 0)
      return -1;
    if (sep && !strchr(",; ", sep))
      return -1;
    // 's + !!sep' is important, because "a=b,c=d" type input will have
    // NULled that ',' (but stored it in 'sep') and 's' would be
    // pointing at that (inserted) NUL then, while sep==NUL indicates that
    // the true end of the original string has been reached, and a
    // simple 's+1' would have been disasterous then:
    s += strspn(s + !!sep, ",; ");   // IE uses commas, FF uses spaces

    if (!strcmp(name, "username")) {
      ah->user = value;
    } else if (!strcmp(name, "cnonce")) {
      ah->cnonce = value;
    } else if (!strcmp(name, "response")) {
      ah->response = value;
    } else if (!strcmp(name, "uri")) {
      ah->uri = value;
    } else if (!strcmp(name, "qop")) {
      ah->qop = value;
    } else if (!strcmp(name, "nc")) {
      ah->nc = value;
    } else if (!strcmp(name, "nonce")) {
      ah->nonce = value;
    } else if (!strcmp(name, "opaque")) {
      ah->opaque = value;
    }
  }

  // CGI needs it as REMOTE_USER
  if (ah->user != NULL) {
    conn->request_info.remote_user = mg_strdup(ah->user);
  } else {
    return 0;
  }

  return 1;
}

// gcc needs TWO call levels to expand a #define to its value and then stringize it; MSVC only requires 1 call level:
#define MG__STRINGIZE(v)  #v
#define MG_STRINGIZE(v)  MG__STRINGIZE(v)

#define USRDMNPWD_BUFSIZ_STR    MG_STRINGIZE(USRDMNPWD_BUFSIZ)

// Authorize against the opened passwords file or user callback.
// (The user callback takes precedence.)
//
// Return 1 if authorized.
static int authorize(struct mg_connection *conn, FILE *fp) {
  struct ah ah;
  char line[USRDMNPWD_BUFSIZ * 3 + 3], f_user[USRDMNPWD_BUFSIZ + 1], ha1[USRDMNPWD_BUFSIZ + 1], f_domain[USRDMNPWD_BUFSIZ + 1], buf[MG_BUF_LEN];
  const char *auth_domain;
  int rv;

  rv = parse_auth_header(conn, buf, sizeof(buf), &ah);
  auth_domain = get_conn_option(conn, AUTHENTICATION_DOMAIN);

  ha1[0] = 0;
  if (conn->ctx->user_functions.password_callback != NULL) {
    int m = conn->ctx->user_functions.password_callback(conn,
                    ah.user, auth_domain,
                    ah.uri, ah.nonce,
                    ah.nc, ah.cnonce,
                    ah.qop, ah.response,
                    ah.opaque,
                    ha1, sizeof(ha1));
    if (m == 2)
      return 1;
    else if (m == 0)
      return 0;
    else if (m == 1)
      fp = NULL; // just use the current ha1[] data
    else if (m != 3) {
      send_http_error(conn, 500, NULL, "");
      return 0;
    }
  }

  if (fp != NULL) {
    // When parse_auth_header() failed, abort the mission:
    if (!rv)
      return 0;

    // Loop over passwords file
    rv = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
      if (sscanf(line, "%" USRDMNPWD_BUFSIZ_STR "[^:]:%" USRDMNPWD_BUFSIZ_STR "[^:]:%" USRDMNPWD_BUFSIZ_STR "s",
                 f_user, f_domain, ha1) != 3) {
        continue;
      }

      if (*f_user &&
          !strcmp(ah.user, f_user) &&
          !strcmp(auth_domain, f_domain)) {
        rv = 1;
        break;
      }
    }
    // no probable hit --> FAIL!
    if (!rv)
      return 0;
  }
  if (!ha1[0])
    return 1;
  return check_password(
        conn->request_info.request_method,
        ha1, ah.uri, ah.nonce, ah.nc, ah.cnonce, ah.qop,
        ah.response /* ah.opaque is unused */ );
}

// Return 1 if request method is allowed, 0 otherwise.
int check_allowed(struct mg_connection *conn) {
  const char *request_method = conn->request_info.request_method;
  const char *allowed_methods = mg_get_allowed_methods(conn);
  struct vec v;

  while ((allowed_methods = next_option(allowed_methods, &v, NULL)) != NULL) {
    if (!memcmp(request_method, v.ptr, v.len))
      return 1;
  }
  return 0;
}

// Return 1 if request is authorized.
static int check_authorization(struct mg_connection *conn, const char *path) {
  FILE *fp;
  char fname[PATH_MAX];
  struct vec uri_vec, filename_vec;
  const char *list;
  int authorized;

  fp = NULL;

  list = get_conn_option(conn, PROTECT_URI);
  while ((list = next_option(list, &uri_vec, &filename_vec)) != NULL) {
    if (!memcmp(conn->request_info.uri, uri_vec.ptr, uri_vec.len)) {
      (void) mg_snprintf(conn, fname, sizeof(fname), "%.*s",
                         (int)filename_vec.len, filename_vec.ptr);
      if ((fp = mg_fopen(fname, "r")) == NULL) {
        mg_cry(conn, "%s: cannot open authorization file %s: %s", __func__, fname, mg_strerror(ERRNO));
      }
      break;
    }
  }

  if (fp == NULL) {
    fp = open_auth_file(conn, path);
  }
  authorized = authorize(conn, fp);
  if (fp != NULL) {
    (void) mg_fclose(fp);
  }

  return authorized;
}

static void send_authorization_request(struct mg_connection *conn) {
  if (mg_is_producing_nested_page(conn) || mg_have_headers_been_sent(conn))
    return;
  if (mg_set_response_code(conn, 401) != 401)
    return;
  //mg_add_response_header(conn, 0, "Connection", "%s", suggest_connection_header(conn)); -- not needed any longer
  mg_add_response_header(conn, 0, "Content-Length", "0");
  mg_add_response_header(conn, 0, "WWW-Authenticate", "Digest qop=\"auth\", "
                         "realm=\"%s\", nonce=\"%lu\"",
                         get_conn_option(conn, AUTHENTICATION_DOMAIN),
                         (unsigned long) time(NULL));
  (void) mg_write_http_response_head(conn, 0, 0);
}

// Return 1 when authorized.
static int is_authorized_for_put(struct mg_connection *conn) {
  FILE *fp = NULL;
  int ret;
  const char *pwd_filepath = get_conn_option(conn, PUT_DELETE_PASSWORDS_FILE);

  if (!is_empty(pwd_filepath)) {
    fp = mg_fopen(pwd_filepath, "r");
    if (fp == NULL) {
      mg_cry(conn, "%s: cannot open authorization file %s: %s", __func__, pwd_filepath, mg_strerror(ERRNO));
      return 0;
    }
  }
  ret = authorize(conn, fp);
  if (fp != NULL) {
    (void) mg_fclose(fp);
  }
  return ret;
}

int mg_modify_passwords_file(const char *fname, const char *domain,
                             const char *user, const char *pass) {
  int found;
  char line[USRDMNPWD_BUFSIZ * 3 + 3], u[USRDMNPWD_BUFSIZ + 1], d[USRDMNPWD_BUFSIZ + 1], ha1[33], tmp[PATH_MAX];
  FILE *fp, *fp2;

  found = 0;
  fp = fp2 = NULL;

  // Regard empty password as no password - remove user record.
  if (pass != NULL && pass[0] == '\0') {
    pass = NULL;
  }

  (void) snprintf(tmp, sizeof(tmp), "%s.tmp", fname);

  // Create the file if does not exist
  if ((fp = mg_fopen(fname, "a")) != NULL) {
    (void) mg_fclose(fp);
  }

  // Open the given file and temporary file
  if ((fp = mg_fopen(fname, "r")) == NULL) {
    return 0;
  } else if ((fp2 = mg_fopen(tmp, "w+")) == NULL) {
    mg_fclose(fp);
    return 0;
  }

  // Copy the stuff to temporary file
  while (fgets(line, sizeof(line), fp) != NULL) {
    if (sscanf(line, "%" USRDMNPWD_BUFSIZ_STR "[^:]:%" USRDMNPWD_BUFSIZ_STR "[^:]:%*s", u, d) != 2) {
      continue;
    }

    if (!strcmp(u, user) && !strcmp(d, domain)) {
      found++;
      if (pass != NULL) {
        mg_md5(ha1, user, ":", domain, ":", pass, NULL);
        fprintf(fp2, "%s:%s:%s\n", user, domain, ha1);
      }
    } else {
      (void) fprintf(fp2, "%s", line);
    }
  }

  // If new user, just add it
  if (!found && pass != NULL) {
    mg_md5(ha1, user, ":", domain, ":", pass, NULL);
    (void) fprintf(fp2, "%s:%s:%s\n", user, domain, ha1);
  }

  // Close files
  (void) mg_fclose(fp);
  (void) mg_fclose(fp2);

  // Put the temp file in place of real file
  (void) mg_remove(fname);
  (void) mg_rename(tmp, fname);

  return 1;
}

static void url_encode(const char *src, char *dst, size_t dst_len) {
  static const char *dont_escape = "._-$,;~()";
  static const char *hex = "0123456789abcdef";
  const char *end = dst + dst_len - 1;

  for (; *src != '\0' && dst < end; src++, dst++) {
    if (isalnum(*(const unsigned char *) src) ||
        strchr(dont_escape, * (const unsigned char *) src) != NULL) {
      *dst = *src;
    } else if (dst + 2 < end) {
      dst[0] = '%';
      dst[1] = hex[(* (const unsigned char *) src) >> 4];
      dst[2] = hex[(* (const unsigned char *) src) & 0xf];
      dst += 2;
    }
  }

  *dst = '\0';
}

static void print_dir_entry(struct mg_direntry *de) {
  char size[64], mod[64], href[PATH_MAX];

  if (de->st.is_directory) {
    (void) mg_snprintf(de->conn, size, sizeof(size), "[DIRECTORY]");
  } else {
     // We use (signed) cast below because MSVC 6 compiler cannot
     // convert unsigned __int64 to double. Sigh.
    if (de->st.size < 1024) {
      (void) mg_snprintf(de->conn, size, sizeof(size),
                         "%lu", (unsigned long) de->st.size);
    } else if (de->st.size < 1024 * 1024) {
      (void) mg_snprintf(de->conn, size, sizeof(size),
                         "%.1fk", (double) de->st.size / 1024.0);
    } else if (de->st.size < 1024 * 1024 * 1024) {
      (void) mg_snprintf(de->conn, size, sizeof(size),
                         "%.1fM", (double) de->st.size / 1048576);
    } else {
      (void) mg_snprintf(de->conn, size, sizeof(size),
                         "%.1fG", (double) de->st.size / 1073741824);
    }
  }
  (void) strftime(mod, sizeof(mod), "%d-%b-%Y %H:%M", localtime(&de->st.mtime));
  url_encode(de->file_name, href, sizeof(href));
  mg_printf(de->conn,
            "<tr><td><a href=\"%s%s%s\">%s%s</a></td>"
            "<td>&nbsp;%s</td><td>&nbsp;&nbsp;%s</td></tr>\n",
            de->conn->request_info.uri, href, de->st.is_directory ? "/" : "",
            de->file_name, de->st.is_directory ? "/" : "", mod, size);
}

// This function is called from send_directory() and used for
// sorting directory entries by size, or name, or modification time.
// On windows, __cdecl specification is needed in case if project is built
// with __stdcall convention. qsort always requires __cdecl callback.
static int WINCDECL compare_dir_entries(const void *p1, const void *p2) {
  const struct mg_direntry *a = (const struct mg_direntry *) p1, *b = (const struct mg_direntry *) p2;
  const char *query_string = a->conn->request_info.query_string;
  int cmp_result = 0;

  if (is_empty(query_string)) {
    query_string = "na";
  }

  if (a->st.is_directory && !b->st.is_directory) {
    return -1;  // Always put directories on top
  } else if (!a->st.is_directory && b->st.is_directory) {
    return 1;   // Always put directories on top
  } else if (*query_string == 'n') {
    cmp_result = strcmp(a->file_name, b->file_name);
  } else if (*query_string == 's') {
    cmp_result = a->st.size == b->st.size ? 0 :
      a->st.size > b->st.size ? 1 : -1;
  } else if (*query_string == 'd') {
    cmp_result = a->st.mtime == b->st.mtime ? 0 :
      a->st.mtime > b->st.mtime ? 1 : -1;
  }

  return query_string[1] == 'd' ? -cmp_result : cmp_result;
}

static int must_hide_file(struct mg_connection *conn, const char *path) {
  const char *pw_pattern = "**" PASSWORDS_FILE_NAME "$";
  const char *pattern = get_conn_option(conn, HIDE_FILES);
  return match_string(pw_pattern, strlen(pw_pattern), path) > 0 ||
    (!is_empty(pattern) && match_string(pattern, strlen(pattern), path) > 0);
}

int mg_scan_directory(struct mg_connection *conn, const char *dir, void *data, mg_process_direntry_cb *cb) {
  char path[PATH_MAX];
  struct dirent *dp;
  DIR *dirp;
  struct mg_direntry de;

  if ((dirp = opendir(dir)) == NULL) {
    return 0;
  } else {
    de.conn = conn;

    while ((dp = readdir(dirp)) != NULL) {
      // Do not show current dir and hidden files
      if (!strcmp(dp->d_name, ".") ||
          !strcmp(dp->d_name, "..") ||
          must_hide_file(conn, dp->d_name)) {
        continue;
      }

      mg_snprintf(conn, path, sizeof(path), "%s%c%s", dir, DIRSEP, dp->d_name);

      // If we don't memset stat structure to zero, mtime will have
      // garbage and strftime() will segfault later on in
      // print_dir_entry(). memset is required only if mg_stat()
      // fails. For more details, see
      // http://code.google.com/p/mongoose/issues/detail?id=79
      if (mg_stat(path, &de.st) != 0) {
        memset(&de.st, 0, sizeof(de.st));
      }
      de.file_name = dp->d_name;

      cb(&de, data);
    }
    (void) closedir(dirp);
  }
  return 1;
}

struct dir_scan_data {
  struct mg_direntry *entries;
  int num_entries;
  int arr_size;
};

static void dir_scan_callback(struct mg_direntry *de, void *data) {
  struct dir_scan_data *dsd = (struct dir_scan_data *) data;

  if (dsd->entries == NULL || dsd->num_entries >= dsd->arr_size) {
    dsd->arr_size *= 2;
    dsd->entries = (struct mg_direntry *) realloc(dsd->entries, dsd->arr_size *
                                         sizeof(dsd->entries[0]));
  }
  if (dsd->entries == NULL) {
    // TODO(lsm): propagate an error to the caller
    dsd->num_entries = 0;
  } else {
    dsd->entries[dsd->num_entries].file_name = mg_strdup(de->file_name);
    dsd->entries[dsd->num_entries].st = de->st;
    dsd->entries[dsd->num_entries].conn = de->conn;
    dsd->num_entries++;
  }
}

static void handle_directory_request(struct mg_connection *conn,
                                     const char *dir) {
  int i, sort_direction;
  struct dir_scan_data data = { NULL, 0, 128 };

  if (mg_is_producing_nested_page(conn))
    return;
  if (!mg_scan_directory(conn, dir, &data, dir_scan_callback)) {
    send_http_error(conn, 500, "Cannot open directory",
                    "Error: opendir(%s): %s", dir, strerror(ERRNO));
    return;
  }

  sort_direction = (!is_empty(conn->request_info.query_string) &&
                    conn->request_info.query_string[1] == 'd') ? 'a' : 'd';

  //mg_set_response_code(conn, 200); -- not needed any longer
  //mg_add_response_header(conn, 0, "Connection", "%s", suggest_connection_header(conn)); -- not needed any longer
  mg_add_response_header(conn, 0, "Content-Type", "text/html; charset=utf-8");
  if (strcmp(conn->request_info.http_version, "1.1") >= 0)
    mg_add_response_header(conn, 0, "Transfer-Encoding", "chunked");
  else // HTTP/1.0:
    conn->must_close = 1;
  mg_write_http_response_head(conn, 200, 0);
  mg_printf(conn,
            "<html><head><title>Index of %s</title>"
            "<style>th {text-align: left;}</style></head>"
            "<body><h1>Index of %s</h1><pre><table cellpadding=\"0\">"
            "<tr><th><a href=\"?n%c\">Name</a></th>"
            "<th><a href=\"?d%c\">Modified</a></th>"
            "<th><a href=\"?s%c\">Size</a></th></tr>"
            "<tr><td colspan=\"3\"><hr></td></tr>",
            conn->request_info.uri, conn->request_info.uri,
            sort_direction, sort_direction, sort_direction);

  // Print first entry - link to a parent directory
  mg_printf(conn,
            "<tr><td><a href=\"%s%s\">%s</a></td>"
            "<td>&nbsp;%s</td><td>&nbsp;&nbsp;%s</td></tr>\n",
            conn->request_info.uri, "..", "Parent directory", "-", "-");

  // Sort and print directory entries
  qsort(data.entries, (size_t) data.num_entries, sizeof(data.entries[0]),
        compare_dir_entries);
  for (i = 0; i < data.num_entries; i++) {
    print_dir_entry(&data.entries[i]);
    free(data.entries[i].file_name);
  }
  free(data.entries);

  mg_printf(conn, "</table></body></html>");
  (void) mg_flush(conn);
}

// Write the content data to the log file, line by line.
//
// Use the 'msg_fmt' printf() format string to format the log line,
// where 'arg0' will be placed in the first %s and the data line in
// the second %s.
//
// Return number of bytes read on success, negative number on error.
static int64_t send_data_to_log(struct mg_connection *conn, FILE *fp, int64_t len, const char *msg_fmt, const char *arg0) {
  char buf[DATA_COPY_BUFSIZ];
  int64_t rlen = 0;
  int offset = 0;

  while (len > 0) {
    // Calculate how much to read from the file in the buffer
    char *line = buf;
    int n = pull(fp, NULL, buf + offset, sizeof(buf) - offset - 1);
    if (n < 0) {
      break;
    }
    rlen += n;
    buf[offset + n] = 0;
    if (n == 0) {
      // log possible last remaining line and then we're done:
      if (buf[0])
        mg_cry(conn, msg_fmt, arg0, buf);
      break; // EOF
    }
    offset = 0;
    // log the stderr produce one line at a time
    do {
      char *eol = line + strcspn(line, "\r\n");
      if (!eol[0])  // break out when we didn't hit a CR/LF/CRLF
        break;
      offset = (int)((eol - buf) + strspn(eol, "\r\n"));
      *eol = 0;
      // tweak: do not log empty stderr lines
      if (line[0])
        mg_cry(conn, msg_fmt, arg0, line);
      line = buf + offset;
    } while (n > offset);
    if (n > offset) {
      memmove(buf, buf + offset, n + 1 - offset);
      offset = n - offset;
    } else {
      buf[0] = 0;
      offset = 0;
    }
  }
  return rlen;
}

// Send len bytes from the opened file to the client.
//
// 'len' may be larger than the amount of data actually available
// in the file; this will not be considered an error and send_file_data()
// will cope seamlessly with this situation.
//
// Return negative number on error; otherwise return the number of bytes
// actually written.
static int64_t send_file_data(struct mg_connection *conn, FILE *fp, int64_t len) {
  char buf[DATA_COPY_BUFSIZ];
  int to_read, num_read, num_written;
  int64_t wlen = 0;

  while (len > 0) {
    // Calculate how much to read from the file in the buffer
    to_read = sizeof(buf);
    if ((int64_t) to_read > len)
      to_read = (int) len;

    if (feof(fp))
        break;

    // Read from file, exit the loop on error
    num_read = (int)fread(buf, 1, (size_t)to_read, fp);
    if (num_read <= 0 && ferror(fp)) {
      send_http_error(conn, 578, NULL, "%s: failed to read from file: %s", __func__, mg_strerror(ERRNO)); // signal internal error in access log file at least
      return -2;
    }

    // Send read bytes to the client, exit the loop on error
    num_written = mg_write(conn, buf, (size_t)num_read);
    if (num_written != num_read) {
      send_http_error(conn, 580, NULL, "%s: incomplete write to socket", __func__); // signal internal error or premature close by client in access log file at least
      return -1;
    }
    // Both read and write were successful, adjust counters
    len -= num_written;
    wlen += num_written;
  }
  return wlen;
}

// Return >= 1 on success.
static int parse_range_header(const char *header, int64_t *a, int64_t *b) {
  return sscanf(header, "bytes=%" SCNd64 "-%" SCNd64, a, b);
}

static void gmt_time_string(char *buf, size_t buf_len, const time_t *t) {
  strftime(buf, buf_len, "%a, %d %b %Y %H:%M:%S GMT", gmtime(t));
}

static char *construct_etag(char *buf, size_t buf_len,
                           const struct mgstat *stp) {
  MG_ASSERT(buf_len > 1);
  mg_snq0printf(fc(NULL), buf, buf_len, "\"%lx.%" PRId64 "\"",
                  (unsigned long) stp->mtime, stp->size);
  return buf;
}

// return negative number on error; 0 on success
static int handle_file_request(struct mg_connection *conn, const char *path,
                                struct mgstat *stp) {
  char date[64], lm[64], etag[64];
  const char *hdr;
  time_t curtime = time(NULL);
  int64_t cl, r1, r2;
  struct vec mime_vec;
  FILE *fp;
  int n;

  get_mime_type(conn->ctx, path, "text/plain", &mime_vec);
  cl = stp->size;
  mg_set_response_code(conn, 200);

  if ((fp = mg_fopen(path, "rb")) == NULL) {
    send_http_error(conn, 500, NULL,
                    "fopen(%s): %s", path, mg_strerror(ERRNO));
    return -1;
  }
  set_close_on_exec(fileno(fp));

  // If Range: header specified, act accordingly
  r1 = r2 = 0;
  hdr = mg_get_header(conn, "Range");
  if (hdr != NULL && (n = parse_range_header(hdr, &r1, &r2)) > 0) {
    mg_set_response_code(conn, 206);
    (void) fseeko(fp, r1, SEEK_SET);
    cl = n == 2 ? r2 - r1 + 1: cl - r1;
    mg_add_response_header(conn, 0, "Content-Range", "bytes "
                           "%" PRId64 "-%"
                           PRId64 "/%" PRId64,
                           r1, r1 + cl - 1, stp->size);
  }

  // Prepare Etag, Date, Last-Modified headers. Must be in UTC, according to
  // http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.3
  gmt_time_string(date, sizeof(date), &curtime);
  gmt_time_string(lm, sizeof(lm), &stp->mtime);

  mg_add_response_header(conn, 0, "Date", "%s", date);
  mg_add_response_header(conn, 0, "Last-Modified", "%s", lm);
  mg_add_response_header(conn, 0, "Etag", "%s", construct_etag(etag, sizeof(etag), stp));
  // 'text/...' mime types default to ISO-8859-1; make sure they use the more modern UTF-8 charset instead:
  if (mime_vec.len > 5 && !memcmp("text/", mime_vec.ptr, 5))
    mg_add_response_header(conn, 0, "Content-Type", "%.*s; charset=%s", (int) mime_vec.len, mime_vec.ptr, "utf-8");
  else
    mg_add_response_header(conn, 0, "Content-Type", "%.*s", (int) mime_vec.len, mime_vec.ptr);
  mg_add_response_header(conn, 0, "Content-Length", "%" PRId64, cl);
  //mg_add_response_header(conn, 0, "Connection", "%s", suggest_connection_header(conn)); -- not needed any longer
  mg_add_response_header(conn, 0, "Accept-Ranges", "bytes");
  n = mg_write_http_response_head(conn, 0, 0);
  n--; // 0 --> -1

  if (n > 0 &&
      strcmp(conn->request_info.request_method, "HEAD") != 0) {
    n = (send_file_data(conn, fp, cl) >= 0);
  }
  (void) mg_fclose(fp);
  (void) mg_flush(conn);
  return (n > 0 ? 0 : -1);
}

int mg_send_file(struct mg_connection *conn, const char *path) {
  struct mgstat st;
  if (mg_stat(path, &st) == 0) {
    return handle_file_request(conn, path, &st);
  } else {
    send_http_error(conn, 404, NULL, "File not found: (%s)", path);
    return 404;
  }
}


// Parse HTTP headers from the given buffer, advance buffer to the point
// where parsing stopped.
//
// Return the number of headers parsed, or -1 on parse error (invalid headers).
static int parse_http_headers(char **buf, struct mg_header *headers, int max_header_count) {
  char *p;
  int i;

  for (i = 0; **buf && i < max_header_count; i++) {
    if (mg_extract_raw_http_header(buf, &headers[i].name, &headers[i].value) < 0)
      return -1;
  }
  p = *buf;
  p += strspn(p, "\r\n");
  *buf = p;

  return i;
}

static int is_valid_http_method(const char *method) {
  return !strcmp(method, "GET") || !strcmp(method, "POST") ||
         !strcmp(method, "HEAD") || !strcmp(method, "CONNECT") ||
         !strcmp(method, "PUT") || !strcmp(method, "DELETE") ||
         !strcmp(method, "OPTIONS") || !strcmp(method, "PROPFIND");
}

// Parse HTTP request, fill in mg_request_info structure.
// This function modifies the buffer by NUL-terminating
// HTTP request components, header names and header values.
static int parse_http_request(char *buf, struct mg_request_info *ri) {
  // RFC says that all initial whitespace should be ignored
  while (*buf != '\0' && isspace(* (unsigned char *) buf)) {
    buf++;
  }
  ri->request_method = skip(&buf, " ");
  ri->uri = skip(&buf, " ");
  if ((ri->query_string = strchr(ri->uri, '?')) != NULL) {
    *ri->query_string++ = '\0';
  } else {
    ri->query_string = "";
  }
  ri->http_version = skip(&buf, "\r\n");
  ri->num_headers = 0;

  if (is_valid_http_method(ri->request_method) &&
      !strncmp(ri->http_version, "HTTP/", 5)) {
    ri->http_version += 5;   // Skip "HTTP/"
    ri->num_headers = parse_http_headers(&buf, ri->http_headers, ARRAY_SIZE(ri->http_headers));
    if (ri->num_headers < 0) {
      ri->num_headers = 0;
      return -1;
    }
  } else {
    return -1;
  }
  return 0;
}

// Keep reading the input (either opened file descriptor fd, or socket sock,
// or SSL descriptor ssl) into buffer buf, until \r\n\r\n appears in the
// buffer (which marks the end of HTTP request). Buffer buf may already
// have some data. The length of the data is stored in nread.
// Upon every read operation, increase nread by the number of bytes read.
static int read_request(FILE *fp, struct mg_connection *conn,
                        char *buf, int bufsiz, int *nread) {
  int request_len, n = 1;

  request_len = get_request_len(buf, *nread);
  while (*nread < bufsiz && request_len == 0 && n > 0) {
    n = pull(fp, conn, buf + *nread, bufsiz - *nread);
    if (n > 0) {
      *nread += n;
      request_len = get_request_len(buf, *nread);
    }
  }

  if (n < 0) {
    // recv() error -> propagate error; do not process a b0rked-with-very-high-probability request
    return -1;
  }
  return request_len;
}

#if defined(TEST_CHUNKING_SEARCH_OPT_TESTSETTING)
static int shift_hit = 0;
static int shift_tail_hit = 0;
#endif

// Read enough bytes into the buffer to completely fetch a HTTP chunk header,
// then decode it.
// Return < 0 on error, >= 0 on success.
static int read_and_parse_chunk_header(struct mg_connection *conn)
{
  // as the user may want to read a fully custom chunk header,
  // call the user callback before commencing with the default treatment.
  struct mg_context *ctx = conn->ctx;
  int rv, pprv, n;
  char *p;
  char *exts, *e;
  struct mg_header chunk_headers[64] = {0};
  int hdr_count;
  // ALWAYS shift when we've got a user-defined custom chunk header function
  // and we're running out of buffer space; it's easier for the user code
  // as ample bufsiz is guaranteed that way.
  int do_shift = (ctx->user_functions.read_chunk_header &&
                  conn->rx_chunk_buf_size - conn->rx_buffer_read_len < CHUNK_HEADER_BUFSIZ);

  for (;;) {
    char *buf = conn->buf + conn->request_len;
    int bufsiz = conn->rx_chunk_buf_size;
    int offset;

    // when a bit of buffered data is still available, make sure it's in the right spot:
    //
    // Note: reduce the number of memmove()s for small chunks and largish buffers by only
    //       shifting the data when there won't be enough space for the next chunk header.
    //       We accomplish this by only shifting the data when we run out of buffer space.
    n = conn->rx_buffer_loaded_len - conn->rx_buffer_read_len;
    if (n > 0 && do_shift && conn->rx_buffer_read_len > 0) {
      memmove(buf, buf + conn->rx_buffer_read_len, n);
      conn->rx_buffer_read_len = 0;
      conn->rx_buffer_loaded_len = n;
    } else if (n <= 0) {
      conn->rx_buffer_read_len = 0;
      conn->rx_buffer_loaded_len = 0;
    }

    conn->rx_chunk_header_parsed = 2;
    if (ctx->user_functions.read_chunk_header) {
      int usr_nread;

      // memoize the conn->rx_buffer_read_len as that one will be damaged by any mg_read() in the user callback!
      offset = conn->rx_buffer_read_len;
      usr_nread = conn->rx_buffer_loaded_len - offset;
      rv = ctx->user_functions.read_chunk_header(conn, buf, bufsiz, &usr_nread);
      conn->rx_buffer_loaded_len = usr_nread + offset;
      conn->rx_buffer_read_len = offset;

      if (rv != 0) {
        // make sure we reset the state first and update the counters
        conn->rx_chunk_header_parsed = 1;
        if (rv >= 0) {
          conn->rx_chunk_count++;

          // mark the chunk header data in the buffer as READ:
          // assume no bytes beyond the header itself have been processed yet:
          conn->rx_buffer_read_len += rv;
        }
        return rv;
      }
    }

    // perform the default behaviour: read a HTTP chunk header:
    MG_ASSERT(conn->rx_chunk_header_parsed == 2);

    // shift the buffer to the 'active' part where the chunk header will reside:
    offset = conn->rx_buffer_read_len;
    buf += offset;
    bufsiz -= offset;
    conn->rx_buffer_loaded_len -= offset;
    conn->rx_buffer_read_len = 0;

    //rv = read_request(NULL, conn, buf, bufsiz, &conn->rx_buffer_loaded_len);
    n = 1;
    // make sure to skip the possible leading CRLF by blowing it away
    //
    // WARNING:
    // also blow it entirely away when it was already partly blasted in the previous
    // round in this outer loop when the buffer space was overflowing and hence data
    // has been shifted (do_shift = 1): this can happen right smack in the middle
    // of a CRLF pair, so we MUST regard them as independent.
    // (This cuts into our flexibility to tolerate non-complaint peers, who don't send
    //  CRLF but LF-only. Alas. Let them b0rk.)
    if (conn->rx_buffer_loaded_len >= 2) {
      if (buf[0] == '\r' || buf[0] == '\n')
        buf[0] = ' ';
      if (buf[1] == '\r' || buf[1] == '\n')
        buf[1] = ' ';
      e = memchr(buf, '\n', conn->rx_buffer_loaded_len);
    } else {
      e = NULL;
    }
    while (conn->rx_buffer_loaded_len < bufsiz && e == NULL && n > 0) {
      n = pull(NULL, conn, buf + conn->rx_buffer_loaded_len, bufsiz - conn->rx_buffer_loaded_len);
      if (n > 0) {
        conn->rx_buffer_loaded_len += n;
        // make sure to skip the possible leading CRLF by blowing it away:
        if (conn->rx_buffer_loaded_len >= 2) {
          if (buf[0] == '\r' || buf[0] == '\n')
            buf[0] = ' ';
          if (buf[1] == '\r' || buf[1] == '\n')
            buf[1] = ' ';
          e = memchr(buf, '\n', conn->rx_buffer_loaded_len);
        }
      }
    }

    if (n < 0) {
      // recv() error -> propagate error; do not process a b0rked-with-very-high-probability request
      conn->rx_buffer_loaded_len += offset;
      conn->rx_buffer_read_len += offset;
      return -1;
    }
    if (e == NULL) {
      conn->rx_buffer_loaded_len += offset;
      conn->rx_buffer_read_len += offset;
      // can we shift, or are we at our wits end?
      if (do_shift) {
        return -1;  // invalid or overlarge chunk header
      }
      do_shift = 1;
#if defined(TEST_CHUNKING_SEARCH_OPT_TESTSETTING)
      shift_hit++;
#endif
      DEBUG_TRACE(0x0004, ("SHIFTing the RX buffer: %d", offset));
      continue;
    }
    rv = e - buf + 1; // ~ request_len

    conn->rx_chunk_header_parsed = 0;
    // when nothing was read, that's an error right now!
    if (rv < 2) {
      conn->rx_buffer_loaded_len += offset;
      conn->rx_buffer_read_len += offset;
      return -1;
    }
    MG_ASSERT(buf[1] != ' ' ? rv > 2 : 1);

    buf[rv - 1] = 0;  // turn chunk header into a C string for further processing
    p = buf;
    p += strspn(p, "\r\n \t");
    // decode HEX length:
    conn->rx_remaining_chunksize = strtoul(p, &p, 16);
    // see if there's any extensions/headers in there:
    p += strspn(p, " \t;");
    exts = p;

    hdr_count = 0;
    // load the trailing headers? (i.e. did we hit the terminating ZERO chunk?)
    if (conn->rx_remaining_chunksize == 0) {
      int nread = conn->rx_buffer_loaded_len;
      int trail;

      // restore the CRLF for the header itself, so read_request()'ll work.
      // Also we need to do this in case we need to locate it again in the next round,
      // when the currently remaining buffer space turns out to be too small for the
      // new chunk header.
      buf[rv - 1] = '\n';

      // read_request() expects a double CRLF as sentinel; allow it to revisit the chunk-size head
      // so as to always provide this double CRLF for the last-chunk, cf. RFC2616, sec 3.6.1
      trail = read_request(NULL, conn, buf, bufsiz, &nread);

      if (trail < 0) {
        // recv() error -> propagate error; do not process a b0rked-with-very-high-probability request
        return -1;
      }
      conn->rx_buffer_loaded_len = nread;
      MG_ASSERT(conn->rx_buffer_read_len == 0);
      conn->rx_buffer_read_len = trail;

      // did we overrun the buffer while fetching headers?
      if (trail == 0 && nread == conn->rx_buffer_loaded_len) {
        conn->rx_buffer_loaded_len += offset;
        conn->rx_buffer_read_len += offset;
        if (do_shift) {
          return -1;  // malformed end chunk header set
        }
        do_shift = 1;
#if defined(TEST_CHUNKING_SEARCH_OPT_TESTSETTING)
        shift_tail_hit++;
#endif
        DEBUG_TRACE(0x000C, ("SHIFTing the RX buffer @ TAIL chunk: %d", offset));
        continue;
      }

      // extract the (optional) chunk extensions, then parse the (optional) headers
      p += strcspn(p, "\r\n");
      *p++ = 0;
      buf[trail - 1] = 0;
      p += strspn(p, "\r\n");
      hdr_count = parse_http_headers(&p, chunk_headers, ARRAY_SIZE(chunk_headers));
      if (hdr_count < 0)
        return -2;
      rv = trail;
    } else {
      // read_request() calls pull() so we must account for the bytes read ourselves here.
      // When the user callback reads the header, it will use mg_read() instead, which
      // will do the accounting for us.
      MG_ASSERT(conn->rx_buffer_read_len == 0);
      conn->rx_buffer_read_len = rv;

      // extract the (optional) check extensions
      p += strcspn(p, "\r\n");
      *p = 0;
    }

    conn->rx_buffer_loaded_len += offset;
    conn->rx_buffer_read_len += offset;

    // call user callback:
    pprv = 0;
    conn->rx_chunk_header_parsed = 3;
    if (ctx->user_functions.process_rx_chunk_header) {
      pprv = ctx->user_functions.process_rx_chunk_header(conn, conn->rx_remaining_chunksize, exts, chunk_headers, hdr_count);
    }
    conn->rx_chunk_header_parsed = 1;

    if (pprv == 0) {
      conn->rx_chunk_count++;
    }

    return pprv < 0 ? pprv : rv;
  }
}

// For given directory path, append the valid index file.
// Return 1 if the index file exists, 0 if no index file could be located in the given directory.
// If the file is found, it's stats are returned in stp and path has been augmented to point at the index file.
int mg_substitute_index_file(struct mg_connection *conn, char *path,
                             size_t path_len, struct mgstat *stp) {
  const char *list = get_conn_option(conn, INDEX_FILES);
  struct mgstat st;
  struct vec filename_vec;
  size_t n = strlen(path);
  int found = 0;

  // The 'path' given to us points to the directory. Remove all trailing
  // directory separator characters from the end of the path, and
  // then append single directory separator character.
  while (n > 0 && IS_DIRSEP_CHAR(path[n - 1])) {
    n--;
  }
  path[n] = DIRSEP;

  // Traverse index files list. For each entry, append it to the given
  // path and see if the file exists. If it exists, break the loop
  while ((list = next_option(list, &filename_vec, NULL)) != NULL) {

    // Ignore too long entries that may overflow path buffer
    if (filename_vec.len > path_len - n - 2)
      continue;

    // Prepare full path to the index file
    (void) mg_strlcpy(path + n + 1, filename_vec.ptr, filename_vec.len + 1);

    // Does it exist?
    if (mg_stat(path, &st) == 0) {
      // Yes it does, break the loop
      *stp = st;
      found = 1;
      break;
    }
  }

  // If no index file exists, restore directory path
  if (!found) {
    path[n] = '\0';
  }

  return found;
}

// Return True if we should reply 304 Not Modified.
static int is_not_modified(const struct mg_connection *conn,
                           const struct mgstat *stp) {
  char etag[64];
  const char *ims = mg_get_header(conn, "If-Modified-Since");
  const char *inm = mg_get_header(conn, "If-None-Match");
  construct_etag(etag, sizeof(etag), stp);
  return (inm != NULL && !mg_strcasecmp(etag, inm)) ||
    (ims != NULL && stp->mtime <= parse_date_string(ims));
}

static int forward_body_data(struct mg_connection *conn, FILE *fp,
                             struct mg_connection *dst_conn, int send_error_on_fail) {
  const char *expect;
  char buf[DATA_COPY_BUFSIZ];
  int to_read, nread, success = 0;

  expect = mg_get_header(conn, "Expect");
  MG_ASSERT(fp != NULL);

  // content_len==-1 is all right; it's just either Transfer-Encoding or a HTTP/1.0 client.
  if (!strcmp(conn->request_info.request_method, "POST") ||
      !strcmp(conn->request_info.request_method, "PUT")) {
    send_http_error(conn, 411, NULL, "");
  } else if (expect != NULL && mg_strcasecmp(expect, "100-continue")) {
    send_http_error(conn, 417, NULL, "");
  } else if (conn->request_len > 0) {
    if (expect != NULL && !mg_have_headers_been_sent(conn)) {
      if (mg_printf(conn, "HTTP/1.1 100 Continue\r\n\r\n") <= 0)
        goto failure;
      // per RFC2616, section 8.2.3: An origin server that sends a
      // 100 (Continue) response MUST ultimately send a final
      // status code, once the request body is received and processed,
      // unless it terminates the transport connection prematurely.
      //
      // Hence, we must ensure that mg_have_headers_been_sent()
      // will produce 0 after this. Hence we tweak the counters:
      conn->num_bytes_sent = -1;
      MG_ASSERT(mg_have_headers_been_sent(conn) == 0);
    }

    nread = 0;
    while (conn->consumed_content < conn->content_len || conn->content_len == -1) {
      int nwrite;

      to_read = sizeof(buf);
      if (conn->content_len >= 0 && (int64_t) to_read > conn->content_len - conn->consumed_content) {
        to_read = (int) (conn->content_len - conn->consumed_content);
      }
      nread = mg_read(conn, buf, to_read);
      if (nread <= 0)
        break;
      nwrite = push(fp, dst_conn, buf, nread);
      if (nwrite != nread) {
        nread = -1;
        break;
      }
    }

    if (conn->consumed_content == conn->content_len || conn->content_len == -1) {
      success = (nread >= 0);
    }

    // Each error code path in this function must send an error
    if (!success) {
failure:
      if (send_error_on_fail) {
        send_http_error(conn, 577, NULL, ((fp && ferror(fp)) ? "%s: I/O error: %s" : "%s: I/O error: failed to forward all bytes"), __func__, mg_strerror(ERRNO));
      }
    }
  } else {
    send_http_error(conn, 577, NULL, "%s: invoked for a clobbered request", __func__);
  }

  return success;
}

#if !defined(NO_CGI)
// This structure helps to create an environment for the spawned CGI program.
// Environment is an array of "VARIABLE=VALUE\0" ASCIIZ strings,
// last element must be NULL.
// However, on Windows there is a requirement that all these VARIABLE=VALUE\0
// strings must reside in a contiguous buffer. The end of the buffer is
// marked by two '\0' characters.
// We satisfy both worlds: we create an envp array (which is vars), all
// entries are actually pointers inside buf.
struct cgi_env_block {
  struct mg_connection *conn;
  char buf[CGI_ENVIRONMENT_SIZE]; // Environment buffer
  int len; // Space taken
  char *vars[MAX_CGI_ENVIR_VARS]; // char **envp
  int nvars; // Number of variables
};

// Append VARIABLE=VALUE\0 string to the buffer, and add a respective
// pointer into the vars array.
//
// Return NULL on error, otherwise return pointer to saved variable=value string.
static char *addenv(struct cgi_env_block *block, PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(2, 3);

static char *addenv(struct cgi_env_block *block, const char *fmt, ...) {
  int n;
  size_t space;
  char *added;
  va_list ap;

  // Calculate how much space is left in the buffer
  space = sizeof(block->buf) - block->len - 2;
  MG_ASSERT((int)space >= 0);

  // Make a pointer to the free space int the buffer
  added = block->buf + block->len;

  // Copy VARIABLE=VALUE\0 string into the free space
  va_start(ap, fmt);
  n = mg_vsnprintf(block->conn, added, space, fmt, ap);
  va_end(ap);

  // Make sure we do not overflow buffer and the envp array
  if (n > 0 && n + 1 < (int)space &&
      block->nvars < (int) ARRAY_SIZE(block->vars) - 2) {
    // Append a pointer to the added string into the envp array
    block->vars[block->nvars++] = added;
    // Bump up used length counter. Include \0 terminator
    block->len += n + 1;
  } else {
    mg_cry(block->conn, "%s: CGI env buffer overflow for fmt '%s'", __func__, fmt);
    added = NULL;
  }

  return added;
}

static int prepare_cgi_environment(struct mg_connection *conn,
                                   const char *prog,
                                   struct cgi_env_block *blk) {
  const char *s, *slash;
  struct vec var_vec = {0};
  char *p, src_addr[SOCKADDR_NTOA_BUFSIZE];
  int  i;

  blk->len = blk->nvars = 0;
  blk->conn = conn;
  sockaddr_to_string(src_addr, sizeof(src_addr), &conn->client.rsa);

  addenv(blk, "SERVER_NAME=%s", get_conn_option(conn, AUTHENTICATION_DOMAIN));
  addenv(blk, "SERVER_ROOT=%s", get_conn_option(conn, DOCUMENT_ROOT));
  addenv(blk, "DOCUMENT_ROOT=%s", get_conn_option(conn, DOCUMENT_ROOT));

  // Prepare the environment block
  addenv(blk, "GATEWAY_INTERFACE=CGI/1.1");
  addenv(blk, "SERVER_PROTOCOL=HTTP/1.1");
  if (conn->request_info.parent) {
    const char *str = conn->request_info.parent->uri;
    size_t slen;
    if (!str) str = "(null)";
    slen = strlen(str);
    addenv(blk, "REDIRECT_STATUS=%d", conn->request_info.status_code); // For PHP
    // REDIRECT_URL ~ REQUEST_URI
    addenv(blk, "REDIRECT_URL=%.*s%s", (int)(slen > PATH_MAX ? PATH_MAX : slen), str, (slen > PATH_MAX ? "(...etc...)" : ""));
    // REDIRECT_METHOD ~ REQUEST_METHOD
    addenv(blk, "REDIRECT_METHOD=%s", conn->request_info.parent->request_method);
    // REDIRECT_QUERY_STRING ~ QUERY_STRING
    if (!is_empty(conn->request_info.parent->query_string)) {
      str = conn->request_info.parent->query_string;
      slen = strlen(str);
      addenv(blk, "REDIRECT_QUERY_STRING=%.*s%s", (int)(slen > MG_BUF_LEN ? MG_BUF_LEN : slen), str, (slen > MG_BUF_LEN ? "&etc=..." : ""));
    }

    p = conn->request_info.status_custom_description;
    if (conn->request_info.parent && !is_empty(conn->request_info.parent->status_custom_description) && is_empty(p)) {
      p = conn->request_info.parent->status_custom_description;
    }
    if (!is_empty(p)) {
      p = addenv(blk, "REDIRECT_ERROR_NOTES=%s", p);
      if (!p) {
        return -1;
      } else {
        while (*p) {
          // tweak: replace all \n and \r in there by \t to make sure it's a single line value
          p += strcspn(p, "\r\n");
          if (*p)
            *p++ = '\t';
        }
      }
    }
  }

  addenv(blk, "SERVER_PORT=%d", get_socket_port(&conn->client.lsa));

  addenv(blk, "REQUEST_METHOD=%s", conn->request_info.request_method);
  addenv(blk, "REMOTE_ADDR=%s", src_addr);
  addenv(blk, "REMOTE_PORT=%d", conn->request_info.remote_port);
  addenv(blk, "REQUEST_URI=%s", conn->request_info.uri);

  // SCRIPT_NAME
  MG_ASSERT(conn->request_info.uri[0] == '/');
  slash = strrchr(conn->request_info.uri, '/');
  if ((s = strrchr(prog, '/')) == NULL)
    s = prog;
  addenv(blk, "SCRIPT_NAME=%.*s%s", (int)(slash - conn->request_info.uri),
         conn->request_info.uri, s);

  addenv(blk, "SCRIPT_FILENAME=%s", prog);
  addenv(blk, "PATH_TRANSLATED=%s", prog);

  if ((s = mg_get_header(conn, "Content-Type")) != NULL)
    addenv(blk, "CONTENT_TYPE=%s", s);

  if (!is_empty(conn->request_info.query_string))
    addenv(blk, "QUERY_STRING=%s", conn->request_info.query_string);

  if ((s = mg_get_header(conn, "Content-Length")) != NULL)
    addenv(blk, "CONTENT_LENGTH=%s", s);

  if ((s = getenv("PATH")) != NULL)
    addenv(blk, "PATH=%s", s);

  if (conn->request_info.path_info != NULL) {
    addenv(blk, "PATH_INFO=%s", conn->request_info.path_info);
  }

#if defined(_WIN32)
  if ((s = getenv("COMSPEC")) != NULL) {
    addenv(blk, "COMSPEC=%s", s);
  }
  if ((s = getenv("SYSTEMROOT")) != NULL) {
    addenv(blk, "SYSTEMROOT=%s", s);
  }
  if ((s = getenv("SystemDrive")) != NULL) {
    addenv(blk, "SystemDrive=%s", s);
  }
#else
  if ((s = getenv("LD_LIBRARY_PATH")) != NULL)
    addenv(blk, "LD_LIBRARY_PATH=%s", s);
#endif // _WIN32

  if ((s = getenv("PERLLIB")) != NULL)
    addenv(blk, "PERLLIB=%s", s);

  if (conn->request_info.remote_user != NULL) {
    addenv(blk, "REMOTE_USER=%s", conn->request_info.remote_user);
    addenv(blk, "AUTH_TYPE=Digest");
  }

  // Add all headers as HTTP_* variables
  for (i = 0; i < conn->request_info.num_headers; i++) {
    p = addenv(blk, "HTTP_%s=%s",
               conn->request_info.http_headers[i].name,
               conn->request_info.http_headers[i].value);
    if (!p)
      return -1;

    // Convert variable name into uppercase, and change - to _
    for (; *p != '=' && *p != '\0'; p++) {
      if (*p == '-')
        *p = '_';
      *p = (char) toupper(* (unsigned char *) p);
    }
  }

  // Add user-specified variables
  s = get_conn_option(conn, CGI_ENVIRONMENT);
  while ((s = next_option(s, &var_vec, NULL)) != NULL) {
    addenv(blk, "%.*s", (int)var_vec.len, var_vec.ptr);
  }

  // check for buffer overflow by looking at the return code of the last variable addition:
  if (!addenv(blk, "HTTPS=%s", conn->ssl == NULL ? "off" : "on"))
    return -1;

  blk->vars[blk->nvars++] = NULL;
  blk->buf[blk->len++] = '\0';

  MG_ASSERT(blk->nvars < (int) ARRAY_SIZE(blk->vars));
  MG_ASSERT(blk->len > 0);
  MG_ASSERT(blk->len < (int) sizeof(blk->buf));
  return 0;
}

static void handle_cgi_request(struct mg_connection *conn, const char *prog) {
  int headers_len, data_len, i, fd_stdin[2], fd_stdout[2], fd_stderr[2];
  const char *status, *connection_status, *content_type;
  char buf[HTTP_HEADERS_BUFSIZ], *pbuf, dir[PATH_MAX], *p, *e;
  struct mg_header cgi_headers[64];
  int cgi_header_count;
  struct cgi_env_block blk;
  FILE *in, *out, *err;
  pid_t pid;
  int is_text_out;

  pid = (pid_t) -1;
  fd_stdin[0] = fd_stdin[1] = fd_stdout[0] = fd_stdout[1] = fd_stderr[0] = fd_stderr[1] = -1;
  in = out = err = NULL;

  if (prepare_cgi_environment(conn, prog, &blk)) {
    send_http_error(conn, 500, NULL,
                    "Cannot create CGI environment variable collection, quite probably due to buffer overflow due to a very long request");
    goto done;
  }

  // CGI must be executed in its own directory. 'dir' must point to the
  // directory containing executable program, 'p' must point to the
  // executable program name relative to 'dir'.
  (void) mg_snprintf(conn, dir, sizeof(dir), "%s", prog);
  for (p = dir, e = p + strlen(p) - 1; e > p; e--) {
    if (IS_DIRSEP_CHAR(*e)) {
      *e = '\0';
      p = e + 1;
      break;
    }
  }
  if (e == p) {
    dir[0] = '.', dir[1] = '\0';
  } else {
    prog = p;
  }

  if (pipe(fd_stdin) != 0 || pipe(fd_stdout) != 0 || pipe(fd_stderr) != 0) {
    send_http_error(conn, 500, NULL,
                    "Cannot create CGI pipe: %s", mg_strerror(ERRNO));
    goto done;
  } else if ((in = fdopen(fd_stdin[1], "wb")) == NULL ||
             (out = fdopen(fd_stdout[0], "rb")) == NULL ||
             (err = fdopen(fd_stderr[0], "rb")) == NULL) {
    send_http_error(conn, 500, NULL,
                    "fopen: %s", mg_strerror(ERRNO));
    goto done;
  }
  setbuf(in, NULL);
  setbuf(out, NULL);
  setbuf(err, NULL);
  pid = spawn_process(conn, prog, blk.buf, blk.vars,
                      fd_stdin[0], fd_stdout[1], fd_stderr[1], dir);

  // spawn_process() must close those!
  // If we don't mark them as closed, close() attempt before
  // return from this function throws an exception on Windows.
  // Windows does not like when closed descriptor is closed again.
  fd_stdin[0] = fd_stdout[1] = fd_stderr[1] = -1;

  if (pid == (pid_t) -1) {
    send_http_error(conn, 500, NULL,
                    "Cannot spawn CGI process: %s", mg_strerror(ERRNO));
    goto done;
  }

  // Send PUT/POST/... data to the CGI process if needed.
  // Log but otherwise IGNORE any failure to send the content, as
  // the CGI script/exe may have already decided to produce a
  // response based on the HTTP headers alone, which is legal
  // behaviour.
  if (conn->request_len > 0 &&
      !forward_body_data(conn, in, NULL, 0)) {
    mg_write2log(conn, NULL, time(NULL), "warning", "Failed to forward request content (body) to the CGI process: %s", mg_strerror(ERRNO));
  }

  // Close so child gets an EOF.
  fclose(in);
  in = NULL;

  // Now read CGI reply into a buffer. We need to set correct
  // status code, thus we need to see all HTTP headers first.
  // Do not send anything back to client, until we buffer in all
  // HTTP headers.
  data_len = 0;
  headers_len = read_request(out, NULL,
                             buf, sizeof(buf), &data_len);
  if (headers_len <= 0) {
    send_http_error(conn, 500, NULL,
                    "CGI program sent malformed HTTP headers or HTTP headers take up more than %u buffer bytes: [%.*s]",
                    (unsigned int)sizeof(buf), data_len, buf);
    goto done;
  }
  pbuf = buf;
  buf[headers_len - 1] = '\0';
  cgi_header_count = parse_http_headers(&pbuf, cgi_headers, ARRAY_SIZE(cgi_headers));
  if (cgi_header_count < 0) {
    send_http_error(conn, 500, NULL, "CGI program sent malformed HTTP headers");
    goto done;
  }

  // the CGI app might send the data to us in chunked mode too!
  status = get_header(cgi_headers, cgi_header_count, "Transfer-Encoding");
  if (status && mg_stristr(status, "chunked")) {
    send_http_error(conn, 500, NULL,
                    "Mongoose does not support Chunked Transfer Mode from the CGI application");
    goto done;
  }

  // Make up and send the status line
  if ((status = get_header(cgi_headers, cgi_header_count, "Status")) != NULL) {
    char * chknum = NULL;
    int response_code = (int)strtol(status, &chknum, 10);
    if (chknum != NULL)
      status = chknum + strspn(chknum, " ");
    else
      status = NULL;
    if (!is_legal_response_code(response_code)) {
      send_http_error(conn, 500, NULL,
                      "CGI program sent malformed HTTP Status header: [%s]",
                      get_header(cgi_headers, cgi_header_count, "Status"));
      goto done;
    }
    if (response_code != mg_set_response_code(conn, response_code))
      status = NULL;
  } else if (get_header(cgi_headers, cgi_header_count, "Location") != NULL) {
    mg_set_response_code(conn, 302);
  } else {
    mg_set_response_code(conn, 200);
  }
  if ((connection_status = get_header(cgi_headers, cgi_header_count, "Connection")) != NULL) {
    // fix: keep-alive (storing connection_status is a performance bonus)
    if (mg_strcasecmp(connection_status, "keep-alive")) {
      conn->must_close = 1;
    }
  }

  // Send headers
  for (i = 0; i < cgi_header_count; i++) {
    mg_add_response_header(conn, 0, cgi_headers[i].name, "%s", cgi_headers[i].value);
  }

  // See if there's any data in the 'err' channel and when there is,
  // discard any Content-Length header as it'll be invalid anyway.
  content_type = get_header(cgi_headers, cgi_header_count, "Content-Type");
  is_text_out = 0;
  if (content_type)
    is_text_out = !mg_strncasecmp(content_type, "text/plain", 10) +
                  2 * !mg_strncasecmp(content_type, "text/html", 9);

  // ri.headers[] are invalid from this point onward!
  i = 0;
  if (is_text_out) {
    MG_ASSERT(headers_len > 0);
    i = pull(err, NULL, buf, headers_len);
    if (i > 0) {
      if (strcmp(conn->request_info.http_version, "1.1") >= 0)
        mg_add_response_header(conn, 0, "Transfer-Encoding", "chunked");
      else {
        // HTTP/1.0:
        mg_remove_response_header(conn, "Content-Length");
        conn->must_close = 1;
      }
    } else if (i < 0) {
      send_http_error(conn, 500, NULL,
                      "CGI program clobbered stderr: %s",
                      mg_strerror(ERRNO));
      goto done;
    }
  } else {
    // Serve all CGI output in 'chunked' mode; it's easier that way.
    // Note that the 'Transfer-Encoding' header add op automatically
    // removes any lingering 'Content-Length' header in the set for
    // those are mutually exclusive. mg_add_response_header() takes
    // care of that, so no worries.
    if (strcmp(conn->request_info.http_version, "1.1") >= 0)
      mg_add_response_header(conn, 0, "Transfer-Encoding", "chunked");
    else // HTTP/1.0:
      conn->must_close = 1;
  }
  // and always send the (up-to-date) Connection: header:
  // this call overwrites any previous value, intentionally.
  mg_add_response_header(conn, 0, "Connection", "%s", suggest_connection_header(conn));
  mg_write_http_response_head(conn, 0, status);

  if (is_text_out && i > 0) {
    if (is_text_out == 2) {
      mg_printf(conn,
                "<!DOCTYPE html>\n"
                "<meta charset=utf-8>\n"
                "<title>Mongoose Doing the B0rk B0rk B0rk</title>\n"
                "<body>\n"
                "<h1>CGI Errors!</h1>\n"
                "<pre>");
    } else {
      mg_printf(conn,
                "CGI Errors!\n"
                "===========\n\n");
    }
    // Send prefetched chunk to client
    (void)mg_write(conn, buf, i);
    // Read the rest of CGI stderr output and send to the client
    (void)send_file_data(conn, err, INT64_MAX);
    if (is_text_out == 2) {
      mg_printf(conn,
                "</pre>\n"
                "<hr/>\n");
    } else {
      mg_printf(conn,
                "\n-----------------------------------------------------------\n\n");
    }
  }

  // Send chunk of data that may have been read after the headers
  if (data_len > headers_len)
    (void)mg_write(conn, buf + headers_len, data_len - headers_len);

  // Read the rest of CGI output and send to the client
  (void)send_file_data(conn, out, INT64_MAX);

  (void)mg_flush(conn);

done:
  if (pid != (pid_t) -1) {
    kill(pid, SIGKILL);
  }
  if (fd_stdin[0] != -1) {
    (void) close(fd_stdin[0]);
  }
  if (fd_stdout[1] != -1) {
    (void) close(fd_stdout[1]);
  }
  if (fd_stderr[1] != -1) {
    (void) close(fd_stderr[1]);
  }

  if (in != NULL) {
    (void) fclose(in);
  } else if (fd_stdin[1] != -1) {
    (void) close(fd_stdin[1]);
  }

  if (out != NULL) {
    (void) fclose(out);
  } else if (fd_stdout[0] != -1) {
    (void) close(fd_stdout[0]);
  }

  if (err != NULL) {
    // copy stderr to error log:
    (void) send_data_to_log(conn, err, INT64_MAX, "CGI [%s] stderr says: %s", prog);
    (void) fclose(err);
  } else if (fd_stderr[0] != -1) {
    (void) close(fd_stderr[0]);
  }
}
#endif // !NO_CGI

// For a given PUT path, create all intermediate subdirectories
// for given path. Return 0 if the path itself is a directory,
// or -1 on error, 1 if OK.
static int put_dir(const char *path) {
  char buf[PATH_MAX];
  const char *s, *p;
  struct mgstat st;
  int len, res = 1;

  for (s = p = path + 2; (p = strchr(s, DIRSEP)) != NULL; s = ++p) {
    len = p - path;
    if (len >= (int) sizeof(buf)) {
      res = -1;
      break;
    }
    memcpy(buf, path, len);
    buf[len] = '\0';

    // Try to create intermediate directory
    DEBUG_TRACE(0x0400, ("mkdir(%s)", buf));
    if (mg_stat(buf, &st) == -1 && mg_mkdir(buf, 0755) != 0) {
      res = -1;
      break;
    }

    // Is path itself a directory?
    if (p[1] == '\0') {
      res = 0;
    }
  }

  return res;
}

static void put_file(struct mg_connection *conn, const char *path) {
  struct mgstat st;
  const char *range;
  int64_t r1, r2;
  FILE *fp;
  int rc;

  if (mg_is_producing_nested_page(conn))
    return;
  mg_set_response_code(conn, mg_stat(path, &st) == 0 ? 200 : 201);

  if ((rc = put_dir(path)) == 0) {
    mg_write_http_response_head(conn, 0, 0);
  } else if (rc == -1) {
    send_http_error(conn, 500, NULL,
                    "put_dir(%s): %s", path, mg_strerror(ERRNO));
  } else if ((fp = mg_fopen(path, "wb+")) == NULL) {
    send_http_error(conn, 500, NULL,
                    "fopen(%s): %s", path, mg_strerror(ERRNO));
  } else {
    set_close_on_exec(fileno(fp));
    range = mg_get_header(conn, "Content-Range");
    r1 = r2 = 0;
    if (range != NULL && parse_range_header(range, &r1, &r2) > 0) {
      mg_set_response_code(conn, 206);
      if (fseeko(fp, r1, SEEK_SET) == -1) {
        send_http_error(conn, 500, NULL,
                    "fseeko(%s, %" PRId64 "): %s", path, r1, mg_strerror(ERRNO));
        (void) mg_fclose(fp);
        return;
      }
    }
    if (forward_body_data(conn, fp, NULL, 1)) {
      mg_write_http_response_head(conn, 0, 0);
    }
    (void) mg_fclose(fp);
  }
}

// Extract VVV from the string ' "VVV"' with optional leading WS and VVV not containing
// any " itself. (Hence only useful for extracting 'simple' values such as file paths, etc.
// from a quoted string.
//
// Return NULL on error.
static char *extract_quoted_value(char *str) {
  char *rv;

  str += strspn(str, " \t\r\n");
  rv = str;
  if (*str != '"') {
    // no quotes around VVV are accepted, but then VVV can't contain whitespace either!
    str += strcspn(str, " \t\r\n\"");
  } else {
    rv++;
    str = strchr(str + 1, '"');
    if (!str) {
      // erroneous format: no closing quote. Return NULL.
      return NULL;
    }
  }
  *str = 0;
  return rv;
}

static int send_ssi_file(struct mg_connection *, const char *, FILE *, int);

// Return 0 on success; non-zero on error, where negative number is a fatal I/O failure.
static int do_ssi_include(struct mg_connection *conn, const char *ssi,
                           char *tag, int include_level) {
  char *file_name, path[PATH_MAX], *p;
  FILE *fp;
  int rv;

  tag += strspn(tag, " \t\r\n");
  if (!strncmp(tag, "virtual=", 8)) {
    // File name is relative to the webserver root
    file_name = extract_quoted_value(tag + 8);
    if (!file_name || !*file_name) goto faulty_tag_value;
    (void) mg_snprintf(conn, path, sizeof(path), "%s%c%s",
                       get_conn_option(conn, DOCUMENT_ROOT), DIRSEP, file_name);
  } else if (!strncmp(tag, "file=", 5)) {
    // File name is relative to the webserver working directory
    // or it is absolute system path
    file_name = extract_quoted_value(tag + 5);
    if (!file_name || !*file_name) goto faulty_tag_value;
    (void) mg_snprintf(conn, path, sizeof(path), "%s", file_name);
  } else if ((file_name = extract_quoted_value(tag)) != NULL && *file_name) {
    // File name is relative to the current document
    (void) mg_snprintf(conn, path, sizeof(path), "%s", ssi);
    if ((p = strrchr(path, '/')) != NULL) {
      p[1] = '\0';
    }
    (void) mg_snprintf(conn, path + strlen(path),
                       sizeof(path) - strlen(path), "%s", file_name);
  } else {
faulty_tag_value:
    mg_cry(conn, "Bad SSI #include: [%s] in SSI file [%s]", tag, ssi);
    return 1;
  }

  // remember the original value in 'p', reset it when we're done processing the SSI element
  p = conn->request_info.phys_path;
  rv = 0;
  conn->request_info.phys_path = path;
  if (!call_user(conn, MG_SSI_INCLUDE_REQUEST)) {
    if ((fp = mg_fopen(conn->request_info.phys_path, "rb")) == NULL) {
      mg_cry(conn, "Cannot open SSI #include: [%s] in SSI file [%s]: %s",
             conn->request_info.phys_path, ssi, mg_strerror(ERRNO));
      rv = 2;
    } else {
      set_close_on_exec(fileno(fp));
      if (match_string(get_conn_option(conn, SSI_EXTENSIONS),
                       -1,
                       conn->request_info.phys_path) > 0) {
        if (send_ssi_file(conn, conn->request_info.phys_path, fp, include_level + 1) < 0)
          rv = -1;
      } else {
        if (send_file_data(conn, fp, INT64_MAX) < 0)
          rv = -1;
      }
      (void) mg_fclose(fp);
    }
  }
  conn->request_info.phys_path = p;
  return rv;
}

#if !defined(NO_POPEN)

static int do_ssi_exec(struct mg_connection *conn, char *tag) {
  char *cmd;
  FILE *fp;

  if ((cmd = extract_quoted_value(tag)) == NULL || !*cmd) {
    send_http_error(conn, 577, NULL, "Bad SSI #exec");
    return -1;
  } else if ((fp = popen(cmd, "r")) == NULL) {
    send_http_error(conn, 577, NULL, "Cannot SSI #exec: [%s]: %s", cmd, mg_strerror(ERRNO));
    return -1;
  } else {
    int rv = (send_file_data(conn, fp, INT64_MAX) < 0);
    (void) pclose(fp);
    return rv;
  }
}

#endif // !NO_POPEN

static int send_ssi_file(struct mg_connection *conn, const char *path,
                          FILE *fp, int include_level) {
  char buf[SSI_LINE_BUFSIZ];
  int rlen, roff, taglen;
  struct vec ssi_start = {0}, ssi_end = {0};
  const char *m;
#if !defined(NO_CGI)
  struct cgi_env_block blk;

  // only init 'blk' when we need it
  blk.conn = NULL;
  blk.nvars = 0; // shut up compiler
#endif

  if (include_level > 10) {
    mg_cry(conn, "SSI #include level is too deep (%s)", path);
    return 1;
  }

  m = next_option(get_conn_option(conn, SSI_MARKER), &ssi_start, NULL);
  ssi_end = ssi_start;
  next_option(m, &ssi_end, NULL);
  if (!ssi_end.len || !ssi_start.len) {
    ssi_start.ptr = "<!--#";
    ssi_start.len = 5;
    ssi_end.ptr = ">";
    ssi_end.len = 1;
  }

  rlen = 0;
  roff = 0;
  taglen = (int)ssi_start.len;

  for(;;) {
    const char *b = buf;
    rlen = (int)fread(buf + roff, 1, sizeof(buf) - roff, fp);
    if (rlen <= 0)
      break;
    rlen += roff;
    for(;;) {
      const char *e;
      const char *s;
      int rv;
      if (rlen < taglen) {
        if (b > buf) {
          memmove(buf, b, rlen);
        }
        roff = rlen;
        break;
      }
      s = mg_memfind(b, rlen, ssi_start.ptr, taglen);
      if (!s) {
        if (rlen >= taglen && mg_write(conn, b, rlen - taglen + 1) != rlen - taglen + 1) {
          send_http_error(conn, 580, NULL, "%s: not all data (len = %d) sent (%s)", __func__, rlen - taglen + 1, path);
          return -1;
        }
        memmove(buf, b + rlen - taglen + 1, taglen - 1);
        roff = taglen - 1;
        break;
      }
      // flush part before start tag:
      if (s > b && mg_write(conn, b, s - b) != s - b) {
        send_http_error(conn, 580, NULL, "%s: not all data (len = %d) sent (%s)", __func__, (int)(s - b), path);
        return -1;
      }
      rlen -= s - b;
      b = s;
      s += taglen + 1;
      e = mg_memfind(s, rlen - (s - b), ssi_end.ptr, ssi_end.len);
      if (!e) {
        // shift to start; load more data and retry, if possible:
        s -= taglen + 1;
        if (s == buf || feof(fp)) {
          /* in this case we already have max data loaded: overlong SSI tag! */
          send_http_error(conn, 577, NULL, "%s: SSI tag is too large / not terminated correctly (%s)", __func__, path);
          return -1;
        }
        memmove(buf, s, rlen - (s - b));
        roff = rlen - (s - b);
        break;
      }
      s--;
      // skip whitespace:
      s += strspn(s, " \t\r\n");
      buf[e - buf] = 0;
      rv = call_user_ssi_command(conn, s, path, include_level);
      if (rv) {
        if (rv < 0) {
          if (conn->request_info.status_code == 200)
            send_http_error(conn, 577, NULL, "%s: SSI tag processing failed (%s)", __func__, path);
          return rv;
        }
      } else if (!strncmp(s, "include", 7)) {
        s += 7;
        s += strspn(s, " \t\r\n");
        if (do_ssi_include(conn, path, (char *)s, include_level) < 0)
          return -1;
#if !defined(NO_POPEN)
      } else if (!strncmp(s, "exec", 4)) {
        s += 4;
        s += strspn(s, " \t\r\n");
        if (do_ssi_exec(conn, (char *)s))
          return -1;
#endif // !NO_POPEN
#if !defined(NO_CGI)
      } else if (!strncmp(s, "echo", 4)) {
        // http://www.ssi-developer.net/ssi/ssi-echo.shtml
        s += 4;
        s += strspn(s, " \t\r\n");
        if (strncmp("var=", s, 4)) {
          mg_cry(conn, "%s: invalid SSI echo command: \"%s\"", path, s);
        } else {
          const char *ve;
          int idx;
          s += 4;
          s = extract_quoted_value((char *)s);
          ve = s + strlen(s);
          if (ve == e || !*s) {
            send_http_error(conn, 577, NULL, "%s: invalid SSI 'echo' command", __func__);
            return -1;
          }
          *((char *)ve) = '=';
          // init 'blk' once, when we need it:
          if (!blk.conn) {
            if (prepare_cgi_environment(conn, path, &blk)) {
              send_http_error(conn, 577, NULL, "%s: failed to set up env.var set", __func__);
              blk.conn = NULL;
              return -1;
            }
          }
          MG_ASSERT(blk.nvars > 0);
          MG_ASSERT(blk.vars[blk.nvars - 1] == NULL);
          for (idx = blk.nvars - 1; idx-- > 0; ) {
            const char *kv = blk.vars[idx];
            if (!strncmp(s, kv, ve + 1 - s)) {
              size_t kvlen;
              kv += ve + 1 - s;
              kvlen = strlen(kv);
              if (mg_write(conn, kv, kvlen) != (int)kvlen) {
                send_http_error(conn, 580, NULL, "%s: not all data (len = %d) sent (%s)", __func__, (int)kvlen, path);
                return -1;
              }
              break;
            }
          }
        }
#endif
      } else {
        // shouldn't we log the error and abort? Nope, in this case we decide to go on. Unsupported SSI features are ignored.
        mg_cry(conn, "%s: unknown SSI command: \"%s\"", path, buf);
      }
      s = e + ssi_end.len;
      rlen -= s - b;
      b = s;
    }
  }
  // Send the rest of buffered data
  rlen += roff;
  if (rlen > 0) {
    if (mg_write(conn, buf, rlen) != rlen) {
      send_http_error(conn, 580, NULL, "%s: not all data (len = %d) sent (%s)", __func__, rlen, path);
      return -1;
    }
  }
  return 0;
}

static void handle_ssi_file_request(struct mg_connection *conn,
                                    const char *path) {
  FILE *fp;

  if ((fp = mg_fopen(path, "rb")) == NULL) {
    send_http_error(conn, 500, NULL, "fopen(%s): %s", path,
                    mg_strerror(ERRNO));
  } else {
    set_close_on_exec(fileno(fp));
    //mg_set_response_code(conn, 200); -- not needed any longer
    mg_add_response_header(conn, 0, "Content-Type", "text/html");
    //mg_add_response_header(conn, 0, "Connection", "%s", suggest_connection_header(conn)); -- not needed any longer
    if (strcmp(conn->request_info.http_version, "1.1") >= 0)
      mg_add_response_header(conn, 0, "Transfer-Encoding", "chunked");
    else // HTTP/1.0:
      conn->must_close = 1;

    mg_write_http_response_head(conn, 200, 0);
    send_ssi_file(conn, path, fp, 0);
    (void) mg_fclose(fp);
    (void) mg_flush(conn);
  }
}

static void send_options(struct mg_connection *conn) {
  if (mg_is_producing_nested_page(conn))
    return;
  //mg_set_response_code(conn, 200); -- not needed any longer
  mg_add_response_header(conn, 0, "Allow", mg_get_allowed_methods(conn));
  mg_add_response_header(conn, 0, "DAV", "1");

  mg_write_http_response_head(conn, 200, 0);
}

// Writes PROPFIND properties for a collection element
static void print_props(struct mg_connection *conn, const char* uri,
                        struct mgstat* st) {
  char mtime[64];
  gmt_time_string(mtime, sizeof(mtime), &st->mtime);
  mg_printf(conn,
            "<d:response>"
             "<d:href>%s</d:href>"
             "<d:propstat>"
              "<d:prop>"
               "<d:resourcetype>%s</d:resourcetype>"
               "<d:getcontentlength>%" PRId64 "</d:getcontentlength>"
               "<d:getlastmodified>%s</d:getlastmodified>"
              "</d:prop>"
              "<d:status>HTTP/1.1 200 OK</d:status>"
             "</d:propstat>"
            "</d:response>\n",
            uri,
            st->is_directory ? "<d:collection/>" : "",
            st->size,
            mtime);
}

static void print_dav_dir_entry(struct mg_direntry *de, void *data) {
  char href[PATH_MAX];
  struct mg_connection *conn = (struct mg_connection *) data;
  mg_snprintf(conn, href, sizeof(href), "%s%s",
              conn->request_info.uri, de->file_name);
  print_props(conn, href, &de->st);
}

static void handle_propfind(struct mg_connection *conn, const char* path,
                            struct mgstat* st) {
  const char *depth = mg_get_header(conn, "Depth");

  if (mg_is_producing_nested_page(conn))
    return;
  //mg_set_response_code(conn, 207); -- not needed any longer
  //mg_add_response_header(conn, 0, "Connection", "close"); -- not needed any longer
  mg_add_response_header(conn, 0, "Content-Type", "text/xml; charset=utf-8");
  if (strcmp(conn->request_info.http_version, "1.1") >= 0)
    mg_add_response_header(conn, 0, "Transfer-Encoding", "chunked");
  else // HTTP/1.0:
    conn->must_close = 1;

  mg_write_http_response_head(conn, 207, 0);

  mg_printf(conn,
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
            "<d:multistatus xmlns:d='DAV:'>\n");

  // Print properties for the requested resource itself
  print_props(conn, conn->request_info.uri, st);

  // If it is a directory, print directory entries too if Depth is not 0
  if (st->is_directory &&
      !mg_strcasecmp(get_conn_option(conn, ENABLE_DIRECTORY_LISTING), "yes") &&
      (depth == NULL || strcmp(depth, "0") != 0)) {
    mg_scan_directory(conn, path, conn, &print_dav_dir_entry);
  }

  mg_printf(conn, "%s\n", "</d:multistatus>");
  (void) mg_flush(conn);
}

// This is the heart of the Mongoose's logic.
// This function is called when the request is read, parsed and validated,
// and Mongoose must decide what action to take: serve a file, or
// a directory, or call embedded function, etcetera.
static void handle_request(struct mg_connection *conn) {
  struct mg_request_info *ri = &conn->request_info;
  char path[PATH_MAX + 1];
  int stat_result, uri_len;
  struct mgstat st;

  uri_len = (int)strlen(ri->uri);
  url_decode(ri->uri, (size_t)uri_len, ri->uri, (size_t)(uri_len + 1), 0);
  remove_double_dots_and_double_slashes(ri->uri);
  stat_result = convert_uri_to_file_name(conn, path, sizeof(path), &st);
  ri->phys_path = path;

  DEBUG_TRACE(0x0800, ("[%s]", ri->uri));

  if (!check_allowed(conn)) {
    send_http_error(conn, 405, NULL, "You cannot %s to this server", conn->request_info.request_method);
  } else if (check_authorization(conn, path) != 1) {
    send_authorization_request(conn);
  } else if (call_user(conn, MG_NEW_REQUEST) != NULL) {
    // Do nothing, callback has served the request

    /*
    Do NOT hack like this but use proper HTTP/1.1 Connection:close responses instead.

    When a connection is marked as to-be-closed but the browser isn't notified through
    the headers about this, then at least IE9 will keep the connection open for up to
    1 minute ( http://support.microsoft.com/kb/813827 ) thus blocking one mongoose
    thread, and IE9 will use 3-4 threads for every page action (be it page request
    + JS/CSS or multiple POST AJAX requests), so you will run out of server threads
    pretty darn quickly.
    */
#if 0
    conn->must_close = 1;
#endif

  } else if (!strcmp(ri->request_method, "OPTIONS")) {
    send_options(conn);
  } else if (is_empty(get_conn_option(conn, DOCUMENT_ROOT))) {
    send_http_error(conn, 404, NULL, "DocumentRoot has not been properly configured.");
  } else if ((!strcmp(ri->request_method, "PUT") ||
              !strcmp(ri->request_method, "DELETE")) &&
             is_authorized_for_put(conn) != 1) {
    send_authorization_request(conn);
  } else if (!strcmp(ri->request_method, "PUT")) {
    put_file(conn, path);
  } else if (!strcmp(ri->request_method, "DELETE")) {
    if (mg_remove(path) == 0) {
      send_http_error(conn, 200, NULL, "");
    } else {
      send_http_error(conn, 500, NULL, "remove(%s): %s", path,
                      mg_strerror(ERRNO));
    }
  } else if (stat_result != 0 || must_hide_file(conn, path)) {
    send_http_error(conn, 404, NULL, "File not found: URI=%s, PATH=%s", ri->uri, path);
  } else if (st.is_directory && ri->uri[uri_len - 1] != '/') {
    if (301 == mg_set_response_code(conn, 301)) {
      mg_add_response_header(conn, 0, "Location", "%s/", ri->uri);
      mg_write_http_response_head(conn, 0, 0);
    } else {
      send_http_error(conn, 500, "%s: failed to set Status Code", __func__);
    }
  } else if (!strcmp(ri->request_method, "PROPFIND")) {
    handle_propfind(conn, path, &st);
  } else if (st.is_directory &&
             !mg_substitute_index_file(conn, path, sizeof(path), &st)) {
    if (!mg_strcasecmp(get_conn_option(conn, ENABLE_DIRECTORY_LISTING), "yes")) {
      handle_directory_request(conn, path);
    } else {
      send_http_error(conn, 403, "Directory Listing Denied",
                      "Directory listing denied");
    }
#if !defined(NO_CGI)
  } else if (match_string(get_conn_option(conn, CGI_EXTENSIONS),
                          -1,
                          path) > 0) {
    if (strcmp(ri->request_method, "POST") &&
        strcmp(ri->request_method, "GET")) {
      send_http_error(conn, 501, NULL,
                      "Method %s is not implemented", ri->request_method);
    } else {
      handle_cgi_request(conn, path);
    }
#endif // !NO_CGI
  } else if (match_string(get_conn_option(conn, SSI_EXTENSIONS),
                          -1,
                          path) > 0) {
    handle_ssi_file_request(conn, path);
  } else if (is_not_modified(conn, &st) &&
             304 == mg_set_response_code(conn, 304)) {
    send_http_error(conn, 304, NULL, "");
  } else {
    handle_file_request(conn, path, &st);
  }
  // and reset stack storage reference(s):
  ri->phys_path = NULL;
  ri->path_info = NULL; // see convert_uri_to_file_name()
}

int mg_produce_nested_page(struct mg_connection *conn, const char *uri, size_t uri_len) {
  if (!uri || !uri_len || mg_have_headers_been_sent(conn))
    return -1;
  {
    size_t l = mg_strnlen(uri, uri_len);
    if (!l)
      return -1;
    uri_len = l;
  }
  if (conn->nested_err_or_pagereq_count == 0) {
    // store the original ri:
    struct mg_request_info ri = conn->request_info;
    char expanded_uri[PATH_MAX];
    const char *s;
    int i;

    // fail when error happens in this section...
    conn->nested_err_or_pagereq_count = 2;
    if (sizeof(expanded_uri) < uri_len + 1)
      goto fail_dramatically;

    s = mg_memfind(uri, uri_len, "$E", 2);
    if (s) {
      int n = mg_snq0printf(conn, expanded_uri, sizeof(expanded_uri), "%.*s%d%.*s",
                            (int)(s - uri), uri,
                            ri.status_code,
                            (int)(uri_len - (s + 2 - uri)), s + 2);
      if (n + 1 >= (int)sizeof(expanded_uri))
        goto fail_dramatically;
    } else {
      mg_strlcpy(expanded_uri, uri, uri_len + 1);
    }
    conn->nested_err_or_pagereq_count = 1;
    // end of section...

    conn->request_info.uri = expanded_uri;
    conn->request_info.request_method = "GET";
    if ((conn->request_info.query_string = strchr(conn->request_info.uri, '?')) != NULL) {
      *conn->request_info.query_string++ = '\0';
    } else {
      conn->request_info.query_string = "";
    }
    conn->request_info.parent = &ri;
    // nuke any Content-Length or Transfer-Encoding header, to prevent the 'nested' handler
    // from incorrectly trying to (re)fetching the request content again.
    // Also nuke Modified-Since header.
    for (i = conn->request_info.num_headers; i-- > 0; ) {
      const char *key = conn->request_info.http_headers[i].name;
      if (!mg_strcasecmp(key, "Content-Length") ||
          !mg_strcasecmp(key, "Transfer-Encoding") ||
          !mg_strcasecmp(key, "If-Modified-Since") ||
          !mg_strcasecmp(key, "Expect")) {
        conn->request_info.http_headers[i].name = "X-Clobbered";
      }
    }

    handle_request(conn);  // may increment nested_err_or_pagereq_count when failing internally!
    // did we actually write a response? If not, make sure we report it as a fail to complete:
    if (!mg_have_headers_been_sent(conn))
      conn->nested_err_or_pagereq_count = 2;

    // reset original values, but keep the latest HTTP response code:
    // that one will have been 'upgraded' with the latest (graver) errors
    // and those should be logged / fed back to the client whenever possible.
fail_dramatically:
    ri.status_code = conn->request_info.status_code;
    conn->request_info = ri;
  }
  MG_ASSERT(conn->nested_err_or_pagereq_count == 1 || conn->nested_err_or_pagereq_count == 2);
  return (conn->nested_err_or_pagereq_count != 1);
}

int mg_is_producing_nested_page(struct mg_connection *conn) {
  return conn ? conn->nested_err_or_pagereq_count : 0;
}

static void close_socket_UNgracefully(SOCKET sock) {
  if (sock != INVALID_SOCKET) {
    struct linger linger;
    set_non_blocking_mode(sock, 0);
    linger.l_onoff = 0;
    linger.l_linger = 0;
    setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *) &linger, sizeof(linger));
    closesocket(sock);
  }
}

static void close_all_listening_sockets(struct mg_context *ctx) {
  struct socket *sp, *tmp;
  for (sp = ctx->listening_sockets; sp != NULL; sp = tmp) {
    tmp = sp->next;
    (void) closesocket(sp->sock);
    sp->sock = INVALID_SOCKET;
    free(sp);
  }
  ctx->listening_sockets = NULL;
}

static int parse_ipvX_addr_string(char *addr_buf, int port, struct usa *usa) {
#if defined(USE_IPV6) && defined(HAVE_INET_NTOP)
  // Only Windoze Vista (and newer) have inet_pton()
  struct in_addr a = {0};
  struct in6_addr a6 = {0};

  memset(usa, 0, sizeof(*usa));
  if (inet_pton(AF_INET6, addr_buf, &a6) > 0) {
    usa->len = sizeof(usa->u.sin6);
    usa->u.sin6.sin6_family = AF_INET6;
    usa->u.sin6.sin6_port = htons((uint16_t) port);
    usa->u.sin6.sin6_addr = a6;
    return 1;
  } else if (inet_pton(AF_INET, addr_buf, &a) > 0) {
    usa->len = sizeof(usa->u.sin);
    usa->u.sin.sin_family = AF_INET;
    usa->u.sin.sin_port = htons((uint16_t) port);
    usa->u.sin.sin_addr = a;
    return 1;
  } else {
    return 0;
  }
#elif defined(HAVE_GETNAMEINFO)
  struct addrinfo hints = {0};
  struct addrinfo *rset = NULL;
#if defined(USE_IPV6)
  hints.ai_family = AF_UNSPEC;
#else
  hints.ai_family = AF_INET;
#endif
  hints.ai_socktype = SOCK_STREAM; // TCP
  hints.ai_flags = AI_NUMERICHOST;
  if (!getaddrinfo(addr_buf, NULL, &hints, &rset) && rset) {
    memcpy(&usa->u.sa, rset->ai_addr, rset->ai_addrlen);
#if defined(USE_IPV6)
    if (rset->ai_family == PF_INET6) {
      usa->len = sizeof(usa->u.sin6);
      MG_ASSERT(rset->ai_addrlen == sizeof(usa->u.sin6));
      MG_ASSERT(usa->u.sin6.sin6_family == AF_INET6);
      usa->u.sin6.sin6_port = htons((uint16_t) port);
      freeaddrinfo(rset);
      return 1;
    } else
#endif
    if (rset->ai_family == PF_INET) {
      usa->len = sizeof(usa->u.sin);
      MG_ASSERT(rset->ai_addrlen == sizeof(usa->u.sin));
      MG_ASSERT(usa->u.sin.sin_family == AF_INET);
      usa->u.sin.sin_port = htons((uint16_t) port);
      freeaddrinfo(rset);
      return 1;
    }
  }
  if (rset) freeaddrinfo(rset);
  return 0;
#else
  int a, b, c, d, len;

  memset(usa, 0, sizeof(*usa));
  if (sscanf(addr_buf, "%d.%d.%d.%d%n", &a, &b, &c, &d, &len) == 4
      && len == (int) strlen(addr_buf)) {
    // Bind to a specific IPv4 address
    usa->len = sizeof(usa->u.sin);
    usa->u.sin.sin_family = AF_INET;
    usa->u.sin.sin_port = htons((uint16_t) port);
    usa->u.sin.sin_addr.s_addr = htonl((a << 24) | (b << 16) | (c << 8) | d);
    return 1;
  }
  return 0;
#endif
}

// Valid listening port specification is: [ip_address:]port[s]
// Examples: 80, 443s, 127.0.0.1:3128, 1.2.3.4:8080s
static int parse_port_string(const struct vec *vec, struct socket *so) {
  struct usa *usa = &so->lsa;
  int port, len;
  char addr_buf[SOCKADDR_NTOA_BUFSIZE];

  // MacOS needs that. If we do not zero it, subsequent bind() will fail.
  // Also, all-zeroes in the socket address means binding to all addresses
  // for both IPv4 and IPv6 (INADDR_ANY and IN6ADDR_ANY_INIT).
  memset(so, 0, sizeof(*so));

  if (sscanf(vec->ptr, " [%40[^]]]:%d%n", addr_buf, &port, &len) == 2
      && len > 0
      && parse_ipvX_addr_string(addr_buf, port, usa)) {
    // all done: probably IPv6 URI
  } else if (sscanf(vec->ptr, " %40[^:]:%d%n", addr_buf, &port, &len) == 2
      && len > 0
      && parse_ipvX_addr_string(addr_buf, port, usa)) {
    // all done: probably IPv4 URI
  } else if (sscanf(vec->ptr, "%d%n", &port, &len) != 1 ||
             len <= 0 ||
             len > (int) vec->len ||
             (vec->ptr[len] && strchr("sp, \t", vec->ptr[len]) == NULL)) {
    return 0;
  } else {
#if defined(USE_IPV6)
    usa->len = sizeof(usa->u.sin6);
    usa->u.sin6.sin6_family = AF_INET6;
    usa->u.sin6.sin6_port = htons((uint16_t) port);
    //usa->u.sin6.sin6_addr = in6addr_any;
#else
    usa->len = sizeof(usa->u.sin);
    usa->u.sin.sin_family = AF_INET;
    usa->u.sin.sin_port = htons((uint16_t) port);
    //usa->u.sin.sin_addr = htonl(INADDR_ANY);
#endif
  }

  so->is_ssl = (vec->ptr[len] == 's');

  return 1;
}

// return 0 on success!
// mask_n and maskbits may be NULL
//
// IP address + netmask input is assumed to be in CIDR notation:
// http://en.wikipedia.org/wiki/CIDR_notation
static int parse_ipvX_addr_and_netmask(const char *src, struct usa *ip, int *mask_n, struct mg_ip_address *maskbits) {
  int n, mask;
  char addr_buf[SOCKADDR_NTOA_BUFSIZE];

  if (sscanf(src, "%40[^/]%n", addr_buf, &n) != 1) {
    return -1;
  } else if (!parse_ipvX_addr_string(addr_buf, 0, ip)) {
    return -2;
  } else if (sscanf(src + n, "/%d", &mask) != 1) {
    // no mask specified
    mask = (ip->u.sa.sa_family == AF_INET ? 32 : 8 * 16);
  } else if (mask < 0 || mask > (ip->u.sa.sa_family == AF_INET ? 32 : 8 * 16)) {
    return -3;
  }
  if (mask_n)
    *mask_n = mask;
  if (maskbits) {
    if (ip->u.sa.sa_family == AF_INET) {
      maskbits->is_ip6 = 0;
      maskbits->ip_addr.v4[0] = (mask < 4 * 8 ? mask > 3 * 8 ? 0xffU << (4 * 8 - mask) : 0 : 0xffU) & 0xffU;
      maskbits->ip_addr.v4[1] = (mask < 3 * 8 ? mask > 2 * 8 ? 0xffU << (3 * 8 - mask) : 0 : 0xffU) & 0xffU;
      maskbits->ip_addr.v4[2] = (mask < 2 * 8 ? mask > 1 * 8 ? 0xffU << (2 * 8 - mask) : 0 : 0xffU) & 0xffU;
      maskbits->ip_addr.v4[3] = (mask < 1 * 8 ? mask > 0 * 8 ? 0xffU << (1 * 8 - mask) : 0 : 0xffU) & 0xffU;
    } else {
      maskbits->is_ip6 = 1;
      maskbits->ip_addr.v6[0] = (mask < 8 * 16 ? mask > 7 * 16 ? 0xffffU << (8 * 16 - mask) : 0 : 0xffffU);
      maskbits->ip_addr.v6[1] = (mask < 7 * 16 ? mask > 6 * 16 ? 0xffffU << (7 * 16 - mask) : 0 : 0xffffU);
      maskbits->ip_addr.v6[2] = (mask < 6 * 16 ? mask > 5 * 16 ? 0xffffU << (6 * 16 - mask) : 0 : 0xffffU);
      maskbits->ip_addr.v6[3] = (mask < 5 * 16 ? mask > 4 * 16 ? 0xffffU << (5 * 16 - mask) : 0 : 0xffffU);
      maskbits->ip_addr.v6[4] = (mask < 4 * 16 ? mask > 3 * 16 ? 0xffffU << (4 * 16 - mask) : 0 : 0xffffU);
      maskbits->ip_addr.v6[5] = (mask < 3 * 16 ? mask > 2 * 16 ? 0xffffU << (3 * 16 - mask) : 0 : 0xffffU);
      maskbits->ip_addr.v6[6] = (mask < 2 * 16 ? mask > 1 * 16 ? 0xffffU << (2 * 16 - mask) : 0 : 0xffffU);
      maskbits->ip_addr.v6[7] = (mask < 1 * 16 ? mask > 0 * 16 ? 0xffffU << (1 * 16 - mask) : 0 : 0xffffU);
    }
  }
  return 0;
}

/*
 * a socket-timeout makes the server more robust, in particular if you
 * unplug a network cable while a request is pending - also required
 * for WLAN/UMTS
 */
static int set_timeout(struct socket *sock, int seconds) {
  int rv = 0;
#ifdef _WIN32
  DWORD timeout, user_timeout;
  user_timeout = timeout = seconds * 1000; //milliseconds
#else
  unsigned int user_timeout = seconds * 1000;
  struct timeval timeout;
  timeout.tv_sec = seconds;
  timeout.tv_usec = 0;
#endif

  sock->max_idle_seconds = seconds;

  if (sock->sock != INVALID_SOCKET && user_timeout > 0) {
    if (setsockopt(sock->sock, SOL_SOCKET, SO_RCVTIMEO, (const void *)&timeout, sizeof(timeout)) < 0 &&
        setsockopt(sock->sock, SOL_SOCKET, SO_SNDTIMEO, (const void *)&timeout, sizeof(timeout)) < 0) {
      DEBUG_TRACE(0x0011,
                  ("setsockopt SO_RCVTIMEO and SO_SNDTIMEO timeout %d set failed on socket: %d",
                   seconds, sock->sock));
      rv = -1;
    }

#if defined(TCP_USER_TIMEOUT)
    if (setsockopt(sock->sock, SOL_SOCKET, TCP_USER_TIMEOUT, (const void *)&user_timeout, sizeof(user_timeout)) < 0) {
      DEBUG_TRACE(0x0010,
                  ("setsockopt TCP_USER_TIMEOUT timeout %d set failed on socket: %d",
                   seconds, sock->sock));
      rv = -1;
    }
#endif
  }
  return 0;
}

#if defined(USE_IPV6)
static int is_all_zeroes(void *ptr, size_t len)
{
  char *s = (char *)ptr;

  for ( ; len > 0; len--) {
    if (*s++) return 0;
  }
  return 1;
}
#endif

static int set_ports_option(struct mg_context *ctx) {
  const char *list = get_option(ctx, LISTENING_PORTS);
  int ignore_occupied_ports = !mg_strcasecmp("yes", get_option(ctx, IGNORE_OCCUPIED_PORTS));
#if !defined(_WIN32)
  int reuseaddr = 1;
#endif // !_WIN32
  int success = 1;
  int on;
#if defined(USE_IPV6) && defined(IPV6_V6ONLY) && (!defined(_WIN32) || (_WIN32_WINNT >= _WIN32_WINNT_WINXP))
  int ipv6_only_on = 1;
#endif
  SOCKET sock;
  struct vec vec;
  struct socket so = {0}, *listener;
  long int num;
  int keep_alive_timeout;
  char * chknum = NULL;

  num = strtol(get_option(ctx, KEEP_ALIVE_TIMEOUT), &chknum, 10);
  if ((chknum != NULL && *chknum == ' ') || num < 0 || num >= INT_MAX / 1000) {
    mg_cry(fc(ctx), "%s: Invalid socket timeout '%s'", __func__, get_option(ctx, KEEP_ALIVE_TIMEOUT));
    success = 0;
  }
  on = (num > 0);
  keep_alive_timeout = num;

  while (success && (list = next_option(list, &vec, NULL)) != NULL) {
    if (!parse_port_string(&vec, &so)) {
      mg_cry(fc(ctx), "%s: %.*s: invalid port spec. Expecting list of: %s",
             __func__, (int)vec.len, vec.ptr, "[IP_ADDRESS:]PORT[s|p]");
      success = 0;
    } else if (so.is_ssl &&
               (ctx->ssl_ctx == NULL || is_empty(get_option(ctx, SSL_CERTIFICATE)))) {
      mg_cry(fc(ctx), "Cannot add SSL socket, is -ssl_certificate option set?");
      success = 0;
    } else {
#if defined(USE_IPV6)
      // when the listener is merely a port, then we want to listen on IPv6 and IPv4 sockets both!
      int rounds = (so.lsa.u.sin6.sin6_family == AF_INET6 && is_all_zeroes(&so.lsa.u.sin6.sin6_addr, sizeof(so.lsa.u.sin6.sin6_addr)));
#else
      int rounds = 0;
#endif
      for ( ; rounds >= 0; rounds--) {
        if ((sock = socket(so.lsa.u.sa.sa_family, SOCK_STREAM, IPPROTO_TCP)) ==
                    INVALID_SOCKET ||
#if !defined(_WIN32)
            // On Windows, SO_REUSEADDR is recommended only for
            // broadcast UDP sockets
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
                       sizeof(reuseaddr)) != 0 ||
#endif // !_WIN32
            // Set TCP keep-alive. This is needed because if HTTP-level
            // keep-alive is enabled, and client resets the connection,
            // server won't get TCP FIN or RST and will keep the connection
            // open forever. With TCP keep-alive, next keep-alive
            // handshake will figure out that the client is down and
            // will close the server end.
            // Thanks to Igor Klopov who suggested the patch.
            setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (const void *) &on,
                       sizeof(on)) != 0 ||
#if defined(USE_IPV6) && defined(IPV6_V6ONLY) && (!defined(_WIN32) || (_WIN32_WINNT >= _WIN32_WINNT_WINXP))
            // Linux et al will b0rk on the second round when binding the IPv4
            // socket to the same port as the IPv6 one, if this option isn't
            // specified. (Because we use two sockets, one for each protocol.)
            //
            // Apparently, Win32/WinSock assumes this by default, as it didn't
            // b0rk without the option?
            (so.lsa.u.sin6.sin6_family == AF_INET6 &&
             setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (const void *) &ipv6_only_on,
                       sizeof(ipv6_only_on)) != 0) ||
#endif
            bind(sock, &so.lsa.u.sa, so.lsa.len) != 0 ||
            listen(sock, SOMAXCONN) != 0) {
          mg_cry(fc(ctx), "%s: cannot bind to port %.*s, port may already be in use by another application: %s", __func__,
                 (int)vec.len, vec.ptr, mg_strerror(ERRNO));
          closesocket(sock);
          if (!ignore_occupied_ports)
            success = 0;
        } else if ((listener = (struct socket *)
                    calloc(1, sizeof(*listener))) == NULL) {
          mg_cry(fc(ctx), "%s: %s", __func__, mg_strerror(ERRNO));
          closesocket(sock);
          success = 0;
        } else {
          *listener = so;
          listener->sock = sock;
          set_close_on_exec(listener->sock);
          set_timeout(listener, keep_alive_timeout);
          listener->next = ctx->listening_sockets;
          ctx->listening_sockets = listener;
          success++;
        }
        so.lsa.len = sizeof(so.lsa.u.sin);
        so.lsa.u.sin.sin_family = AF_INET;
        //so.lsa.u.sin.sin_port = htons((uint16_t) port); -- maps to the same spot as sin6_sin6_port so nothing to do
        //so.lsa.u.sin.sin_addr = htonl(INADDR_LOOPBACK);
      }
    }
  }

  // when ignoring occupied ports, we should end up serving at at least ONE port
  if (!success || (ignore_occupied_ports && success < 2)) {
    close_all_listening_sockets(ctx);
    success = 0;
  }

  return success;
}

static void log_header(const struct mg_connection *conn, const char *header,
                       FILE *fp) {
  const char *header_value;

  if ((header_value = mg_get_header(conn, header)) == NULL) {
    (void) fprintf(fp, " -");
  } else {
    (void) fprintf(fp, " \"%s\"", header_value);
  }
}

static void log_access(struct mg_connection *conn) {
  const struct mg_request_info *ri;
  FILE *fp;
  char date[64];
  char src_addr[SOCKADDR_NTOA_BUFSIZE];
  const char *fpath = mg_get_default_access_logfile_path(conn);

  (void) strftime(date, sizeof(date), "%d/%b/%Y:%H:%M:%S %z",
                  localtime(&conn->birth_time));

  ri = &conn->request_info;

  sockaddr_to_string(src_addr, sizeof(src_addr), &conn->client.rsa);

  fp = mg_fopen(fpath, "a+");
  if (fp == NULL)
    return;
  flockfile(fp);

  (void) fprintf(fp, "%s - %s [%s] \"%s %s HTTP/%s\" %d %s%" PRId64 "%s",
                 src_addr, ri->remote_user == NULL ? "-" : ri->remote_user, date,
                 ri->request_method ? ri->request_method : "-",
                 ri->uri ? ri->uri : "-", ri->http_version,
                 conn->request_info.status_code,
                 (conn->num_bytes_sent < 0 ? "(" : ""),
                 (conn->num_bytes_sent < 0 ? -1 - conn->num_bytes_sent : conn->num_bytes_sent),
                 (conn->num_bytes_sent < 0 ? ")" : ""));
  log_header(conn, "Referer", fp);    // http://en.wikipedia.org/wiki/HTTP_referer
  log_header(conn, "User-Agent", fp);
  (void) fputc('\n', fp);
  (void) fflush(fp);

  funlockfile(fp);
  (void) mg_fclose(fp);
}

// Verify given socket address against the ACL.
// Return -1 if ACL is malformed, 0 if address is disallowed, 1 if allowed.
static int check_acl(struct mg_context *ctx, const struct usa *usa) {
  int i, mask = 0, allowed;
  char flag;
  struct mg_ip_address acl_subnet, acl_mask, remote_ip;
  struct usa ip;
  struct vec vec;
  const char *list = get_option(ctx, ACCESS_CONTROL_LIST);

  if (is_empty(list)) {
    return 1;
  }

  get_socket_ip_address(&remote_ip, usa);
  cvt_ipv4_to_ipv6(&remote_ip, &remote_ip);

  // If any ACL is set, deny by default
  allowed = '-';

  while ((list = next_option(list, &vec, NULL)) != NULL) {
    char acl_buf[SOCKADDR_NTOA_BUFSIZE * 2 + 10];

    if (vec.len >= sizeof(acl_buf)) {
      mg_cry(fc(ctx), "%s: bad acl ip/mask: [%.*s]", __func__, (int)vec.len, vec.ptr);
      return -1;
    }
    mg_strlcpy(acl_buf, vec.ptr, vec.len + 1);

    flag = acl_buf[0];
    if (sscanf(acl_buf, " %c%n", &flag, &i) != 1 && flag != '+' && flag != '-') {
      mg_cry(fc(ctx), "%s: flag must be + or -: [%s]", __func__, vec.ptr);
      return -1;
    }
    switch (parse_ipvX_addr_and_netmask(acl_buf + i, &ip, &mask, &acl_mask)) {
    case 0:
      break;
    default:
      mg_cry(fc(ctx), "%s: subnet must be [+|-]<IPv4 address: x.x.x.x>[/x] or [+|-]<IPv6 address>[/x], instead we see [%s]", __func__, acl_buf);
      return -1;
    case -2:
      mg_cry(fc(ctx), "%s: bad ip address: [%s]", __func__, acl_buf);
      return -1;
    case -3:
      mg_cry(fc(ctx), "%s: bad subnet mask: %d [%s]", __func__, mask, acl_buf);
      return -1;
    }
    get_socket_ip_address(&acl_subnet, &ip);
    cvt_ipv4_to_ipv6(&acl_subnet, &acl_subnet);
    cvt_ipv4_to_ipv6(&acl_mask, &acl_mask);

    for (i = 0; i < 8; i++) {
      if ((acl_subnet.ip_addr.v6[i]  & acl_mask.ip_addr.v6[i]) != (remote_ip.ip_addr.v6[i] & acl_mask.ip_addr.v6[i])) {
        flag = 0;
        break;
      }
    }
    if (flag) {
      allowed = flag;
    }
  }

  return allowed == '+';
}

#if !defined(_WIN32)
static int set_uid_option(struct mg_context *ctx) {
  struct passwd *pw;
  const char *uid = get_option(ctx, RUN_AS_USER);
  int success = 0;

  if (is_empty(uid)) {
    success = 1;
  } else {
    if ((pw = getpwnam(uid)) == NULL) {
      mg_cry(fc(ctx), "%s: unknown user [%s]", __func__, uid);
    } else if (setgid(pw->pw_gid) == -1) {
      mg_cry(fc(ctx), "%s: setgid(%s): %s", __func__, uid, mg_strerror(ERRNO));
    } else if (setuid(pw->pw_uid) == -1) {
      mg_cry(fc(ctx), "%s: setuid(%s): %s", __func__, uid, mg_strerror(ERRNO));
    } else {
      success = 1;
    }
  }

  return success;
}
#endif // !_WIN32

#if !defined(NO_SSL)
static pthread_mutex_t *ssl_mutexes = NULL;

// Return OpenSSL error message
static const char *ssl_error(void) {
  unsigned long err;
  err = ERR_get_error();
  return err == 0 ? "" : ERR_error_string(err, NULL);
}

static void ssl_locking_callback(int mode, int mutex_num, const char *file,
                                 int line) {
  line = 0;    // Unused
  file = NULL; // Unused

  if (mode & CRYPTO_LOCK) {
    (void) pthread_mutex_lock(&ssl_mutexes[mutex_num]);
  } else {
    (void) pthread_mutex_unlock(&ssl_mutexes[mutex_num]);
  }
}

static unsigned long ssl_id_callback(void) {
  union {
    pthread_t pt;
    unsigned long l;
  } v = {0};
  v.pt = pthread_self();
  return v.l;
}

#if !defined(NO_SSL_DL)
static int load_dll(struct mg_context *ctx, const char *dll_name,
                    struct ssl_func *sw) {
  union {void *p; void (*fp)(void);} u;
  void  *dll_handle;
  struct ssl_func *fp;

  if ((dll_handle = dlopen(dll_name, RTLD_LAZY)) == NULL) {
    mg_cry(fc(ctx), "%s: cannot load %s", __func__, dll_name);
    return 0;
  }

  for (fp = sw; fp->name != NULL; fp++) {
#ifdef _WIN32
    // GetProcAddress() returns pointer to function
    u.fp = (void (*)(void)) dlsym(dll_handle, fp->name);
#else
    // dlsym() on UNIX returns void *. ISO C forbids casts of data pointers to
    // function pointers. We need to use a union to make a cast.
    u.p = dlsym(dll_handle, fp->name);
#endif // _WIN32
    if (u.fp == NULL) {
      mg_cry(fc(ctx), "%s: %s: cannot find %s", __func__, dll_name, fp->name);
      return 0;
    } else {
      fp->ptr = u.fp;
    }
  }

  return 1;
}
#endif // NO_SSL_DL

// Dynamically load SSL library. Set up ctx->ssl_ctx pointer.
static int set_ssl_option(struct mg_context *ctx) {
  int i, size;
  const char *pem = get_option(ctx, SSL_CERTIFICATE);

  if (is_empty(pem)) {
    return 1;
  }

#if !defined(NO_SSL_DL)
  if (!load_dll(ctx, SSL_LIB, ssl_sw) ||
      !load_dll(ctx, CRYPTO_LIB, crypto_sw)) {
    return 0;
  }
#endif // NO_SSL_DL

  // Initialize SSL crap
  SSL_library_init();
  SSL_load_error_strings();

  if ((ctx->client_ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
    mg_cry(fc(ctx), "SSL_CTX_new (client) error: %s", ssl_error());
  }

  if ((ctx->ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
    mg_cry(fc(ctx), "SSL_CTX_new (server) error: %s", ssl_error());
  } else {
    call_user_over_ctx(ctx, ctx->ssl_ctx, MG_INIT_SSL);
  }

  if (ctx->ssl_ctx != NULL &&
      SSL_CTX_use_certificate_file(ctx->ssl_ctx, pem, SSL_FILETYPE_PEM) == 0) {
    mg_cry(fc(ctx), "%s: cannot open cert file %s: %s", __func__, pem, ssl_error());
    return 0;
  }
  if (ctx->ssl_ctx != NULL &&
      SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, pem, SSL_FILETYPE_PEM) == 0) {
    mg_cry(fc(ctx), "%s: cannot open private key file %s: %s", __func__, pem, ssl_error());
    return 0;
  }
  if (ctx->ssl_ctx != NULL &&
      SSL_CTX_use_certificate_chain_file(ctx->ssl_ctx, pem) == 0) {
    mg_cry(fc(ctx), "%s: cannot open cert chain file %s: %s", __func__, pem, ssl_error());
    return 0;
  }

  // Initialize locking callbacks, needed for thread safety.
  // http://www.openssl.org/support/faq.html#PROG1
  size = sizeof(pthread_mutex_t) * CRYPTO_num_locks();
  if ((ssl_mutexes = (pthread_mutex_t *) malloc((size_t)size)) == NULL) {
    mg_cry(fc(ctx), "%s: cannot allocate mutexes: %s", __func__, ssl_error());
    return 0;
  }

  for (i = 0; i < CRYPTO_num_locks(); i++) {
    pthread_mutex_init(&ssl_mutexes[i], NULL);
  }

  CRYPTO_set_locking_callback(&ssl_locking_callback);
  CRYPTO_set_id_callback(&ssl_id_callback);

  return 1;
}

static void uninitialize_ssl(struct mg_context *ctx) {
  int i;
  if (ctx->ssl_ctx != NULL) {
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
      pthread_mutex_destroy(&ssl_mutexes[i]);
    }
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
  }
}
#endif // !NO_SSL

static int set_gpass_option(struct mg_context *ctx) {
  struct mgstat mgstat;
  const char *path = get_option(ctx, GLOBAL_PASSWORDS_FILE);
  return is_empty(path) || mg_stat(path, &mgstat) == 0;
}

static int set_acl_option(struct mg_context *ctx) {
  struct usa fake = {0};
  return check_acl(ctx, &fake) >= 0;
}

static void reset_per_request_attributes(struct mg_connection *conn) {
  struct mg_request_info *ri = &conn->request_info;

  // Reset request info attributes. DO NOT TOUCH is_ssl, remote_ip, remote_port, local_ip, local_port
  if (ri->remote_user != NULL) {
    free((void *) ri->remote_user);
    ri->remote_user = NULL;
  }
  ri->request_method = NULL;
  ri->query_string = "";
  ri->uri = NULL;
  ri->http_version = NULL;
  ri->phys_path = NULL;
  ri->path_info = NULL;
  ri->num_headers = 0;
  ri->num_response_headers = 0;
  memset(&ri->http_headers, 0, sizeof(ri->http_headers));
  memset(&ri->response_headers, 0, sizeof(ri->response_headers));
  ri->status_code = -1;
  ri->status_custom_description = NULL;

  ri->log_message = NULL;
  ri->log_severity = 0;
  ri->log_dstfile = NULL;
  ri->log_timestamp = 0;

  // compensate for the reset of conn->request_len: keep the buffered data accessible
  if (conn->request_len > 0 && conn->rx_buffer_loaded_len > conn->rx_buffer_read_len) {
    conn->rx_buffer_loaded_len += conn->request_len;
    conn->rx_buffer_read_len += conn->request_len;
  } else {
    conn->rx_buffer_loaded_len = 0;
    conn->rx_buffer_read_len = 0;
  }

  conn->num_bytes_sent = -1;
  conn->consumed_content = 0;
  conn->content_len = -1;
  conn->request_len = 0;
  //conn->must_close = 0;  -- do NOT reset must_close: once set, it should remain so until the connection is closed/dropped
  conn->nested_err_or_pagereq_count = 0;
  conn->tx_can_compact_hdrstore = 0;
  conn->tx_headers_len = 0;

  // reset all chunked-transfer related datums as those are per-request:
  conn->tx_is_in_chunked_mode = 0;
  conn->rx_is_in_chunked_mode = 0;
  conn->tx_chunk_header_sent = 0;
  conn->rx_chunk_header_parsed = 0;
  conn->tx_chunk_count = 0;
  conn->tx_remaining_chunksize = 0;
  conn->tx_next_chunksize = 0;
  conn->rx_chunk_count = 0;
  conn->rx_remaining_chunksize = 0;
  conn->rx_chunk_buf_size = 0;
  //conn->rx_buffer_loaded_len = 0;
}

static void close_socket_gracefully(struct mg_connection *conn) {
  char buf[MG_BUF_LEN];
  struct linger linger;
  int n, w;
  int linger_timeout = atoi(get_conn_option(conn, SOCKET_LINGER_TIMEOUT)) * 1000;
  SOCKET sock;
  int abort_when_server_stops;

  if (!conn || conn->client.sock == INVALID_SOCKET)
    return;
  sock = conn->client.sock;
  abort_when_server_stops = conn->abort_when_server_stops;

  MG_ASSERT(!conn->client.is_ssl == !conn->ssl);
  if (conn->ssl) {
    // see http://www.openssl.org/docs/ssl/SSL_set_shutdown.html#NOTES
    // and http://www.openssl.org/docs/ssl/SSL_shutdown.html
    SSL_shutdown(conn->ssl);
    // don't call SSL_shutdown() a second time as that would make us
    // block & wait for the client to complete the close, which would
    // be a server vulnerability.
    SSL_free(conn->ssl);
    conn->ssl = NULL;
  }

  /*

  ( http://msdn.microsoft.com/en-us/library/ms739165(v=vs.85).aspx )
  linger: "Note that enabling a nonzero timeout on a nonblocking socket is not recommended."

  The issues are gone as soon as you do the graceful close on a BLOCKING socket - with a little
  help from select(): essentially we do the linger timeout in userland entirely by fetching
  pending (surplus) RX data with a timeout upper bound of the configured linger timeout.

  The major point is that:

  - you must use BLOCKING sockets by the time you decide to go into graceful close.

  - you need to fetch pending RX data after shutdown(WR), i.e. flush the TCP RX buffer at least.
    (One would really like to wait until all pending TX is done: we can only check for it
    on Linux, but we do not have that ironclad guarantee on other platforms such as
    Win32/WinSock - it just turns out that for our test scenarios at least, it is sufficient
    to wait-and-check before calling closesocket() after all.)

  - only set LINGER ON for the BLOCKING socket (or you're toast)

  */

  // See http://msdn.microsoft.com/en-us/library/ms739165(v=vs.85).aspx:
  // linger: "Note that enabling a nonzero timeout on a nonblocking socket is not recommended."
  //
  // Also consider http://blog.netherlabs.nl/articles/2009/01/18/the-ultimate-so_linger-page-or-why-is-my-tcp-not-reliable
  // and in particular the section titled "Some notes on non-blocking sockets".

  // older mongoose set socket to non-blocking. That turned out to be VERY evil.
  // Now we set socket to BLOCKING before we go into the 'graceful close' phase:
  set_non_blocking_mode(sock, 0);

  // make sure the connection can be flushed even while the server shuts down: trick mg_read()/pull()
  conn->abort_when_server_stops = 0;

  // Send FIN to the client
  (void) shutdown(sock, SHUT_WR);

  // Read and discard pending incoming data. If we do not do that and close the
  // socket, the data in the send buffer may be discarded. This
  // behaviour is seen on Windows, when client keeps sending data
  // when server decides to close the connection; then when client
  // does recv() it gets no data back.
  do {
    // we still need to fetch it (see WinSock comments elsewhere for what
    // happens if you don't. Doing this on a NON-BLOCKING socket would
    // as data may still be incoming (but we don't wanna hear about it),
    // still cause a disaster every once in a while, producing 'aborted'
    // socket errors client-side.
    fd_set fds;
    struct timeval tv = {0};
    int sv;

    tv.tv_sec = 0;
    tv.tv_usec = MG_SELECT_TIMEOUT_MSECS * 1000;

    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    sv = select(sock + 1, &fds, 0, 0, &tv);
    switch (sv) {
    case 1:
      // optimize the number of select() calls in the path: tell pull() we know there's some data waiting already
      conn->client.was_idle = 1;
      conn->client.has_read_data = 1;
      // only fetch RX data when there actually is some:
      n = pull(NULL, conn, buf, sizeof(buf));
      DEBUG_TRACE(0x0020,
                  ("close(%d -> n=%d/t=%d/sel=%d)",
                   sock, n, linger_timeout, sv));
      w = 0;
      if (n < 0) {
        linger_timeout = 0;
        break;
      }
      // hasten the close when this connection should abort on server stop:
      if (n > 0 && conn->ctx->stop_flag && abort_when_server_stops) {
        linger_timeout -= MG_SELECT_TIMEOUT_MSECS;
        break;
      }
      // connection closed from the other side. Don't count this against our linger time.
      //MG_ASSERT(n == 0);
      break;

    case 0:
      // timeout expired:
      n = 0;
      linger_timeout -= MG_SELECT_TIMEOUT_MSECS;
#if defined(SIOCOUTQ)
      w = 0;
      // as we can detect how much TX data is pending, we can use that to terminate faster:
      {
        int wr_pending = 0;
        if (ioctl(sock, SIOCOUTQ, &wr_pending)) {
          w = wr_pending;
        }
      }
#else
      w = 0;
#endif
      break;

    default:
      // fatality:
      n = 0;
      w = 0;
      linger_timeout = 0;
      break;
    }
    //printf("graceful close: %d/%d/%d/%d\n", n, w, linger_timeout, sv);
  } while ((n > 0 || w > 0) && linger_timeout > 0);

  // Set linger option to avoid socket hanging out after close. This prevent
  // ephemeral port exhaust problem under high QPS.
  //
  // Note: as we've already spent part of the 'linger timeout' time in user land
  //       (that is: in the code above), we have a possibly reduced linger
  //       time by now.
  //       Also note that linger_timeout==0 by now when a failure has been
  //       observed above: in that case we do NOT want to linger any longer
  //       so this will then be a *DIS*graveful close.
  linger.l_onoff = (linger_timeout > 0 && (conn->ctx->stop_flag == 0 || !abort_when_server_stops));
  linger.l_linger = (linger_timeout + 999) / 1000; // round up
  setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *) &linger, sizeof(linger));
  DEBUG_TRACE(0x0020,
              ("linger-on-close(%d:t=%d[s])",
               sock, (int)linger.l_linger));

  if (linger.l_onoff)
    (void) __DisconnectEx(sock, 0, 0, 0);

  // Now we know that our FIN is ACK-ed, safe to close
  (void) closesocket(sock);
  conn->client.sock = INVALID_SOCKET;
}

static void close_connection(struct mg_connection *conn) {
  (void) mg_flush(conn);       // shut down chunked transfers 'cleanly', if possible
  close_socket_gracefully(conn);
}

void mg_close_connection(struct mg_connection *conn) {
  close_connection(conn);
  free(conn);
}

int mg_shutdown(struct mg_connection *conn, int how) {
  if (conn && conn->client.sock != INVALID_SOCKET) {
    // make sure to properly terminate a chunked/segmented transfer before we shut down the write side!
    if (how & SHUT_WR) {
      mg_flush(conn);
    }
    return shutdown(conn->client.sock, how);
  }
  return -1;
}

struct mg_connection *mg_connect(struct mg_context *ctx,
                                 const char *host, int port, mg_connect_flags_t flags) {
  struct mg_connection *newconn = NULL;
  SOCKET sock;
  struct addrinfo *result = NULL;
  struct addrinfo *ptr;
  struct addrinfo hints = {0};
  int http_io_buf_size;

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  MG_ASSERT(ctx);
  if (flags & MG_CONNECT_HTTP_IO) {
    http_io_buf_size = MAX_REQUEST_SIZE;
  } else {
    http_io_buf_size = 0;
  }
  if (ctx->client_ssl_ctx == NULL && (flags & MG_CONNECT_USE_SSL)) {
    mg_cry(fc(ctx), "%s: SSL is not initialized", __func__);
  } else if (getaddrinfo(host, NULL, &hints, &result)) {
    mg_cry(fc(ctx), "%s: getaddrinfo(%s): %s", __func__, host, mg_strerror(ERRNO));
  } else if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
    mg_cry(fc(ctx), "%s: socket: %s", __func__, mg_strerror(ERRNO));
  } else if ((newconn = (struct mg_connection *)
      calloc(1, sizeof(*newconn) + (http_io_buf_size
        ? http_io_buf_size * 2 + CHUNK_HEADER_BUFSIZ /* RX headers, TX headers, RX chunked scratch space */
        : 0))) == NULL) {
    mg_cry(fc(ctx), "%s: calloc: %s", __func__, mg_strerror(ERRNO));
    closesocket(sock);
  } else {
    newconn->last_active_time = newconn->birth_time = time(NULL);
    newconn->is_client_conn = 1;
    newconn->ctx = ctx;
    newconn->client.sock = sock;
    // by default, a client-side connection is assumed to be an arbitrary client,
    // not necessarily a HTTP client:
    if (!http_io_buf_size) {
      newconn->num_bytes_sent = 0; // = -1; would mean we're expecting (HTTP) headers first
      //newconn->consumed_content = 0;
      newconn->content_len = -1;
      //newconn->request_len = 0;
      //newconn->must_close = 0;
      //newconn->rx_chunk_buf_size = 0;
    } else {
      newconn->num_bytes_sent = -1; // means we're expecting (HTTP) headers first
      //newconn->consumed_content = 0;
      newconn->content_len = -1;
      newconn->buf = (char *)(newconn + 1);
      newconn->buf_size = http_io_buf_size;
      newconn->rx_chunk_buf_size = CHUNK_HEADER_BUFSIZ;
    }
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
      if (ptr->ai_socktype != SOCK_STREAM || ptr->ai_protocol != IPPROTO_TCP)
        continue;
      switch (ptr->ai_family) {
      default:
        continue;

      case AF_INET:
        newconn->client.rsa.len = sizeof(newconn->client.rsa.u.sin);
        newconn->client.rsa.u.sin = * (struct sockaddr_in *)ptr->ai_addr;
        newconn->client.rsa.u.sin.sin_family = AF_INET;
        newconn->client.rsa.u.sin.sin_port = htons((uint16_t) port);
        break;

#if defined(USE_IPV6)
      case AF_INET6:
        newconn->client.rsa.len = sizeof(newconn->client.rsa.u.sin6);
        newconn->client.rsa.u.sin6 = * (struct sockaddr_in6 *)ptr->ai_addr;
        newconn->client.rsa.u.sin6.sin6_family = AF_INET6;
        newconn->client.rsa.u.sin6.sin6_port = htons((uint16_t) port);
        break;
#endif
      }
      break;
    }
    if (!ptr) {
      mg_cry(fc(ctx), "%s: getaddrinfo(%s): no TCP/IP v4/6 support found", __func__, host);
      closesocket(sock);
    }
    else if (connect(sock, &newconn->client.rsa.u.sa, newconn->client.rsa.len) != 0) {
      mg_cry(fc(ctx), "%s: connect(%s:%d): %s", __func__, host, port,
             mg_strerror(ERRNO));
      closesocket(sock);
    } else {
      newconn->client.lsa.len = newconn->client.rsa.len;
      if (0 != getsockname(sock, &newconn->client.lsa.u.sa, &newconn->client.lsa.len)) {
        mg_cry(fc(ctx), "%s: getsockname: %s", __func__, mg_strerror(ERRNO));
        newconn->client.lsa.len = 0;
      }
      if ((flags & MG_CONNECT_USE_SSL) && !sslize(newconn, newconn->ctx->client_ssl_ctx, SSL_connect)) {
        mg_cry(fc(ctx), "%s: sslize(%s:%d): cannot establish SSL connection", __func__, host, port);
        closesocket(sock);
      } else {
        if (result) freeaddrinfo(result);
        return newconn;
      }
    }
  }

  if (result) freeaddrinfo(result);
  if (newconn) free(newconn);
  return NULL;
}

int mg_cleanup_after_request(struct mg_connection *conn) {
  if (conn) {
    reset_per_request_attributes(conn);
    if (!conn->buf_size) {
      conn->num_bytes_sent = 0; // = -1; would mean we're expecting (HTTP) headers first
      conn->content_len = -1;
    } else {
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

  MG_ASSERT(conn->buf);
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
    if (rv >= (int)sizeof(uribuf) - 2 || rv > conn->buf_size - 5) {
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

int mg_read_http_response_head(struct mg_connection *conn) {
  char *buf;
  struct mg_request_info *ri;
  const char *status_code;
  char * chknum;
  int data_len;

  if (!conn || !conn->buf_size)
    return -1;

  MG_ASSERT(conn->content_len == -1);
  ri = &conn->request_info;
  ri->num_headers = 0;

  // when a bit of buffered data is still available, make sure it's in the right spot:
  data_len = conn->rx_buffer_loaded_len - conn->rx_buffer_read_len;
  if (data_len > 0) {
    memmove(conn->buf, conn->buf + conn->request_len + conn->rx_buffer_read_len, data_len);
  } else {
    data_len = 0;
  }

  conn->request_len = read_request(NULL, conn,
                                   conn->buf, conn->buf_size,
                                   &data_len);
  MG_ASSERT(data_len >= conn->request_len);
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
    if (ri->num_headers < 0) {
      ri->num_headers = 0;
      return -7; // HTTP response contains invalid headers
    }
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
    MG_ASSERT(conn->content_len == -1);
    if (cl && mg_stristr(cl, "chunked")) {
      MG_ASSERT(conn->content_len == -1);
      mg_set_rx_mode(conn, MG_IOMODE_CHUNKED_DATA);
    } else {
      MG_ASSERT(!conn->rx_is_in_chunked_mode);
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

FILE *mg_fetch(struct mg_context *ctx, const char *url, const char *path, struct mg_connection **conn_ref) {
  struct mg_connection *conn = NULL;
  int n, nread, nwrite, port, is_ssl, is_persistent_conn, rv;
  char host[1025], proto[10], buf2[DATA_COPY_BUFSIZ];
  FILE *fp = NULL;

  if (sscanf(url, "%9[htps]://%1024[^:]:%d/%n", proto, host, &port, &n) == 3) {
    is_ssl = (mg_strcasecmp(proto, "https") == 0);
  } else if (sscanf(url, "%9[htps]://%1024[^/]/%n", proto, host, &n) == 2) {
    is_ssl = (mg_strcasecmp(proto, "https") == 0);
    port = (is_ssl ? 443 : 80);
  } else {
    mg_cry(fc(ctx), "%s: invalid URL: [%s]", __func__, url);
    return NULL;
  }

  if (conn_ref) {
    conn = *conn_ref;
    is_persistent_conn = (conn != NULL);
  } else {
    is_persistent_conn = 0;
  }
  if (conn == NULL &&
      (conn = mg_connect(ctx, host, port, (is_ssl ? MG_CONNECT_USE_SSL : 0) | MG_CONNECT_HTTP_IO)) == NULL) {
    mg_cry(fc(ctx), "%s: mg_connect(%s): %s", __func__, url, mg_strerror(ERRNO));
  } else {
    mg_add_tx_header(conn, 0, "Host", host);
    //mg_add_tx_header(conn, 0, "Connection", "close");
    if (!is_persistent_conn) {
      conn->must_close = 1;
    } else {
      mg_add_tx_header(conn, 0, "Content-Length", "0");
    }

    rv = mg_write_http_request_head(conn, "GET", "/%s", url + n);
    if (rv <= 0) {
      mg_cry(fc(ctx), "%s(%s): failed to send the HTTP request", __func__, url);
    } else {
      MG_ASSERT(!strcmp(conn->request_info.http_version, "1.1"));

      // signal request phase done:
      if (!is_persistent_conn)
        mg_shutdown(conn, SHUT_WR);

      // fetch response, blocking I/O:
      //
      // but since this is a HTTP I/O savvy connection, we should first read the headers and parse them:
      rv = mg_read_http_response_head(conn);
      if (rv < 0) {
        mg_cry(fc(ctx), "%s(%s): invalid HTTP reply or invalid HTTP response headers, error code %d", __func__, url, rv);
      } else if ((fp = fopen(path, "w+b")) == NULL) {
        mg_cry(fc(ctx), "%s: fopen(%s): %s", __func__, path, mg_strerror(ERRNO));
      } else {
        // Read all response data and store in the file:
        for (;;) {
          nread = mg_read(conn, buf2, sizeof(buf2));
          if (nread < 0) {
            mg_cry(fc(ctx), "%s(%s): failed to read data, connection may have been closed prematurely by the server: %s", __func__, url, mg_strerror(ERRNO));
            break;
          }
          if (nread == 0) {
            // end of data reached
            break;
          }
          nwrite = push(fp, NULL, buf2, nread);
          if (nwrite != nread) {
            nread = -1;
            mg_cry(fc(ctx), "%s: fwrite(%s): %s", __func__, path, mg_strerror(ERRNO));
            break;
          }
        }

        if (nread < 0) {
          fclose(fp);
          fp = NULL;

          // make sure corrupt file doesn't remain
          mg_remove(path);
        }
      }
    }
    if (!conn_ref) {
      mg_close_connection(conn);
      conn = NULL;
    }
  }

  if (conn_ref) {
    *conn_ref = conn;
  }

  return fp;
}

static void discard_current_request_from_buffer(struct mg_connection *conn) {
  int n;
  char buf[MG_BUF_LEN];

  // Don't do this for connections which are NOT HTTP/1.1 keep-alive enabled:
  if (!should_keep_alive(conn))
    return;

  // make sure we fetch all content (and discard it), if we
  // haven't done so already (f.e.: event callback handler might've
  // ignored part or whole of the received content) otherwise
  // we've got a b0rked keep-alive HTTP stream:
  //
  // as mg_read() will return 0 as soon as the entire content of the
  // current request has been read, we can simply check for that:
  do {
    n = mg_read(conn, buf, sizeof(buf));
  } while (n > 0 && conn->ctx->stop_flag == 0);
  // when an error occurred, we must close the connection
  if (n < 0) {
    conn->must_close = 1;
  }
}

static int is_valid_uri(const char *uri) {
  // Conform to http://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html#sec5.1.2
  // URI can be an asterisk (*) or should start with slash.
  return (uri[0] == '/' || (uri[0] == '*' && uri[1] == '\0'));
}

// Process HTTP requests for the given connection as long as there's any request
// data incoming (pending), i.e. as long as the connection is 'active'.
//
// Return 0 when the connection should be 'kept alive' but is possibly idle,
// return -1 on error, +1 when the connection should be closed but was otherwise okay.
static int process_new_connection(struct mg_connection *conn) {
  struct mg_request_info *ri = &conn->request_info;
  //int keep_alive_enabled;  -- checked in the should_keep_alive() call anyway
  const char *cl;

  do {
    int data_len;

#if MG_DEBUG_TRACING
    if (conn->request_info.seq_no > 0) {
      DEBUG_TRACE(0x0002,
                  ("****** round: %d! ******",
                   conn->request_info.seq_no + 1));
    }
#endif
    reset_per_request_attributes(conn);

    // when a bit of buffered data is still available, make sure it's in the right spot:
    data_len = conn->rx_buffer_loaded_len - conn->rx_buffer_read_len;
    if (data_len > 0) {
      memmove(conn->buf, conn->buf + conn->request_len + conn->rx_buffer_read_len, data_len);
    } else {
      data_len = 0;
    }

    conn->request_len = read_request(NULL, conn,
                                     conn->buf, conn->buf_size,
                                     &data_len);
    MG_ASSERT(data_len >= conn->request_len);
    conn->request_info.seq_no++;
    if (conn->request_len <= 0) {
      if (conn->request_len == 0 && data_len == conn->buf_size) {
        send_http_error(conn, 413, NULL, "%s: client sent malformed HTTP headers or HTTP headers take up more than %u buffer bytes",
                        __func__, (unsigned int)conn->buf_size);
        return -1;
      }
      // In case we didn't receive ANY data, we don't mess with the connection any further
      // by trying to send any error response data, so we tag the connection as done for that:
      if (data_len == 0) {
        mg_mark_end_of_header_transmission(conn);
      }
      // when persistent connection was closed, we simply exit,
      // IFF at least 1 request has been serviced already:
      if (conn->request_len == 0 && data_len == 0 && conn->request_info.seq_no > 1) {
        // NOT an error! Just quit!
        return -1;
      }
      // don't mind we cannot send the 5xx response code, as long as we log the issue at least...
      send_http_error(conn, 579, NULL, "%s: no data received or socket/network error: %s", __func__, mg_strerror(ERRNO));
      return -1;  // Remote end closed the connection or malformed request
    }
    conn->rx_chunk_buf_size = conn->buf_size + CHUNK_HEADER_BUFSIZ - conn->request_len;
    conn->rx_buffer_loaded_len = data_len - conn->request_len;
    conn->rx_buffer_read_len = 0;

    // NUL-terminate the request cause parse_http_request() is C-string based
    conn->buf[conn->request_len - 1] = '\0';
    if (parse_http_request(conn->buf, ri) ||
        !is_valid_uri(ri->uri)) {
      // Do not put garbage in the access log, just send it back to the client
      send_http_error(conn, 400, NULL,
                      "Cannot parse HTTP request: [%.*s]", data_len, conn->buf);
    } else if (strcmp(ri->http_version, "1.0") &&
               strcmp(ri->http_version, "1.1")) {
      // Request seems valid, but HTTP version is strange
      send_http_error(conn, 505, NULL, "");
      log_access(conn);
    } else {
      // Request is valid, handle it
      cl = get_header(ri->http_headers, ri->num_headers, "Transfer-Encoding");
      MG_ASSERT(conn->content_len == -1);
      if (cl && mg_stristr(cl, "chunked")) {
        mg_set_rx_mode(conn, MG_IOMODE_CHUNKED_DATA);
      } else {
        char *chknum = NULL;
        MG_ASSERT(!conn->rx_is_in_chunked_mode);
        cl = get_header(ri->http_headers, ri->num_headers, "Content-Length");
        if (cl != NULL)
          conn->content_len = strtoll(cl, &chknum, 10);
        if (chknum != NULL)
          chknum += strspn(chknum, " ");
        if (!is_empty(chknum))
          return 400; // Cannot parse HTTP request header
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
      handle_request(conn);
      // always make sure that chunked I/O, etc. is completed before we go and process the next request.
      if (mg_flush(conn) > 0) {
        // chunked transfer was not completed; complain and close the connection forcibly.
        send_http_error(conn, 579, NULL,
                        "%s: chunked transfer was not completed (%" PRId64 " bytes remain)",
                        __func__, mg_get_tx_remaining_chunk_size(conn));
      }
      call_user(conn, MG_REQUEST_COMPLETE);
      log_access(conn);
      discard_current_request_from_buffer(conn);
    }
    if (ri->remote_user != NULL) {
      free((void *) ri->remote_user);
      ri->remote_user = NULL;
    }
    if (conn->ctx->stop_flag != 0)
      return -1;
    if (!should_keep_alive(conn))
      return 1;
    // check whether the connection is still active, i.e. whether it has any
    // more request data pending...
  } while (conn->rx_buffer_read_len < conn->rx_buffer_loaded_len);
  return 0;
}

// extract N idle connections from the queue to test; locking should be done by caller!
//
// NOTE: we tweak the extracted elements' was_idle bits (they're ours now)
//       so that we can check when we've tested ALL queued items easily,
//       as re-inserted nodes are appended at the back, unless there's
//       some good news (i.e. active nodes) to report.
//
// Return index to start of extracted set (cyclic linked list), -1 ~ empty set.
static int pull_testset_from_idle_queue(struct mg_context *ctx, int n) {
  struct mg_idle_connection *arr = ctx->queue_store;
  int head = ctx->sq_head; // the compiler MAY optimize sq_head access in this entire routine!

  if (head >= 0) {
    int p, idle_test_set;

    p = idle_test_set = head;
    do {
      if ((arr[p].client.was_idle && arr[p].client.has_read_data) || arr[p].client.idle_time_expired) {
        // we don't need to test as we already know this node has data for us ~ is 'active',
        // so we only return this one:
        arr[arr[p].prev].next = arr[p].next;
        arr[arr[p].next].prev = arr[p].prev;
        if (head == p) {
          if (arr[p].prev == p)
            head = -1;
          else
            head = arr[p].next;
        }
        arr[p].next = p;
        arr[p].prev = p;
        ctx->sq_head = head;
        return p;
      }
      arr[p].client.was_idle = 0;
      MG_ASSERT(arr[p].client.has_read_data == 0);
      p = arr[p].next;
    } while (--n > 0 && p != idle_test_set);
    // decouple set from idle queue:
    if (p == idle_test_set) {
      // grabbed entire set, so that's easy:
      ctx->sq_head = -1;
      return idle_test_set;
    }
    arr[arr[idle_test_set].prev].next = arr[p].next;
    arr[arr[p].next].prev = arr[idle_test_set].prev;

    arr[idle_test_set].prev = p;
    arr[p].next = idle_test_set;

    ctx->sq_head = head;
    return idle_test_set;
  }
  return -1;
}

// re-insert a series of idle connections into the idle queue: place these
// at the back when they are not marked as 'active', place the nodes which are
// marked as 'active' at the front of the queue so they can be picked off
// as fast as possible.
// This procedure makes the idle queue testing behave like a Round Robin process.
static void insert_testset_into_idle_queue(struct mg_context *ctx, int idle_test_set) {
  // nasty: as we need to re-order the nodes, we do it quick&dirty by placing
  // them in proper order in this local array (of same size as the idle_queue_store)
  // and then rebuild the linked lists in CTX in one fell swoop.
  int node_set[ARRAY_SIZE(ctx->queue_store) + 4 /* front/end sentinels */];
  int a, z, p, i;
  struct mg_idle_connection *arr = ctx->queue_store;
  int head = ctx->sq_head; // the compiler MAY optimize sq_head access in this entire routine!

  a = 1;
  z = ARRAY_SIZE(node_set) - 1;
  node_set[0] = node_set[ARRAY_SIZE(node_set) - 1] = -1;
  MG_ASSERT(idle_test_set >= 0);
  MG_ASSERT(idle_test_set < ARRAY_SIZE(ctx->queue_store));
  p = idle_test_set;
  do {
    if (arr[p].client.was_idle && arr[p].client.has_read_data)
      node_set[--z] = p;
    else
      node_set[a++] = p;
    p = arr[p].next;
    MG_ASSERT(p >= 0);
    MG_ASSERT(p < ARRAY_SIZE(ctx->queue_store));
    MG_ASSERT(a < z);
  } while (p != idle_test_set);
  node_set[a] = node_set[z - 1] = -1;

  // rebuild both partial sets:
  for (i = 1; i < a; i++) {
    int x = node_set[i];
    int nx = node_set[i + 1];
    int px = node_set[i - 1];

    arr[x].next = nx;
    arr[x].prev = px;
  }
  for (i = z; i < (int)ARRAY_SIZE(node_set) - 1; i++) {
    int x = node_set[i];
    int nx = node_set[i + 1];
    int px = node_set[i - 1];

    arr[x].next = nx;
    arr[x].prev = px;
  }

  // 'active' set at the front:
  if (z < (int)ARRAY_SIZE(node_set) - 1) {
    int x = node_set[z];
    int lx = node_set[ARRAY_SIZE(node_set) - 2];

    if (head < 0) {
      // this one's easy!
      head = x;
      arr[x].prev = lx;
      arr[lx].next = x;
    } else {
      arr[x].prev = arr[head].prev;
      arr[lx].next = head;
      arr[head].prev = lx;
      arr[arr[head].prev].next = x;
    }
  }
  // still idle set at the back:
  if (a > 1) {
    int x = node_set[1];
    int lx = node_set[a - 1];

    if (head < 0) {
      // this one's easy!
      head = x;
      arr[x].prev = lx;
      arr[lx].next = x;
    } else {
      int q = arr[head].prev;

      arr[x].prev = q;
      MG_ASSERT(arr[q].next == head);
      arr[lx].next = head;
      arr[q].next = x;
      arr[head].prev = lx;
    }
  }

  ctx->sq_head = head;
}

// Remove the given element from the idle queue / storage and init the 'conn' connection with its data.
// Locking should be done by the caller!
//
// This routine doesn't care whether you remove the node from an 'extracted' test list or the
// queue at large: both scenarios are served:
// this function returns a reference to the next node in the list, so the caller can track the list.
static int pop_node_from_idle_queue(struct mg_context *ctx, int node, struct mg_connection *conn) {
  struct mg_idle_connection *arr = ctx->queue_store + node;
  int r;

  MG_ASSERT(node >= 0);
  MG_ASSERT(node < (int)ARRAY_SIZE(ctx->queue_store));
  conn->request_info.req_user_data = arr->req_user_data;
  conn->request_info.remote_ip = arr->remote_ip;
  conn->request_info.local_ip = arr->local_ip;
  conn->request_info.remote_port = arr->remote_port;
  conn->request_info.local_port = arr->local_port;
  conn->request_info.seq_no = arr->seq_no;

  conn->is_inited = arr->is_inited;
  conn->ssl = arr->ssl;
  conn->client = arr->client;
  conn->birth_time = arr->birth_time;
  conn->last_active_time = arr->last_active_time;

  // remove node from any cyclic linked list out there:
  if (arr->next == node) {
    r = -1;
  } else {
    struct mg_idle_connection *arr_base = ctx->queue_store;

    r = arr->next;
    arr_base[r].prev = arr->prev;
    arr_base[arr->prev].next = r;
  }
  // mark element as 'free': add it to the 'free list'.
  arr->next = ctx->idle_q_store_free_slot;
  ctx->idle_q_store_free_slot = node;

  return r;
}

// push the given connection onto the idle queue (it will be located at the back: FIFO).
// Locking should be done by the caller!
//
// Return -1 if the queue is full and hence the pushback failed. Return queued node on success.
static int push_conn_onto_idle_queue(struct mg_context *ctx, struct mg_connection *conn) {
  int i = ctx->idle_q_store_free_slot;
  struct mg_idle_connection *arr = ctx->queue_store + i;
  int head = ctx->sq_head; // the compiler MAY optimize sq_head access in this entire routine!

  if (i < 0)
    return -1;
  MG_ASSERT(i < (int)ARRAY_SIZE(ctx->queue_store));
  ctx->idle_q_store_free_slot = arr->next;

  arr->req_user_data = conn->request_info.req_user_data;
  arr->remote_ip = conn->request_info.remote_ip;
  arr->local_ip = conn->request_info.local_ip;
  arr->remote_port = conn->request_info.remote_port;
  arr->local_port = conn->request_info.local_port;
  arr->seq_no = conn->request_info.seq_no;

  arr->is_inited = conn->is_inited;
  arr->ssl = conn->ssl;
  arr->client = conn->client;
  arr->birth_time = conn->birth_time;
  arr->last_active_time = conn->last_active_time = time(NULL);

  // make sure to clear the 'has_read_data' when it would be in an unknown state before
  if (!arr->client.was_idle)
    arr->client.has_read_data = 0;
  arr->client.was_idle = 1;

  // add element at the end of the queue:
  if (head < 0) {
    head = i;
    arr->prev = arr->next = i;
  } else {
    arr = ctx->queue_store;
    arr[i].prev = arr[head].prev;
    arr[arr[i].prev].next = i;
    arr[i].next = head;
    arr[head].prev = i;
  }
  ctx->sq_head = head;
  return i;
}

// Worker threads fetch an accepted (and 'active') connection/socket from the queue,
// 'active' meaning the connection has data waiting to be read.
//
// NOTE: conn->client may already point at a valid connection/socket: that socket will be
//       tested alongside the queued sockets:
//       - when it proves to be 'active', it will be returned (preferential use of
//         currently served connection)
//       - when it is 'inactive' but another, queued, connection is, then the current
//         connection is pushed back onto the queue and the active one loaded into 'conn'.
//
// Return 1 on success, 0 on error.
static int consume_socket(struct mg_context *ctx, struct mg_connection *conn) {
  int head;

  if (ctx->stop_flag)
    return 0;

  (void) pthread_mutex_lock(&ctx->mutex);
  // If the queue is empty, wait. We're idle at this point.
  while (ctx->sq_head < 0 && ctx->stop_flag == 0) {
    pthread_cond_wait(&ctx->sq_full, &ctx->mutex);
  }

  do {
    int idle_test_set = -1;
    time_t now = time(NULL);

    head = ctx->sq_head;
    // If we're stopping, queue may be empty.
    if (head >= 0 && ctx->stop_flag == 0) {
      idle_test_set = pull_testset_from_idle_queue(ctx, FD_SETSIZE);
      MG_ASSERT(idle_test_set >= 0 ? idle_test_set != head ? ctx->queue_store[idle_test_set].client.was_idle == 1 : 1 : 1);
      MG_ASSERT(idle_test_set >= 0 ? idle_test_set != head ? (ctx->queue_store[idle_test_set].client.has_read_data || ctx->queue_store[idle_test_set].client.idle_time_expired) : 1 : 1);
      head = ctx->sq_head;
    }
    (void) pthread_mutex_unlock(&ctx->mutex);

    while (idle_test_set >= 0) {
      int sn = idle_test_set;

      // did a previous scan already produce another 'active' node?
      if (!((ctx->queue_store[idle_test_set].client.was_idle && ctx->queue_store[idle_test_set].client.has_read_data) || ctx->queue_store[idle_test_set].client.idle_time_expired)) {
        fd_set fdr;
        int max_fh = -1;
        struct timeval tv;
        struct mg_idle_connection *arr = ctx->queue_store;
        int p;

        DEBUG_TRACE(0x0002, ("testing pushed-back (idle) keep-alive connections"));
        FD_ZERO(&fdr);
        p = idle_test_set;
        do {
          // while setting up the FD_SET, also check for idle-timed-out sockets and mark 'em:
          if (arr[p].client.max_idle_seconds > 0 &&
              arr[p].last_active_time + arr[p].client.max_idle_seconds <= now)
            arr[p].client.idle_time_expired = 1;

          add_to_set(arr[p].client.sock, &fdr, &max_fh);
          p = arr[p].next;
        } while (p != idle_test_set);
        /*
         Do NOT wait in the select(), just check if anybody has anything for us or not.

         Unless, that is, when we're checking the _last_ chunk of pending handles: if
         none of those deliver anything 'read ready' either, we know _none_ of them
         have anything useful for us right now and as the sq_full is still (correctly!)
         triggered, we just need to wait until there's some read data ready somewhere.
         Meanwhile, we don't want this loop to load the CPU @ 100% for this particular
         'everybody is silent now' scenario, so we add a wee bit of a delay here, just
         very small, so that us not seeing anything happening in this last series doesn't
         delay anything pending _now_ in the former chunks if the _very large_ (> FD_SETSIZE)
         connection queue we might have.
         If the connection queue is <= FD_SETSIZE elements large, then we might think
         we're safe with any delay as long as it's in select() here, as select() will
         be watching _all_ our queued connections then, but there can still be new
         connections incoming, getting queued and possibly with data ready, without us
         knowing yet -- we're outside the mutex-ed zone here!

         'head' is a thread-safe copy of the ctx->sq_head after extracting the current
         series from the connection queue; remember that it's not up-to-date as it
         represents the state of affairs while we were in the mutexed zone: the situation
         may have changed by now, so we MUST keep our select() delay as low as possible
         here to balance between CPU load reduction in 'everybody is silent' mode while
         ensuring swift reponse to new incoming connections with data available in them.
        */
        if (head >= 0) {
          tv.tv_sec = 0;
          tv.tv_usec = 0;
        } else {
          tv.tv_sec = MG_SELECT_TIMEOUT_MSECS_TINY / 1000;
          tv.tv_usec = MG_SELECT_TIMEOUT_MSECS_TINY * 1000;
        }
        sn = select(max_fh + 1, &fdr, NULL, NULL, &tv);
        if (sn > 0) {
          sn = -1;
          p = idle_test_set;
          do {
            arr[p].client.was_idle = 1;  // mark node as tested
            if (FD_ISSET(arr[p].client.sock, &fdr)) {
              if (sn < 0)
                sn = p;
              arr[p].client.has_read_data = 1;
            } else {
              MG_ASSERT(arr[p].client.has_read_data == 0);
              if (arr[p].client.idle_time_expired && sn < 0)
                sn = p;
            }
            p = arr[p].next;
          } while (p != idle_test_set);
        } else {
          sn = -1;
          p = idle_test_set;
          do {
            if (arr[p].client.idle_time_expired && sn < 0)
              sn = p;
            arr[p].client.was_idle = 1;  // mark node as tested
            MG_ASSERT(arr[p].client.has_read_data == 0);
            p = arr[p].next;
          } while (p != idle_test_set);
        }
      }

      // did we find an active node? if yes, then remove it from the queue/set and re-insert the rest:
      if (sn >= 0) {
        int p;

        (void) pthread_mutex_lock(&ctx->mutex);
        p = pop_node_from_idle_queue(ctx, sn, conn);
        if (sn == idle_test_set) {
          idle_test_set = p;
        }
        if (idle_test_set >= 0) {
          insert_testset_into_idle_queue(ctx, idle_test_set);
        }
        (void) pthread_mutex_unlock(&ctx->mutex);

        DEBUG_TRACE(0x0002, ("grabbed socket %d, going busy", conn->client.sock));
        return 1;
      } else {
        (void) pthread_mutex_lock(&ctx->mutex);
        MG_ASSERT(idle_test_set >= 0);
        insert_testset_into_idle_queue(ctx, idle_test_set);
        // did we get to test them all yet? (see NOTE above pull_testset_from_idle_queue() function implementation about was_idle manipulation)
        head = ctx->sq_head;
        if (head >= 0 && ctx->stop_flag == 0 && ctx->queue_store[head].client.was_idle == 0) {
          // still more nodes to test
          idle_test_set = pull_testset_from_idle_queue(ctx, FD_SETSIZE);
          head = ctx->sq_head;
        } else {
          idle_test_set = -1;
        }
        (void) pthread_mutex_unlock(&ctx->mutex);
      }
    }

    // when we get here, we can be sure there's no-one active in the test set: try again until it's server termination time
    DEBUG_TRACE(0x0002, ("going idle"));

    (void) pthread_mutex_lock(&ctx->mutex);
    (void) pthread_cond_signal(&ctx->sq_empty);

    // If the queue is empty, wait longer. We're idle at this point.
    while (ctx->stop_flag == 0) {
      struct timespec tv = {0};

      // While we wait here, one or more queued connections may receive data,
      // which should be processed ASAP, so we shouldn't wait long then:
      if (ctx->sq_head >= 0) {
        tv.tv_sec = MG_SELECT_TIMEOUT_MSECS_TINY / 1000;
        tv.tv_nsec = MG_SELECT_TIMEOUT_MSECS_TINY * 1000000;
      } else {
        tv.tv_sec = MG_SELECT_TIMEOUT_MSECS / 1000;
        tv.tv_nsec = MG_SELECT_TIMEOUT_MSECS * 1000000;
      }
      pthread_cond_timedwait(&ctx->sq_full, &ctx->mutex, &tv);
      if (ctx->sq_head >= 0)
        break;
    }
  } while (ctx->stop_flag == 0);
  (void) pthread_mutex_unlock(&ctx->mutex);

  return 0;
}

// Master thread adds accepted socket to a queue
//
// Return 1 on success, 0 on error.
static int produce_socket(struct mg_context *ctx, struct mg_connection *conn) {
  int rv = 0;

  // this timestamp is important as it is used to check the keep alive timeout (socket::max_idle_seconds) too!
  conn->last_active_time = conn->birth_time = time(NULL);

  (void) pthread_mutex_lock(&ctx->mutex);

  while (ctx->stop_flag == 0 && rv == 0) {
    int full = push_conn_onto_idle_queue(ctx, conn);
    // If the queue is full, wait
    if (full < 0 && ctx->stop_flag == 0) {
      (void) pthread_cond_wait(&ctx->sq_empty, &ctx->mutex);
    } else if (full >= 0) {
      rv = 1;
      DEBUG_TRACE(0x0002, ("queued socket %d", (int)conn->client.sock));
    }
  }

  // one should NEVER call pthread_cond_signal() when a server stop is in progress:
  // see the note at pthread_cond_broadcast() ~ line 1944.
  //
  // During a server stop we call pthread_cond_broadcast() so, given the race condition
  // mentioned there, we should NEVER call this pthread_cond_signal() while that server
  // stop is in progress. Besides, it's okay we don't as the master thread, who otherwise
  // would act upon this signal, is shutting down already.
  if (rv && ctx->stop_flag == 0)
    (void) pthread_cond_signal(&ctx->sq_full);
  (void) pthread_mutex_unlock(&ctx->mutex);

  return rv;
}

static void * WINCDECL worker_thread(struct mg_context *ctx) {
  struct mg_connection *conn = NULL;

  conn = (struct mg_connection *) malloc(sizeof(*conn) + MAX_REQUEST_SIZE * 2 + CHUNK_HEADER_BUFSIZ); /* RX headers, TX headers, chunk header space */
  if (conn == NULL) {
    mg_cry(fc(ctx), "Cannot create new connection struct, OOM");
    goto fail_dramatically;
  }
  memset(conn, 0, sizeof(conn[0]));
  conn->client.sock = INVALID_SOCKET;

  // Call consume_socket() even when ctx->stop_flag > 0, to let it signal
  // sq_empty condvar to wake up the master waiting in produce_socket()
  while (consume_socket(ctx, conn)) {
    int doing_fine = 1;

    // everything in 'conn' is zeroed at this point in time: set up the buffers, etc.
    conn->buf_size = MAX_REQUEST_SIZE;
    conn->buf = (char *) (conn + 1);
    conn->ctx = ctx;
    conn->request_info.is_ssl = conn->client.is_ssl;
    conn->abort_when_server_stops = 1;
    if (conn->client.idle_time_expired) {
      DEBUG_TRACE(0x0023, ("kept-alive(?) connection expired (keep-alive-timeout)"));
      conn->must_close = 1;
      // when we expire, don't spend ANY further effort on this connection:
      doing_fine = 0;
    }

    if (!conn->is_inited && doing_fine) {
      doing_fine = 0;

      // Fill in IP, port info early so even if SSL setup below fails,
      // error handler would have the corresponding info.
      // Thanks to Johannes Winkelmann for the patch.
      conn->request_info.remote_port = get_socket_port(&conn->client.rsa);
      get_socket_ip_address(&conn->request_info.remote_ip, &conn->client.rsa);
      // get the actual local IP address+port the client connected to:
      if (0 != getsockname(conn->client.sock, &conn->client.lsa.u.sa, &conn->client.lsa.len)) {
        mg_cry(conn, "%s: getsockname: %s", __func__, mg_strerror(ERRNO));
        //conn->client.lsa.len = 0;
      }
      conn->request_info.local_port = get_socket_port(&conn->client.lsa);
      get_socket_ip_address(&conn->request_info.local_ip, &conn->client.lsa);

      if (!conn->client.is_ssl ||
        (conn->client.is_ssl && sslize(conn, conn->ctx->ssl_ctx, SSL_accept))) {
        //reset_per_request_attributes(conn); // otherwise the callback will receive arbitrary (garbage) data
        doing_fine = 1;
        conn->is_inited = 1;
        call_user(conn, MG_INIT_CLIENT_CONN);
      } else {
        mg_cry(conn, "%s: socket %d failed to initialize completely: %s", __func__, (int)conn->client.sock, mg_strerror(ERRNO));
      }
    } else if (doing_fine) {
      DEBUG_TRACE(0x0002, ("revived kept-alive socket %d", (int)conn->client.sock));
    } else {
      DEBUG_TRACE(0x0003, ("closing expired connection socket %d", (int)conn->client.sock));
    }

    if (doing_fine) {
      doing_fine = !process_new_connection(conn);
    }

    if (!doing_fine) {
      DEBUG_TRACE(0x0022, ("closing connection"));
      //reset_per_request_attributes(conn); // otherwise the callback will receive arbitrary (garbage) data
      call_user(conn, MG_EXIT_CLIENT_CONN);
      close_connection(conn);
      // Clear everything in conn to ensure no value makes it into the next connection/session.
      // (Also clears the cached logfile path so it is recalculated on the next log operation.)
      memset(conn, 0, sizeof(*conn));
      conn->client.sock = INVALID_SOCKET;
    } else {
      // The simplest way is to push the current connection onto the queue, and then
      // let consume_socket() [and its internal select() logic] cope with it.
      DEBUG_TRACE(0x0022, ("pushing MAYBE-IDLE connection back onto the queue"));
      if (!produce_socket(ctx, conn)) {
        char src_addr[SOCKADDR_NTOA_BUFSIZE];
        mg_cry(conn, "%s: closing active connection %s because server is shutting down",
               __func__, sockaddr_to_string(src_addr, sizeof(src_addr), &conn->client.rsa));
        //reset_per_request_attributes(conn); // otherwise the callback will receive arbitrary (garbage) data
        call_user(conn, MG_EXIT_CLIENT_CONN);
        close_connection(conn);
        break;
      }
    }
  }
  // close the kept-alive connection when a failure occurred, e.g. server stop pending:
  if (conn->client.sock != INVALID_SOCKET) {
    char src_addr[SOCKADDR_NTOA_BUFSIZE];
    mg_cry(conn, "%s: closing keep-alive connection %s because server is shutting down",
           __func__, sockaddr_to_string(src_addr, sizeof(src_addr), &conn->client.rsa));
    //reset_per_request_attributes(conn); // otherwise the callback will receive arbitrary (garbage) data
    call_user(conn, MG_EXIT_CLIENT_CONN);
    close_connection(conn);
  }
  free(conn);
  conn = NULL;

fail_dramatically:
  MG_ASSERT(conn == NULL);
#if defined(_WIN32)
  // wait a wee bit to prevent possible _createthread race condition in Windows.
  // See also Remarks section in http://msdn.microsoft.com/en-us/library/kdzttdcb(v=vs.80).aspx,
  // at the paragraph that begins "It is safer to use...". We don't, as _beginthread() is fitting
  // our purposes nicely, but we need to tweak the behaviour to prevent the race:
  mg_sleep(1 + 1000 / CLK_TCK);
#endif
  DEBUG_TRACE(~0, ("exiting"));

  // Signal master that we're done with connection and exiting
  (void) pthread_mutex_lock(&ctx->mutex);
  ctx->num_threads--;
  (void) pthread_cond_signal(&ctx->cond);
  MG_ASSERT(ctx->num_threads >= 1);
  (void) pthread_mutex_unlock(&ctx->mutex);

  // WARNING: ctx->num_threads-- MUST be the VERY LAST THING this thread does.
  //          any DEBUG_TRACE(), etc. after it will run past the moment in time
  //          when mg_stop() completes -- and that one destroys all the
  //          mutexes so writing DEBUG_TRACE() right here would cause a random
  //          crash due to race conditions, due to this thread then running
  //          DEBUG_TRACE() or other code while the master thread completes
  //          due to num_threads reaching zero, which in turn will signal
  //          mg_stop() to destroy the mutexes, etc..
  pthread_exit(0);
  return 0;
}

static int accept_new_connection(const struct socket *listener,
                                  struct mg_context *ctx) {
  struct socket accepted = {0};  // NIL all connection parameters to prevent surprises in user code accessing any of these.
  char src_addr[SOCKADDR_NTOA_BUFSIZE];
  int allowed;

  accepted.rsa.len = listener->lsa.len; // making sure both peers use the same IPvX records, otherwise accept() will b0rk
  accepted.lsa = listener->lsa;
  accepted.sock = accept(listener->sock, &accepted.rsa.u.sa, &accepted.rsa.len);
  if (accepted.sock != INVALID_SOCKET) {
    int keep_alive_timeout = atoi(get_option(ctx, KEEP_ALIVE_TIMEOUT));

    if (set_timeout(&accepted, keep_alive_timeout)) {
      mg_cry(fc(ctx), "%s: %s failed to set the socket timeout",
             __func__, sockaddr_to_string(src_addr, sizeof(src_addr), &accepted.rsa));
      (void) closesocket(accepted.sock);
      return 0; // this is NOT a GRAVE error; this is not cause enough to go and unbind/rebind the listeners!
    }

    allowed = check_acl(ctx, &accepted.rsa);
    if (allowed) {
      struct mg_connection dummy_conn = {0};

      // Put accepted socket structure into the queue
      DEBUG_TRACE(0x0020, ("accepted socket %d", accepted.sock));
      accepted.is_ssl = listener->is_ssl;
      dummy_conn.client = accepted;
      if (!produce_socket(ctx, &dummy_conn)) {
        mg_cry(fc(ctx), "%s: closing accepted connection %s because server is shutting down",
               __func__, sockaddr_to_string(src_addr, sizeof(src_addr), &accepted.rsa));
        (void) closesocket(accepted.sock);
      }
    } else {
      sockaddr_to_string(src_addr, sizeof(src_addr), &accepted.rsa);
      mg_cry(fc(ctx), "%s: %s is not allowed to connect", __func__, src_addr);
      (void) closesocket(accepted.sock);
    }
    return 0;
  } else {
    const char *errmsg = mg_strerror(ERRNO);
    sockaddr_to_string(src_addr, sizeof(src_addr), &listener->lsa);
    mg_cry(fc(ctx), "%s: accept() failed for listener %s : %s", __func__, src_addr, errmsg);
    /*
    This is a VERY SEVERE ERROR: when this happens, the next thing that will
    happen with very high probability is that the next round of select()
    will detect that the incoming connection has not been accepted and hence
    fire immediately, resulting in maximum CPU usage in the main thread.

    It is therefore better to unbind and rebind to the listening port(s)
    in order to clear/discard the incoming connection attempt which failed
    to be accepted.
    */
    return -1;
  }
}

static void * WINCDECL master_thread(struct mg_context *ctx) {
  fd_set read_set;
  struct timeval tv;
  struct socket *sp;
  int max_fd;

  // Increase priority of the master thread (issue #317)
#if defined(_WIN32)
  SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
#elif defined(MASTER_THREAD_SCHED_PRIORITY)
  // fix: do not use the most time critical thread in the entire system
  struct sched_param sched_param;
  int min_prio = sched_get_priority_min(SCHED_RR);
  int max_prio = sched_get_priority_max(SCHED_RR);
  if ((min_prio >=0) && (max_prio >= 0) &&
      (MASTER_THREAD_SCHED_PRIORITY <= max_prio) &&
      (MASTER_THREAD_SCHED_PRIORITY >= min_prio)
      ) {
    struct sched_param sched_param = {0};
    sched_param.sched_priority = MASTER_THREAD_SCHED_PRIORITY;
    pthread_setschedparam(pthread_self(), SCHED_RR, &sched_param);
  }
#endif

  // fix: issue 345 for the master thread (TODO: set the priority in the callback)
  call_user_over_ctx(ctx, 0, MG_ENTER_MASTER);

  while (ctx->stop_flag == 0) {
    int n;
    FD_ZERO(&read_set);
    max_fd = -1;

    // Add listening sockets to the read set
    for (sp = ctx->listening_sockets; sp != NULL; sp = sp->next) {
      add_to_set(sp->sock, &read_set, &max_fd);
    }

    tv.tv_sec = 0;
    tv.tv_usec = MG_SELECT_TIMEOUT_MSECS * 1000;

    n = select(max_fd + 1, &read_set, NULL, NULL, &tv);
    if (n < 0) {
      // On windows, if read_set and write_set are empty,
      // select() returns "Invalid parameter" error
      // (at least on my Windows XP Pro). So in this case, we sleep here.
      //
      // [i_a]: always sleep a bit on error, unless the error is due to a stop signal
      if (ctx->stop_flag == 0)
        mg_sleep(10);
    } else if (n == 0) {
      // timeout
      call_user_over_ctx(ctx, 0, MG_IDLE_MASTER);
    } else {
      for (sp = ctx->listening_sockets; sp != NULL; sp = sp->next) {
        if (ctx->stop_flag == 0 && FD_ISSET(sp->sock, &read_set)) {
          if (accept_new_connection(sp, ctx)) {
            call_user_over_ctx(ctx, 0, MG_RESTART_MASTER_BEGIN);
            // severe failure; unbind and rebind to listening sockets
            // in order to discard pending incoming connections:
            close_all_listening_sockets(ctx);
            do {
              // sleep to unload the CPU in case of very grave issues
              mg_sleep(MG_SELECT_TIMEOUT_MSECS);
              if (set_ports_option(ctx))
                break;
              // failed to rebind; retry after another bit of sleep
            } while (ctx->stop_flag == 0);
            call_user_over_ctx(ctx, 0, MG_RESTART_MASTER_END);
            break; // do NOT check the other (now invalid) listeners!
          }
        }
      }
    }
  }

  // fix: issue 345 for the master thread
  call_user_over_ctx(ctx, 0, MG_EXIT_MASTER);

  DEBUG_TRACE(~0, ("stopping workers"));

  // Stop signal received: somebody called mg_stop. Quit.
  close_all_listening_sockets(ctx);

  (void) pthread_mutex_lock(&ctx->mutex);
  // Wakeup workers that are waiting for connections to handle.
  pthread_cond_broadcast(&ctx->sq_full);

  // Wait until all threads finish
  while (ctx->num_threads > 1) {
    (void) pthread_cond_wait(&ctx->cond, &ctx->mutex);
  }

  // forcibly close all pending (accepted) sockets remaining in the queue:

  // If we're stopping, sq_head may be equal to sq_tail.
  while (ctx->sq_head >= 0) {
    // close socket from the queue and increment tail
    struct mg_connection dummy_conn = {0};
    ctx->sq_head = pop_node_from_idle_queue(ctx, ctx->sq_head, &dummy_conn);
    DEBUG_TRACE(0x0023, ("grabbed socket %d, forcibly closing the bugger", (int)dummy_conn.client.sock));
    close_socket_UNgracefully(dummy_conn.client.sock);
  }

  // Account for ourselves (master) being done and exiting
  ctx->num_threads--;
  MG_ASSERT(ctx->num_threads == 0);

  (void) pthread_mutex_unlock(&ctx->mutex);

  // All threads exited, no sync is needed. Destroy mutex and condvars
  (void) pthread_mutex_destroy(&ctx->mutex);
  (void) pthread_cond_destroy(&ctx->cond);
  (void) pthread_cond_destroy(&ctx->sq_empty);
  (void) pthread_cond_destroy(&ctx->sq_full);

#if !defined(NO_SSL)
  uninitialize_ssl(ctx);
#endif

  // fix: issue 345 for the master thread
  call_user_over_ctx(ctx, 0, MG_EXIT_SERVER);

  DEBUG_TRACE(~0, ("exiting"));

  // Signal mg_stop() that we're done; ctx will be invalid after this as main thread may finish mg_stop() at any time now
  ctx->stop_flag = 2;

  // WARNING: stop_flag = 2 MUST be the VERY LAST THING this thread does.
  //          any DEBUG_TRACE(), etc. after it will run past the moment in time
  //          when mg_stop() completes -- and that one destroys all the
  //          mutexes so writing DEBUG_TRACE() right here would cause a random
  //          crash due to race conditions.
  pthread_exit(0);
  return 0;
}

static void free_context(struct mg_context *ctx) {
  int i;

  // Deallocate config parameters
  for (i = 0; i < NUM_OPTIONS; i++) {
    if (ctx->config[i] != NULL)
      free(ctx->config[i]);
  }

  // Deallocate SSL context
  if (ctx->ssl_ctx != NULL) {
    SSL_CTX_free(ctx->ssl_ctx);
  }
  if (ctx->client_ssl_ctx != NULL) {
    SSL_CTX_free(ctx->client_ssl_ctx);
  }
#ifndef NO_SSL
  if (ssl_mutexes != NULL) {
    free(ssl_mutexes);
    ssl_mutexes = NULL; // issue 361 fix
  }
#endif // !NO_SSL

  // Deallocate context itself
  free(ctx);
}

/*
May only be invoked from the main thread, i.e. none of the worker threads!

When you want to signal a FULL STOP condition from any of those, call
mg_signal_stop() instead.
*/
void mg_stop(struct mg_context *ctx) {
  if (!ctx)
    return;

  mg_signal_stop(ctx); // only set stop=1 when not set already!

  // Wait until master_thread() stops
  while (ctx->stop_flag != 2) {
    (void) mg_sleep(10);
  }

  MG_ASSERT(ctx->num_threads == 0);

  // call the user event handler to make sure the custom code is aware of this termination as well and do some final cleanup:
  call_user_over_ctx(ctx, ctx->ssl_ctx, MG_EXIT0);

  free_context(ctx);

#if defined(_WIN32) && !defined(__SYMBIAN32__)
  global_log_file_lock.active = 0;
  DeleteCriticalSection(&global_log_file_lock.lock);
  DeleteCriticalSection(&DisconnectExPtrCS);
  (void) WSACleanup();
#endif // _WIN32
}

struct mg_context *mg_start(const struct mg_user_class_t *user_functions,
                            const char **options) {
  struct mg_context *ctx;
  const char *name, *value, *default_value;
  int i;

#if defined(_WIN32) && !defined(__SYMBIAN32__)
  WSADATA data;
  WSAStartup(MAKEWORD(2,2), &data);
  InitializeCriticalSection(&global_log_file_lock.lock);
  global_log_file_lock.active = 1;
#if _WIN32_WINNT >= _WIN32_WINNT_NT4_SP3
  InitializeCriticalSectionAndSpinCount(&DisconnectExPtrCS, 1000);
#else
  InitializeCriticalSection(&DisconnectExPtrCS);
#endif
#endif // _WIN32

  // Allocate context and initialize reasonable general case defaults.
  ctx = (struct mg_context *) calloc(1, sizeof(*ctx));
  if (!ctx) return NULL;

  // init queue (free list)
  ctx->sq_head = -1;
  for (i = 0; i < (int)ARRAY_SIZE(ctx->queue_store) - 1; i++) {
    ctx->queue_store[i].next = i + 1;
  }
  ctx->queue_store[ARRAY_SIZE(ctx->queue_store) - 1].next = -1;
  ctx->idle_q_store_free_slot = 0;

  if (user_functions) {
    ctx->user_functions = *user_functions;
  }

  while (options && (name = *options++) != NULL) {
    value = *options++;
    if ((i = get_option_index(name)) == -1) {
      if (!call_user_option_decode(ctx, name, value)) {
        mg_cry(fc(ctx), "Invalid option: %s", name);
        free_context(ctx);
        return NULL;
      } else {
        DEBUG_TRACE(0x1000, ("[%s] -> [%s]", name, value));
        continue;
      }
    } else if (value == NULL) {
      mg_cry(fc(ctx), "%s: option value cannot be NULL", name);
      free_context(ctx);
      return NULL;
    }
    if (ctx->config[i] != NULL) {
      mg_cry(fc(ctx), "%s: duplicate option", name);
    }
    MG_ASSERT(i < (int)ARRAY_SIZE(ctx->config));
    MG_ASSERT(i >= 0);
    ctx->config[i] = mg_strdup(value);
    // at least on Windows, replace single quotes around CGI binary path
    // by double quotes or your CGI won't ever run.
    // And you can't easily put double quotes around it from the command line,
    // so kludge it is.
    if (i == CGI_INTERPRETER && value[0] == '\'') {
      char *qp = ctx->config[i];
      *qp++ = '"';
      qp = strchr(qp, '\'');
      if (!qp) {
        mg_cry(fc(ctx), "Invalid option value (improper quoting): %s=%s", name, value);
        free_context(ctx);
        return NULL;
      }
      *qp = '"';
    }
    DEBUG_TRACE(0x1000, ("[%s] -> [%s]", name, ctx->config[i]));
  }

  // Set default value if needed
  for (i = 0; config_options[i * MG_ENTRIES_PER_CONFIG_OPTION] != NULL; i++) {
    default_value = config_options[i * MG_ENTRIES_PER_CONFIG_OPTION + 2];
    if (ctx->config[i] == NULL && default_value != NULL) {
      ctx->config[i] = mg_strdup(default_value);
      DEBUG_TRACE(0x1000,
                  ("Setting default: [%s] -> [%s]",
                   config_options[i * MG_ENTRIES_PER_CONFIG_OPTION + 1],
                   default_value));
    }
  }
  if (!call_user_option_fill(ctx)) {
    free_context(ctx);
    return NULL;
  }

  // NOTE(lsm): order is important here. SSL certificates must
  // be initialized before listening ports. UID must be set last.
  if (!set_gpass_option(ctx) ||
#if !defined(NO_SSL)
      (ctx->config[SSL_CERTIFICATE] != NULL && !set_ssl_option(ctx)) ||
#endif
      !set_ports_option(ctx) ||
#if !defined(_WIN32)
      !set_uid_option(ctx) ||
#endif
      !set_acl_option(ctx)) {
    free_context(ctx);
    return NULL;
  }

#if !defined(_WIN32) && !defined(__SYMBIAN32__)
  // Ignore SIGPIPE signal, so if browser cancels the request, it
  // won't kill the whole process.
  (void) signal(SIGPIPE, SIG_IGN);
  // Also ignoring SIGCHLD to let the OS to reap zombies properly.
  (void) signal(SIGCHLD, SIG_IGN);
#endif // !_WIN32

  (void) pthread_mutex_init(&ctx->mutex, NULL);
  (void) pthread_cond_init(&ctx->cond, NULL);
  (void) pthread_cond_init(&ctx->sq_empty, NULL);
  (void) pthread_cond_init(&ctx->sq_full, NULL);

  call_user_over_ctx(ctx, ctx->ssl_ctx, MG_INIT0);

  // Start master (listening) thread
  if (mg_start_thread(ctx, (mg_thread_func_t) master_thread, ctx) != 0) {
    mg_cry(fc(ctx), "Cannot start master thread: %d (%s)", ERRNO, mg_strerror(ERRNO));
    free_context(ctx);
    return NULL;
  }

  // Start worker threads; always start at least one of those.
  i = atoi(get_option(ctx, NUM_THREADS));
  if (i < 1) i = 1;
  for ( ; i > 0; i--) {
    if (mg_start_thread(ctx, (mg_thread_func_t) worker_thread, ctx) != 0) {
      mg_cry(fc(ctx), "Cannot start worker thread: %d (%s)", ERRNO, mg_strerror(ERRNO));
    }
  }

  return ctx;
}


const char *mg_get_response_code_text(int response_code) {
  switch (response_code) {
  case 100:   return "Continue"; // RFC2616 Section 10.1.1:
  case 101:   return "Switching Protocols"; // RFC2616 Section 10.1.2:
  case 102:   return "Processing"; // WebDAV RFC2518
  case 200:   return "OK"; // RFC2616 Section 10.2.1:
  case 201:   return "Created"; // RFC2616 Section 10.2.2:
  case 202:   return "Accepted"; // RFC2616 Section 10.2.3:
  case 203:   return "Non-Authoritative Information"; // RFC2616 Section 10.2.4:
  case 204:   return "No Content"; // RFC2616 Section 10.2.5:
  case 205:   return "Reset Content"; // RFC2616 Section 10.2.6:
  case 206:   return "Partial Content"; // RFC2616 Section 10.2.7:
  case 207:   return "Multi-Status"; // WebDAV RFC4918
  case 208:   return "Already Reported"; // WebDAV RFC5842
  case 226:   return "IM Used"; // RFC3229
  case 300:   return "Multiple Choices"; // RFC2616 Section 10.3.1:
  case 301:   return "Moved Permanently"; // RFC2616 Section 10.3.2:
  case 302:   return "Found"; // RFC2616 Section 10.3.3:
  case 303:   return "See Other"; // RFC2616 Section 10.3.4:
  case 304:   return "Not Modified"; // RFC2616 Section 10.3.5:
  case 305:   return "Use Proxy"; // RFC2616 Section 10.3.6:
  case 307:   return "Temporary Redirect"; // RFC2616 Section 10.3.8:
  case 308:   return "Permanent Redirect";
  case 400:   return "Bad Request"; // RFC2616 Section 10.4.1:
  case 401:   return "Unauthorized"; // RFC2616 Section 10.4.2:
  case 402:   return "Payment Required"; // RFC2616 Section 10.4.3:
  case 403:   return "Forbidden"; // RFC2616 Section 10.4.4:
  case 404:   return "Not Found"; // RFC2616 Section 10.4.5:
  case 405:   return "Method Not Allowed"; // RFC2616 Section 10.4.6:
  case 406:   return "Not Acceptable"; // RFC2616 Section 10.4.7:
  case 407:   return "Proxy Authentication Required"; // RFC2616 Section 10.4.8:
  case 408:   return "Request Time-out"; // RFC2616 Section 10.4.9:
  case 409:   return "Conflict"; // RFC2616 Section 10.4.10:
  case 410:   return "Gone"; // RFC2616 Section 10.4.11:
  case 411:   return "Length Required"; // RFC2616 Section 10.4.12:
  case 412:   return "Precondition Failed"; // RFC2616 Section 10.4.13:
  case 413:   return "Request Entity Too Large"; // RFC2616 Section 10.4.14:
  case 414:   return "Request-URI Too Large"; // RFC2616 Section 10.4.15:
  case 415:   return "Unsupported Media Type"; // RFC2616 Section 10.4.16:
  case 416:   return "Requested range not satisfiable"; // RFC2616 Section 10.4.17:
  case 417:   return "Expectation Failed"; // RFC2616 Section 10.4.18:
  case 420:   return "Enhance Your Calm"; // Twitter rate limiting
  case 422:   return "Unprocessable Entity"; // WebDAV RFC4918
  case 423:   return "Locked"; // WebDAV RFC4918
  case 424:   return "Failed Dependency"; // WebDAV RFC4918
  case 425:   return "Unordered Collection"; // WebDAV RFC4918
  case 426:   return "Upgrade Required"; // RFC2817
  case 428:   return "Precondition Required"; // RFC6585
  case 429:   return "Too Many Requests"; // RFC6585
  case 431:   return "Request Headers Field Too Large"; // RFC6585
  case 500:   return "Internal Server Error"; // RFC2616 Section 10.5.1:
  case 501:   return "Not Implemented"; // RFC2616 Section 10.5.2:
  case 502:   return "Bad Gateway"; // RFC2616 Section 10.5.3:
  case 503:   return "Service Unavailable"; // RFC2616 Section 10.5.4:
  case 504:   return "Gateway Time-out"; // RFC2616 Section 10.5.5:
  case 505:   return "HTTP Version not supported"; // RFC2616 Section 10.5.6:
  case 506:   return "Variant Also Negotiates"; // RFC2295
  case 507:   return "Insufficient Storage"; // WebDAV RFC4918
  case 508:   return "Loop Detected"; // WebDAV RFC5842
  case 510:   return "Not Extended"; // RFC2774
  case 511:   return "Network Authentication Required"; // RFC6585
/*
  case 418:   return "I'm a teapot";
  case 419:   return "unused";
  case 421:   return "unused";
  case 508:   return "unused";
  case 509:   return "unused";
*/
  case 577:   return "Mongoose Internal Server Error";
  case 578:   return "Mongoose Internal Server Error: file I/O";
  case 579:   return "Mongoose Internal Server Error: socket I/O";
  case 580:   return "Mongoose Internal Server Error or client closed connection prematurely";

  default:    return "Unknown Response Code";
  }
}

struct mg_user_class_t *mg_get_user_data(struct mg_context *ctx) {
  return ctx ? &ctx->user_functions : NULL;
}

void *mg_get_request_user_data(struct mg_connection *conn) {
  if (conn) {
    return conn->request_info.req_user_data;
  }
  return NULL;
}

void mg_set_request_user_data(struct mg_connection *conn, void *user_data) {
  if (conn) {
    conn->request_info.req_user_data = user_data;
  }
}

void mg_set_http_version(struct mg_connection *conn, const char *http_version_str) {
  if (conn) {
    conn->request_info.http_version = (is_empty(http_version_str) ? "1.1" : http_version_str);
  }
}

struct mg_context *mg_get_context(struct mg_connection *conn) {
  return conn ? conn->ctx : NULL;
}

const char *mg_suggest_connection_header(struct mg_connection *conn) {
  return suggest_connection_header(conn);
}

void mg_connection_must_close(struct mg_connection *conn) {
  conn->must_close = 1;
}

void mg_send_http_error(struct mg_connection *conn, int status, const char *reason, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vsend_http_error(conn, status, reason, fmt, ap);
  va_end(ap);
}

void mg_vsend_http_error(struct mg_connection *conn, int status, const char *reason, const char *fmt, va_list ap) {
  vsend_http_error(conn, status, reason, fmt, ap);
}

int mg_get_stop_flag(struct mg_context *ctx) {
  return ctx && ctx->stop_flag;
}

void mg_signal_stop(struct mg_context *ctx) {
  if (ctx->stop_flag == 0)
    ctx->stop_flag = 1;
}


void mg_set_tx_mode(struct mg_connection *conn, mg_iomode_t mode) {
  if (conn) {
    conn->tx_is_in_chunked_mode = (mode >= MG_IOMODE_CHUNKED_DATA);
    conn->tx_remaining_chunksize = 0;
    conn->tx_next_chunksize = 0;
    conn->tx_chunk_header_sent = 0;
    conn->tx_chunk_count = 0;
  }
}

mg_iomode_t mg_get_tx_mode(struct mg_connection *conn) {
  if (conn) {
    return conn->tx_is_in_chunked_mode ?
            conn->tx_chunk_header_sent != 1 ?
              MG_IOMODE_CHUNKED_HEADER :
              MG_IOMODE_CHUNKED_DATA :
            MG_IOMODE_STANDARD;
  }
  return MG_IOMODE_UNKNOWN;
}

int mg_get_tx_chunk_no(struct mg_connection *conn) {
  if (conn && conn->tx_is_in_chunked_mode) {
    return conn->tx_chunk_count;
  }
  return -1;
}

int64_t mg_get_tx_remaining_chunk_size(struct mg_connection *conn) {
  if (conn && conn->tx_is_in_chunked_mode) {
    return conn->tx_remaining_chunksize;
  }
  return -1;
}

int mg_set_tx_next_chunk_size(struct mg_connection *conn, int64_t chunk_size) {
  if (conn && conn->tx_is_in_chunked_mode && chunk_size >= 0) {
    // chunk_size == 0 POSSIBLY marks the end of chunked transmission:
    // out of mg_write()), mg_flush() and mg_close(), the first one called
    // will determine the exact behaviour:
    // when mg_flush() or mg_close() are next, they will write the final
    // chunk header (sentinel) then, while mg_write() would
    // 'expand' the chunk size to the number of data bytes sent through
    // the mg_write() call.
    // This process flow is designed to facilitate simple user code like
    //
    //   mg_set_tx_next_chunk_size(conn, 0);
    //   // oh! forgot to write something!
    //   mg_write/mg_printf(conn, "bla bla"); -- one more chunk, size = 7
    //   mg_set_tx_next_chunk_size(conn, 0);
    //   // this time it's End All, Good All:
    //   mg_flush(conn, 0);  -- we want to persist the connection, so we don't mg_close() here instead.
    //
    conn->tx_next_chunksize = chunk_size;
    return (conn->tx_remaining_chunksize > 0);
  }
  return -1;
}


int mg_flush(struct mg_connection *conn) {
  if (conn) {
    // nothing to do unless we're in TX chunked mode
    // and chunk_size == 0 while the chunk header hasn't been
    // sent yet. This marks the end of a chunked transmission.
    if (conn->tx_is_in_chunked_mode) {
        if (conn->tx_chunk_header_sent == 0 &&
            conn->tx_remaining_chunksize == 0) {
          // prep and transmit a SENTINEL 'chunk header'
          return mg_write_chunk_header(conn, 0);
        }
        return !(conn->tx_chunk_header_sent == 1 &&
                 conn->tx_remaining_chunksize == 0);
    }
    return 0;
  }
  return -1;
}



void mg_set_rx_mode(struct mg_connection *conn, mg_iomode_t mode) {
  if (conn) {
    conn->rx_is_in_chunked_mode = (mode >= MG_IOMODE_CHUNKED_DATA);
    conn->rx_remaining_chunksize = 0;
    conn->rx_chunk_count = 0;
  }
}

mg_iomode_t mg_get_rx_mode(struct mg_connection *conn) {
  if (conn) {
    return conn->rx_is_in_chunked_mode ?
            conn->rx_chunk_header_parsed != 1 ?
              MG_IOMODE_CHUNKED_HEADER :
              MG_IOMODE_CHUNKED_DATA :
            MG_IOMODE_STANDARD;
  }
  return MG_IOMODE_UNKNOWN;
}

int mg_get_rx_chunk_no(struct mg_connection *conn) {
  if (conn && conn->rx_is_in_chunked_mode) {
    return conn->rx_chunk_count;
  }
  return -1;
}

int64_t mg_get_rx_remaining_chunk_size(struct mg_connection *conn) {
  if (conn && conn->rx_is_in_chunked_mode) {
    return conn->rx_remaining_chunksize;
  }
  return -1;
}

int mg_set_rx_chunk_size(struct mg_connection *conn, int64_t chunk_size) {
  if (conn && conn->rx_is_in_chunked_mode && chunk_size >= 0) {
    if (conn->rx_remaining_chunksize > 0) {
      return 1;
    }
    // chunk_size == 0 marks end of chunked transmission: the next
    // mg_read() should fetch and parse the sentinel chunk header then.
    conn->rx_remaining_chunksize = chunk_size;
    conn->rx_chunk_header_parsed = 1;
    return 0;
  }
  return -1;
}

int mg_write_chunk_header(struct mg_connection *conn, int64_t chunk_size) {
  if (!conn->buf_size) // mg_connect() creates connections without header buffer space
    return -1;

  if (conn && conn->tx_is_in_chunked_mode && chunk_size >= 0) {
    char buf[CHUNK_HEADER_BUFSIZ];
    char *d;

    // report special error code when calling us repeatedly or in re-entrant fashion:
    if (conn->tx_chunk_header_sent != 0)
      return 1 + conn->tx_chunk_header_sent;

    // reset the 'next chunk size' first thing, so that the user callback MAY update it for the NEXT chunk:
    conn->tx_next_chunksize = 0;

    // switch to 'header TX mode' to cajole mg_write() et al into writing straight through.
    conn->tx_chunk_header_sent = 2;

    // No matter which protocol the user callback will be doing, we'll prep the buffer for the
    // first bit of a HTTP/1.1 chunk header; it's low cost and that way the callback can write
    // any HTTP/1.1 header extensions directly to our write buffer when it wants to do that.
    d = buf;

    // HTTP/1.1 chunking it is. Four scenarios to account for:
    // 1) initial chunk (~ dump hex size + extras, CRLF and go: data)
    // 2) subsequent chunks (~ write final CRLF, then as (1))
    // 3) sentinel ('zero') chunk (~ write final CRLF, then write 0 + extras, trailer, last CRLF and we're done)
    // 4) sentinel ('zero') chunk which is also the very first chunk: no data at all. (~ like (3) but without the CRLF)
    //
    // --> write CRLF when we're terminating a previous chunk:
    if (conn->tx_chunk_count > 0) {
      *d++ = 13;
      *d++ = 10;
    }
    // write basic chunk header plus header extension prefix all at once:
    d += mg_snq0printf(conn, d, sizeof(buf) - 3, "%" PRIx64 ";", chunk_size);

    // user callback anyone?
    *d = 0;
    if (conn->ctx->user_functions.write_chunk_header != NULL) {
      int rv = conn->ctx->user_functions.write_chunk_header(conn, chunk_size, buf, sizeof(buf) - 4, d);
      // do we fall back to the default (HTTP 1.1 chunking) or are we done?
      if (rv != 0) {
        // make sure we reset the state first and update the counters
        if (conn->tx_chunk_header_sent == 2)
          conn->tx_chunk_header_sent = 1;
        if (rv >= 0) {
          conn->tx_chunk_count++;
          rv = 0;
        }
        return rv;
      }

      // do we need to write chunk extensions? If so, then they were produced by the user callback,
      // otherwise we wind back to a basic chunk header, as HTTP/1.1 chunked transfer it is when we get here.
      if (!*d) {
        // undo that ';' up there
        --d;
      } else {
        d += strlen(d);
      }
    }

    *d++ = 13;
    *d++ = 10;
    // if we're writing the sentinel chunk, we should dump all changed/added headers in the 'trailer':
    if (chunk_size == 0) {
      int n = conn->request_info.num_response_headers;
      int i;

      for (i = 0; i < n; i++) {
        struct mg_header *h = conn->request_info.response_headers + i;
        int n_l = (int)strlen(h->name), v_l;

        // Was this tag edited/added after we had all headers written in the HTTP response header?
        // If yes, dump it in the trailer block!
        if (h->name[n_l + 1] == '!') {
          int wl = (int)(d - buf);
          int buflen_rem = (int)sizeof(buf) - 7 /* [: ]+[\r\n]+[\r\n]+NUL */ - wl;

          v_l = (int)strlen(h->value);
          if (buflen_rem >= n_l + v_l) {
            d += mg_snq0printf(conn, d, sizeof(buf) - wl, "%s: %s\r\n", h->name, h->value);
          } else {
            DEBUG_TRACE(0x0008, ("buffer overflow while writing sentinel chunk trailer; writing headers collected so far"));
            MG_ASSERT(conn->tx_chunk_header_sent == 2);
            if (wl == 0 || wl != mg_write(conn, buf, wl))
              goto fail_dramatically;

            // risk: tag:value may not fit buffer in extreme case, so we write it directly, to make sure:
            if (n_l + v_l + 4 != mg_printf(conn, "%s: %s\r\n", h->name, h->value))
              goto fail_dramatically;
            d = buf;
          }
        }
      }
      if (d + 2 >= buf + sizeof(buf)) {
        mg_cry(conn, "%s: buffer overflow while writing sentinel chunk trailer", __func__);
        goto fail_dramatically;
      }
      // and the final CRLF after the (possibly empty) trailer:
      *d++ = 13;
      *d++ = 10;
    }

    MG_ASSERT(conn->tx_chunk_header_sent == 2);
    MG_ASSERT((d - buf) >= 2);
    if ((d - buf) != mg_write(conn, buf, (d - buf)))
      goto fail_dramatically;

    // make sure we reset the state first and update the counters
    if (conn->tx_chunk_header_sent == 2)
      conn->tx_chunk_header_sent = 1;
    conn->tx_chunk_count++;
    conn->tx_remaining_chunksize = chunk_size;
    return 0;

fail_dramatically:
    // make sure we reset the state first
    if (conn->tx_chunk_header_sent == 2)
      conn->tx_chunk_header_sent = 1;
  }
  return -1;
}

int mg_is_read_data_available(struct mg_connection *conn) {
  if (conn) {
    // do we already know whether there's incoming data pending?
    if (conn->client.was_idle && conn->client.has_read_data) {
      return +1;
    } else if (conn->ssl) {
      char buf[16];
      int l = SSL_peek(conn->ssl, buf, sizeof(buf));
      int rv = ssl_renegotiation_ongoing(conn, &l);
      if (l > 0 || (l == 0 && rv == 0) /* session termination signaled */) {
        conn->client.was_idle = 1;
        conn->client.has_read_data = 1;
        return +1;
      }
    } else {
      int sn;
      struct timeval tv = {0};
      fd_set fdr;
      int max_fh = 0;
      FD_ZERO(&fdr);
      add_to_set(conn->client.sock, &fdr, &max_fh);
      // waste no time on this check...
      //tv.tv_sec = 0;
      //tv.tv_usec = MG_SELECT_TIMEOUT_MSECS * 1000;
      sn = select(max_fh + 1, &fdr, NULL, NULL, &tv);
      if (sn > 0) {
        MG_ASSERT(FD_ISSET(conn->client.sock, &fdr));
        conn->client.was_idle = 1;
        conn->client.has_read_data = 1;
        return +1;
      }
    }
  }
  return 0;
}


int mg_match_string(const char *pattern, int pattern_len, const char *str) {
  if (!str || !pattern)
    return -1;

  return match_string(pattern, pattern_len, str);
}

time_t mg_parse_date_string(const char *datetime) {
  if (!datetime)
    return (time_t)0;

  return parse_date_string(datetime);
}

void mg_gmt_time_string(char *buf, size_t bufsize, const time_t *tm) {
  gmt_time_string(buf, bufsize, tm);
}




#ifdef MG_SIGNAL_ASSERT
int mg_signal_assert(const char *expr, const char *filepath, unsigned int lineno) {
	fprintf(stderr, "[assert] assertion failed: \"%s\" (%s @ line %u)\n", expr, filepath, lineno);

	// Also write the assertion failure to the logfile, iff we're able to...
	struct mg_connection *conn = fc(NULL);
	if (conn) {
		const char *logfile = mg_get_default_error_logfile_path(conn);
		if (logfile) {
			FILE *fp = mg_fopen(logfile, "a+");
			if (fp != NULL) {
				flockfile(fp);
				fprintf(fp, "[assert] assertion failed: \"%s\" (%s @ line %u)\n", expr, filepath, lineno);
				fflush(fp);
				funlockfile(fp);
				mg_fclose(fp);
			}
		}

		// Assertion failures are fatal: attempt to abort/stop the server in a sane manner immediately:
		mg_signal_stop(conn->ctx);
	}
	return 1;
}
#endif
