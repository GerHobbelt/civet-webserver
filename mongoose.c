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


#include "mongoose.h"



#define MONGOOSE_VERSION "3.2"
#define PASSWORDS_FILE_NAME ".htpasswd"
#define CGI_ENVIRONMENT_SIZE 4096
#define MAX_CGI_ENVIR_VARS 64


// The maximum amount of data we're willing to dump in a single mg_cry() log call.
// In embedded environments with limited RAM, you may want to override this
// value as this value determines the malloc() size used inside mg_vasprintf().
#ifndef MG_MAX_LOG_LINE_SIZE
#define MG_MAX_LOG_LINE_SIZE    1024 * 1024
#endif

// The number of msecs to wait inside select() when there's nothing to do.
#ifndef MG_SELECT_TIMEOUT_MSECS
#define MG_SELECT_TIMEOUT_MSECS 200
#endif


#if defined(_WIN32)

int mgW32_get_errno(void) {
  DWORD e1 = GetLastError();
  DWORD e2 = WSAGetLastError();
  int e3 = errno;

  return (e2 ? e2 : e1 ? e1 : e3);
}

static CRITICAL_SECTION global_log_file_lock;

void mgW32_flockfile(UNUSED_PARAMETER(FILE *unused)) {
  EnterCriticalSection(&global_log_file_lock);
}

void mgW32_funlockfile(UNUSED_PARAMETER(FILE *unused)) {
  LeaveCriticalSection(&global_log_file_lock);
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
    LPFN_DISCONNECTEX DisconnectExPtr = 0;
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



#if !defined(NO_SSL)

// Snatched from OpenSSL includes. I put the prototypes here to be independent
// from the OpenSSL source installation. Having this, mongoose + SSL can be
// built on any system with binary SSL libraries installed.
typedef struct ssl_st SSL;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_ctx_st SSL_CTX;

#define SSL_ERROR_WANT_READ 2
#define SSL_ERROR_WANT_WRITE 3
#define SSL_FILETYPE_PEM 1
#define CRYPTO_LOCK  1

#if defined(NO_SSL_DL)
extern void SSL_free(SSL *);
extern int SSL_accept(SSL *);
extern int SSL_connect(SSL *);
extern int SSL_shutdown(SSL *);
extern int SSL_read(SSL *, void *, int);
extern int SSL_write(SSL *, const void *, int);
extern int SSL_get_error(const SSL *, int);
extern int SSL_set_fd(SSL *, int);
extern SSL *SSL_new(SSL_CTX *);
extern SSL_CTX *SSL_CTX_new(SSL_METHOD *);
extern SSL_METHOD *SSLv23_server_method(void);
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
#define SSL_get_error (* (int (*)(SSL *, int)) ssl_sw[6].ptr)
#define SSL_set_fd (* (int (*)(SSL *, SOCKET)) ssl_sw[7].ptr)
#define SSL_new (* (SSL * (*)(SSL_CTX *)) ssl_sw[8].ptr)
#define SSL_CTX_new (* (SSL_CTX * (*)(SSL_METHOD *)) ssl_sw[9].ptr)
#define SSLv23_server_method (* (SSL_METHOD * (*)(void)) ssl_sw[10].ptr)
#define SSL_library_init (* (int (*)(void)) ssl_sw[11].ptr)
#define SSL_CTX_use_PrivateKey_file (* (int (*)(SSL_CTX *, \
        const char *, int)) ssl_sw[12].ptr)
#define SSL_CTX_use_certificate_file (* (int (*)(SSL_CTX *, \
        const char *, int)) ssl_sw[13].ptr)
#define SSL_CTX_set_default_passwd_cb \
  (* (void (*)(SSL_CTX *, mg_callback_t)) ssl_sw[14].ptr)
#define SSL_CTX_free (* (void (*)(SSL_CTX *)) ssl_sw[15].ptr)
#define SSL_load_error_strings (* (void (*)(void)) ssl_sw[16].ptr)
#define SSL_CTX_use_certificate_chain_file \
  (* (int (*)(SSL_CTX *, const char *)) ssl_sw[17].ptr)

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
  struct socket *next;          // Linkage
  SOCKET sock;                  // Listening socket
  struct usa lsa;               // Local socket address
  struct usa rsa;               // Remote socket address
  int max_idle_seconds;         // 'keep alive' timeout (used while monitoring the idle queue, used together with the recv()-oriented SO_RCVTIMEO, etc. socket options), 0 is infinity.
  unsigned is_ssl: 1;           // Is socket SSL-ed
  unsigned read_error: 1;       // Receive error occurred on this socket (recv())
  unsigned write_error: 1;      // Write error occurred on this socket (send())
  unsigned has_read_data: 1;    // 1 when active ~ when read data is available. This is used to 'signal' a node when a idle-test select() turns up multiple active nodes at once. (speedup)
  unsigned was_idle: 1;         // 1 when a socket has been pulled from the 'idle queue' just now: '1' means 'has_read_data' is valid (and can be used instead of select()).
  unsigned idle_time_expired: 1; // 1 when the idle time (max_idle_seconds) has expired
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
  unsigned is_inited: 1;

  // book-keeping:
  int next;                         // next in chain; cyclic linked list!
  int prev;                         // previous in chain; cyclic linked list!
};


typedef enum {
  CGI_EXTENSIONS, CGI_ENVIRONMENT, PUT_DELETE_PASSWORDS_FILE, CGI_INTERPRETER,
  PROTECT_URI, AUTHENTICATION_DOMAIN, SSI_EXTENSIONS, SSI_MARKER, ERROR_FILE, ACCESS_LOG_FILE,
  SSL_CHAIN_FILE, ENABLE_DIRECTORY_LISTING, ERROR_LOG_FILE,
  GLOBAL_PASSWORDS_FILE, INDEX_FILES,
  ENABLE_KEEP_ALIVE, KEEP_ALIVE_TIMEOUT, SOCKET_LINGER_TIMEOUT, ACCESS_CONTROL_LIST, MAX_REQUEST_SIZE,
  EXTRA_MIME_TYPES, LISTENING_PORTS,
  DOCUMENT_ROOT, SSL_CERTIFICATE, NUM_THREADS, RUN_AS_USER, REWRITE,
  NUM_OPTIONS
} mg_option_index_t;

static const char *config_options[(NUM_OPTIONS + 1/* sentinel*/) * MG_ENTRIES_PER_CONFIG_OPTION] = {
  "C", "cgi_pattern",                   "**.cgi$|**.pl$|**.php$",
  "E", "cgi_environment",               NULL,
  "G", "put_delete_passwords_file",     NULL,
  "I", "cgi_interpreter",               NULL,
  "P", "protect_uri",                   NULL,
  "R", "authentication_domain",         "mydomain.com",
  "S", "ssi_pattern",                   "**.shtml$|**.shtm$",
  "",  "ssi_marker",                    NULL,
  "Z", "error_file",                    "404=/error/404.shtml,0=/error/error.shtml",
  "a", "access_log_file",               NULL,
  "c", "ssl_chain_file",                NULL,
  "d", "enable_directory_listing",      "yes",
  "e", "error_log_file",                NULL,
  "g", "global_passwords_file",         NULL,
  "i", "index_files",                   "index.html,index.htm,index.cgi,index.shtml,index.php",
  "k", "enable_keep_alive",             "yes",
  "K", "keep_alive_timeout",            "5",
  "L", "socket_linger_timeout",         "5",
  "l", "access_control_list",           NULL,
  "M", "max_request_size",              "16384",
  "m", "extra_mime_types",              NULL,
  "p", "listening_ports",               "8080",
  "r", "document_root",                 ".",
  "s", "ssl_certificate",               NULL,
  "t", "num_threads",                   "10",
  "u", "run_as_user",                   NULL,
  "w", "url_rewrite_patterns",          NULL,
  NULL, NULL, NULL
};

struct mg_context {
  volatile int stop_flag;     // Should we stop event loop
  SSL_CTX *ssl_ctx;           // SSL context
  char *config[NUM_OPTIONS];  // Mongoose configuration parameters
  struct mg_user_class_t user_functions; // user-defined callbacks and data

  struct socket *listening_sockets;

  volatile int num_threads;   // Number of threads
  pthread_mutex_t mutex;      // Protects (max|num)_threads
  pthread_cond_t  cond;       // Condvar for tracking workers terminations


  struct mg_idle_connection queue_store[128]; // Cut down on malloc()/free()ing cost by using a static queue.
  volatile int sq_head;       // Index to first node of cyclic linked list of 'pushed back' sockets which expect to serve more requests but are currently inactive. '-1' ~ empty!
  int idle_q_store_free_slot; // index into the idle_queue_store[] where scanning for a free slot should start. Single linked list on '.next'.

  pthread_cond_t sq_full;     // Signaled when socket is produced
  pthread_cond_t sq_empty;    // Signaled when socket is consumed
};

struct mg_connection {
  unsigned must_close: 1;     // 1 if connection must be closed
  unsigned is_inited: 1;      // 1 when the connection been completely set up (SSL, local and remote peer info, ...)
  int nested_err_or_pagereq_count;     // 1 when we're requesting an error page; > 1 when the error page request is failing (nested errors)
  struct mg_request_info request_info;
  struct mg_context *ctx;
  SSL *ssl;                   // SSL descriptor
  struct socket client;       // Connected client
  time_t birth_time;          // Time when connection was accepted
  int64_t num_bytes_sent;     // Total bytes sent to client; negative number is the amount of header bytes sent; positive number is the amount of data bytes
  int64_t content_len;        // received Content-Length header value
  int64_t consumed_content;   // How many bytes of content is already read
  char *buf;                  // Buffer for received data
  int buf_size;               // Buffer size for received data / same buffer size is also used for transmitting data (response headers)
  int request_len;            // Size of the request + headers in buffer buf[]
  int data_len;               // Total size of received data in buffer buf[]

  int tx_headers_len;         // Size of the response headers in buffer buf[]
  int tx_can_compact;         // signal whether a 'compact' operation would have any effect at all

  char error_logfile_path[PATH_MAX+1]; // cached value: path to the error logfile designated to this connection/CTX
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
  assert(index >= 0 && index < NUM_OPTIONS);
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
  assert(index >= 0 && index < NUM_OPTIONS);
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
  strncpy(buf, inet_ntoa(usa->u.sin.sin_addr), len);
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
  if (fake_connection.birth_time == 0) {
    fake_connection.birth_time = time(NULL);
  }
  return &fake_connection;
}

// replace %[P] with client port number
//         %[C] with client IP (sanitized for filesystem paths)
//         %[p] with server port number
//         %[s] with server IP (sanitized for filesystem paths)
//         %[U] with the request URI path section (sanitized for filesystem paths and limited to 64 characters max. (+ 8 characters URL hash))
//         %[Q] with the request URI query section (sanitized for filesystem paths and limited to 64 characters max. (+ 8 characters query hash))
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
      if (s[1] == '[' && s[2] && s[3] == ']') {
        size_t len = PATH_MAX - (d - fnbuf); // assert(len > 0);
        const char *u = NULL;
        // enough space for all: ntoa() output, URL path and it's limited-length copy + MD5 hash at the end:
        //char addr_buf[MAX(MAX(64+32-8+1, SOCKADDR_NTOA_BUFSIZE), PATH_MAX)];
        char addr_buf[PATH_MAX];
        char *old_d = d;

        *d = 0;
        switch (s[2]) {
        case 'P':
          if (conn) {
            unsigned short int port = get_socket_port(&conn->client.rsa);

            if (port != 0) {
              (void)mg_snprintf(conn, d, len, "%u", (unsigned int)port);
              d += strlen(d);
            }
          }
          goto replacement_done;

        case 'C':
          if (conn) {
            sockaddr_to_string(addr_buf, sizeof(addr_buf), &conn->client.rsa);

            if (addr_buf[0]) {
              u = addr_buf;
              goto copy_partial2dst;
            }
          }
          goto replacement_done;

        case 'p':
          if (conn) {
            unsigned short int port = get_socket_port(&conn->client.lsa);

            if (port != 0) {
              (void)mg_snprintf(conn, d, len, "%u", (unsigned int)port);
              d += strlen(d);
            }
          }
          goto replacement_done;

        case 's':
          if (conn) {
            sockaddr_to_string(addr_buf, sizeof(addr_buf), &conn->client.lsa);

            if (addr_buf[0]) {
              u = addr_buf;
              goto copy_partial2dst;
            }
          }
          goto replacement_done;

        case 'U':
        case 'Q':
          // filter URI so the result is a valid filepath piece without any format codes (so % is transformed to %% here as well!)
          if (conn && conn->request_info.uri) {
            const char *q;

            u = conn->request_info.uri;
            q = strchr(u, '?');
            if (s[2] == 'Q') {
              if (!q) {
                // empty query section: replace as empty string.
                q = "";
              }
              u = q + 1;
              q = NULL;
            }
            // limit the length to process:
            strncpy(addr_buf, u, sizeof(addr_buf));
            addr_buf[sizeof(addr_buf) - 1] = 0;
            if (q && q - u < sizeof(addr_buf)) {
              addr_buf[q - u] = 0;
            }
            // limit the string inserted into the filepath template to 64 characters:
            mg_md5(addr_buf + 64 - 8, addr_buf, NULL);
            addr_buf[64] = 0;
            u = addr_buf;
            goto copy_partial2dst;
          }
          goto replacement_done;

copy_partial2dst:
          if (len > 0 && u) {
            // anticipate the occurrence of a '%' in here: that one gets expended to '%%' so we keep an extra slot for that second '%' in the condition:
            for ( ; d - fnbuf < PATH_MAX - 1; u++) {
              switch (*u) {
              case 0:
                break;

              case '%':
                *d++ = '%';
                *d++ = '%';
                continue;

              case ':':
              case '/':
              case '.':
                // don't allow output sequences with multiple dots following one another,
                // nor do we allow a dot at the start or end of the produced part (which would
                // possibly generate hidden files/dirs and file create issues on some
                // OS/storage formats):
                if (d > fnbuf && !strchr(":\\/.", d[-1])) {
                  *d++ = '.';
                }
                continue;

              default:
                // be very conservative in our estimate what your filesystem will tolerate as valid characters in a filename:
                if (strchr("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-", *u)) {
                  *d++ = *u;
                  continue;
                }
                *d++ = '_';
                continue;
              }
              break;
            }

            // make sure there's no '.' dot at the very end to prevent file create issues on some platforms:
            if (d != old_d && d[-1] == '.')
              d--;
          }
replacement_done:
          // and the %[?] macros ALWAYS produce at least ONE character output in the template,
          // otherwise you get screwed up paths with, f.e. 'a/%[Q]/b' --> 'a//b':
          if (d == old_d && d - fnbuf < PATH_MAX)
            *d++ = '_';

          s += 4;
          continue;

        default:
          // illegal format code: keep as is, but add another % to make a literal code:
          if (len >= 2) {
            *d++ = '%';
            *d++ = '%';
          }
          s++;
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
  if (!strchr(fmt, '%'))
  {
    return (int)mg_strlcpy(buf, fmt, buflen);
  }
  else if (!strcmp(fmt, "%s"))
  {
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
  int size = BUFSIZ;
  char *buf = (char *)malloc(size);

  if (buf == NULL) {
    *buf_ref = NULL;
    return 0;
  }

  if (max_buflen == 0 || max_buflen > INT_MAX) {
    max_buflen = INT_MAX;
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
    strcpy(buf + size - 1 - 7, " (...)\n"); // mark the string as clipped
    //n = size - 1;
    //buf[n] = '\0';
    n = (int)strlen(buf);
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

// Skip the characters until one of the delimiters characters found.
// 0-terminate resulting word. Skip the delimiter and following whitespace if any.
// Advance pointer to buffer to the next word. Return found 0-terminated word.
// Delimiters can be quoted with quotechar.
static char *skip_quoted(char **buf, const char *delimiters, const char *whitespace, char quotechar) {
  char *p, *begin_word, *end_word, *end_whitespace;

  begin_word = *buf;
  end_word = begin_word + strcspn(begin_word, delimiters);

  // Check for quotechar
  if (end_word > begin_word) {
    p = end_word - 1;
    while (*p == quotechar) {
      // If there is anything beyond end_word, copy it
      if (*end_word == '\0') {
        *p = '\0';
        break;
      } else {
        size_t end_off = strcspn(end_word + 1, delimiters);
        memmove (p, end_word, end_off + 1);
        p += end_off; // p must correspond to end_word - 1
        end_word += end_off + 1;
      }
    }
    for (p++; p < end_word; p++) {
      *p = '\0';
    }
  }

  if (*end_word == '\0') {
    *buf = end_word;
  } else {
    end_whitespace = end_word + 1 + strspn(end_word + 1, whitespace);

    for (p = end_word; p < end_whitespace; p++) {
      *p = '\0';
    }

    *buf = end_whitespace;
  }

  return begin_word;
}

// Simplified version of skip_quoted without quote char
// and whitespace == delimiters
static char *skip(char **buf, const char *delimiters) {
  return skip_quoted(buf, delimiters, delimiters, 0);
}


// Return HTTP header value, or NULL if not found.
static const char *get_header(const struct mg_request_info *ri,
                              const char *name) {
  int i;

  for (i = 0; i < ri->num_headers; i++)
    if (!mg_strcasecmp(name, ri->http_headers[i].name))
      return ri->http_headers[i].value;

  return NULL;
}

const char *mg_get_header(const struct mg_connection *conn, const char *name) {
  return get_header(&conn->request_info, name);
}

// A helper function for traversing comma separated list of values.
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
    if (eq_val) {
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

static int match_prefix(const char *pattern, int pattern_len, const char *str) {
  const char *or_str;
  int i, j, len, res;

  if (pattern_len == -1)
    pattern_len = (int)strlen(pattern);
  if ((or_str = (const char *) memchr(pattern, '|', pattern_len)) != NULL) {
    res = match_prefix(pattern, or_str - pattern, str);
    return res > 0 ? res :
        match_prefix(or_str + 1, (pattern + pattern_len) - (or_str + 1), str);
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
        res = match_prefix(pattern + i, pattern_len - i, str + j + len);
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
    assert(old_series >= 1);
    assert(series >= 1);
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
  const char *header = mg_get_header(conn, "Connection");

  DEBUG_TRACE(("must_close: %d, status: %d, legal: %d, keep-alive: %s, header: %s / ver: %s, stop: %d\n",
               (int)conn->must_close,
               (int)conn->request_info.status_code,
               (int)is_legal_response_code(conn->request_info.status_code),
               get_conn_option(conn, ENABLE_KEEP_ALIVE),
               header, http_version,
               mg_get_stop_flag(conn->ctx)));

  return (!conn->must_close &&
          conn->request_info.status_code != 401 &&
          // only okay persistence when we see legal response codes;
          // anything else means we're foobarred ourselves already,
          // so it's time to close and let them retry.
          conn->request_info.status_code < 500 &&
          is_legal_response_code(conn->request_info.status_code) &&
          !mg_strcasecmp(get_conn_option(conn, ENABLE_KEEP_ALIVE), "yes") &&
          (header == NULL ?
           (http_version && !strcmp(http_version, "1.1")) :
           !mg_strcasecmp(header, "keep-alive")) &&
          mg_get_stop_flag(conn->ctx) == 0);
}

static const char *suggest_connection_header(struct mg_connection *conn) {
  DEBUG_TRACE(("suggest_connection_header() --> %s\n", should_keep_alive(conn) ? "keep-alive" : "close"));
  return should_keep_alive(conn) ? "keep-alive" : "close";
}

// Return negative value on error; otherwise number of bytes saved by compacting.
static int compact_tx_headers(struct mg_connection *conn) {
  char *scratch;
  int i, n;
  int space;
  struct mg_header hdrs[ARRAY_SIZE(conn->request_info.response_headers)];

  if (!conn->buf_size) // mg_connect() creates connections without header buffer space
    return -1;

  if (!conn->tx_can_compact)
    return 0;

  scratch = conn->buf + 2 * conn->buf_size;
  space = conn->buf_size;

  memcpy(hdrs, conn->request_info.response_headers, sizeof(hdrs));

  n = conn->request_info.num_response_headers;
  for (i = 0; i < n; i++) {
    int l = (int)mg_strlcpy(scratch, conn->request_info.response_headers[i].name, space);
    // calc new name+value pointers for when we're done with the compact cycle:
    hdrs[i].name = scratch - conn->buf_size;
    l += 2;
    scratch += l;
    space -= l;
    l = (int)mg_strlcpy(scratch, conn->request_info.response_headers[i].value, space);
    hdrs[i].value = scratch - conn->buf_size;
    l += 2;
    scratch += l;
    space -= l;
  }
  conn->tx_can_compact = 0;
  n = scratch - conn->buf - 2 * conn->buf_size;
  i = conn->tx_headers_len - n;
  conn->tx_headers_len = n;

  memcpy(conn->request_info.response_headers, hdrs, sizeof(hdrs));
  memcpy(conn->buf + conn->buf_size, conn->buf + 2 * conn->buf_size, conn->buf_size);

  return i;
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
    conn->tx_can_compact = 1;
  }
  return found;
}

int mg_add_response_header(struct mg_connection *conn, int force_add, const char *tag, const char *value_fmt, ...) {
  int i = -1;
  int n, space;
  char *dst;
  char *bufbase;
  va_list ap;

  if (is_empty(tag) || !conn->buf_size) // mg_connect() creates connections without header buffer space
    return -1;
  if (!value_fmt)
    value_fmt = "";

  bufbase = conn->buf + conn->buf_size;
  dst = bufbase + conn->tx_headers_len;
  space = conn->buf_size - conn->tx_headers_len;

  if (!force_add) {
    // check whether tag is already listed in the set:
    for (i = conn->request_info.num_response_headers; i-- > 0; ) {
      const char *key = conn->request_info.response_headers[i].name;

      if (!mg_strcasecmp(tag, key)) {
        // re-use the tag, ditch the value:
        conn->tx_can_compact = 1;
        break;
      }
    }
  }
  if (i < 0) { // this tag wasn't found: add it
    i = conn->request_info.num_response_headers;
    if (i >= ARRAY_SIZE(conn->request_info.response_headers)) {
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
    n += 2; // include NUL+[?] sentinel in count
    conn->tx_headers_len += n;
    dst += n;
    space -= n;
  }

  // now store the value:
  for(;;) {
    va_start(ap, value_fmt);
    n = mg_vsnq0printf(conn, dst, space, value_fmt, ap);
    va_end(ap);
    // n==0 is also possible when snprintf() fails dramatically (see notes in mg_snq0printf() et al)
    if (n + 4 < space && n > 0) // + NUL+[?]+[?]+[?]
      break;
    // only accept n==0 when the value_fmt is empty and there's nothing to compact or (heuristic!) when there's 'sufficient space' to write:
    if (n == 0 && 4 < space && (!conn->tx_can_compact || is_empty(value_fmt) || space >= MG_MAX(BUFSIZ, conn->buf_size / 4)))
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
  assert(i <= conn->request_info.num_response_headers);
  if (i == conn->request_info.num_response_headers)
    conn->request_info.num_response_headers++;
  n += 2; // include NUL+[?] sentinel in count
  conn->tx_headers_len += n;
  dst += n;
  space -= n;

  // now we know we still have two extra bytes free space; this is used in mg_write_http_response_head()
  return 0;
}

int mg_write_http_response_head(struct mg_connection *conn, int status_code, const char *status_text) {
  int i, n, rv;
  char *buf;

  if (mg_have_headers_been_sent(conn))
    return 0;

  /*
  This code expects all headers to be stored in memory 'in order'.

  This assumption holds when headers have been only been added, never
  removed or replaced, OR when compact_tx_headers() has run
  after the last replace/remove operation.
  */
  if (compact_tx_headers(conn) < 0)
    return -1;

  if (status_code <= 0)
    status_code = conn->request_info.status_code;
  if (is_empty(status_text))
    status_text = mg_get_response_code_text(conn->request_info.status_code);

  /*
  Once we are sure of the header order assumption, this becomes an
  'in place' operation, where NUL sentinels are temporarily replaced
  with ": " and "\r\n" respectively.

  Since the assumption above is now assured, we know that the very
  first header starts at the beginning of the buffer!
  */
  buf = conn->buf + conn->buf_size;

  n = conn->request_info.num_response_headers;
  if (n) {
    int rv2;

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
    assert(conn->tx_headers_len + 2 <= conn->buf_size);
    buf[conn->tx_headers_len] = '\r';
    buf[conn->tx_headers_len + 1] = '\n';

    rv = mg_printf(conn, "HTTP/1.1 %d %s\r\n", status_code, status_text);
    rv2 = mg_write(conn, buf, conn->tx_headers_len + 2);
    if (rv2 < 0)
      rv = rv2;
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
    rv = mg_printf(conn, "HTTP/1.1 %d %s\r\n\r\n", status_code, status_text);
  }

  mg_mark_end_of_header_transmission(conn);

  return rv;
}

/*
Send HTTP error response headers, if we still can. Log the error anyway.

'reason' may be NULL, in which case the default RFC2616 response code text will be used instead.

'fmt' + args is the content sent along as error report (request response).
*/
static void vsend_http_error(struct mg_connection *conn, int status,
                             const char *reason, const char *fmt, va_list ap) {
  char buf[BUFSIZ];
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
  }

  mg_set_response_code(conn, status);
  conn->request_info.status_custom_description = buf;

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
    p = strchr(conn->request_info.status_custom_description, '\t');
    if (p)
      *p = 0;

    mg_cry(conn, "%s: %s (HTTP v%s: %s %s%s%s) %s",
            __func__, conn->request_info.status_custom_description,
            (conn->request_info.http_version ? conn->request_info.http_version : "(unknown)"),
            (conn->request_info.request_method ? conn->request_info.request_method : "???"),
            (conn->request_info.uri ? conn->request_info.uri : "???"),
            (conn->request_info.query_string ? "?" : ""),
            (conn->request_info.query_string ? conn->request_info.query_string : ""),
            (p ? p + 1 : ""));

    // Errors 1xx, 204 and 304 MUST NOT send a body
    if (status > 199 && status != 204 && status != 304) {
      if (p)
        *p = '\n';
    } else {
      len = 0;
    }
    DEBUG_TRACE(("[%s]", conn->request_info.status_custom_description));

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
          (mg_produce_nested_page(conn, filename_vec.ptr, filename_vec.len) &&
           !mg_have_headers_been_sent(conn))) {
        /* issue #229: Only include the content-length if there is a response body.
         Otherwise an incorrect Content-Type generates a warning in
         some browsers when a static file request returns a 304
         "not modified" error. */
        if (len > 0) {
          mg_add_response_header(conn, 0, "Content-Length", "%d", len);
          mg_add_response_header(conn, 0, "Content-Type", "text/plain");
        }
        mg_add_response_header(conn, 0, "Connection", suggest_connection_header(conn));
        mg_write_http_response_head(conn, status, reason);

        if (len > 0) {
          mg_write(conn, conn->request_info.status_custom_description, len);
        }
      }
    } else if (mg_is_producing_nested_page(conn)) {
      // mark nested error anyhow
      conn->nested_err_or_pagereq_count++;
    }
  } else if (mg_is_producing_nested_page(conn)) {
    // mark nested error anyhow
    conn->nested_err_or_pagereq_count++;
  }
  // kill lingering reference to local storage:
  conn->request_info.status_custom_description = NULL;
}

static void send_http_error(struct mg_connection *conn, int status,
  const char *reason, const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 4, 5)))
#endif
  ;

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



// rwlock types have been moved to mongoose_sys_porting.h

#if defined(RTL_SRWLOCK_INIT) // Winows 7 / Server 2008 with the correct header files, i.e. this also 'fixes' MingW casualties

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
  // some garbage in the end of file name. So fopen("a.cgi    ", "r")
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
    MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, (int) wbuf_len);
    WideCharToMultiByte(CP_UTF8, 0, wbuf, (int) wbuf_len, buf2, sizeof(buf2),
                        NULL, NULL);
    if (strcmp(buf, buf2) != 0) {
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
  MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, ARRAY_SIZE(wmode));

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
      (void) WideCharToMultiByte(CP_UTF8, 0,
          dir->info.cFileName, -1, result->d_name,
          sizeof(result->d_name), NULL, NULL);

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

static int start_thread(UNUSED_PARAMETER(struct mg_context *ctx), mg_thread_func_t f, void *p) {
  return _beginthread((void (__cdecl *)(void *)) f, 0, p) == -1L ? -1 : 0;
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

  DEBUG_TRACE(("Running [%s]", cmdline));
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

static int start_thread(UNUSED_PARAMETER(struct mg_context *ctx), mg_thread_func_t func,
                        void *param) {
  pthread_t thread_id;
  pthread_attr_t attr;
  int retval;

  (void) pthread_attr_init(&attr);
  (void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  // TODO(lsm): figure out why mongoose dies on Linux if next line is enabled
  // (void) pthread_attr_setstacksize(&attr, sizeof(struct mg_connection) * 5);

  if ((retval = pthread_create(&thread_id, &attr, func, param)) != 0) {
    mg_cry(fc(ctx), "%s: %s", __func__, mg_strerror(retval));
  }

  return retval;
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

      // Execute CGI program. No need to lock: new process
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

// Write data to the IO channel - opened file descriptor, socket or SSL
// descriptor. Return number of bytes written.
static int64_t push(FILE *fp, struct socket *sock, SSL *ssl, const char *buf,
                    int64_t len) {
  int64_t sent;
  int n, k;

  sent = 0;
  while (sent < len) {

    // How many bytes we send in this iteration
    k = len - sent > INT_MAX ? INT_MAX : (int) (len - sent);

    if (ssl != NULL) {
      n = SSL_write(ssl, buf + sent, k);
      assert(sock);
      sock->write_error = (n < 0);
    } else if (fp != NULL) {
      n = (int)fwrite(buf + sent, 1, (size_t)k, fp);
      if (ferror(fp))
        n = -1;
    } else if (sock && sock->sock != INVALID_SOCKET) {
      /* Ignore "broken pipe" errors (i.e., clients that disconnect instead of waiting for their answer) */
      n = send(sock->sock, buf + sent, (size_t) k, MSG_NOSIGNAL);
      sock->write_error = (n < 0);
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
static int pull(FILE *fp, struct socket *sock, SSL *ssl, char *buf, int len) {
  int nread;

  if (ssl != NULL) {
    nread = SSL_read(ssl, buf, len);
    assert(sock);
    sock->read_error = (nread < 0);
    // and reset the select() markers used by consume_socket() et al:
    sock->was_idle = 0;
    sock->has_read_data = 0;
  } else if (fp != NULL) {
    // Use read() instead of fread(), because if we're reading from the CGI
    // pipe, fread() may block until IO buffer is filled up. We cannot afford
    // to block and must pass all read bytes immediately to the client.
    nread = read(fileno(fp), buf, (size_t) len);
    if (ferror(fp))
      nread = -1;
  } else if (sock && sock->sock != INVALID_SOCKET) {
    nread = recv(sock->sock, buf, (size_t) len, 0);
    sock->read_error = (nread < 0);
    // and reset the select() markers used by consume_socket() et al:
    sock->was_idle = 0;
    sock->has_read_data = 0;
  } else {
    nread = -1;
  }

  return nread;
}

int mg_read(struct mg_connection *conn, void *buf, size_t len) {
  int n, buffered_len, nread;
  const char *buffered;

  assert((conn->content_len == -1 && conn->consumed_content == 0) ||
         conn->consumed_content <= conn->content_len);
  DEBUG_TRACE(("%p %" INT64_FMT " %" INT64_FMT " %" INT64_FMT, buf, (int64_t)len,
               conn->content_len, conn->consumed_content));
  nread = 0;
  if (conn->consumed_content < conn->content_len) {

    // Adjust number of bytes to read.
    int64_t to_read = conn->content_len - conn->consumed_content;
    if (to_read < (int64_t) len) {
      len = (size_t) to_read;
    }

    // How many bytes of data we have buffered in the request buffer?
    assert(conn->request_len >= 0);
    buffered = conn->buf + conn->request_len + conn->consumed_content;
    buffered_len = conn->data_len - conn->request_len;
    assert(buffered_len >= 0);

    // Return buffered data back if we haven't done that yet.
    if (conn->consumed_content < (int64_t) buffered_len) {
      buffered_len -= (int) conn->consumed_content;
      if (len < (size_t) buffered_len) {
        buffered_len = (int)len;
      }
      memcpy(buf, buffered, (size_t)buffered_len);
      len -= buffered_len;
      buf = (char *) buf + buffered_len;
      conn->consumed_content += buffered_len;
      nread = buffered_len;
    }

    // We have returned all buffered data. Read new data from the remote socket.
    while (len > 0) {
      n = pull(NULL, &conn->client, conn->ssl, (char *) buf, (int) len);
      if (n < 0) {
        // always propagate the error
        return n;
      } else if (n == 0) {
        break;
      }
      buf = (char *) buf + n;
      conn->consumed_content += n;
      nread += n;
      len -= n;
    }
  }
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
  int rv = (int) push(NULL, &conn->client, conn->ssl, (const char *) buf,
                    (int64_t) len);
  if (rv > 0) {
    if (conn->num_bytes_sent < 0)
      conn->num_bytes_sent -= rv; // count as header data
    else
      conn->num_bytes_sent += rv; // count as content data
  }
  return rv;
}

int mg_vprintf(struct mg_connection *conn, const char *fmt, va_list ap) {
  char *buf = NULL;
  int len;
  int rv;

  // handle the special case where there's nothing to do in terms of formatting --> print without the malloc/speed penalty:
  if (!strchr(fmt, '%')) {
    rv = mg_write(conn, fmt, strlen(fmt));
    return (rv < 0 ? 0 : rv);
  } else if (!strcmp(fmt, "%s")) {
    fmt = va_arg(ap, const char *);
    if (!fmt) fmt = "???";
    rv = mg_write(conn, fmt, strlen(fmt));
    return (rv < 0 ? 0 : rv);
  } else {
    len = mg_vasprintf(conn, &buf, 0, fmt, ap);

    if (buf) {
      rv = mg_write(conn, buf, (size_t)len);
      free(buf);
      return (rv < 0 ? 0 : rv);
    } else {
      return 0;
    }
  }
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
// The dst[] buffer is always NUL-terminated, also when -1 is returned.
int mg_get_var(const char *buf, size_t buf_len, const char *name,
               char *dst, size_t dst_len) {
  const char *p, *e, *s;
  size_t name_len;
  int len;

  name_len = strlen(name);
  e = buf + buf_len;
  len = -1;
  dst[0] = '\0';

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
      assert(s >= p);

      // Decode variable into destination buffer
      if ((size_t) (s - p) < dst_len) {
        len = (int)url_decode(p, (size_t)(s - p), dst, dst_len, 1);
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
    if ((match_len = match_prefix(a.ptr, (int)a.len, uri)) > 0) {
      mg_snprintf(conn, buf, buf_len, "%.*s%s", (int)b.len, b.ptr, uri + match_len);
      break;
    }
  }

  // Win32: CGI can fail when being fed an interpreter plus relative path to the script;
  // keep in mind that other scenarios, e.g. user event handlers, may fail similarly
  // when receiving relative filesystem paths, so we solve the issue once and for all,
  // right here:
#if defined(_WIN32)
  {
    wchar_t woldbuf[PATH_MAX];
    wchar_t wnewbuf[PATH_MAX];
    int pos;

    to_unicode(buf, woldbuf, ARRAY_SIZE(woldbuf));
    pos = GetFullPathNameW(woldbuf, ARRAY_SIZE(wnewbuf), wnewbuf, NULL);
    assert(pos < ARRAY_SIZE(wnewbuf));
    wnewbuf[pos] = 0;
    WideCharToMultiByte(CP_UTF8, 0, wnewbuf, pos + 1 /* include NUL sentinel */, buf, (int)buf_len, NULL, NULL);
    pos = (int)strlen(buf);
    while (pos-- > 0) {
      if (buf[pos] == '\\')
        buf[pos] = '/';
    }
  }
#endif

  if ((stat_result = mg_stat(buf, st)) != 0) {
    const char *cgi_exts = get_conn_option(conn, CGI_EXTENSIONS);
    int cgi_exts_len = (int)strlen(cgi_exts);

    // Support PATH_INFO for CGI scripts.
    for (p = buf + strlen(buf); p > buf + 1; p--) {
      if (*p == '/') {
        *p = '\0';
        if (match_prefix(cgi_exts, cgi_exts_len, buf) > 0 &&
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

  DEBUG_TRACE(("[%s] -> [%s], [%.*s]", uri, buf, (int) b.len, b.ptr));

  return stat_result;
}

#if !defined(NO_SSL)
static int sslize(struct mg_connection *conn, int (*func)(SSL *)) {
  return (conn->ssl = SSL_new(conn->ctx->ssl_ctx)) != NULL &&
    SSL_set_fd(conn->ssl, conn->client.sock) == 1 &&
    func(conn->ssl) == 1;
}
#else // NO_SSL
#define sslize(conn, f)     0
#endif // NO_SSL

// Check whether full request is buffered. Return:
//   -1  if request is malformed
//    0  if request is not yet fully buffered
//   >0  actual request length, including last \r\n\r\n
static int get_request_len(const char *buf, int buflen) {
  const char *s, *e;
  int len = 0;

  DEBUG_TRACE(("buf: %p, len: %d", buf, buflen));
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
  size_t mime_type_len;
} builtin_mime_types[] = {
  {".html",     5, "text/html",                      9},
  {".htm",      4, "text/html",                      9},
  {".shtm",     5, "text/html",                      9},
  {".shtml",    6, "text/html",                      9},
  {".css",      4, "text/css",                       8},
  {".js",       3, "application/x-javascript",      24},
  {".txt",      4, "text/plain",                    10},
  {".ico",      4, "image/x-icon",                  12},
  {".gif",      4, "image/gif",                      9},
  {".jpg",      4, "image/jpeg",                    10},
  {".jpeg",     5, "image/jpeg",                    10},
  {".png",      4, "image/png",                      9},
  {".svg",      4, "image/svg+xml",                 13},
  {".torrent",  8, "application/x-bittorrent",      24},
  {".wav",      4, "audio/x-wav",                   11},
  {".mp3",      4, "audio/x-mp3",                   11},
  {".mid",      4, "audio/mid",                      9},
  {".m3u",      4, "audio/x-mpegurl",               15},
  {".ram",      4, "audio/x-pn-realaudio",          20},
  {".xml",      4, "text/xml",                       8},
  {".xslt",     5, "application/xml",               15},
  {".ra",       3, "audio/x-pn-realaudio",          20},
  {".doc",      4, "application/msword",            19},
  {".exe",      4, "application/octet-stream",      24},
  {".zip",      4, "application/x-zip-compressed",  28},
  {".xls",      4, "application/excel",             17},
  {".tgz",      4, "application/x-tar-gz",          20},
  {".tar",      4, "application/x-tar",             17},
  {".gz",       3, "application/x-gunzip",          20},
  {".arj",      4, "application/x-arj-compressed",  28},
  {".rar",      4, "application/x-arj-compressed",  28},
  {".rtf",      4, "application/rtf",               15},
  {".pdf",      4, "application/pdf",               15},
  {".swf",      4, "application/x-shockwave-flash", 29},
  {".mpg",      4, "video/mpeg",                    10},
  {".mpeg",     5, "video/mpeg",                    10},
  {".mp4",      4, "video/mp4",                      9},
  {".m4v",      4, "video/x-m4v",                   11},
  {".asf",      4, "video/x-ms-asf",                14},
  {".avi",      4, "video/x-msvideo",               15},
  {".bmp",      4, "image/bmp",                      9},
  {NULL,        0, NULL,                             0}
};

// Look at the "path" extension and figure what mime type it has.
// Store mime type in the vector.
static void get_mime_type(struct mg_context *ctx, const char *path,
                          struct vec *vec) {
  struct vec ext_vec, mime_vec;
  const char *list, *ext;
  size_t i, path_len;

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

  // Now scan built-in mime types
  for (i = 0; builtin_mime_types[i].extension != NULL; i++) {
    ext = path + (path_len - builtin_mime_types[i].ext_len);
    if (path_len > builtin_mime_types[i].ext_len &&
        mg_strcasecmp(ext, builtin_mime_types[i].extension) == 0) {
      vec->ptr = builtin_mime_types[i].mime_type;
      vec->len = builtin_mime_types[i].mime_type_len;
      return;
    }
  }

  // Nothing found. Fall back to "text/plain"
  vec->ptr = "text/plain";
  vec->len = 10;
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

// Parsed Authorization header
struct ah {
  char *user, *uri, *cnonce, *response, *qop, *nc, *nonce;
};

static int parse_auth_header(struct mg_connection *conn, char *buf,
                             size_t buf_size, struct ah *ah) {
  char *name, *value, *s;
  const char *auth_header;

  if ((auth_header = mg_get_header(conn, "Authorization")) == NULL ||
      mg_strncasecmp(auth_header, "Digest ", 7) != 0) {
    return 0;
  }

  // Make modifiable copy of the auth header
  (void) mg_strlcpy(buf, auth_header + 7, buf_size);

  s = buf;
  (void) memset(ah, 0, sizeof(*ah));

  // Parse authorization header
  for (;;) {
    // Gobble initial spaces
    while (isspace(* (unsigned char *) s)) {
      s++;
    }
    name = skip_quoted(&s, "=", " ", 0);
    // Value is either quote-delimited, or ends at first comma or space.
    if (s[0] == '\"') {
      s++;
      value = skip_quoted(&s, "\"", " ", '\\');
      if (s[0] == ',') {
        s++;
      }
    } else {
      value = skip_quoted(&s, ", ", " ", 0);  // IE uses commas, FF uses spaces
    }
    if (*name == '\0') {
      break;
    }

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

// Authorize against the opened passwords file. Return 1 if authorized.
static int authorize(struct mg_connection *conn, FILE *fp) {
  struct ah ah;
  char line[256], f_user[256], ha1[256], f_domain[256], buf[BUFSIZ];
  const char *auth_domain;

  if (!parse_auth_header(conn, buf, sizeof(buf), &ah)) {
    return 0;
  }

  // Loop over passwords file
  auth_domain = get_conn_option(conn, AUTHENTICATION_DOMAIN);
  while (fgets(line, sizeof(line), fp) != NULL) {
    if (sscanf(line, "%[^:]:%[^:]:%s", f_user, f_domain, ha1) != 3) {
      continue;
    }

    if (*f_user && *f_domain &&
        !strcmp(ah.user, f_user) &&
        !strcmp(auth_domain, f_domain))
      return check_password(
            conn->request_info.request_method,
            ha1, ah.uri, ah.nonce, ah.nc, ah.cnonce, ah.qop,
            ah.response);
  }

  return 0;
}

// Return 1 if request is authorized, 0 otherwise.
static int check_authorization(struct mg_connection *conn, const char *path) {
  FILE *fp;
  char fname[PATH_MAX];
  struct vec uri_vec, filename_vec;
  const char *list;
  int authorized;

  fp = NULL;
  authorized = 1;

  list = get_conn_option(conn, PROTECT_URI);
  while ((list = next_option(list, &uri_vec, &filename_vec)) != NULL) {
    if (!memcmp(conn->request_info.uri, uri_vec.ptr, uri_vec.len)) {
      (void) mg_snprintf(conn, fname, sizeof(fname), "%.*s",
          (int)filename_vec.len, filename_vec.ptr);
      if ((fp = mg_fopen(fname, "r")) == NULL) {
        mg_cry(conn, "%s: cannot open %s: %s", __func__, fname, mg_strerror(ERRNO));
      }
      break;
    }
  }

  if (fp == NULL) {
    fp = open_auth_file(conn, path);
  }

  if (fp != NULL) {
    authorized = authorize(conn, fp);
    (void) mg_fclose(fp);
  }

  return authorized;
}

static void send_authorization_request(struct mg_connection *conn) {
  if (mg_is_producing_nested_page(conn))
    return;
  conn->request_info.status_code = 401;
  mg_add_response_header(conn, 0, "Connection", "%s", suggest_connection_header(conn));
  mg_add_response_header(conn, 0, "Content-Length", "0");
  mg_add_response_header(conn, 0, "WWW-Authenticate", "Digest qop=\"auth\", "
                         "realm=\"%s\", nonce=\"%lu\"",
                         get_conn_option(conn, AUTHENTICATION_DOMAIN),
                         (unsigned long) time(NULL));
  (void) mg_write_http_response_head(conn, 0, 0);
}

static int is_authorized_for_put(struct mg_connection *conn) {
  FILE *fp;
  int ret = 0;
  const char *pwd_filepath = get_conn_option(conn, PUT_DELETE_PASSWORDS_FILE);

  if (!is_empty(pwd_filepath)) {
    fp = mg_fopen(pwd_filepath, "r");
    if (fp != NULL) {
      ret = authorize(conn, fp);
      (void) mg_fclose(fp);
    }
  }
  return ret;
}

int mg_modify_passwords_file(const char *fname, const char *domain,
                             const char *user, const char *pass) {
  int found;
  char line[512], u[512], d[512], ha1[33], tmp[PATH_MAX];
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
    if (sscanf(line, "%[^:]:%[^:]:%*s", u, d) != 2) {
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

struct de {
  struct mg_connection *conn;
  char *file_name;
  struct mgstat st;
};

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

static void print_dir_entry(struct de *de) {
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
// with __stdcall convention. qsort always requires __cdels callback.
static int WINCDECL compare_dir_entries(const void *p1, const void *p2) {
  const struct de *a = (const struct de *) p1, *b = (const struct de *) p2;
  const char *query_string = a->conn->request_info.query_string;
  int cmp_result = 0;

  if (query_string == NULL) {
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

static int scan_directory(struct mg_connection *conn, const char *dir,
                          void *data, void (*cb)(struct de *, void *)) {
  char path[PATH_MAX];
  struct dirent *dp;
  DIR *dirp;
  struct de de;

  if ((dirp = opendir(dir)) == NULL) {
    return 0;
  } else {
    de.conn = conn;

    while ((dp = readdir(dirp)) != NULL) {
      // Do not show current dir and passwords file
      if (!strcmp(dp->d_name, ".") ||
          !strcmp(dp->d_name, "..") ||
          !strcmp(dp->d_name, PASSWORDS_FILE_NAME))
        continue;

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
  struct de *entries;
  int num_entries;
  int arr_size;
};

static void dir_scan_callback(struct de *de, void *data) {
  struct dir_scan_data *dsd = (struct dir_scan_data *) data;

  if (dsd->entries == NULL || dsd->num_entries >= dsd->arr_size) {
    dsd->arr_size *= 2;
    dsd->entries = (struct de *) realloc(dsd->entries, dsd->arr_size *
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
  if (!scan_directory(conn, dir, &data, dir_scan_callback)) {
    send_http_error(conn, 500, "Cannot open directory",
                    "Error: opendir(%s): %s", dir, strerror(ERRNO));
    return;
  }

  sort_direction = conn->request_info.query_string != NULL &&
    conn->request_info.query_string[1] == 'd' ? 'a' : 'd';

  conn->must_close = 1;
  conn->request_info.status_code = 200;
  mg_add_response_header(conn, 0, "Connection", "%s", suggest_connection_header(conn));
  mg_add_response_header(conn, 0, "Content-Type", "text/html; charset=utf-8");
  mg_write_http_response_head(conn, 0, 0);
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
    int n = pull(fp, NULL, NULL, buf + offset, sizeof(buf) - offset - 1);
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
    if (num_read == 0 && ferror(fp)) {
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

static int parse_range_header(const char *header, int64_t *a, int64_t *b) {
  return sscanf(header, "bytes=%" INT64_FMT "-%" INT64_FMT, a, b);
}

static void gmt_time_string(char *buf, size_t buf_len, const time_t *t) {
  strftime(buf, buf_len, "%a, %d %b %Y %H:%M:%S GMT", gmtime(t));
}

// return negative number on error; 0 on success
static int handle_file_request(struct mg_connection *conn, const char *path,
                                struct mgstat *stp) {
  char date[64], lm[64];
  const char *hdr;
  time_t curtime = time(NULL);
  int64_t cl, r1, r2;
  struct vec mime_vec;
  FILE *fp;
  int n;

  get_mime_type(conn->ctx, path, &mime_vec);
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
    conn->request_info.status_code = 206;
    (void) fseeko(fp, (off_t) r1, SEEK_SET);
    cl = n == 2 ? r2 - r1 + 1: cl - r1;
    mg_add_response_header(conn, 0, "Content-Range", "bytes "
        "%" INT64_FMT "-%"
        INT64_FMT "/%" INT64_FMT,
        r1, r1 + cl - 1, stp->size);
  }

  // Prepare Etag, Date, Last-Modified headers. Must be in UTC, according to
  // http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.3
  gmt_time_string(date, sizeof(date), &curtime);
  gmt_time_string(lm, sizeof(lm), &stp->mtime);

  mg_add_response_header(conn, 0, "Date", "%s", date);
  mg_add_response_header(conn, 0, "Last-Modified", "%s", lm);
  mg_add_response_header(conn, 0, "Etag", "\"%lx.%lx\"",
                         (unsigned long) stp->mtime, (unsigned long) stp->size);
  mg_add_response_header(conn, 0, "Content-Type", "%.*s", (int) mime_vec.len, mime_vec.ptr);
  mg_add_response_header(conn, 0, "Content-Length", "%" INT64_FMT, cl);
  mg_add_response_header(conn, 0, "Connection", "%s", suggest_connection_header(conn));
  mg_add_response_header(conn, 0, "Accept-Ranges", "bytes");
  n = mg_write_http_response_head(conn, 0, 0);
  n--; // 0 --> -1

  if (n > 0 &&
      strcmp(conn->request_info.request_method, "HEAD") != 0) {
    n = (send_file_data(conn, fp, cl) >= 0);
  }
  (void) mg_fclose(fp);
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
static void parse_http_headers(char **buf, struct mg_request_info *ri) {
  int i;

  ri->num_headers = 0;
  for (i = 0; i < (int) ARRAY_SIZE(ri->http_headers); i++) {
    ri->http_headers[i].name = skip_quoted(buf, ":", " ", 0);
    ri->http_headers[i].value = skip(buf, "\r\n");
    if (ri->http_headers[i].name[0] == '\0')
      break;
    ri->num_headers = i + 1;
  }
}

static int is_valid_http_method(const char *method) {
  return !strcmp(method, "GET") || !strcmp(method, "POST") ||
    !strcmp(method, "HEAD") || !strcmp(method, "CONNECT") ||
    !strcmp(method, "PUT") || !strcmp(method, "DELETE") ||
    !strcmp(method, "OPTIONS") || !strcmp(method, "PROPFIND");
}

// Parse HTTP request, fill in mg_request_info structure.
static int parse_http_request(char *buf, struct mg_request_info *ri) {
  int status = 0;

  // RFC says that all initial whitespace should be ignored
  while (*buf != '\0' && isspace(* (unsigned char *) buf)) {
    buf++;
  }

  ri->request_method = skip(&buf, " ");
  ri->uri = skip(&buf, " ");
  ri->http_version = skip(&buf, "\r\n");
  ri->num_headers = 0;

  if (is_valid_http_method(ri->request_method) &&
      strncmp(ri->http_version, "HTTP/", 5) == 0) {
    ri->http_version += 5;   // Skip "HTTP/"
    parse_http_headers(&buf, ri);
    status = 1;
  }

  return status;
}

// Keep reading the input (either opened file descriptor fd, or socket sock,
// or SSL descriptor ssl) into buffer buf, until \r\n\r\n appears in the
// buffer (which marks the end of HTTP request). Buffer buf may already
// have some data. The length of the data is stored in nread.
// Upon every read operation, increase nread by the number of bytes read.
static int read_request(FILE *fp, struct socket *sock, SSL *ssl, char *buf, int bufsiz,
                        int *nread) {
  int request_len, n = 0;

  do {
    request_len = get_request_len(buf, *nread);
    if (request_len == 0 &&
        (n = pull(fp, sock, ssl, buf + *nread, bufsiz - *nread)) > 0) {
      *nread += n;
    }
  } while (*nread < bufsiz && request_len == 0 && n > 0);

  if (n < 0) {
    // recv() error -> propagate error; do not process a b0rked-with-very-high-probability request
    return -1;
  }
  return request_len;
}

// For given directory path, substitute it to valid index file.
// Return 0 if index file has been found, -1 if not found.
// If the file is found, it's stats is returned in stp.
static int substitute_index_file(struct mg_connection *conn, char *path,
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
  const char *ims = mg_get_header(conn, "If-Modified-Since");
  return ims != NULL && stp->mtime <= parse_date_string(ims);
}

static int forward_body_data(struct mg_connection *conn, FILE *fp,
                             struct socket *sock, SSL *ssl, int send_error_on_fail) {
  const char *expect, *buffered;
  char buf[DATA_COPY_BUFSIZ];
  int to_read, nread, buffered_len, success = 0;

  expect = mg_get_header(conn, "Expect");
  assert(fp != NULL);

  if (conn->content_len == -1 &&
      (!strcmp(conn->request_info.request_method, "POST") ||
       !strcmp(conn->request_info.request_method, "PUT"))) {
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
      assert(mg_have_headers_been_sent(conn) == 0);
    }

    buffered = conn->buf + conn->request_len;
    buffered_len = conn->data_len - conn->request_len;
    assert(buffered_len >= 0);
    assert(conn->consumed_content == 0);

    if (buffered_len > 0) {
      if ((int64_t) buffered_len > conn->content_len) {
        buffered_len = (int) conn->content_len;
      }
      if (push(fp, sock, ssl, buffered, (int64_t) buffered_len) != buffered_len)
        goto failure;
      conn->consumed_content += buffered_len;
    }

    while (conn->consumed_content < conn->content_len) {
      to_read = sizeof(buf);
      if ((int64_t) to_read > conn->content_len - conn->consumed_content) {
        to_read = (int) (conn->content_len - conn->consumed_content);
      }
      nread = pull(NULL, &conn->client, conn->ssl, buf, to_read);
      if (nread <= 0 || push(fp, sock, ssl, buf, nread) != nread) {
        break;
      }
      conn->consumed_content += nread;
    }

    if (conn->consumed_content == conn->content_len ||
        (conn->consumed_content == 0 && conn->content_len == -1)) {
      success = 1;
    }

    // Each error code path in this function must send an error
    if (!success) {
failure:
      if (send_error_on_fail) {
        send_http_error(conn, 577, NULL, ((fp && ferror(fp)) ? "%s: I/O error: %s" : ""), __func__, mg_strerror(ERRNO));
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
static char *addenv(struct cgi_env_block *block, const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 2, 3)))
#endif
    ;

static char *addenv(struct cgi_env_block *block, const char *fmt, ...)
{
  int n;
  size_t space;
  char *added;
  va_list ap;

  // Calculate how much space is left in the buffer
  space = sizeof(block->buf) - block->len - 2;
  assert((int)space >= 0);

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
      addenv(blk, "REDIRECT_QUERY_STRING=%.*s%s", (int)(slen > BUFSIZ ? BUFSIZ : slen), str, (slen > BUFSIZ ? "&etc=..." : ""));
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
  assert(conn->request_info.uri[0] == '/');
  slash = strrchr(conn->request_info.uri, '/');
  if ((s = strrchr(prog, '/')) == NULL)
    s = prog;
  addenv(blk, "SCRIPT_NAME=%.*s%s", (int)(slash - conn->request_info.uri),
         conn->request_info.uri, s);

  addenv(blk, "SCRIPT_FILENAME=%s", prog);
  addenv(blk, "PATH_TRANSLATED=%s", prog);

  if ((s = mg_get_header(conn, "Content-Type")) != NULL)
    addenv(blk, "CONTENT_TYPE=%s", s);

  if (is_empty(conn->request_info.query_string))
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

  assert(blk->nvars < (int) ARRAY_SIZE(blk->vars));
  assert(blk->len > 0);
  assert(blk->len < (int) sizeof(blk->buf));
  return 0;
}

static void handle_cgi_request(struct mg_connection *conn, const char *prog) {
  int headers_len, data_len, i, fd_stdin[2], fd_stdout[2], fd_stderr[2];
  const char *status, *connection_status, *content_type;
  char buf[HTTP_HEADERS_BUFSIZ], *pbuf, dir[PATH_MAX], *p, *e;
  struct mg_request_info ri = {0};
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
      !forward_body_data(conn, in, NULL, NULL, 0)) {
    mg_write2log(conn, NULL, time(NULL), "warning", "Failed to forward request content (body) to the CGI process: %s", mg_strerror(ERRNO));
  }

  // Now read CGI reply into a buffer. We need to set correct
  // status code, thus we need to see all HTTP headers first.
  // Do not send anything back to client, until we buffer in all
  // HTTP headers.
  data_len = 0;
  headers_len = read_request(out, NULL, NULL,
                             buf, sizeof(buf), &data_len);
  if (headers_len <= 0) {
    send_http_error(conn, 500, NULL,
                    "CGI program sent malformed HTTP headers: [%.*s]",
                    data_len, buf);
    goto done;
  }
  pbuf = buf;
  buf[headers_len - 1] = '\0';
  parse_http_headers(&pbuf, &ri);

  // Make up and send the status line
  if ((status = get_header(&ri, "Status")) != NULL) {
    char * chknum = NULL;
    int response_code = (int)strtol(status, &chknum, 10);
    if (chknum != NULL)
      status = chknum + strspn(chknum, " ");
    else
      status = NULL;
    if (!is_legal_response_code(response_code)) {
      send_http_error(conn, 500, NULL,
            "CGI program sent malformed HTTP Status header: [%s]",
            get_header(&ri, "Status"));
      goto done;
    }
    if (response_code != mg_set_response_code(conn, response_code))
      status = NULL;
  } else if (get_header(&ri, "Location") != NULL) {
    mg_set_response_code(conn, 302);
  } else {
    mg_set_response_code(conn, 200);
  }
  if ((connection_status = get_header(&ri, "Connection")) != NULL) {
    // fix: keep-alive (storing connection_status is a performance bonus)
    if (mg_strcasecmp(connection_status, "keep-alive")) {
      conn->must_close = 1;
    }
  }

  // Send headers
  for (i = 0; i < ri.num_headers; i++) {
    mg_add_response_header(conn, 0, ri.http_headers[i].name, "%s", ri.http_headers[i].value);
  }

  // See if there's any data in the 'err' channel and when there is,
  // discard any Content-Length header as it'll be invalid anyway.
  content_type = get_header(&ri, "Content-Type");
  is_text_out = 0;
  if (content_type)
    is_text_out = !mg_strncasecmp(content_type, "text/plain", 10) +
                2 * !mg_strncasecmp(content_type, "text/html", 9);

  // ri.headers[] are invalid from this point onward!
  i = 0;
  if (is_text_out) {
    assert(headers_len > 0);
    i = pull(err, NULL, NULL, buf, headers_len);
    if (i > 0) {
      mg_remove_response_header(conn, "Content-Length");
      conn->must_close = 1;
    } else if (i < 0) {
      send_http_error(conn, 500, NULL,
            "CGI program clobbered stderr: %s",
            mg_strerror(ERRNO));
      goto done;
    }
  }
  // and always send the Connection: header:
  if (get_header(&ri, "Connection") == NULL) {
    mg_add_response_header(conn, 0, "Connection", "%s", suggest_connection_header(conn));
  }
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
    (void) mg_write(conn, buf, i);
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
  (void) mg_write(conn, buf + headers_len, data_len - headers_len);

  // Read the rest of CGI output and send to the client
  (void)send_file_data(conn, out, INT64_MAX);

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
    DEBUG_TRACE(("mkdir(%s)", buf));
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
      conn->request_info.status_code = 206;
      // TODO(lsm): handle seek error
      (void) fseeko(fp, (off_t) r1, SEEK_SET);
    }
    if (forward_body_data(conn, fp, NULL, NULL, 1)) {
      mg_write_http_response_head(conn, 0, 0);
    }
    (void) mg_fclose(fp);
  }
}

static int send_ssi_file(struct mg_connection *, const char *, FILE *, int);

// Return 0 on success; non-zero on error, where negative number is a fatal I/O failure.
static int do_ssi_include(struct mg_connection *conn, const char *ssi,
                           const char tag[PATH_MAX+64], int include_level) {
  char file_name[PATH_MAX+64], path[PATH_MAX], *p;
  FILE *fp;
  int rv;

  // sscanf() is safe here, since send_ssi_file() guarantees that tag is
  // no larger than PATH_MAX+64 bytes, so strlen(tag) is always < PATH_MAX+64.
  if (sscanf(tag, " virtual=\"%[^\"]\"", file_name) == 1) {
    // File name is relative to the webserver root
    (void) mg_snprintf(conn, path, sizeof(path), "%s%c%s",
        get_conn_option(conn, DOCUMENT_ROOT), DIRSEP, file_name);
  } else if (sscanf(tag, " file=\"%[^\"]\"", file_name) == 1) {
    // File name is relative to the webserver working directory
    // or it is absolute system path
    (void) mg_snprintf(conn, path, sizeof(path), "%s", file_name);
  } else if (sscanf(tag, " \"%[^\"]\"", file_name) == 1) {
    // File name is relative to the current document
    (void) mg_snprintf(conn, path, sizeof(path), "%s", ssi);
    if ((p = strrchr(path, '/')) != NULL) {
      p[1] = '\0';
    }
    (void) mg_snprintf(conn, path + strlen(path),
        sizeof(path) - strlen(path), "%s", file_name);
  } else {
    mg_cry(conn, "Bad SSI #include: [%s]", tag);
    return 1;
  }

  // remember the original value in 'p', reset it when we're done processing the SSI element
  p = conn->request_info.phys_path;
  rv = 0;
  conn->request_info.phys_path = path;
  if (!call_user(conn, MG_SSI_INCLUDE_REQUEST)) {
    if ((fp = mg_fopen(conn->request_info.phys_path, "rb")) == NULL) {
      mg_cry(conn, "Cannot open SSI #include: [%s]: fopen(%s): %s",
          tag, conn->request_info.phys_path, mg_strerror(ERRNO));
      rv = 2;
    } else {
      set_close_on_exec(fileno(fp));
      if (match_prefix(get_conn_option(conn, SSI_EXTENSIONS),
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

static int do_ssi_exec(struct mg_connection *conn, const char *tag) {
  char cmd[SSI_LINE_BUFSIZ];
  FILE *fp;

  // sscanf() is safe here, since send_ssi_file() also uses buffer
  // of size SSI_LINE_BUFSIZ to get the tag. So strlen(tag) is always < SSI_LINE_BUFSIZ.
  if (sscanf(tag, " \"%[^\"]\"", cmd) != 1) {
    send_http_error(conn, 577, NULL, "Bad SSI #exec: [%s]", tag);
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

const char *mg_memfind(const char *haystack, size_t haysize, const char *needle, size_t needlesize)
{
    if (haysize < needlesize)
        return NULL;
    haysize -= needlesize - 1;
    while (haysize > 0)
    {
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

static int send_ssi_file(struct mg_connection *conn, const char *path,
                          FILE *fp, int include_level) {
  char buf[SSI_LINE_BUFSIZ + 64];
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
      if (!memcmp(s, "include", 7)) {
        if (e - s - 7 > PATH_MAX + 64) {
          send_http_error(conn, 577, NULL, "%s: SSI INCLUDE tag is too large (%s)", __func__, path);
          return -1;
        } else {
          do_ssi_include(conn, path, s + 7, include_level);
        }
#if !defined(NO_POPEN)
      } else if (!memcmp(s, "exec", 4)) {
        if (do_ssi_exec(conn, s + 4))
          return -1;
#endif // !NO_POPEN
#if !defined(NO_CGI)
      } else if (!memcmp(s, "echo", 4)) {
        // http://www.ssi-developer.net/ssi/ssi-echo.shtml
        s = mg_memfind(s, e - s, "var=", 4);
        if (!s)
          mg_cry(conn, "%s: invalid SSI echo command: \"%s\"", path, buf);
        else {
          const char *ve;
          int idx;
          s += 4;
          s += strspn(s, "\" ");
          ve = s + strcspn(s, " \"");
          if (ve > e) ve = e;
          *((char *)ve) = '=';
          // init 'blk' once, when we need it:
          if (!blk.conn) {
            if (prepare_cgi_environment(conn, path, &blk)) {
              send_http_error(conn, 577, NULL, "%s: failed to set up env.var set", __func__);
              blk.conn = NULL;
              return -1;
            }
          }
          assert(blk.nvars > 0);
          assert(blk.vars[blk.nvars - 1] == NULL);
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
    conn->must_close = 1;
    set_close_on_exec(fileno(fp));
    mg_set_response_code(conn, 200);
    mg_add_response_header(conn, 0, "Content-Type", "text/html");
    mg_add_response_header(conn, 0, "Connection", "%s", suggest_connection_header(conn));

    mg_write_http_response_head(conn, 0, 0);
    send_ssi_file(conn, path, fp, 0);
    (void) mg_fclose(fp);
  }
}

static void send_options(struct mg_connection *conn) {
  if (mg_is_producing_nested_page(conn))
    return;
  mg_set_response_code(conn, 200);
  mg_add_response_header(conn, 0, "Allow", "GET, POST, HEAD, CONNECT, PUT, DELETE, OPTIONS");
  mg_add_response_header(conn, 0, "DAV", "1");

  mg_write_http_response_head(conn, 0, 0);
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
         "<d:getcontentlength>%" INT64_FMT "</d:getcontentlength>"
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

static void print_dav_dir_entry(struct de *de, void *data) {
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
  conn->must_close = 1;
  mg_set_response_code(conn, 207);
  mg_add_response_header(conn, 0, "Connection", "close");
  mg_add_response_header(conn, 0, "Content-Type", "text/xml; charset=utf-8");

  mg_write_http_response_head(conn, 0, 0);

  mg_printf(conn,
      "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
      "<d:multistatus xmlns:d='DAV:'>\n");

  // Print properties for the requested resource itself
  print_props(conn, conn->request_info.uri, st);

  // If it is a directory, print directory entries too if Depth is not 0
  if (st->is_directory &&
      !mg_strcasecmp(get_conn_option(conn, ENABLE_DIRECTORY_LISTING), "yes") &&
      (depth == NULL || strcmp(depth, "0") != 0)) {
    scan_directory(conn, path, conn, &print_dav_dir_entry);
  }

  mg_printf(conn, "%s\n", "</d:multistatus>");
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

  if ((conn->request_info.query_string = strchr(ri->uri, '?')) != NULL) {
    *conn->request_info.query_string++ = '\0';
  }
  uri_len = (int)strlen(ri->uri);
  url_decode(ri->uri, (size_t)uri_len, ri->uri, (size_t)(uri_len + 1), 0);
  remove_double_dots_and_double_slashes(ri->uri);
  stat_result = convert_uri_to_file_name(conn, path, sizeof(path), &st);
  ri->phys_path = path;

  DEBUG_TRACE(("%s", ri->uri));
  if (!check_authorization(conn, path)) {
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
    conn->must_close = 1; // TODO: currently there is no way to set the close flag in the callback
#endif

  } else if (!strcmp(ri->request_method, "OPTIONS")) {
    send_options(conn);
  } else if (strstr(path, PASSWORDS_FILE_NAME)) {
    // Do not allow to view passwords files
    send_http_error(conn, 403, NULL, "No peeking at the passwords file!");
  } else if (is_empty(get_conn_option(conn, DOCUMENT_ROOT))) {
    send_http_error(conn, 404, NULL, "DocumentRoot has not been properly configured.");
  } else if ((!strcmp(ri->request_method, "PUT") ||
        !strcmp(ri->request_method, "DELETE")) &&
      (is_empty(get_conn_option(conn, PUT_DELETE_PASSWORDS_FILE)) ||
       !is_authorized_for_put(conn))) {
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
  } else if (stat_result != 0) {
    send_http_error(conn, 404, NULL, "File not found: URI=%s, PATH=%s", ri->uri, path);
  } else if (st.is_directory && ri->uri[uri_len - 1] != '/') {
    if (301 == mg_set_response_code(conn, 301)) {
      mg_add_response_header(conn, 0, "Location", "%s/", ri->uri);
      mg_write_http_response_head(conn, 0, 0);
    }
  } else if (!strcmp(ri->request_method, "PROPFIND")) {
    handle_propfind(conn, path, &st);
  } else if (st.is_directory &&
             !substitute_index_file(conn, path, sizeof(path), &st)) {
    if (!mg_strcasecmp(get_conn_option(conn, ENABLE_DIRECTORY_LISTING), "yes")) {
      handle_directory_request(conn, path);
    } else {
      send_http_error(conn, 403, "Directory Listing Denied",
          "Directory listing denied");
    }
#if !defined(NO_CGI)
  } else if (match_prefix(get_conn_option(conn, CGI_EXTENSIONS),
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
  } else if (match_prefix(get_conn_option(conn, SSI_EXTENSIONS),
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
  conn->nested_err_or_pagereq_count++;
  if (conn->nested_err_or_pagereq_count == 1) {
    // store the original ri:
    struct mg_request_info ri = conn->request_info;
    char expanded_uri[PATH_MAX];
    const char *s;
    int i;

    // fail when error happens in this section...
    conn->nested_err_or_pagereq_count++;
    if (sizeof(expanded_uri) < uri_len + 1)
      goto fail_dramatically;

    s = mg_memfind(uri, uri_len, "$E", 2);
    if (s) {
      int n = mg_snq0printf(conn, expanded_uri, sizeof(expanded_uri), "%.*s%d%.*s",
                            (int)(s - uri), uri,
                            ri.status_code,
                            (int)(uri_len - (s + 2 - uri)), s + 2);
      if (n + 1 >= sizeof(expanded_uri))
        goto fail_dramatically;
    } else {
      mg_strlcpy(expanded_uri, uri, uri_len + 1);
    }
    conn->nested_err_or_pagereq_count--;
    // end of section...

    conn->request_info.uri = expanded_uri;
    conn->request_info.request_method = "GET";
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

    // reset original values, but keep the latest HTTP response code:
    // that one will have been 'upgraded' with the latest (graver) errors
    // and those should be logged / fed back to the client whenever possible.
fail_dramatically:
    ri.status_code = conn->request_info.status_code;
    conn->request_info = ri;
  }
  return (conn->nested_err_or_pagereq_count == 1);
}

int mg_is_producing_nested_page(struct mg_connection *conn) {
  return conn ? conn->nested_err_or_pagereq_count : 0;
}

static void close_socket_UNgracefully(SOCKET sock)
{
  if (sock != INVALID_SOCKET)
  {
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
      assert(rset->ai_addrlen == sizeof(usa->u.sin6));
      assert(usa->u.sin6.sin6_family == AF_INET6);
      usa->u.sin6.sin6_port = htons((uint16_t) port);
      freeaddrinfo(rset);
      return 1;
    } else
#endif
    if (rset->ai_family == PF_INET) {
      usa->len = sizeof(usa->u.sin);
      assert(rset->ai_addrlen == sizeof(usa->u.sin));
      assert(usa->u.sin.sin_family == AF_INET);
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
static int parse_ipvX_addr_and_netmask(const char *src, struct usa *ip, int *mask_n, struct mg_ip_address *maskbits)
{
  int n, mask;
  char addr_buf[SOCKADDR_NTOA_BUFSIZE];

  if (sscanf(src, "%40[^/]%n", addr_buf, &n) != 2) {
    return -1;
  } else if (!parse_ipvX_addr_string(addr_buf, 0, ip)) {
    return -2;
  } else if (sscanf(src + n, "/%d", &mask) == 0) {
    // no mask specified
    mask = (ip->u.sa.sa_family == AF_INET ? 32 : 8 * 16);
  } else if (mask < 0 || mask > (ip->u.sa.sa_family == AF_INET ? 32 : 8 * 16)) {
    return -3;
  }
  if (mask_n)
    *mask_n = mask;
  if (maskbits) {
    if (ip->u.sa.sa_family == AF_INET) {
      mask = 32 - mask;
      // convert IPv4 mask to IPv6 mask:
      mask += (mask >= 24 ? 24 : mask >= 16 ? 16 : mask >= 8 ? 8 : 0);
    } else {
      mask = 8 * 16 - mask;
    }
    maskbits->ip_addr.v6[0] = (mask < 8 * 16 ? mask > 7 * 16 ? 0xffffU << (8 * 16 - mask) : 0 : 0xffffU);
    maskbits->ip_addr.v6[1] = (mask < 7 * 16 ? mask > 6 * 16 ? 0xffffU << (7 * 16 - mask) : 0 : 0xffffU);
    maskbits->ip_addr.v6[2] = (mask < 6 * 16 ? mask > 5 * 16 ? 0xffffU << (6 * 16 - mask) : 0 : 0xffffU);
    maskbits->ip_addr.v6[3] = (mask < 5 * 16 ? mask > 4 * 16 ? 0xffffU << (5 * 16 - mask) : 0 : 0xffffU);
    maskbits->ip_addr.v6[4] = (mask < 4 * 16 ? mask > 3 * 16 ? 0xffffU << (4 * 16 - mask) : 0 : 0xffffU);
    maskbits->ip_addr.v6[5] = (mask < 3 * 16 ? mask > 2 * 16 ? 0xffffU << (3 * 16 - mask) : 0 : 0xffffU);
    maskbits->ip_addr.v6[6] = (mask < 2 * 16 ? mask > 1 * 16 ? 0xffffU << (2 * 16 - mask) : 0 : 0xffffU);
    maskbits->ip_addr.v6[7] = (mask < 1 * 16 ? mask > 0 * 16 ? 0xffffU << (1 * 16 - mask) : 0 : 0xffffU);
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
      DEBUG_TRACE(("setsockopt SO_RCVTIMEO and SO_SNDTIMEO timeout %d set failed on socket: %d", seconds, sock->sock));
      rv = -1;
    }

#if defined(TCP_USER_TIMEOUT)
    if (setsockopt(sock->sock, SOL_SOCKET, TCP_USER_TIMEOUT, (const void *)&user_timeout, sizeof(user_timeout)) < 0) {
      DEBUG_TRACE(("setsockopt TCP_USER_TIMEOUT timeout %d set failed on socket: %d", seconds, sock->sock));
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
    } else if (so.is_ssl && ctx->ssl_ctx == NULL) {
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
        }
        so.lsa.len = sizeof(so.lsa.u.sin);
        so.lsa.u.sin.sin_family = AF_INET;
        //so.lsa.u.sin.sin_port = htons((uint16_t) port); -- maps to the same spot as sin6_sin6_port so nothing to do
        //so.lsa.u.sin.sin_addr = htonl(INADDR_LOOPBACK);
      }
    }
  }

  if (!success) {
    close_all_listening_sockets(ctx);
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

  (void) fprintf(fp, "%s - %s [%s] \"%s %s HTTP/%s\" %d %s%" INT64_FMT "%s",
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
    flag = vec.ptr[0];
    if (sscanf(vec.ptr, " %c%n", &flag, &i) != 1 && flag != '+' && flag != '-') {
      mg_cry(fc(ctx), "%s: flag must be + or -: [%s]", __func__, vec.ptr);
      return -1;
    }
    switch (parse_ipvX_addr_and_netmask(vec.ptr + i, &ip, &mask, &acl_mask)) {
    case 0:
      break;
    default:
      mg_cry(fc(ctx), "%s: subnet must be [+|-]<IPv4 address: x.x.x.x>[/x] or [+|-]<IPv6 address>[/x], instead we see [%s]", __func__, vec.ptr);
      return -1;
    case -2:
      mg_cry(fc(ctx), "%s: bad ip address: [%s]", __func__, vec.ptr);
      return -1;
    case -3:
      mg_cry(fc(ctx), "%s: bad subnet mask: %d [%s]", __func__, mask, vec.ptr);
      return -1;
    }
    get_socket_ip_address(&acl_subnet, &ip);
    cvt_ipv4_to_ipv6(&acl_subnet, &acl_subnet);

    for (i = 0; i < 8; i++) {
      if (acl_subnet.ip_addr.v6[i] != (remote_ip.ip_addr.v6[i] & acl_mask.ip_addr.v6[i])) {
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

static void add_to_set(SOCKET fd, fd_set *set, int *max_fd) {
  FD_SET(fd, set);
  if (((int)fd) > *max_fd) {
    *max_fd = (int) fd;
  }
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
  SSL_CTX *CTX;
  int i, size;
  const char *pem = get_option(ctx, SSL_CERTIFICATE);
  const char *chain = get_option(ctx, SSL_CHAIN_FILE);

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

  if ((CTX = SSL_CTX_new(SSLv23_server_method())) == NULL) {
    mg_cry(fc(ctx), "SSL_CTX_new error: %s", ssl_error());
  } else {
    call_user_over_ctx(ctx, CTX, MG_INIT_SSL);
  }

  if (CTX != NULL && SSL_CTX_use_certificate_file(CTX, pem,
        SSL_FILETYPE_PEM) == 0) {
    mg_cry(fc(ctx), "%s: cannot open cert file %s: %s", __func__, pem, ssl_error());
    return 0;
  } else if (CTX != NULL && SSL_CTX_use_PrivateKey_file(CTX, pem,
        SSL_FILETYPE_PEM) == 0) {
    mg_cry(fc(ctx), "%s: cannot open private key file %s: %s", __func__, pem, ssl_error());
    return 0;
  }

  if (CTX != NULL && !is_empty(chain) &&
      SSL_CTX_use_certificate_chain_file(CTX, chain) == 0) {
    mg_cry(fc(ctx), "%s: cannot open cert chain file %s: %s", __func__, chain, ssl_error());
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

  // Done with everything. Save the context.
  ctx->ssl_ctx = CTX;

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
  struct usa fake;
  return check_acl(ctx, &fake) != -1;
}

static void reset_per_request_attributes(struct mg_connection *conn) {
  struct mg_request_info *ri = &conn->request_info;

  // Reset request info attributes. DO NOT TOUCH is_ssl, remote_ip, remote_port, local_ip, local_port
  ri->phys_path = NULL;
  ri->remote_user = NULL;
  ri->request_method = NULL;
  ri->query_string = NULL;
  ri->uri = NULL;
  ri->http_version = NULL;
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

  conn->num_bytes_sent = -1;
  conn->consumed_content = 0;
  conn->content_len = -1;
  conn->request_len = 0;
  //conn->must_close = 0;  -- do NOT reset must_close: once set, it should remain so until the connection is closed/dropped
  conn->nested_err_or_pagereq_count = 0;
  conn->tx_can_compact = 0;
  conn->tx_headers_len = 0;
}

static void close_socket_gracefully(struct mg_connection *conn) {
  char buf[BUFSIZ];
  struct linger linger;
  int n, w;
  int linger_timeout = atoi(get_conn_option(conn, SOCKET_LINGER_TIMEOUT)) * 1000;
  SOCKET sock;

  if (!conn || conn->client.sock == INVALID_SOCKET)
      return;
  sock = conn->client.sock;

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

  // Send FIN to the client
  (void) shutdown(sock, SHUT_WR);

  // Read and discard pending incoming data. If we do not do that and close the
  // socket, the data in the send buffer may be discarded. This
  // behaviour is seen on Windows, when client keeps sending data
  // when server decides to close the connection; then when client
  // does recv() it gets no data back.
  w = 1;
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
      // only fetch RX data when there actually is some:
      n = pull(NULL, &conn->client, NULL, buf, sizeof(buf));
      DEBUG_TRACE(("close(%d -> n=%d/t=%d/sel=%d)", sock, n, linger_timeout, sv));
      if (n < 0) {
        w = 0;
        linger_timeout = 0;
        break;
      }
      // fall through: connection closed from the other side. Don't count this against our linger time.
      if (n == 0) {
        tv.tv_sec = tv.tv_usec = 0;
    case 0:
        // timeout expired or remote close signaled:
        n = 0;
        linger_timeout -= tv.tv_sec * 1000;
        linger_timeout -= tv.tv_usec / 1000;
      }
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
  } while ((n > 0 || w > 0) && linger_timeout > 0 && mg_get_stop_flag(conn->ctx) == 0);

  // Set linger option to avoid socket hanging out after close. This prevent
  // ephemeral port exhaust problem under high QPS.
  //
  // Note: as we've already spent part of the 'linger timeout' time in user land
  //       (that is: in the code above), we have a possibly reduced linger
  //       time by now.
  //       Also note that linger_timeout==0 by now when a failure has been
  //       observed above: in that case we do NOT want to linger any longer
  //       so this will then be a *DIS*graveful close.
  linger.l_onoff = (linger_timeout > 0 && mg_get_stop_flag(conn->ctx) == 0);
  linger.l_linger = (linger_timeout + 999) / 1000; // round up
  setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *) &linger, sizeof(linger));
  DEBUG_TRACE(("linger-on-close(%d:t=%d[s])", sock, (int)linger.l_linger));

  if (linger.l_onoff > 0)
    (void) __DisconnectEx(sock, 0, 0, 0);

  // Now we know that our FIN is ACK-ed, safe to close
  (void) closesocket(sock);
  conn->client.sock = INVALID_SOCKET;
}

static void close_connection(struct mg_connection *conn) {
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
  close_socket_gracefully(conn);
}

static void discard_current_request_from_buffer(struct mg_connection *conn) {
  int n;

  // make sure we fetch all content (and discard it), if we
  // haven't done so already (f.e.: event callback handler might've
  // ignored part or whole of the received content) otherwise
  // we've got a b0rked keep-alive HTTP stream:
  //
  // as mg_read() will return 0 as soon as the entire content of the
  // current request has been read, we can simply check for that:
  do {
    char buf[BUFSIZ];
    n = mg_read(conn, buf, sizeof(buf));
  } while (n > 0 && mg_get_stop_flag(conn->ctx) == 0);
  // when an error occurred, we must close the connection
  if (n < 0) {
    conn->must_close = 1;
  } else if (conn->data_len > conn->request_len + conn->consumed_content) {
    int remaining = conn->data_len - conn->request_len - (int)conn->consumed_content;
    memmove(conn->buf, conn->buf + conn->data_len + remaining, remaining);
    conn->data_len = remaining;
  } else {
    conn->data_len = 0;
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
    if (conn->request_info.seq_no > 0) {
      DEBUG_TRACE(("**************************************** round: %d!\n", conn->request_info.seq_no + 1));
    }
    reset_per_request_attributes(conn);
    conn->request_len = read_request(NULL, &conn->client, conn->ssl,
                                     conn->buf, conn->buf_size,
                                     &conn->data_len);
    assert(conn->data_len >= conn->request_len);
    conn->request_info.seq_no++;
    if (conn->request_len == 0 && conn->data_len == conn->buf_size) {
      send_http_error(conn, 413, NULL, "");
      return -1;
    }
    if (conn->request_len <= 0) {
      // In case we didn't receive ANY data, we don't mess with the connection any further
      // by trying to send any error response data, so we tag the connection as done for that:
      if (conn->data_len == 0) {
        mg_mark_end_of_header_transmission(conn);
      }
      // don't mind we cannot send the 5xx response code, as long as we log the issue at least...
      send_http_error(conn, 580, NULL, "%s", mg_strerror(ERRNO));
      return -1;  // Remote end closed the connection or malformed request
    }

    // Nul-terminate the request cause parse_http_request() is C-string based
    conn->buf[conn->request_len - 1] = '\0';
    if (!parse_http_request(conn->buf, ri)
        || !is_valid_uri(ri->uri)) {
      // Do not put garbage in the access log, just send it back to the client
      conn->must_close = 1;
      send_http_error(conn, 400, NULL,
          "Cannot parse HTTP request: [%.*s]", conn->data_len, conn->buf);
    } else if (strcmp(ri->http_version, "1.0") &&
               strcmp(ri->http_version, "1.1")) {
      // Request seems valid, but HTTP version is strange
      conn->must_close = 1;
      send_http_error(conn, 505, NULL, "");
      log_access(conn);
    } else {
      // Request is valid, handle it
      cl = get_header(ri, "Content-Length");
      conn->content_len = (cl == NULL ? -1 : strtoll(cl, NULL, 10));
      conn->birth_time = time(NULL);
      handle_request(conn);
      call_user(conn, MG_REQUEST_COMPLETE);
      log_access(conn);
      discard_current_request_from_buffer(conn);
    }
    if (ri->remote_user != NULL) {
      free((void *) ri->remote_user);
      ri->remote_user = NULL;
    }
    if (!should_keep_alive(conn))
      return 1;
    if (conn->ctx->stop_flag != 0)
      return -1;
    // check whether the connection is still active, i.e. whether it has any
    // more request data pending:
  } while (conn->data_len > 0);
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
static int pull_testset_from_idle_queue(struct mg_context *ctx, int n)
{
  struct mg_idle_connection *arr = ctx->queue_store;
  int head = ctx->sq_head; // the compiler MAY optimize sq_head access in this entire routine!

  if (head >= 0)
  {
    int p, idle_test_set;

    p = idle_test_set = head;
    do
    {
      if ((arr[p].client.was_idle && arr[p].client.has_read_data) || arr[p].client.idle_time_expired)
      {
        // we don't need to test as we already know this node has data for us ~ is 'active',
        // so we only return this one:
        arr[arr[p].prev].next = arr[p].next;
        arr[arr[p].next].prev = arr[p].prev;
        if (head == p)
        {
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
      arr[p].client.has_read_data = 0;
      p = arr[p].next;
    } while (--n > 0 && p != idle_test_set);
    // decouple set from idle queue:
    if (p == idle_test_set)
    {
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
// marked as 'active' at the front of the queue so thy can be picked off
// as fast as possible.
// This procedure makes the idle queue testing behave like a Round Robin process.
static void insert_testset_into_idle_queue(struct mg_context *ctx, int idle_test_set)
{
  // nasty: as we need to re-order the nodes, we do it quick&dirty by placing
  // them in proper in order in this local array (of same size as the idle_queue_store)
  // and then rebuild the linked lists in CTX in one feel swoop.
  int node_set[ARRAY_SIZE(ctx->queue_store) + 4 /* front/end sentinels */];
  int a, z, p, i;
  struct mg_idle_connection *arr = ctx->queue_store;
  int head = ctx->sq_head; // the compiler MAY optimize sq_head access in this entire routine!

  a = 1;
  z = ARRAY_SIZE(node_set) - 1;
  node_set[0] = node_set[ARRAY_SIZE(node_set) - 1] = -1;
  assert(idle_test_set >= 0);
  p = idle_test_set;
  do
  {
    if (arr[p].client.was_idle && arr[p].client.has_read_data)
      node_set[--z] = p;
    else
      node_set[a++] = p;
    p = arr[p].next;
  } while (p != idle_test_set);
  node_set[a] = node_set[z - 1] = -1;

  // rebuild both partial sets:
  for (i = 1; i < a; i++)
  {
    int x = node_set[i];
    int nx = node_set[i + 1];
    int px = node_set[i - 1];

    arr[x].next = nx;
    arr[x].prev = px;
  }
  for (i = z; i < ARRAY_SIZE(node_set) - 1; i++)
  {
    int x = node_set[i];
    int nx = node_set[i + 1];
    int px = node_set[i - 1];

    arr[x].next = nx;
    arr[x].prev = px;
  }

  // 'active' set at the front:
  if (z < ARRAY_SIZE(node_set) - 1)
  {
    int x = node_set[z];
    int lx = node_set[ARRAY_SIZE(node_set) - 2];

    if (head < 0)
    {
      // this one's easy!
      head = x;
      arr[x].prev = lx;
      arr[lx].next = x;
    }
    else
    {
      arr[x].prev = arr[head].prev;
      arr[lx].next = head;
      arr[head].prev = lx;
      arr[arr[head].prev].next = x;
    }
  }
  // still idle set at the back:
  if (a > 1)
  {
    int x = node_set[1];
    int lx = node_set[a - 1];

    if (head < 0)
    {
      // this one's easy!
      head = x;
      arr[x].prev = lx;
      arr[lx].next = x;
    }
    else
    {
      int q = arr[head].prev;

      arr[x].prev = q;
      assert(arr[q].next == head);
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
static int pop_node_from_idle_queue(struct mg_context *ctx, int node, struct mg_connection *conn)
{
  struct mg_idle_connection *arr = ctx->queue_store + node;
  int r;

  assert(node >= 0);
  assert(node < ARRAY_SIZE(ctx->queue_store));
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

  // remove node from any cyclic linked list out there:
  if (arr->next == node)
  {
    r = -1;
  }
  else
  {
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
static int push_conn_onto_idle_queue(struct mg_context *ctx, struct mg_connection *conn)
{
  int i = ctx->idle_q_store_free_slot;
  struct mg_idle_connection *arr = ctx->queue_store + i;
  int head = ctx->sq_head; // the compiler MAY optimize sq_head access in this entire routine!

  if (i < 0)
    return -1;
  assert(i < ARRAY_SIZE(ctx->queue_store));
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
  arr->client.was_idle = 1;

  // add element at the end of the queue:
  if (head < 0)
  {
    head = i;
    arr->prev = arr->next = i;
  }
  else
  {
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

  (void) pthread_mutex_lock(&ctx->mutex);
  // If the queue is empty, wait. We're idle at this point.
  while (ctx->sq_head < 0 && ctx->stop_flag == 0) {
    pthread_cond_wait(&ctx->sq_full, &ctx->mutex);
  }

  do
  {
    int idle_test_set = -1;
    time_t now = time(NULL);

    head = ctx->sq_head;
    // If we're stopping, queue may be empty.
    if (head >= 0 && ctx->stop_flag == 0) {
      idle_test_set = pull_testset_from_idle_queue(ctx, FD_SETSIZE);
      assert(idle_test_set >= 0 ? idle_test_set != head ? ctx->queue_store[idle_test_set].client.was_idle == 1 : 1 : 1);
      assert(idle_test_set >= 0 ? idle_test_set != head ? (ctx->queue_store[idle_test_set].client.has_read_data || ctx->queue_store[idle_test_set].client.idle_time_expired) : 1 : 1);
    }
    (void) pthread_mutex_unlock(&ctx->mutex);

    while (idle_test_set >= 0)
    {
      int sn = idle_test_set;

      // did a previous scan already produce another 'active' node?
      if (!((ctx->queue_store[idle_test_set].client.was_idle && ctx->queue_store[idle_test_set].client.has_read_data) || ctx->queue_store[idle_test_set].client.idle_time_expired))
      {
        fd_set fdr;
        int max_fh = -1;
        struct timeval tv;
        struct mg_idle_connection *arr = ctx->queue_store;
        int p;

        //DEBUG_TRACE(("%s: testing pushed-back (idle) keep-alive connections:", __func__));
        FD_ZERO(&fdr);
        p = idle_test_set;
        do
        {
          // while setting up the FD_SET, also check for idle-timed-out sockets and mark 'em:
          if (arr[p].client.max_idle_seconds > 0 &&
			  arr[p].birth_time + arr[p].client.max_idle_seconds <= now)
            arr[p].client.idle_time_expired = 1;

          add_to_set(arr[p].client.sock, &fdr, &max_fh);
          p = arr[p].next;
        } while (p != idle_test_set);
        // do NOT wait in the select(), just check if anybody has anything for us or not.
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        sn = select(max_fh, &fdr, NULL, NULL, &tv);
        if (sn > 0)
        {
          sn = -1;
          p = idle_test_set;
          do
          {
            arr[p].client.was_idle = 1;  // mark node as tested
            if (FD_ISSET(arr[p].client.sock, &fdr))
            {
              if (sn < 0)
                sn = p;
              arr[p].client.has_read_data = 1;
            }
            else
            {
              assert(arr[p].client.has_read_data == 0);
              if (arr[p].client.idle_time_expired && sn < 0)
                sn = p;
            }
            p = arr[p].next;
          } while (p != idle_test_set);
        }
        else
        {
          sn = -1;
          p = idle_test_set;
          do
          {
            if (arr[p].client.idle_time_expired && sn < 0)
              sn = p;
            arr[p].client.was_idle = 1;  // mark node as tested
            assert(arr[p].client.has_read_data == 0);
            p = arr[p].next;
          } while (p != idle_test_set);
        }
      }

      // did we find an active node? if yes, then remove it from the queue/set and re-insert the rest:
      if (sn >= 0)
      {
        int p;
         
        (void) pthread_mutex_lock(&ctx->mutex);
        p = pop_node_from_idle_queue(ctx, sn, conn);
        if (sn == idle_test_set)
        {
          idle_test_set = p;
        }
        if (idle_test_set >= 0)
        {
          insert_testset_into_idle_queue(ctx, idle_test_set);
        }
        (void) pthread_mutex_unlock(&ctx->mutex);
        
        DEBUG_TRACE(("grabbed socket %d, going busy", conn->client.sock));
        return 1;
      }
      else
      {
        (void) pthread_mutex_lock(&ctx->mutex);
        assert(idle_test_set >= 0);
        insert_testset_into_idle_queue(ctx, idle_test_set);
        // did we get to test them all yet? (see NOTE above pull_testset_from_idle_queue() function implementation about was_idle manipulation)
        head = ctx->sq_head;
        if (head >= 0 && ctx->stop_flag == 0 && ctx->queue_store[head].client.was_idle == 0)
        {
          // still more nodes to test
          idle_test_set = pull_testset_from_idle_queue(ctx, FD_SETSIZE);
        }
        else
        {
          idle_test_set = -1;
        }
        (void) pthread_mutex_unlock(&ctx->mutex);
      }
    }

    // when we get here, we can be sure there's no-one active in the test set: try again until it's server termination time
    //DEBUG_TRACE(("going idle"));

    (void) pthread_mutex_lock(&ctx->mutex);
    (void) pthread_cond_signal(&ctx->sq_empty);

    // If the queue is empty, wait longer. We're idle at this point.
    while (ctx->stop_flag == 0) {
      struct timespec tv = {0};

      if (ctx->sq_head >= 0) {
        tv.tv_sec = (MG_SELECT_TIMEOUT_MSECS / 10) / 1000;
        tv.tv_nsec = (MG_SELECT_TIMEOUT_MSECS / 10) * 1000000;
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
  conn->birth_time = time(NULL);

  (void) pthread_mutex_lock(&ctx->mutex);

  while (ctx->stop_flag == 0 && rv == 0) {
    int full = push_conn_onto_idle_queue(ctx, conn);
    // If the queue is full, wait
    if (full < 0 && ctx->stop_flag == 0) {
      (void) pthread_cond_wait(&ctx->sq_empty, &ctx->mutex);
    } else if (full >= 0) {
      rv = 1;
      DEBUG_TRACE(("queued socket %d", conn->client.sock));
    }
  }

  if (rv)
    (void) pthread_cond_signal(&ctx->sq_full);
  (void) pthread_mutex_unlock(&ctx->mutex);
  
  return rv;
}

static void worker_thread(struct mg_context *ctx) {
  struct mg_connection *conn;
  int buf_size = atoi(get_option(ctx, MAX_REQUEST_SIZE));

  conn = (struct mg_connection *) calloc(1, sizeof(*conn) + buf_size * 3); /* RX headers, TX headers, scratch space */
  if (conn == NULL) {
    mg_cry(fc(ctx), "Cannot create new connection struct, OOM");
    return;
  }

  // Call consume_socket() even when ctx->stop_flag > 0, to let it signal
  // sq_empty condvar to wake up the master waiting in produce_socket()
  while (consume_socket(ctx, conn)) {
    int doing_fine = 1;

    // everything in 'conn' is zeroed at this point in time: set up the buffers, etc.
    conn->buf_size = buf_size;
    conn->buf = (char *) (conn + 1);
    conn->ctx = ctx;
    conn->request_info.is_ssl = conn->client.is_ssl;
    if (conn->client.idle_time_expired) {
      DEBUG_TRACE(("%s: kept-alive(?) connection expired (keep-alive-timeout)", __func__));
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
          (conn->client.is_ssl && sslize(conn, SSL_accept))) {
        reset_per_request_attributes(conn); // otherwise the callback will receive arbitrary (garbage) data
        doing_fine = 1;
        conn->is_inited = 1;
        call_user(conn, MG_INIT_CLIENT_CONN);
      } else {
        mg_cry(conn, "%s: socket %d failed to initialize completely: %s", __func__, (int)conn->client.sock, mg_strerror(ERRNO));
      }
    } else if (doing_fine) {
      DEBUG_TRACE(("%s: revived kept-alive socket %d", __func__, (int)conn->client.sock));
    } else {
      DEBUG_TRACE(("%s: closing expired connection socket %d", __func__, (int)conn->client.sock));
    }

    if (doing_fine) {
      doing_fine = !process_new_connection(conn);
    }

    if (!doing_fine) {
      DEBUG_TRACE(("%s: closing connection", __func__));
      reset_per_request_attributes(conn); // otherwise the callback will receive arbitrary (garbage) data
      call_user(conn, MG_EXIT_CLIENT_CONN);
      close_connection(conn);
      // Clear everything in conn to ensure no value makes it into the next connection/session.
      // (Also clears the cached logfile path so it is recalculated on the next log operation.)
      memset(conn, 0, sizeof(*conn));
    } else {
      // The simplest way is to push the current connection onto the queue, and then
      // let consume_socket() [and its internal select() logic] cope with it.
      DEBUG_TRACE(("%s: pushing MAYBE-IDLE connection back onto the queue", __func__));
      if (!produce_socket(ctx, conn)) {
        char src_addr[SOCKADDR_NTOA_BUFSIZE];
        mg_cry(fc(ctx), "%s: closing active connection %s because server is shutting down",
               __func__, sockaddr_to_string(src_addr, sizeof(src_addr), &conn->client.rsa));
        break;
      }
    }
  }
  free(conn);

  // Signal master that we're done with connection and exiting
  (void) pthread_mutex_lock(&ctx->mutex);
  ctx->num_threads--;
  (void) pthread_cond_signal(&ctx->cond);
  assert(ctx->num_threads >= 0);
  (void) pthread_mutex_unlock(&ctx->mutex);

  DEBUG_TRACE(("exiting"));
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
      DEBUG_TRACE(("accepted socket %d", accepted.sock));
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

static void master_thread(struct mg_context *ctx) {
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
            break; // do NOT check the other (now invalid) listeners!
          }
        }
      }
    }
  }

  // fix: issue 345 for the master thread
  call_user_over_ctx(ctx, 0, MG_EXIT_MASTER);

  DEBUG_TRACE(("stopping workers"));

  // Stop signal received: somebody called mg_stop. Quit.
  close_all_listening_sockets(ctx);

  // Wakeup workers that are waiting for connections to handle.
  pthread_cond_broadcast(&ctx->sq_full);

  // Wait until all threads finish
  (void) pthread_mutex_lock(&ctx->mutex);
  while (ctx->num_threads > 0) {
    (void) pthread_cond_wait(&ctx->cond, &ctx->mutex);
  }

  // forcibly close all pending (accepted) sockets remaining in the queue:

  // If we're stopping, sq_head may be equal to sq_tail.
  while (ctx->sq_head >= 0) {
    // close socket from the queue and increment tail
    struct mg_connection dummy_conn = {0};
    ctx->sq_head = pop_node_from_idle_queue(ctx, ctx->sq_head, &dummy_conn);
    DEBUG_TRACE(("grabbed socket %d, forcibly closing the bugger", dummy_conn.client.sock));
    close_socket_UNgracefully(dummy_conn.client.sock);
  }

  (void) pthread_mutex_unlock(&ctx->mutex);

  // All threads exited, no sync is needed. Destroy mutex and condvars
  (void) pthread_mutex_destroy(&ctx->mutex);
  (void) pthread_cond_destroy(&ctx->cond);
  (void) pthread_cond_destroy(&ctx->sq_empty);
  (void) pthread_cond_destroy(&ctx->sq_full);

#if !defined(NO_SSL)
  uninitialize_ssl(ctx);
#endif

  // Signal mg_stop() that we're done
  ctx->stop_flag = 2;

  DEBUG_TRACE(("exiting"));

  // fix: issue 345 for the master thread
  call_user_over_ctx(ctx, 0, MG_EXIT_SERVER);
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
  ctx->stop_flag = 1;

  // Wait until mg_finish() stops
  while (ctx->stop_flag != 2) {
    (void) mg_sleep(10);
  }

  // call the user event handler to make sure the custom code is aware of this termination as well and do some final cleanup:
  call_user_over_ctx(ctx, ctx->ssl_ctx, MG_EXIT0);

  free_context(ctx);

#if defined(_WIN32) && !defined(__SYMBIAN32__)
  DeleteCriticalSection(&global_log_file_lock);
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
  InitializeCriticalSection(&global_log_file_lock);
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
  for (i = 0; i < ARRAY_SIZE(ctx->queue_store) - 1; i++) {
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
        DEBUG_TRACE(("[%s] -> [%s]", name, value));
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
    assert(i < (int)ARRAY_SIZE(ctx->config));
    assert(i >= 0);
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
    DEBUG_TRACE(("[%s] -> [%s]", name, ctx->config[i]));
  }

  // Set default value if needed
  for (i = 0; config_options[i * MG_ENTRIES_PER_CONFIG_OPTION] != NULL; i++) {
    default_value = config_options[i * MG_ENTRIES_PER_CONFIG_OPTION + 2];
    if (ctx->config[i] == NULL && default_value != NULL) {
      ctx->config[i] = mg_strdup(default_value);
      DEBUG_TRACE(("Setting default: [%s] -> [%s]",
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
      !set_ssl_option(ctx) ||
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
  if (start_thread(ctx, (mg_thread_func_t) master_thread, ctx) != 0) {
    mg_cry(fc(ctx), "Cannot start master thread: %d (%s)", ERRNO, mg_strerror(ERRNO));
    free_context(ctx);
    return NULL;
  }

  // Start worker threads
  i = atoi(get_option(ctx, NUM_THREADS));
  if (i < 1) i = 1;
  for ( ; i > 0; i--) {
    if (start_thread(ctx, (mg_thread_func_t) worker_thread, ctx) != 0) {
      mg_cry(fc(ctx), "Cannot start worker thread: %d (%s)", ERRNO, mg_strerror(ERRNO));
    } else {
      (void) pthread_mutex_lock(&ctx->mutex);
      ctx->num_threads++;
      (void) pthread_mutex_unlock(&ctx->mutex);
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

struct mg_context *mg_get_context(struct mg_connection *conn) {
    return conn ? conn->ctx : NULL;
}

struct mg_request_info *mg_get_request_info(struct mg_connection *conn) {
  return conn ? &conn->request_info : NULL;
}



int mg_get_stop_flag(struct mg_context *ctx) {
    return ctx && ctx->stop_flag;
}

void mg_signal_stop(struct mg_context *ctx) {
  ctx->stop_flag = 1;
}

