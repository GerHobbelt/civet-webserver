#ifndef INTERNAL_HEADER_INCLUDED
#define INTERNAL_HEADER_INCLUDED
// Copyright (c) 2004-2013 Sergey Lyubka <valenok@gmail.com>
// Copyright (c) 2013 Cesanta Software Limited
// All rights reserved
//
// This library is dual-licensed: you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation. For the terms of this
// license, see <http://www.gnu.org/licenses/>.
//
// You are free to use this library under the terms of the GNU General
// Public License, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// Alternatively, you can license this library under a commercial
// license, as set out in <http://cesanta.com/products.html>.

#define _XOPEN_SOURCE 600     // For flockfile() on Linux

#if !defined(_LARGEFILE_SOURCE)
#define _LARGEFILE_SOURCE     // Enable 64-bit file offsets
#endif

#define __STDC_FORMAT_MACROS  // <inttypes.h> wants this for C++
#define __STDC_LIMIT_MACROS   // C++ wants that for INT64_MAX


#if defined (_MSC_VER)
// conditional expression is constant: introduced by FD_SET(..)
#pragma warning (disable : 4127)
// non-constant aggregate initializer: issued due to missing C99 support
#pragma warning (disable : 4204)
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>

#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdint.h>
#include <inttypes.h>
#include <netdb.h>

#include <pwd.h>
#include <unistd.h>
#include <dirent.h>
#if !defined(NO_SSL_DL) && !defined(NO_SSL)
#include <dlfcn.h>
#endif
#include <pthread.h>
#if defined(__MACH__)
#define SSL_LIB   "libssl.dylib"
#define CRYPTO_LIB  "libcrypto.dylib"
#else
#if !defined(SSL_LIB)
#define SSL_LIB   "libssl.so"
#endif
#if !defined(CRYPTO_LIB)
#define CRYPTO_LIB  "libcrypto.so"
#endif
#endif
#ifndef O_BINARY
#define O_BINARY  0
#endif // O_BINARY
#define closesocket(a) close(a)
#define mg_mkdir(x, y) mkdir(x, y)
#define mg_remove(x) remove(x)
#define mg_sleep(x) usleep((x) * 1000)
#define ERRNO errno
#define INVALID_SOCKET (-1)
#define INT64_FMT PRId64
typedef int SOCKET;
#define WINCDECL

#include "mingoose.h"

#define MONGOOSE_VERSION "0.0.1"
#define PASSWORDS_FILE_NAME ".htpasswd"
#define CGI_ENVIRONMENT_SIZE 4096
#define MAX_CGI_ENVIR_VARS 64
#define MG_BUF_LEN 8192
#define MAX_REQUEST_SIZE 16384
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#ifdef DEBUG_TRACE
#undef DEBUG_TRACE
#define DEBUG_TRACE(x)
#else
#if defined(DEBUG)
#define DEBUG_TRACE(x) do { \
  flockfile(stdout); \
  printf("*** %lu.%p.%s.%d: ", \
         (unsigned long) time(NULL), (void *) pthread_self(), \
         __func__, __LINE__); \
  printf x; \
  putchar('\n'); \
  fflush(stdout); \
  funlockfile(stdout); \
} while (0)
#else
#define DEBUG_TRACE(x)
#endif // DEBUG
#endif // DEBUG_TRACE

// Darwin prior to 7.0 and Win32 do not have socklen_t
#ifdef NO_SOCKLEN_T
typedef int socklen_t;
#endif // NO_SOCKLEN_T
#define _DARWIN_UNLIMITED_SELECT

#define IP_ADDR_STR_LEN 50  // IPv6 hex string is 46 chars

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#if !defined(SOMAXCONN)
#define SOMAXCONN 100
#endif

#if !defined(PATH_MAX)
#define PATH_MAX 4096
#endif

// Size of the accepted socket queue
#if !defined(MGSQLEN)
#define MGSQLEN 20
#endif

// Extra HTTP headers to send in every static file reply
#if !defined(EXTRA_HTTP_HEADERS)
#define EXTRA_HTTP_HEADERS ""
#endif

static const char *http_500_error = "Internal Server Error";

#include <openssl/ssl.h>
#include <openssl/err.h>

// Unified socket address. For IPv6 support, add IPv6 address structure
// in the union u.
union usa {
  struct sockaddr sa;
  struct sockaddr_in sin;
#if defined(USE_IPV6)
  struct sockaddr_in6 sin6;
#endif
};

// Describes a string (chunk of memory).
struct vec {
  const char *ptr;
  size_t len;
};

struct file {
  int is_directory;
  time_t modification_time;
  int64_t size;
  // set to 1 if the content is gzipped
  // in which case we need a content-encoding: gzip header
  int gzipped;
};
#define STRUCT_FILE_INITIALIZER { 0, 0, 0, 0 }

// Describes listening socket, or socket which was accept()-ed by the master
// thread and queued for future handling by the worker thread.
struct socket {
  SOCKET sock;          // Listening socket
  union usa lsa;        // Local socket address
  union usa rsa;        // Remote socket address
  unsigned is_ssl:1;    // Is port SSL-ed
  unsigned ssl_redir:1; // Is port supposed to redirect everything to SSL port
};

// NOTE(lsm): this enum shoulds be in sync with the config_options.
enum {
  CGI_EXTENSIONS, CGI_ENVIRONMENT, PUT_DELETE_PASSWORDS_FILE, CGI_INTERPRETER,
  PROTECT_URI, AUTHENTICATION_DOMAIN, SSI_EXTENSIONS, THROTTLE,
  ACCESS_LOG_FILE, ENABLE_DIRECTORY_LISTING, ERROR_LOG_FILE,
  GLOBAL_PASSWORDS_FILE, INDEX_FILES, ENABLE_KEEP_ALIVE, ACCESS_CONTROL_LIST,
  EXTRA_MIME_TYPES, LISTENING_PORTS, DOCUMENT_ROOT, SSL_CERTIFICATE,
  NUM_THREADS, RUN_AS_USER, REWRITE, HIDE_FILES, REQUEST_TIMEOUT,
  NUM_OPTIONS
};

struct mg_context {
  volatile int stop_flag;         // Should we stop event loop
  SSL_CTX *ssl_ctx;               // SSL context
  char *config[NUM_OPTIONS];      // Mongoose configuration parameters
  mg_event_handler_t event_handler;  // User-defined callback function
  void *user_data;                // User-defined data

  struct socket *listening_sockets;
  int num_listening_sockets;

  volatile int num_threads;  // Number of threads
  pthread_mutex_t mutex;     // Protects (max|num)_threads
  pthread_cond_t  cond;      // Condvar for tracking workers terminations

  struct socket queue[MGSQLEN];   // Accepted sockets
  volatile int sq_head;      // Head of the socket queue
  volatile int sq_tail;      // Tail of the socket queue
  pthread_cond_t sq_full;    // Signaled when socket is produced
  pthread_cond_t sq_empty;   // Signaled when socket is consumed
};

struct mg_connection {
  struct mg_request_info request_info;
  struct mg_event event;
  struct mg_context *ctx;
  SSL *ssl;                   // SSL descriptor
  SSL_CTX *client_ssl_ctx;    // SSL context for client connections
  struct socket client;       // Connected client
  time_t birth_time;          // Time when request was received
  int64_t num_bytes_sent;     // Total bytes sent to client
  int64_t content_len;        // Content-Length header value
  int64_t num_bytes_read;     // Bytes read from a remote socket
  char *buf;                  // Buffer for received data
  char *path_info;            // PATH_INFO part of the URL
  int must_close;             // 1 if connection must be closed
  int buf_size;               // Buffer size
  int request_len;            // Size of the request + headers in a buffer
  int data_len;               // Total size of data in a buffer
  int status_code;            // HTTP reply status code, e.g. 200
  int throttle;               // Throttling, bytes/sec. <= 0 means no throttle
  time_t last_throttle_time;  // Last time throttled data was sent
  int64_t last_throttle_bytes;// Bytes sent this second
};

// Directory entry
struct de {
  struct mg_connection *conn;
  char *file_name;
  struct file file;
};

static FILE *mg_fopen(const char *path, const char *mode);
static int mg_stat(const char *path, struct file *filep);
static void send_http_error(struct mg_connection *, int, const char *,
                            PRINTF_FORMAT_STRING(const char *fmt), ...)
                            PRINTF_ARGS(4, 5);
static void cry(struct mg_connection *conn,
                PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(2, 3);
static int getreq(struct mg_connection *conn, char *ebuf, size_t ebuf_len);

#ifdef USE_LUA
#include "lua_5.2.1.h"
static int handle_lsp_request(struct mg_connection *, const char *,
                              struct file *, struct lua_State *);
#endif

#endif // INTERNAL_HEADER_INCLUDED

