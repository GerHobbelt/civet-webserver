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


#ifndef MONGOOSE_SYS_PORTING_INCLUDE
#define MONGOOSE_SYS_PORTING_INCLUDE

#if defined(_WIN32)
#define _CRT_SECURE_NO_WARNINGS // Disable deprecation warning in VS2005
#else
#define _XOPEN_SOURCE 600     // For PATH_MAX and flockfile() on Linux
#define _LARGEFILE_SOURCE     // Enable 64-bit file offsets
#define __STDC_FORMAT_MACROS  // <inttypes.h> wants this for C++
#define __STDC_LIMIT_MACROS   // C++ wants that for INT64_MAX
#endif

#if defined(__SYMBIAN32__)
#define NO_SSL // SSL is not supported
#define NO_CGI // CGI is not supported
#define PATH_MAX FILENAME_MAX
#endif // __SYMBIAN32__

#ifndef _WIN32_WCE // Some ANSI #includes are not available on Windows CE
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#endif // !_WIN32_WCE

#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>

#if defined(_WIN32) && !defined(__SYMBIAN32__) // Windows specific
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600 // To make it link in VS200x (with IPv6 support from Vista onwards)
#endif
// load winSock2 before windows.h or you won't be able to access to IPv6 goodness due to windows.h loading winsock.h (v1):
#include <ws2tcpip.h>
#include <windows.h>

#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif

#ifndef _WIN32_WCE
#include <process.h>
#include <direct.h>
#include <io.h>
#else // _WIN32_WCE
#define NO_CGI // WinCE has no pipes

typedef long off_t;
#define BUFSIZ  4096

#define errno   GetLastError()
#define strerror(x)  _ultoa(x, (char *) _alloca(sizeof(x) *3 ), 10)
#endif // _WIN32_WCE

#define MAKEUQUAD(lo, hi) ((uint64_t)(((uint32_t)(lo)) | \
      ((uint64_t)((uint32_t)(hi))) << 32))
#define RATE_DIFF 10000000 // 100 nsecs
#define EPOCH_DIFF MAKEUQUAD(0xd53e8000, 0x019db1de)
#define SYS2UNIX_TIME(lo, hi) \
  (time_t) ((MAKEUQUAD((lo), (hi)) - EPOCH_DIFF) / RATE_DIFF)

// Visual Studio 6 does not know __func__ or __FUNCTION__
// The rest of MS compilers use __FUNCTION__, not C99 __func__
// Also use _strtoui64 on modern M$ compilers
#if defined(_MSC_VER)
#if _MSC_VER < 1300
#define STRX(x) #x
#define STR(x) STRX(x)
#define __func__ "line " STR(__LINE__)
#define strtoull(x, y, z) strtoul(x, y, z)
#define strtoll(x, y, z) strtol(x, y, z)
#else
#define __func__  __FUNCTION__
#define strtoull(x, y, z) _strtoui64(x, y, z)
#define strtoll(x, y, z) _strtoi64(x, y, z)
#endif // _MSC_VER
#endif // _MSC_VER

#define ERRNO   GetLastError()
#define NO_SOCKLEN_T
#define SSL_LIB   "ssleay32.dll"
#define CRYPTO_LIB  "libeay32.dll"
#define DIRSEP '\\'
#define IS_DIRSEP_CHAR(c) ((c) == '/' || (c) == '\\')
#define PATH_MAX MAX_PATH
#define S_ISDIR(x) ((x) & _S_IFDIR)
#define O_NONBLOCK  0

#if !defined(EWOULDBLOCK)
#define EWOULDBLOCK  WSAEWOULDBLOCK
#endif // !EWOULDBLOCK

#ifndef ETIMEOUT
#define ETIMEOUT    WSAETIMEDOUT
#endif

#define _POSIX_
#define INT64_FMT  "I64d"

#define WINCDECL __cdecl
#define SHUT_WR 1
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define mg_sleep(x) Sleep(x)

#define pipe(x) _pipe(x, BUFSIZ, _O_BINARY)
#define popen(x, y) _popen(x, y)
#define pclose(x) _pclose(x)
#define close(x) _close(x)
#define dlsym(x,y) GetProcAddress((HINSTANCE) (x), (y))
#define RTLD_LAZY  0
#define fseeko(x, y, z) fseek((x), (y), (z))
#define fdopen(x, y) _fdopen((x), (y))
#define write(x, y, z) _write((x), (y), (unsigned) z)
#define read(x, y, z) _read((x), (y), (unsigned) z)

void mgW32_flockfile(FILE *x);
void mgW32_funlockfile(FILE *x);
#define flockfile mgW32_flockfile
#define funlockfile mgW32_funlockfile

#if !defined(fileno)
#define fileno(x) _fileno(x)
#endif // !fileno MINGW #defines fileno

#if !defined(HAVE_PTHREAD)

typedef HANDLE pthread_mutex_t;
typedef struct {HANDLE signal, broadcast;} pthread_cond_t;
typedef DWORD pthread_t;

struct timespec {
  long tv_nsec;
  long tv_sec;
};

#else

#include <pthread.h>

#endif

#define pid_t HANDLE // MINGW typedefs pid_t to int. Using #define here.  It also overrides the pid_t typedef in pthread.h (--> sched.h) for pthread-win32




#if defined(HAVE_STDINT) || (defined(_MSC_VER) && _MSC_VER >= 1500)
#include <stdint.h>
#else
typedef unsigned int  uint32_t;
typedef unsigned char  uint8_t;
typedef unsigned short  uint16_t;
typedef unsigned __int64 uint64_t;
typedef __int64   int64_t;
#define INT64_MAX  9223372036854775807LL
#endif // HAVE_STDINT

// POSIX dirent interface
struct dirent {
  char d_name[PATH_MAX];
};

typedef struct DIR {
  HANDLE   handle;
  WIN32_FIND_DATAW info;
  struct dirent  result;
} DIR;

int mg_rename(const char* oldname, const char* newname);
int mg_remove(const char *path);
int mg_mkdir(const char *path, int mode);

#else    // UNIX  specific

#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
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
#define DIRSEP   '/'
#define IS_DIRSEP_CHAR(c) ((c) == '/')
#ifndef O_BINARY
#define O_BINARY  0
#endif // O_BINARY
#define closesocket(a) close(a)
//#define mg_fopen(x, y) fopen(x, y)
#define mg_mkdir(x, y) mkdir(x, y)
#define mg_remove(x) remove(x)
#define mg_rename(x, y) rename(x, y)
#define mg_sleep(x) usleep((x) * 1000)
#define ERRNO errno
#define INVALID_SOCKET (-1)
#define INT64_FMT PRId64
typedef int SOCKET;
#define WINCDECL

#endif // End of Windows and UNIX specific includes

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#define MG_MAX(a, b)      ((a) >= (b) ? (a) : (b))

/*
 * The following VA_COPY was coded following an example in
 * the Samba project.  It may not be sufficient for some
 * esoteric implementations of va_list (i.e. it may need
 * something involving a memcpy) but (hopefully) will be
 * sufficient for mongoose (code taken from libxml2 and augmented).
 */
#ifndef VA_COPY
  #if defined(HAVE_VA_COPY) || defined(va_copy) /* Linux stdarg.h 'regular' flavor */
    #define VA_COPY(dest, src) va_copy(dest, src)
  #else
    #if defined(HAVE___VA_COPY) || defined(__va_copy)  /* Linux stdarg.h 'strict ANSI' flavor */
      #define VA_COPY(dest,src) __va_copy(dest, src)
    #else
      #define VA_COPY(dest,src) do { (dest) = (src); } while (0) /* MSVC: doesn't offer va_copy at all. */
    #endif
  #endif
#endif


/* <bel>: Local fix for some linux sdk headers that do not know these options */
#ifndef SOMAXCONN
#define SOMAXCONN 128
#endif
/* <bel>: end fix */

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif


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

// Darwin prior to 7.0 and Win32 do not have socklen_t
#ifdef NO_SOCKLEN_T
typedef int socklen_t;
#endif // NO_SOCKLEN_T

/* buffer size that will fit both IPv4 and IPv6 addresses formatted by ntoa() / ntop() */
#define SOCKADDR_NTOA_BUFSIZE			42

/* buffer size used when copying data to/from file/socket/... */
#define DATA_COPY_BUFSIZ                MG_MAX(BUFSIZ, 4096)
/* buffer size used to load all HTTP headers into: if the client sends more header data than this, we'll barf a hairball! */
#define HTTP_HEADERS_BUFSIZ             MG_MAX(BUFSIZ, 2048)
/* buffer size used to extract/decode an SSI command line / file path; hence must be equal or larger than PATH_MAX, at least */
#define SSI_LINE_BUFSIZ                 MG_MAX(BUFSIZ, PATH_MAX)




#if defined(_WIN32) && !defined(__SYMBIAN32__)

#if !defined(HAVE_PTHREAD)

/*
 * POSIX pthread features support:
 */
#undef _POSIX_THREADS

#undef _POSIX_READER_WRITER_LOCKS
#define _POSIX_READER_WRITER_LOCKS	200809L

#undef _POSIX_SPIN_LOCKS
#define _POSIX_SPIN_LOCKS			200809L

#undef _POSIX_BARRIERS

#undef _POSIX_THREAD_SAFE_FUNCTIONS

#undef _POSIX_THREAD_ATTR_STACKSIZE

int pthread_mutex_init(pthread_mutex_t *mutex, void *unused);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_cond_init(pthread_cond_t *cv, const void *unused);
int pthread_cond_wait(pthread_cond_t *cv, pthread_mutex_t *mutex);
int pthread_cond_timedwait(pthread_cond_t *cv, pthread_mutex_t *mutex, const struct timespec *abstime);
int pthread_cond_signal(pthread_cond_t *cv);
int pthread_cond_broadcast(pthread_cond_t *cv);
int pthread_cond_destroy(pthread_cond_t *cv);
pthread_t pthread_self(void);

typedef struct {
    SRWLOCK lock;
    unsigned rw: 1;
} pthread_rwlock_t;

typedef void pthread_rwlockattr_t;

int pthread_rwlock_init(pthread_rwlock_t *rwlock, const pthread_rwlockattr_t *attr);

#define PTHREAD_RWLOCK_INITIALIZER			{ RTL_SRWLOCK_INIT }

int pthread_rwlock_destroy(pthread_rwlock_t *rwlock);
int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_unlock(pthread_rwlock_t *rwlock);

//#define PTHREAD_SPINLOCK_INITIALIZER		PTHREAD_MUTEX_INITIALIZER

typedef pthread_mutex_t pthread_spinlock_t;

int pthread_spin_init(pthread_spinlock_t *lock, int pshared);
int pthread_spin_destroy(pthread_spinlock_t *lock);
int pthread_spin_lock(pthread_spinlock_t *lock);
//int pthread_spin_trylock(pthread_spinlock_t *lock);
int pthread_spin_unlock(pthread_spinlock_t *lock);

#endif



#if defined(_WIN32_WCE)
time_t time(time_t *ptime);

struct tm *localtime(const time_t *ptime, struct tm *ptm);

struct tm *gmtime(const time_t *ptime, struct tm *ptm);

static size_t strftime(char *dst, size_t dst_size, const char *fmt,
                       const struct tm *tm);

#endif


#else


#endif // _WIN32






#endif // MONGOOSE_SYS_PORTING_INCLUDE

