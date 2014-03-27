#include "internal.h"

static int mg_stat(const char *path, struct file *filep) {
  struct stat st;

  filep->modification_time = (time_t) 0;
  if (stat(path, &st) == 0) {
    filep->size = st.st_size;
    filep->modification_time = st.st_mtime;
    filep->is_directory = S_ISDIR(st.st_mode);

    // See https://github.com/cesanta/mongoose/issues/109
    // Some filesystems report modification time as 0. Artificially
    // bump it up to mark mg_stat() success.
    if (filep->modification_time == (time_t) 0) {
      filep->modification_time = (time_t) 1;
    }
  }

  return filep->modification_time != (time_t) 0;
}

static void set_close_on_exec(int fd) {
  fcntl(fd, F_SETFD, FD_CLOEXEC);
}

int mg_start_thread(mg_thread_func_t func, void *param) {
  pthread_t thread_id;
  pthread_attr_t attr;
  int result;

  (void) pthread_attr_init(&attr);
  (void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

#if USE_STACK_SIZE > 1
  // Compile-time option to control stack size, e.g. -DUSE_STACK_SIZE=16384
  (void) pthread_attr_setstacksize(&attr, USE_STACK_SIZE);
#endif

  result = pthread_create(&thread_id, &attr, func, param);
  pthread_attr_destroy(&attr);

  return result;
}


static int set_non_blocking_mode(SOCKET sock) {
  int flags;

  flags = fcntl(sock, F_GETFL, 0);
  (void) fcntl(sock, F_SETFL, flags | O_NONBLOCK);

  return 0;
}
