// Copyright (c) 2004-2011 Sergey Lyubka
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

#if defined(_WIN32)
#define _CRT_SECURE_NO_WARNINGS  // Disable deprecation warning in VS2005
#else
#define _XOPEN_SOURCE 600  // For PATH_MAX on linux
#endif

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdarg.h>

#include "mongoose.h"

#ifdef _WIN32
#include <windows.h>
#include <winsvc.h>
#define PATH_MAX MAX_PATH
#define S_ISDIR(x) ((x) & _S_IFDIR)
#define DIRSEP '\\'
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define sleep(x) Sleep((x) * 1000)
#define WINCDECL __cdecl
#else
#include <sys/wait.h>
#include <unistd.h>
#define DIRSEP '/'
#define WINCDECL
#endif // _WIN32

#define MAX_OPTIONS 40
#define MAX_CONF_FILE_LINE_SIZE (8 * 1024)

static int exit_flag;
static char server_name[40];        // Set by init_server_name()
static char config_file[PATH_MAX];  // Set by process_command_line_arguments()
static struct mg_context *ctx;      // Set by start_mongoose()

#if !defined(CONFIG_FILE)
#define CONFIG_FILE "mongoose.conf"
#endif /* !CONFIG_FILE */

static void WINCDECL signal_handler(int sig_num) {
  exit_flag = sig_num;
}

static void die(const char *fmt, ...) {
  va_list ap;
  char msg[200];

  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);

#if defined(_WIN32)
  MessageBox(NULL, msg, "Error", MB_OK);
#else
  fprintf(stderr, "%s\n", msg);
#endif

  exit(EXIT_FAILURE);
}

static void show_usage_and_exit(void) {
  const char **names;
  int i;

  fprintf(stderr, "Mongoose version %s (c) Sergey Lyubka\n", mg_version());
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  mongoose -A <htpasswd_file> <realm> <user> <passwd>\n");
  fprintf(stderr, "  mongoose <config_file>\n");
  fprintf(stderr, "  mongoose [-option value ...]\n");
  fprintf(stderr, "OPTIONS:\n");

  names = mg_get_valid_option_names();
  for (i = 0; names[i] != NULL; i += 3) {
    fprintf(stderr, "  -%s %s (default: \"%s\")\n",
            names[i], names[i + 1], names[i + 2] == NULL ? "" : names[i + 2]);
  }
  fprintf(stderr, "See  http://code.google.com/p/mongoose/wiki/MongooseManual"
          " for more details.\n");
  fprintf(stderr, "Example:\n  mongoose -s cert.pem -p 80,443s -d no\n");
  exit(EXIT_FAILURE);
}

static void verify_document_root(const char *root) {
  const char *p, *path;
  char buf[PATH_MAX];
  struct stat st;

  path = root;
  if ((p = strchr(root, ',')) != NULL && (size_t) (p - root) < sizeof(buf)) {
    memcpy(buf, root, p - root);
    buf[p - root] = '\0';
    path = buf;
  }

  if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
    die("Invalid root directory: [%s]: %s", root, strerror(errno));
  }
}

static char *sdup(const char *str) {
  char *p;
  if ((p = (char *) malloc(strlen(str) + 1)) != NULL) {
    strcpy(p, str);
  }
  return p;
}

static void set_option(char **options, const char *name, const char *value) {
  int i;

  if (!strcmp(name, "document_root") || !(strcmp(name, "r"))) {
    verify_document_root(value);
  }

  for (i = 0; i < MAX_OPTIONS - 3; i++) {
    if (options[i] == NULL) {
      options[i] = sdup(name);
      options[i + 1] = sdup(value);
      options[i + 2] = NULL;
      break;
    }
  }

  if (i == MAX_OPTIONS - 3) {
    die("%s", "Too many options specified");
  }
}

static void process_command_line_arguments(char *argv[], char **options) {
  char line[MAX_CONF_FILE_LINE_SIZE], opt[sizeof(line)], val[sizeof(line)], *p;
  FILE *fp = NULL;
  size_t i, cmd_line_opts_start = 1, line_no = 0;

  options[0] = NULL;

  // Should we use a config file ?
  if (argv[1] != NULL && argv[1][0] != '-') {
    snprintf(config_file, sizeof(config_file), "%s", argv[1]);
    cmd_line_opts_start = 2;
  } else if ((p = strrchr(argv[0], DIRSEP)) == NULL) {
    // No command line flags specified. Look where binary lives
    snprintf(config_file, sizeof(config_file), "%s", CONFIG_FILE);
  } else {
    snprintf(config_file, sizeof(config_file), "%.*s%c%s",
             (int) (p - argv[0]), argv[0], DIRSEP, CONFIG_FILE);
  }

  fp = fopen(config_file, "r");

  // If config file was set in command line and open failed, die
  if (cmd_line_opts_start == 2 && fp == NULL) {
    die("Cannot open config file %s: %s", config_file, strerror(errno));
  }

  // Load config file settings first
  if (fp != NULL) {
    fprintf(stderr, "Loading config file %s\n", config_file);
    
    // Loop over the lines in config file
    while (fgets(line, sizeof(line), fp) != NULL) {

      if (!line_no && !memcmp(line,"\xEF\xBB\xBF",3)) {
        // strip UTF-8 BOM
        p = line+3;
      } else {
        p = line;
      }

      line_no++;

      // Ignore empty lines and comments
      if (p[0] == '#' || p[0] == '\r' || p[0] == '\n')
        continue;

      if (sscanf(p, "%s %[^\r\n#]", opt, val) != 2) {
        die("%s: line %d is invalid", config_file, (int) line_no);
      }
      set_option(options, opt, val);
    }

    (void) fclose(fp);
  }

  // Now handle command line flags. They override config file settings.
  for (i = cmd_line_opts_start; argv[i] != NULL; i += 2) {
    if (argv[i][0] != '-' || argv[i + 1] == NULL) {
      show_usage_and_exit();
    }
    set_option(options, &argv[i][1], argv[i + 1]);
  }
}

static void init_server_name(void) {
  snprintf(server_name, sizeof(server_name), "Mongoose web server v. %s",
           mg_version());
}

// example and test case for a callback
// this callback creates a statistics of request methods and the requested uris
// it is not ment as a feature but as a simple test case
#if defined(_WIN32) && !defined(__SYMBIAN32__)
typedef HANDLE pthread_mutex_t;

static int pthread_mutex_init(pthread_mutex_t *mutex, void *unused) {
  unused = NULL;
  *mutex = CreateMutex(NULL, FALSE, NULL);
  return *mutex == NULL ? -1 : 0;
}

static int pthread_mutex_destroy(pthread_mutex_t *mutex) {
  return CloseHandle(*mutex) == 0 ? -1 : 0;
}

static int pthread_mutex_lock(pthread_mutex_t *mutex) {
  return WaitForSingleObject(*mutex, INFINITE) == WAIT_OBJECT_0? 0 : -1;
}

static int pthread_mutex_unlock(pthread_mutex_t *mutex) {
  return ReleaseMutex(*mutex) == 0 ? -1 : 0;
}
#endif

struct t_stat {
  const char * name;
  unsigned long getCount;
  unsigned long postCount;
  struct t_stat * next;
};

struct t_user_arg {   
   pthread_mutex_t mutex;
   struct t_stat * uris[0x10000];
};

unsigned short crc16(const void * data, unsigned long bitCount) {
  unsigned short r = 0xFFFFu;
	unsigned long i;
  for (i=0;i<bitCount;i++) {
    unsigned short b = ((unsigned char*)data)[i>>3];
    b >>= i & 0x7ul;    
    r = ((r & 1u) != (b & 1u)) ? ((r>>1) ^ 0xA001u) : (r>>1);
  }
  r ^= 0xFFFFu;
  return r;
}

static void * callback(enum mg_event event, struct mg_connection *conn, const struct mg_request_info *request_info) {
  int i;
  struct t_user_arg * udata = (struct t_user_arg *)request_info->user_data;
  const char * uri;
  unsigned short crc;
  struct t_stat ** st;

  if (event != MG_NEW_REQUEST) {
    // This callback currently only handles new requests
    return NULL;
  }

  // This callback adds the request method and the uri to a list.
  uri = sdup(request_info->uri);
  if (!uri) {
    die("out of memory");
  }

  // In C++ one could use a STL-map. However, this is just a test case here.
  crc = crc16(uri, (strlen(uri)+1)<<3);
  st = &udata->uris[crc];

  // This is a multithreaded system, so a mutex is required
  pthread_mutex_lock(&udata->mutex);

  while (*st) {
    if (!strcmp((*st)->name, uri)) {      
      break;
    } else {
      st = &((*st)->next);
    }
  }
  if (*st == NULL) {
    *st = (struct t_stat*) calloc(1, sizeof(struct t_stat));
    if (!st) {
      die("out of memory");
    }
    (*st)->name = uri;
    (*st)->next = 0;
  }
  if (!strcmp(request_info->request_method,"GET")) {
    (*st)->getCount++;
  } else if (!strcmp(request_info->request_method,"POST")) {
    (*st)->postCount++;
  }

  if (!strcmp(uri, "/_stat")) {
    //conn->must_close = 1; <TODO: currently there is no way to set the close flag in the callback>
    mg_printf(conn,
              "HTTP/1.1 200 OK\r\n"
              "Connection: close\r\n"
              "Cache-Control: no-cache"
              "Content-Type: text/html; charset=utf-8\r\n\r\n");

    mg_printf(conn,
              "<html><head><title>HTTP server statistics</title>"
              "<style>th {text-align: left;}</style></head>"
              "<body><h1>HTTP server statistics</h1>\r\n");

    mg_printf(conn,
              "<p><pre><table border=\"1\" rules=\"all\">"
              "<tr><th>Resource</th>"
              "<th>GET</th><th>POST</th></tr>\r\n");

    for (i=0;i<sizeof(udata->uris)/sizeof(udata->uris[0]);i++) {
      st = &udata->uris[i];
      while (*st) {
        mg_printf(conn, "<tr><td>%s</td><td>%u</td><td>%u</td></tr>\r\n",
                  (*st)->name, (*st)->getCount, (*st)->postCount);
        st = &((*st)->next);
      }
    }
    
    mg_printf(conn, "</table></pre></p></body></html>\r\n");

    pthread_mutex_unlock(&udata->mutex);
    return (void *)1;

  } else if (!strcmp(uri, "/_echo")) {

    const char * contentLength = mg_get_header(conn, "Content-Length");
    const char * contentType = mg_get_header(conn, "Content-Type");

    //conn->must_close = 1; <TODO: currently there is no way to set the close flag in the callback>
    mg_printf(conn,
              "HTTP/1.1 200 OK\r\n"
              "Connection: close\r\n"
              "Cache-Control: no-cache"
              "Content-Type: text/plain; charset=utf-8\r\n\r\n");
    
    if (!strcmp(request_info->request_method, "POST")) {
      int dataSize = atoi(contentLength);
      int gotSize = 0;
      char * data = (char*) ((dataSize>0) ? malloc(dataSize) : 0);
      if (data) {
        while (gotSize<dataSize) {
          int got = mg_read(conn, data + gotSize, dataSize - gotSize);
          if (got != dataSize) {
            int breakpoint = 1;  // did not happen in the test
          }
          gotSize += got;
        }
        mg_write(conn, data, gotSize);
        free(data);
      }            
    } else {
      mg_printf(conn, "%s", request_info->request_method);
    }

    pthread_mutex_unlock(&udata->mutex);
    return (void *)1;
  }

  pthread_mutex_unlock(&udata->mutex);  
  return NULL;
}

static void start_mongoose(int argc, char *argv[]) {
  char *options[MAX_OPTIONS];
  struct t_user_arg * pUser_arg;
  int i;

  // Edit passwords file if -A option is specified
  if (argc > 1 && !strcmp(argv[1], "-A")) {
    if (argc != 6) {
      show_usage_and_exit();
    }
    exit(mg_modify_passwords_file(argv[2], argv[3], argv[4], argv[5]) ?
         EXIT_SUCCESS : EXIT_FAILURE);
  }

  // Show usage if -h or --help options are specified
  if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
    show_usage_and_exit();
  }

  /* Update config based on command line arguments */
  process_command_line_arguments(argv, options);

  /* Setup signal handler: quit on Ctrl-C */
  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  /* prepare the user_arg */
  pUser_arg = (struct t_user_arg *)calloc(1, sizeof(struct t_user_arg));
  if (!pUser_arg) {
    die("out of memory");
  }
  pthread_mutex_init(&pUser_arg->mutex, 0);

  /* Start Mongoose */
  ctx = mg_start(callback, pUser_arg, (const char **) options);
  for (i = 0; options[i] != NULL; i++) {
    free(options[i]);
  }

  if (ctx == NULL) {
    die("%s", "Failed to start Mongoose. Maybe some options are "
        "assigned bad values?\nTry to run with '-e error_log.txt' "
        "and check error_log.txt for more information.");
  }
}

#if defined(_WIN32) && !defined(_CONSOLE)
static SERVICE_STATUS ss;
static SERVICE_STATUS_HANDLE hStatus;
static const char *service_magic_argument = "--";

static void WINAPI ControlHandler(DWORD code) {
  if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) {
    ss.dwWin32ExitCode = 0;
    ss.dwCurrentState = SERVICE_STOPPED;
  }
  SetServiceStatus(hStatus, &ss);
}

static void WINAPI ServiceMain(void) {
  ss.dwServiceType = SERVICE_WIN32;
  ss.dwCurrentState = SERVICE_RUNNING;
  ss.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

  hStatus = RegisterServiceCtrlHandler(server_name, ControlHandler);
  SetServiceStatus(hStatus, &ss);

  while (ss.dwCurrentState == SERVICE_RUNNING) {
    Sleep(1000);
  }
  mg_stop(ctx);

  ss.dwCurrentState = SERVICE_STOPPED;
  ss.dwWin32ExitCode = (DWORD) -1;
  SetServiceStatus(hStatus, &ss);
}

#define ID_TRAYICON 100
#define ID_QUIT 101
#define ID_EDIT_CONFIG 102
#define ID_SEPARATOR 103
#define ID_INSTALL_SERVICE 104
#define ID_REMOVE_SERVICE 105
#define ID_ICON 200
static NOTIFYICONDATA TrayIcon;

static void edit_config_file(void) {
  const char **names, *value;
  FILE *fp;
  int i;
  char cmd[200];

  // Create config file if it is not present yet
  if ((fp = fopen(config_file, "r")) != NULL) {
    fclose(fp);
  } else if ((fp = fopen(config_file, "a+")) != NULL) {
    fprintf(fp,
            "# Mongoose web server configuration file.\n"
            "# Lines starting with '#' and empty lines are ignored.\n"
            "# For detailed description of every option, visit\n"
            "# http://code.google.com/p/mongoose/wiki/MongooseManual\n\n");
    names = mg_get_valid_option_names();
    for (i = 0; names[i] != NULL; i += 3) {
      value = mg_get_option(ctx, names[i]);
      fprintf(fp, "# %s %s\n", names[i + 1], *value ? value : "<value>");
    }
    fclose(fp);
  }

  snprintf(cmd, sizeof(cmd), "notepad.exe %s", config_file);
  WinExec(cmd, SW_SHOW);
}

static void show_error(void) {
  char buf[256];
  FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, GetLastError(),
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                buf, sizeof(buf), NULL);
  MessageBox(NULL, buf, "Error", MB_OK);
}

static int manage_service(int action) {
  static const char *service_name = "Mongoose";
  SC_HANDLE hSCM = NULL, hService = NULL;
  SERVICE_DESCRIPTION descr = {server_name};
  char path[PATH_MAX + 20];  // Path to executable plus magic argument
  int success = 1;

  if ((hSCM = OpenSCManager(NULL, NULL, action == ID_INSTALL_SERVICE ?
                            GENERIC_WRITE : GENERIC_READ)) == NULL) {
    success = 0;
    show_error();
  } else if (action == ID_INSTALL_SERVICE) {
    GetModuleFileName(NULL, path, sizeof(path));
    strncat(path, " ", sizeof(path));
    strncat(path, service_magic_argument, sizeof(path));
    hService = CreateService(hSCM, service_name, service_name,
                             SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                             SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                             path, NULL, NULL, NULL, NULL, NULL);
    if (hService) {
      ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, &descr);
    } else {
      show_error();
    }
  } else if (action == ID_REMOVE_SERVICE) {
    if ((hService = OpenService(hSCM, service_name, DELETE)) == NULL ||
        !DeleteService(hService)) {
      show_error();
    }
  } else if ((hService = OpenService(hSCM, service_name,
                                     SERVICE_QUERY_STATUS)) == NULL) {
    success = 0;
  }

  CloseServiceHandle(hService);
  CloseServiceHandle(hSCM);

  return success;
}

static LRESULT CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wParam,
                                   LPARAM lParam) {
  static SERVICE_TABLE_ENTRY service_table[] = {
    {server_name, (LPSERVICE_MAIN_FUNCTION) ServiceMain},
    {NULL, NULL}
  };
  int service_installed;
  char buf[200], *service_argv[] = {__argv[0], NULL};
  POINT pt;
  HMENU hMenu;

  switch (msg) {
    case WM_CREATE:
      if (__argv[1] != NULL &&
          !strcmp(__argv[1], service_magic_argument)) {
        start_mongoose(1, service_argv);
        StartServiceCtrlDispatcher(service_table);
        exit(EXIT_SUCCESS);
      } else {
        start_mongoose(__argc, __argv);
      }
      break;
    case WM_COMMAND:
      switch (LOWORD(wParam)) {
        case ID_QUIT:
          mg_stop(ctx);
          Shell_NotifyIcon(NIM_DELETE, &TrayIcon);
          PostQuitMessage(0);
          break;
        case ID_EDIT_CONFIG:
          edit_config_file();
          break;
        case ID_INSTALL_SERVICE:
        case ID_REMOVE_SERVICE:
          manage_service(LOWORD(wParam));
          break;
      }
      break;
    case WM_USER:
      switch (lParam) {
        case WM_RBUTTONUP:
        case WM_LBUTTONUP:
        case WM_LBUTTONDBLCLK:
          hMenu = CreatePopupMenu();
          AppendMenu(hMenu, MF_STRING | MF_GRAYED, ID_SEPARATOR, server_name);
          AppendMenu(hMenu, MF_SEPARATOR, ID_SEPARATOR, "");
          service_installed = manage_service(0);
          snprintf(buf, sizeof(buf), "NT service: %s installed",
                   service_installed ? "" : "not");
          AppendMenu(hMenu, MF_STRING | MF_GRAYED, ID_SEPARATOR, buf);
          AppendMenu(hMenu, MF_STRING | (service_installed ? MF_GRAYED : 0),
                     ID_INSTALL_SERVICE, "Install service");
          AppendMenu(hMenu, MF_STRING | (!service_installed ? MF_GRAYED : 0),
                     ID_REMOVE_SERVICE, "Deinstall service");
          AppendMenu(hMenu, MF_SEPARATOR, ID_SEPARATOR, "");
          AppendMenu(hMenu, MF_STRING, ID_EDIT_CONFIG, "Edit config file");
          AppendMenu(hMenu, MF_STRING, ID_QUIT, "Exit");
          GetCursorPos(&pt);
          SetForegroundWindow(hWnd);
          TrackPopupMenu(hMenu, 0, pt.x, pt.y, 0, hWnd, NULL);
          PostMessage(hWnd, WM_NULL, 0, 0);
          DestroyMenu(hMenu);
          break;
      }
      break;
  }

  return DefWindowProc(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmdline, int show) {
  WNDCLASS cls;
  HWND hWnd;
  MSG msg;

  init_server_name();
  memset(&cls, 0, sizeof(cls));
  cls.lpfnWndProc = (WNDPROC) WindowProc;
  cls.hIcon = LoadIcon(NULL, IDI_APPLICATION);
  cls.lpszClassName = server_name;

  RegisterClass(&cls);
  hWnd = CreateWindow(cls.lpszClassName, server_name, WS_OVERLAPPEDWINDOW,
                      0, 0, 0, 0, NULL, NULL, NULL, NULL);
  ShowWindow(hWnd, SW_HIDE);

  TrayIcon.cbSize = sizeof(TrayIcon);
  TrayIcon.uID = ID_TRAYICON;
  TrayIcon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
  TrayIcon.hIcon = LoadImage(GetModuleHandle(NULL), MAKEINTRESOURCE(ID_ICON),
                             IMAGE_ICON, 16, 16, 0);
  TrayIcon.hWnd = hWnd;
  snprintf(TrayIcon.szTip, sizeof(TrayIcon.szTip), "%s", server_name);
  TrayIcon.uCallbackMessage = WM_USER;
  Shell_NotifyIcon(NIM_ADD, &TrayIcon);

  while (GetMessage(&msg, hWnd, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
}
#else
int main(int argc, char *argv[]) {
  init_server_name();
  start_mongoose(argc, argv);
  printf("%s started on port(s) %s with web root [%s]\n",
         server_name, mg_get_option(ctx, "listening_ports"),
         mg_get_option(ctx, "document_root"));
  while (exit_flag == 0) {
    sleep(1);
  }
  printf("Exiting on signal %d, waiting for all threads to finish...",
         exit_flag);
  fflush(stdout);
  mg_stop(ctx);
  printf("%s", " done.\n");

  return EXIT_SUCCESS;
}
#endif /* _WIN32 */
