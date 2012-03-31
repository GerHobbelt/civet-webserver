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


#include "mongoose_sys_porting.h"

#include "mongoose_ex.h"

#ifdef _WIN32
#include <winsvc.h>
#endif // _WIN32

#define MAX_OPTIONS 40
#define MAX_CONF_FILE_LINE_SIZE (8 * 1024)

static volatile int exit_flag;
static char server_name[40];        // Set by init_server_name()
static char config_file[PATH_MAX];  // Set by process_command_line_arguments()
static struct mg_context *ctx;      // Set by start_mongoose()

#if !defined(CONFIG_FILE)
#define CONFIG_FILE "mongoose.conf"
#endif /* !CONFIG_FILE */

static void WINCDECL signal_handler(int sig_num) {
  exit_flag = sig_num;
}

static const char *default_options[] = {
    "document_root",         "./html",
    "listening_ports",       "8081",                         // "8081,8082s"
    //"ssl_certificate",     "ssl_cert.pem",
    "num_threads",           "5",
    "error_log_file",        "./log/%Y/%m/tws_ib_if_srv-%Y%m%d.%H-IP-%[s]-%[p].log",

    NULL
};

void die(const char *fmt, ...) {
  va_list ap;
  char msg[200];

  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);

#if defined(_WIN32)
  MessageBoxA(NULL, msg, "Error", MB_OK);
#else
  fprintf(stderr, "%s\n", msg);
#endif

  exit(EXIT_FAILURE);
}

static void show_usage_and_exit(const struct mg_context *ctx) {
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
        die("Invalid root directory: [%s]: %s", root, mg_strerror(errno));
    }
}


static void set_option(char **options, const char *name, const char *value) {
  int i;

  if (!strcmp(name, "document_root") || !(strcmp(name, "r"))) {
    verify_document_root(value);
  }

    for (i = 0; i < MAX_OPTIONS * 2; i += 2) {
        // replace option value when it was set before: command line overrules config file, which overrules global defaults.
        if (options[i] == NULL) {
            options[i] = mg_strdup(name);
            options[i + 1] = mg_strdup(value);
            break;
        } else if (strcmp(options[i], name) == 0) {
            free(options[i + 1]);
            options[i + 1] = mg_strdup(value);
            break;
        }
    }

    if (i > MAX_OPTIONS * 2 - 2) {
        die("%s", "Too many options specified");
    }
}

static void process_command_line_arguments(char *argv[], char **options) {
  char line[MAX_CONF_FILE_LINE_SIZE], opt[sizeof(line)], val[sizeof(line)], *p;
  FILE *fp = NULL;
  size_t i;
  int line_no = 0;

  options[0] = NULL;

  // Should we use a config file ?
  if (argv[1] != NULL && argv[2] == NULL) {
    snprintf(config_file, sizeof(config_file), "%s", argv[1]);
  } else if ((p = strrchr(argv[0], DIRSEP)) == NULL) {
    // No command line flags specified. Look where binary lives
    snprintf(config_file, sizeof(config_file), "%s", CONFIG_FILE);
  } else {
    snprintf(config_file, sizeof(config_file), "%.*s%c%s",
             (int) (p - argv[0]), argv[0], DIRSEP, CONFIG_FILE);
  }

  fp = fopen(config_file, "r");

    // If config file was set in command line and open failed, exit
    if (argv[1] != NULL && argv[2] == NULL && fp == NULL) {
        die("Cannot open config file %s: %s", config_file, mg_strerror(errno));
    }

    // use the default values for starters (so that all options have a known reasonable value):
    for (i = 0; default_options[i]; i += 2) {
        set_option(options, default_options[i], default_options[i+1]);
    }

  // Load config file settings first
  if (fp != NULL) {
    fprintf(stderr, "Loading config file %s\n", config_file);

    // Loop over the lines in config file
    while (fgets(line, sizeof(line), fp) != NULL) {

      line_no++;

      // Ignore empty lines (with optional, ignored, whitespace) and comments
      if (line[0] == '#')
        continue;

      switch (sscanf(line, "%s %[^\r\n#]", opt, val))
      {
      case 0:
        // empty line!
        continue;

      case 2:
        set_option(options, opt, val);
        continue;

      default:
        die("%s: line %d is invalid", config_file, line_no);
        break;
      }
    }

    (void) fclose(fp);
  }

  // Now handle command line flags. They override config file / default settings.
  for (i = 1; argv[i] != NULL; i += 2) {
    if (argv[i][0] != '-' || argv[i + 1] == NULL) {
      show_usage_and_exit(ctx);
    }
    set_option(options, &argv[i][1], argv[i + 1]);
  }
}

static void init_server_name(void) {
  snprintf(server_name, sizeof(server_name), "Mongoose web server v.%s",
           mg_version());
}

static void start_mongoose(int argc, char *argv[]) {
    char *options[MAX_OPTIONS * 2] = { NULL };
    int i;
	struct mg_user_class_t userdef = {0};

    /* Edit passwords file if -A option is specified */
    if (argc > 1 && argv[1][0] == '-' && argv[1][1] == 'A') {
        if (argc != 6) {
            show_usage_and_exit(ctx);
        }
        exit(mg_modify_passwords_file(argv[2], argv[3], argv[4], argv[5]) ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    /* Show usage if -h or --help options are specified */
    if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
        show_usage_and_exit(ctx);
    }

  /* Update config based on command line arguments */
  process_command_line_arguments(argv, options);

  /* Setup signal handler: quit on Ctrl-C */
  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  /* Start Mongoose */
  ctx = mg_start(&userdef, options);
  for (i = 0; options[i] != NULL; i++) {
    free(options[i]);
  }

  if (ctx == NULL) {
    die("%s", "Failed to start Mongoose. Maybe some options are "
        "assigned bad values?\nTry to run with '-e error_log.txt' "
        "and check error_log.txt for more information.");
  }
}

#if defined(_WIN32) && defined(MONGOOSE_AS_SERVICE)
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

  hStatus = RegisterServiceCtrlHandlerA(server_name, ControlHandler);
  SetServiceStatus(hStatus, &ss);

  while (ss.dwCurrentState == SERVICE_RUNNING) {
    mg_sleep(1000);
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
static NOTIFYICONDATAA TrayIcon;

static void edit_config_file(const struct mg_context *ctx) {
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
  FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, GetLastError(),
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                buf, sizeof(buf), NULL);
  MessageBoxA(NULL, buf, "Error", MB_OK);
}

static int manage_service(int action) {
  static const char *service_name = "Mongoose";
  SC_HANDLE hSCM = NULL, hService = NULL;
  SERVICE_DESCRIPTIONA descr = {server_name};
  char path[PATH_MAX + 20];  // Path to executable plus magic argument
  int success = 1;

  if ((hSCM = OpenSCManager(NULL, NULL, action == ID_INSTALL_SERVICE ?
                            GENERIC_WRITE : GENERIC_READ)) == NULL) {
    success = 0;
    show_error();
  } else if (action == ID_INSTALL_SERVICE) {
    GetModuleFileNameA(NULL, path, sizeof(path));
    strncat(path, " ", sizeof(path));
    strncat(path, service_magic_argument, sizeof(path));
    hService = CreateServiceA(hSCM, service_name, service_name,
                             SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                             SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                             path, NULL, NULL, NULL, NULL, NULL);
    if (hService) {
      ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, &descr);
    } else {
      show_error();
    }
  } else if (action == ID_REMOVE_SERVICE) {
    if ((hService = OpenServiceA(hSCM, service_name, DELETE)) == NULL ||
        !DeleteService(hService)) {
      show_error();
    }
  } else if ((hService = OpenServiceA(hSCM, service_name,
                                     SERVICE_QUERY_STATUS)) == NULL) {
    success = 0;
  }

  CloseServiceHandle(hService);
  CloseServiceHandle(hSCM);

  return success;
}

static LRESULT CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wParam,
                                   LPARAM lParam) {
  static SERVICE_TABLE_ENTRYA service_table[] = {
    {server_name, (LPSERVICE_MAIN_FUNCTIONA) ServiceMain},
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
        StartServiceCtrlDispatcherA(service_table);
        exit(EXIT_SUCCESS);
      } else {
        start_mongoose(__argc, __argv);
      }
      break;
    case WM_COMMAND:
      switch (LOWORD(wParam)) {
        case ID_QUIT:
          mg_stop(ctx);
          Shell_NotifyIconA(NIM_DELETE, &TrayIcon);
          PostQuitMessage(EXIT_SUCCESS);
          break;
        case ID_EDIT_CONFIG:
          edit_config_file(ctx);
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
          AppendMenuA(hMenu, MF_STRING | MF_GRAYED, ID_SEPARATOR, server_name);
          AppendMenuA(hMenu, MF_SEPARATOR, ID_SEPARATOR, "");
          service_installed = manage_service(0);
          snprintf(buf, sizeof(buf), "NT service: %s installed",
                   service_installed ? "" : "not");
          AppendMenuA(hMenu, MF_STRING | MF_GRAYED, ID_SEPARATOR, buf);
          AppendMenuA(hMenu, MF_STRING | (service_installed ? MF_GRAYED : 0),
                     ID_INSTALL_SERVICE, "Install service");
          AppendMenuA(hMenu, MF_STRING | (!service_installed ? MF_GRAYED : 0),
                     ID_REMOVE_SERVICE, "Deinstall service");
          AppendMenuA(hMenu, MF_SEPARATOR, ID_SEPARATOR, "");
          AppendMenuA(hMenu, MF_STRING, ID_EDIT_CONFIG, "Edit config file");
          AppendMenuA(hMenu, MF_STRING, ID_QUIT, "Exit");
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
  WNDCLASSA cls;
  HWND hWnd;
  MSG msg;

  init_server_name();
  memset(&cls, 0, sizeof(cls));
  cls.lpfnWndProc = (WNDPROC) WindowProc;
  cls.hIcon = LoadIcon(NULL, IDI_APPLICATION);
  cls.lpszClassName = server_name;

  RegisterClassA(&cls);
  hWnd = CreateWindowA(cls.lpszClassName, server_name, WS_OVERLAPPEDWINDOW,
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
  Shell_NotifyIconA(NIM_ADD, &TrayIcon);

  while (GetMessage(&msg, hWnd, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }

  // return the WM_QUIT value:
  return msg.wParam;
}
#else
int main(int argc, char *argv[]) {
  init_server_name();
  start_mongoose(argc, argv);
  printf("%s started on port(s) %s with web root [%s]\n",
         server_name, mg_get_option(ctx, "listening_ports"),
         mg_get_option(ctx, "document_root"));
  while (exit_flag == 0 && !mg_get_stop_flag(ctx)) {
    mg_sleep(10);
  }
    printf("Exiting on signal %d/%d, waiting for all threads to finish...",
        exit_flag, mg_get_stop_flag(ctx));
  fflush(stdout);
  mg_stop(ctx);
  printf("%s", " done.\n");

  return EXIT_SUCCESS;
}
#endif /* _WIN32 */


