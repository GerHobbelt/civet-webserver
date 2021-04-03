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


#include "civetweb.h"

#ifdef _WIN32
#include "win32/resource.h"
#endif // _WIN32

#define USE_BEL2125_TEST_NR_18_EVENT_HANDLER        1

#define MAX_OPTIONS (1 + 27 /* NUM_OPTIONS */ * 3 /* once as defaults, once from config file, once from command line */)
#define MAX_CONF_FILE_LINE_SIZE (8 * 1024)

static volatile int exit_flag = 0;
static char server_name[40];          // Set by init_server_name()
static char config_file[PATH_MAX];    // Set by process_command_line_arguments()
static struct mg_context *ctx = NULL; // Set by start_civetweb()

#if !defined(CONFIG_FILE)
#define CONFIG_FILE "civetweb.conf"
#endif /* !CONFIG_FILE */

static void WINCDECL signal_handler(int sig_num) {
  exit_flag = sig_num;
}

static const char *default_options[] = {
  "document_root",         "./test",
  "listening_ports",       "8080",                         // "8081,8082s"
  //"ssl_certificate",     "ssl_cert.pem",
  "num_threads",           "1",
  "error_log_file",        "./log/%Y/%m/tws_ib_if_srv-%Y%m%d.%H-IP-%[s]-%[p]-error.log",
  "access_log_file",       "./log/%Y/%m/tws_ib_if_srv-%Y%m%d.%H-IP-%[s]-%[p]-access.log",
  "keep_alive_timeout",    "5",

  NULL
};

#if defined(_WIN32)
static int error_dialog_shown_previously = 0;
#endif

void die(const char *fmt, ...) {
  va_list ap;
  char msg[200];

  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);

#if defined(_WIN32)
  if (!error_dialog_shown_previously)
  {
    MessageBoxA(NULL, msg, "Error", MB_OK);
    error_dialog_shown_previously = 1;
  }
#else
  fprintf(stderr, "%s\n", msg);
#endif

  exit(EXIT_FAILURE);
}

static void show_usage_and_exit(const struct mg_context *ctx) {
  const char **names;
  int i;

  fprintf(stderr, "CivetWeb version %s (c) Sergey Lyubka, built %s\n",
          mg_version(), __DATE__);
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  civetweb -A <htpasswd_file> <realm> <user> <passwd>\n");
  fprintf(stderr, "  civetweb <config_file>\n");
  fprintf(stderr, "  civetweb [-option value ...]\n");
  fprintf(stderr, "\nOPTIONS:\n");

  names = mg_get_valid_option_names();
  for (i = 0; names[i] != NULL; i += MG_ENTRIES_PER_CONFIG_OPTION) {
    fprintf(stderr, "  %s%s %s (default: \"%s\")\n",
            (names[i][0] ? "-" : "  "),
            names[i], names[i + 1], names[i + 2] == NULL ? "" : names[i + 2]);
  }
  fprintf(stderr, "\nSee  http://code.google.com/p/civetweb/wiki/CivetWebManual"
          " for more details.\n");
  fprintf(stderr, "Example:\n  civetweb -s cert.pem -p 80,443s -d no\n");
  exit(EXIT_FAILURE);
}

static void verify_document_root(const char *root) {
  struct mgstat st;
  char buf[PATH_MAX];

  getcwd(buf, sizeof(buf));
  if (mg_stat(root, &st) != 0 || !st.is_directory) {
    die("Invalid root directory: [%s]: %s; current directory = [%s]", root, mg_strerror(ERRNO), buf);
  }
}


static void set_option(char **options, const char *name, const char *value) {
  int i;

  if (mg_get_option_long_name(name))
    name = mg_get_option_long_name(name);

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
    die("Too many options specified");
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

  fp = mg_fopen(config_file, "r");

  // If config file was set in command line and open failed, exit
  if (argv[1] != NULL && argv[2] == NULL && fp == NULL) {
    die("Cannot open config file %s: %s", config_file, mg_strerror(ERRNO));
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

      if (!line_no && !memcmp(line,"\xEF\xBB\xBF", 3)) {
        // strip UTF-8 BOM
        p = line+3;
      } else {
        p = line;
      }

      line_no++;

      // Ignore empty lines (with optional, ignored, whitespace) and comments
      if (line[0] == '#')
        continue;

	  // MS sscanf() says: The return value is EOF for an error or if the end of the string is reached before the first conversion.
	  // Hence we make sure we don't feed it an empty line --> -1 will only have one meaning then.
	  if (line[strspn(line, " \t\r\n")] == 0)
		continue;

      if (2 == sscanf(line, "%s %[^\r\n#]", opt, val)) {
        set_option(options, opt, val);
        continue;
	  } else {
        die("%s: line %d is invalid", config_file, line_no);
        break;
      }
    }

    (void) mg_fclose(fp);
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
  snprintf(server_name, sizeof(server_name), "CivetWeb web server v%s",
           mg_version());
}


#if USE_BEL2125_TEST_NR_18_EVENT_HANDLER

// used in conjuction with /test/ajax/test_18.html

#define BUFFER_SIZE 4094

#endif


static void *civetweb_callback(enum mg_event event, struct mg_connection *conn) {
  const struct mg_request_info *request_info = mg_get_request_info(conn);

  if (event == MG_INIT0)
  {
    verify_document_root(mg_get_conn_option(conn, "document_root"));
    return (void *)1;
  }

#if defined(_WIN32)
  if (event == MG_EVENT_LOG &&
      strstr(request_info->log_message, "cannot bind to") &&
      !strcmp(request_info->log_severity, "error"))
  {
    if (!error_dialog_shown_previously)
    {
      MessageBoxA(NULL, request_info->log_message, "Error", MB_OK);
      error_dialog_shown_previously = 1;
    }
    return 0;
  }
#endif

#if USE_BEL2125_TEST_NR_18_EVENT_HANDLER
  {
    int contentLength = 0;
    int dataRead = 0;
    char postData[BUFFER_SIZE] = { 0 };
    const char* contentType = NULL;

    if (event == MG_NEW_REQUEST)
    {
        if (strstr(request_info->uri, "/echo") == request_info->uri)
        {
            int ie_hack = 0;  // testing an assumption; turns out it doesn't matter whether headers make it into TCP stack before you expect to fetch all input data at once.
            int ie_hack2 = 0;

            contentLength = atoi(mg_get_header(conn, "Content-Length"));
            MG_ASSERT(contentLength <= BUFFER_SIZE);

            mg_set_response_code(conn, 200);

            if (ie_hack2) mg_connection_must_close(conn);  // the stackoverflow suggested fix: http://stackoverflow.com/questions/3731420/why-does-ie-issue-random-xhr-408-12152-responses-using-jquery-post

            contentType = mg_get_header(conn, "Content-Type");

            if (ie_hack)
            {
                //mg_add_response_header(conn, 0, "Connection", mg_suggest_connection_header(conn)); -- not needed any longer
                mg_add_response_header(conn, 0, "Content-Type", contentType);
                mg_add_response_header(conn, 0, "Content-Length", "%d", contentLength);
                mg_write_http_response_head(conn, 0, 0);  // let the previous mg_set_response_code() decide for us
            }

            dataRead = mg_read(conn, postData, contentLength);
            if (dataRead > 0)
            {
                MG_ASSERT(dataRead == contentLength);

                if (!ie_hack)
                {
                    //mg_add_response_header(conn, 0, "Connection", mg_suggest_connection_header(conn)); -- not needed any longer
                    mg_add_response_header(conn, 0, "Content-Type", contentType);
                    mg_add_response_header(conn, 0, "Content-Length", "%d", dataRead);
                    mg_write_http_response_head(conn, 0, 0);  // let the previous mg_set_response_code() decide for us
                }

                if (mg_write(conn, postData, dataRead) != contentLength)
                {
                    mg_send_http_error(conn, 580, NULL, "not all data was written to the socket (len: %u)", (unsigned int)contentLength); // internal error in our custom handler or client closed connection prematurely
                }

                return (void*)1;
            }
            else
            {
                mg_send_http_error(conn, 500, NULL, "I/O failure during mg_read() from connection: %s", mg_strerror(ERRNO));
            }
        }
    }
  }
#endif // USE_BEL2125_TEST_NR_18_EVENT_HANDLER

  if (event != MG_NEW_REQUEST) {
    // This callback currently only handles new requests
    return NULL;
  }

  {
    int file_found;
    struct mgstat fst;

    MG_ASSERT(request_info->phys_path);
    file_found = (0 == mg_stat(request_info->phys_path, &fst) && !fst.is_directory);
    if (file_found) {
      return NULL; // let civetweb handle the default of 'file exists'...
    }

#ifdef _WIN32
    // Send the systray icon as favicon
    if (!strcmp("/favicon.ico", request_info->uri)) {
      HMODULE module;
      HRSRC icon;
      DWORD len;
      void *data;

      module = GetModuleHandle(NULL);

      icon = FindResource(module, MAKEINTRESOURCE(IDR_FAVICON), RT_RCDATA);
      data = LockResource(LoadResource(module, icon));
      len = SizeofResource(module, icon);

      mg_add_response_header(conn, 0, "Content-Type", "image/x-icon");
      mg_add_response_header(conn, 0, "Cache-Control", "no-cache");
      mg_add_response_header(conn, 0, "Content-Length", "%u", (unsigned int)len);
      //mg_add_response_header(conn, 0, "Connection", suggest_connection_header(conn)); -- not needed any longer
      mg_write_http_response_head(conn, 200, NULL);

      if ((int)len != mg_write(conn, data, len)) {
        mg_send_http_error(conn, 580, NULL, "not all data was written to the socket (len: %u)", (unsigned int)len); // internal error in our custom handler or client closed connection prematurely
      }
      return (void *)1;
    }
#endif
  }

  return NULL;
}

#if defined(_WIN32)

static BOOL WINAPI mg_win32_break_handler(DWORD signal_type)
{
  switch(signal_type)
  {
  // Handle the CTRL-C signal.
  case CTRL_C_EVENT:
  // CTRL-CLOSE: confirm that the user wants to exit.
  case CTRL_CLOSE_EVENT:
  case CTRL_BREAK_EVENT:
    exit_flag = 1000 + signal_type;
    //mg_signal_stop(ctx);
    return TRUE;

  // Pass other signals to the next handler.
  case CTRL_LOGOFF_EVENT:
  case CTRL_SHUTDOWN_EVENT:
  default:
    return FALSE;
  }
}

#endif


static void start_civetweb(int argc, char *argv[]) {
  char *options[MAX_OPTIONS * 2] = { NULL };
  int i;
  struct mg_user_class_t userdef = {
      0,
      &civetweb_callback
  };

  /* Edit passwords file if -A option is specified */
  if (argc > 1 && !strcmp(argv[1], "-A")) {
    if (argc != 6) {
      show_usage_and_exit(ctx);
    }
    exit(mg_modify_passwords_file(argv[2], argv[3], argv[4], argv[5]) ?
         EXIT_SUCCESS : EXIT_FAILURE);
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
  signal(SIGABRT, signal_handler);
  signal(SIGILL, signal_handler);
  signal(SIGSEGV, signal_handler);
  signal(SIGFPE, signal_handler);
  // SIGINT and SIGTERM are pretty darn useless for Win32 applications.
  // See http://msdn.microsoft.com/en-us/library/ms685049%28VS.85%29.aspx
#if defined(_WIN32)
  if (!SetConsoleCtrlHandler(mg_win32_break_handler, TRUE))
  {
    die("Failed to set up the Win32 console Ctrl-Break handler.");
  }
#endif

  /* Start CivetWeb */
  ctx = mg_start(&userdef, (const char **)options);
  for (i = 0; options[i] != NULL; i++) {
    free(options[i]);
  }

  if (ctx == NULL) {
    die("Failed to start CivetWeb. Maybe some options are "
        "assigned bad values?\nTry to run with '-e error_log.txt' "
        "and check error_log.txt for more information.");
  }
}

#if defined(_WIN32) && defined(CIVETWEB_AS_SERVICE)
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

static NOTIFYICONDATAA TrayIcon;

static void edit_config_file(struct mg_context *ctx) {
  const char **names, *value;
  FILE *fp;
  int i;
  char cmd[200];

  // Create config file if it is not present yet
  if ((fp = mg_fopen(config_file, "r")) != NULL) {
    mg_fclose(fp);
  } else if ((fp = fopen(config_file, "a+")) != NULL) {
    fprintf(fp,
            "# CivetWeb web server configuration file.\n"
            "# Lines starting with '#' and empty lines are ignored.\n"
            "# For detailed description of every option, visit\n"
            "# http://code.google.com/p/civetweb/wiki/CivetWebManual\n\n");
    names = mg_get_valid_option_names();
    for (i = 0; names[i] != NULL; i += MG_ENTRIES_PER_CONFIG_OPTION) {
      value = mg_get_option(ctx, names[i + 1]);
      fprintf(fp, "# %s %s\n", names[i + 1], *value ? value : "<value>");
    }
    mg_fclose(fp);
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
  static const char *service_name = "CivetWeb";
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
        start_civetweb(1, service_argv);
        StartServiceCtrlDispatcherA(service_table);
        exit(EXIT_SUCCESS);
      } else {
        start_civetweb(__argc, __argv);
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
    case WM_CLOSE:
      mg_stop(ctx);
      Shell_NotifyIconA(NIM_DELETE, &TrayIcon);
      PostQuitMessage(EXIT_SUCCESS);
      return 0;  // We've just sent our own quit message, with proper hwnd.
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
  TrayIcon.hIcon = LoadImage(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON),
                             IMAGE_ICON, 16, 16, 0);
  TrayIcon.hWnd = hWnd;
  snprintf(TrayIcon.szTip, sizeof(TrayIcon.szTip), "%s", server_name);
  TrayIcon.uCallbackMessage = WM_USER;
  Shell_NotifyIconA(NIM_ADD, &TrayIcon);

  while (GetMessage(&msg, hWnd, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }

  // return the WM_QUIT value:
  return msg.wParam;
}
#else
int main(int argc, char *argv[]) {
  init_server_name();
  start_civetweb(argc, argv);
  printf("%s started on port(s) %s with web root [%s]\n",
         server_name, mg_get_option(ctx, "listening_ports"),
         mg_get_option(ctx, "document_root"));
  while (exit_flag == 0 && !mg_get_stop_flag(ctx)) {
    mg_sleep(100);
  }
  printf("Exiting on signal %d/%d, waiting for all threads to finish...",
        exit_flag, mg_get_stop_flag(ctx));
  fflush(stdout);
  mg_stop(ctx);
  printf(" done.\n");

  return EXIT_SUCCESS;
}
#endif /* _WIN32 */

