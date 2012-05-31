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


#include "mongoose_sys_porting.h"
#include "mongoose_ex.h"
#include "win32/resource.h"

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
	fprintf(stderr, "\nsignal: %d\n", sig_num);
  exit_flag = sig_num;
}

static const char *default_options[] = {
    "document_root",         "./test",
	"listening_ports",       "8081",                         // "8081,8082s"
    //"ssl_certificate",     "ssl_cert.pem",
    "num_threads",           "5",
    "error_log_file",        "./log/%Y/%m/tws_ib_if_srv-%Y%m%d.%H-IP-%[s]-%[p]-error.log",
	"access_log_file",       "./log/%Y/%m/tws_ib_if_srv-%Y%m%d.%H-IP-%[s]-%[p]-access.log",

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
    fprintf(stderr, "  %s%s %s (default: \"%s\")\n",
            (names[i][0] ? "-" : "  "),
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
  struct mgstat st;

  path = root;
  if ((p = strchr(root, ',')) != NULL && (size_t) (p - root) < sizeof(buf)) {
    memcpy(buf, root, p - root);
    buf[p - root] = '\0';
    path = buf;
  }

    if (mg_stat(path, &st) != 0 || !st.is_directory) {
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

  fp = mg_fopen(config_file, "r");

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

      if (!line_no && !memcmp(line,"\xEF\xBB\xBF",3)) {
        // strip UTF-8 BOM
        p = line+3;
      } else {
        p = line;
      }

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
  snprintf(server_name, sizeof(server_name), "Mongoose web server v%s",
           mg_version());
}

// example and test case for a callback
// this callback creates a statistics of request methods and the requested uris
// it is not meant as a feature but as a simple test case

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

static void *event_callback(enum mg_event event, struct mg_connection *conn) {
  struct mg_context *ctx = mg_get_context(conn);
  struct mg_request_info *request_info = mg_get_request_info(conn);
  int i;
  struct t_user_arg * udata = (struct t_user_arg *)mg_get_user_data(ctx)->user_data;
  const char * uri;
  unsigned short crc;
  struct t_stat ** st;

#if 0
  if (event == MG_EXIT_CLIENT_CONN && !request_info->request_method && !request_info->uri)
  {
	printf("Boom?\n");
  }
#endif
  if (event != MG_NEW_REQUEST) {
    // This callback currently only handles new requests
    return NULL;
  }

  // This callback adds the request method and the uri to a list.
  uri = request_info->uri;

  // In C++ one could use a STL-map. However, this is just a test case here.
  crc = crc16(uri, (strlen(uri)+1)<<3);

  // This is a multithreaded system, so a mutex is required
  pthread_mutex_lock(&udata->mutex);

  st = &udata->uris[crc];

  while (*st) {
    if (!strcmp((*st)->name, uri)) {      
      break;
    } else {
      st = &((*st)->next);
    }
  }
  if (*st == NULL) {
    uri = mg_strdup(uri);
    *st = (struct t_stat*) calloc(1, sizeof(struct t_stat));
    if (!st || !uri) {
      pthread_mutex_unlock(&udata->mutex);
      die("out of memory");
    }
    (*st)->name = uri;
    (*st)->next = 0;
  }
  if (!strcmp(request_info->request_method, "GET")) {
    (*st)->getCount++;
  } else if (!strcmp(request_info->request_method, "POST")) {
    (*st)->postCount++;
  }
  pthread_mutex_unlock(&udata->mutex);

  if (!strcmp(uri, "/_stat")) {
    mg_connection_must_close(conn);
    request_info->status_code = 200;
    mg_printf(conn,
              "HTTP/1.1 200 OK\r\n"
              "Connection: close\r\n"
              "Cache-Control: no-cache"
              "Content-Type: text/html; charset=utf-8\r\n\r\n");
    mg_mark_end_of_header_transmission(conn);
    mg_printf(conn,
              "<html><head><title>HTTP server statistics</title>"
              "<style>th {text-align: left;}</style></head>"
              "<body><h1>HTTP server statistics</h1>\r\n");

    mg_printf(conn,
              "<p><pre><table border=\"1\" rules=\"all\">"
              "<tr><th>Resource</th>"
              "<th>GET</th><th>POST</th></tr>\r\n");

    pthread_mutex_lock(&udata->mutex);

    for (i=0;i<sizeof(udata->uris)/sizeof(udata->uris[0]);i++) {
      st = &udata->uris[i];
      while (*st) {
        mg_printf(conn, "<tr><td>%s</td><td>%8u</td><td>%8u</td></tr>\r\n",
                  (*st)->name, (*st)->getCount, (*st)->postCount);
        st = &((*st)->next);
      }
    }
    pthread_mutex_unlock(&udata->mutex);
    
    mg_printf(conn, "</table></pre></p></body></html>\r\n");
    return (void *)1;
  } else if (!strcmp(uri, "/_echo")) {
    const char * contentLength = mg_get_header(conn, "Content-Length");
    const char * contentType = mg_get_header(conn, "Content-Type");

    mg_connection_must_close(conn);
    request_info->status_code = 200;
    mg_printf(conn,
              "HTTP/1.1 200 OK\r\n"
              "Connection: close\r\n"
              "Cache-Control: no-cache"
              "Content-Type: text/plain; charset=utf-8\r\n\r\n");
    mg_mark_end_of_header_transmission(conn);

	mg_printf(conn,	"Received headers:\r\n");
	for (i = 0; i < request_info->num_headers; i++)
	{
		mg_printf(conn,	"Header[%d]: '%s' = '%s'\r\n", 
			i, request_info->http_headers[i].name, request_info->http_headers[i].value);
	}
	mg_printf(conn,	"----- info bits ------\r\n");
	mg_printf(conn,	"URL: [%s]\r\n", request_info->uri);
	mg_printf(conn,	"Query: [%s]\r\n", request_info->query_string);
	mg_printf(conn,	"Phys.Path: [%s]\r\n", request_info->phys_path);
	mg_printf(conn,	"----- data? ------\r\n");

    if (!strcmp(request_info->request_method, "POST")) {
      long int dataSize = atol(contentLength);
#if 0
	  int bufferSize = (dataSize > 1024 * 1024 ? 1024 * 1024 : (int)dataSize);
#else
	  int bufferSize = (int)dataSize;
#endif
	  long int gotSize = 0;
	  int bufferFill = 0;
      char * data = (char*) ((dataSize>0) ? malloc(bufferSize) : 0);
      if (data) {
		mg_set_non_blocking_mode(mg_get_client_socket(conn), 1);
		{
			const int tcpbuflen = 1 * 1024 * 1024;

			mg_setsockopt(mg_get_client_socket(conn), SOL_SOCKET, SO_RCVBUF, (const void *)&tcpbuflen, sizeof(tcpbuflen));
			mg_setsockopt(mg_get_client_socket(conn), SOL_SOCKET, SO_SNDBUF, (const void *)&tcpbuflen, sizeof(tcpbuflen));
		}

        while (gotSize < dataSize && !mg_get_stop_flag(ctx)) {
		  int gotNow = 0;
		{
			// check whether there's anything available:
			fd_set read_set;
			struct timeval tv;
			int max_fd;

			FD_ZERO(&read_set);
			max_fd = -1;

			tv.tv_sec = 1;
			tv.tv_usec = 0;

			while (mg_get_stop_flag(ctx) == 0)
			{
				struct timeval tv2 = tv;

				FD_ZERO(&read_set);
				max_fd = -1;

				// Add listening sockets to the read set
				mg_FD_SET(mg_get_client_socket(conn), &read_set, &max_fd);
				if (select(max_fd + 1, &read_set, NULL, NULL, &tv2) < 0)
				{
					// signal a fatal failure:
					// clear the handles sets to prevent 'surprises' from processing these a second time (below):
					FD_ZERO(&read_set);
					max_fd = -1;
					assert(!"Should never get here");
                    request_info->status_code = 579; // internal error in our custom handler
					break;
				}
				else
				{
					if (mg_FD_ISSET(mg_get_client_socket(conn), &read_set))
					{
						break;
					}
					max_fd = -1;
				}
			}
	
			if (max_fd >= 0)
			{
				// use mg_pull() instead when you're accessing custom protocol sockets
				long int len = dataSize - gotSize;
				unsigned long int readLen = 0;
				if (len > bufferSize - bufferFill)
					len = bufferSize - bufferFill;
				gotNow = mg_read(conn, data + bufferFill, len);
				if (gotNow > 0)
				{
					bufferFill += gotNow;
					if (bufferFill == bufferSize && bufferSize != dataSize)
					{
						bufferFill = mg_write(conn, data, bufferSize);
						if (bufferFill < 0)
						{
							// TODO: report failure to handle request after all
							mg_write2log(conn, "-", time(NULL), "error", "POST /_echo: ***ERR*** at dataSize=%lu, gotNow=%u, gotSize=%lu\n", dataSize, gotNow, gotSize);
							request_info->status_code = 579; // internal error in our custom handler
							break;
						}
						bufferFill = bufferSize - bufferFill;
					}
				}
			}
		  }

			if (gotNow == 0)
			{
				mg_write2log(conn, "-", time(NULL), "info", "POST /_echo: ***CLOSE*** at dataSize=%lu, gotNow=%u, gotSize=%lu\n", dataSize, gotNow, gotSize);
				break;
			}
          gotSize += gotNow;
        }
		mg_set_non_blocking_mode(mg_get_client_socket(conn), 0);
		//mg_write(conn, data, gotSize);
		if (bufferFill > 0)
		{
			int wlen;

			do
			{
				unsigned long dataReady = 0;
			    if (mg_ioctlsocket(mg_get_client_socket(conn), FIONREAD, &dataReady) < 0) 
					wlen = -1;
				else
					wlen = dataReady;

				wlen = mg_write(conn, data, bufferFill);
				if (bufferFill != wlen)
				{
					mg_write2log(conn, "-", time(NULL), "error", "POST /_echo: ***ERR*** at dataSize=%lu, gotSize=%lu, wlen=%d\n", dataSize, gotSize, wlen);
                    request_info->status_code = 580; // internal error in our custom handler
				}
				if (wlen > 0)
					bufferFill -= wlen;
			} while (bufferFill > 0 && mg_get_stop_flag(ctx) == 0 && wlen != 0);
		}
        free(data);
      }            
    } else {
      mg_printf(conn, "%s", request_info->request_method);
    }

    return (void *)1;
  }
  else
  {
	int file_found;
	struct mgstat fst;

	assert(request_info->phys_path);
	file_found = (0 == mg_stat(request_info->phys_path, &fst) && !fst.is_directory);
	if (file_found) {
	  return NULL; // let mongoose handle the default of 'file exists'...
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

      request_info->status_code = 200;
      (void) mg_printf(conn,
          "HTTP/1.1 200 OK\r\n"
          "Content-Type: image/x-icon\r\n"
          "Cache-Control: no-cache\r\n"
          "Content-Length: %u\r\n"
          "Connection: close\r\n\r\n", (unsigned int)len);
      mg_mark_end_of_header_transmission(conn);

      if (len != mg_write(conn, data, len))
	  {
        request_info->status_code = 580; // internal error in our custom handler or client closed connection prematurely
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

static void start_mongoose(int argc, char *argv[]) {
    char *options[MAX_OPTIONS * 2] = { NULL };
    int i;
    struct mg_user_class_t userdef = {
        &event_callback,
        0,
        0,
        0,
        0
    };

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

  /* prepare the user_arg */
  {
	struct t_user_arg *pUser_arg = (struct t_user_arg *)calloc(1, sizeof(struct t_user_arg));
	if (!pUser_arg) {
		die("out of memory");
	}
	pthread_mutex_init(&pUser_arg->mutex, 0);
	userdef.user_data = pUser_arg;
  }

  /* Start Mongoose */
  ctx = mg_start(&userdef, (const char **)options);
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

static NOTIFYICONDATAA TrayIcon;

static void edit_config_file(const struct mg_context *ctx) {
  const char **names, *value;
  FILE *fp;
  int i;
  char cmd[200];

  // Create config file if it is not present yet
  if ((fp = mg_fopen(config_file, "r")) != NULL) {
    mg_fclose(fp);
  } else if ((fp = fopen(config_file, "a+")) != NULL) {
    fprintf(fp,
            "# Mongoose web server configuration file.\n"
            "# Lines starting with '#' and empty lines are ignored.\n"
            "# For detailed description of every option, visit\n"
            "# http://code.google.com/p/mongoose/wiki/MongooseManual\n\n");
    names = mg_get_valid_option_names();
    for (i = 0; names[i] != NULL; i += 3) {
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
  TrayIcon.hIcon = LoadImage(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON),
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
  printf(" done.\n");

  return EXIT_SUCCESS;
}
#endif /* _WIN32 */

