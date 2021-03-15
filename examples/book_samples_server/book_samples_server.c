// Mongoose is Copyright (c) 2004-2012 Sergey Lyubka
// Book Samples Server code is Copyright (c) 2012-2015 Ger Hobbelt
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

/*
    Shows/tests how to completely restart the mongoose server:
    when someone visits the '/restart' URL, the server is stopped and restarted after waiting
    3 seconds.
*/


// Override ASSERT in debug mode
#ifndef NDEBUG
#define MG_ASSERT(expr)                                   \
  do                                                      \
  {                                                       \
    if (!(expr))                                          \
    {                                                     \
      srv_signal_assert(#expr, __FILE__, __LINE__);       \
    }                                                     \
  } while (0)

void srv_signal_assert(const char *expr, const char *filepath, unsigned int lineno);
#endif



#include "civetweb.h"

#ifdef _WIN32
#include "civetweb_book_samples_server.resource.h"
#define _RICHEDIT_VER 0x0800
#include <richedit.h>
#ifndef AURL_ENABLEURL
#define AURL_ENABLEURL   1
#endif
#ifndef AURL_ENABLEEAURLS
#define AURL_ENABLEEAURLS 0
#endif
#include <shlwapi.h>
#include <winnls.h>
#include <winreg.h>
#ifndef WC_ERR_INVALID_CHARS
#define WC_ERR_INVALID_CHARS      0 // 0x00000080  // error for invalid chars
#endif
#endif // _WIN32

#include <upskirt/src/markdown.h>
#include <upskirt/html/html.h>



#define MAX_OPTIONS (1 + 27 /* NUM_OPTIONS */ * 3 /* once as defaults, once from config file, once from command line */)
#define MAX_CONF_FILE_LINE_SIZE (8 * 1024)

static volatile int exit_flag = 0;
static volatile int should_restart = 0;
static char server_name[40];          // Set by init_server_name()::recallDocumentRoot()
static char config_file[PATH_MAX];    // Set by process_command_line_arguments()
static struct mg_context *ctx = NULL; // Set by start_mongoose()
#if defined(_WIN32)
static HWND app_hwnd = NULL;
static int edit_control_version = 0;
#define WM_START_SERVER         (WM_APP + 42)
#define WM_SERVER_IS_STOPPING   (WM_APP + 43)
#define WM_RESTART_SERVER       (WM_APP + 44)
#define WM_TRAY_ICON_HIT        (WM_APP + 45)
#define WM_APPEND_LOG           (WM_APP + 46)
static char server_url[256] = "";
#define _T(text)        TEXT(text)
#endif
static char document_root_dir[PATH_MAX];		// Set by init_server_name()::recallDocumentRoot()

#if !defined(CONFIG_FILE)
#define CONFIG_FILE "mongoose.conf"
#endif /* !CONFIG_FILE */

static void WINCDECL signal_handler(int sig_num)
{
  exit_flag = sig_num;
}

static const char *default_options[] =
{
  "document_root",         document_root_dir,
  "listening_ports",       "9999",                         // "8081,8082s"
  //"ssl_certificate",     "ssl_cert.pem",
  "num_threads",           "5",
  "error_log_file",        "./log/%Y/%m/tws_ib_if_srv-%Y%m%d.%H-IP-%[s]-%[p]-error.log",
  "access_log_file",       "./log/%Y/%m/tws_ib_if_srv-%Y%m%d.%H-IP-%[s]-%[p]-access.log",
  "index_files",           "index.html,index.htm,index.cgi,index.shtml,index.php,default.html",
  "ssi_pattern",           "**.html$|**.htm|**.shtml$|**.shtm$",
  //"ssi_marker",          "{!--#,}",
  "keep_alive_timeout",    "5",
  "enable_keep_alive",	   "no",		// Privoxy plays nasty and causes timeouts when this is set to "yes"
  "error_file",			   "0=/_help/error/$E.shtml",			// '$E' will be replaced by the response code

  NULL
};

#if defined(_WIN32)

void append_log(const char *msg, ...)
{
  va_list args;
  char *buf = NULL;
  const char *msgbuf = msg;

  va_start(args, msg);
  if (strchr(msg, '%'))
  {
    mg_vasprintf(NULL, &buf, 0, msg, args);
    msgbuf = buf;
  }
  va_end(args);
  if (IsWindow(app_hwnd))
  {
    SendMessage(app_hwnd, WM_APPEND_LOG, 0, (LPARAM)msgbuf);
  }
  else
  {
    OutputDebugStringA(msgbuf);
  }
  free(buf);
}

static int error_dialog_shown_previously = 0;


struct rc_info
{
	unsigned int data_len;
	void *data;

	LPCTSTR id;
	LPCTSTR category;
	char mime[64];
};

static int load_internal_resource(struct rc_info *dst, struct mg_context *ctx, struct mg_connection *conn,
	const char *uri)
{
	// Send the resource matching the given name
	struct res_def
	{
		LPCTSTR id;
		LPCTSTR category;
		const char *path;
		const char *mime;
	};
	static const struct res_def res_defs[] =
	{
		// Send the systray icon as favicon
		{
			MAKEINTRESOURCE(IDR_FAVICON),
			RT_RCDATA,
			"/favicon.ico",
			"image/x-icon"
		},
		{
			MAKEINTRESOURCE(IDR_HTML_ERROR_404),
			RT_HTML,
			"/_help/error/404.shtml",
			NULL
		},
		{
			MAKEINTRESOURCE(IDR_HTML_ERROR_GENERAL),
			RT_HTML,
			"/_help/error/error.shtml",
			NULL
		},
		{
			MAKEINTRESOURCE(IDR_HTML_HELP_OVERVIEW),
			RT_HTML,
			"/_help/help_overview.html",
			NULL
		},
		{
			MAKEINTRESOURCE(IDR_HTML_DEVELOPER_INFO),
			RT_HTML,
			"/_help/developer_info.html",
			NULL
		},
		{
			MAKEINTRESOURCE(IDR_RC_BIOHAZARD_RED_BG_SVG),
			RT_RCDATA,
			"/_help/images/biohazard-red-bg.svg",
			NULL
		},
	};
	int i;

	memset(dst, 0, sizeof(*dst));

	for (i = 0; i < ARRAY_SIZE(res_defs); i++)
	{
		const struct res_def *def = &res_defs[i];
		if (0 == strcmp(def->path, uri))
		{
			HMODULE module;
			HRSRC icon;
			DWORD len;
			void *data;

			module = GetModuleHandle(NULL);

			icon = FindResource(module, def->id, def->category);
			data = LockResource(LoadResource(module, icon));
			len = SizeofResource(module, icon);
			MG_ASSERT(data);
			MG_ASSERT(len > 0);

			dst->data = data;
			dst->data_len = len;
			dst->id = def->id;
			dst->category = def->category;
			if (!def->mime) 
			{
				struct mg_mime_vec mime_vec;

				mg_get_mime_type(ctx, uri, NULL, &mime_vec);
				mg_strlcpy(dst->mime, mime_vec.ptr, MG_MIN(mime_vec.len + 1, sizeof(dst->mime)));
			}
			else 
			{
				mg_strlcpy(dst->mime, def->mime, sizeof(dst->mime));
			}

			return 1;
		}
	}
	return 0;
}


#define WEBSERVER_REGISTRY_KEY   _T("Software\\CivetWebServer\\ForTheBook")
static void recallDocumentRoot(const char *default_path)
{
	int fail = TRUE;
	HKEY hKey;
	LONG rv = RegOpenKeyEx(HKEY_CURRENT_USER, WEBSERVER_REGISTRY_KEY, 0, KEY_READ | KEY_WOW64_32KEY, &hKey);
	if (rv == ERROR_SUCCESS)
	{
		DWORD type_code;
		TCHAR buf[ARRAY_SIZE(document_root_dir)];
		DWORD buflen = sizeof(buf);			// https://msdn.microsoft.com/en-us/library/windows/desktop/ms724911(v=vs.85).aspx says: number of BYTES!
		rv = RegQueryValueEx(hKey, _T("DocumentRoot"), 0, &type_code, (LPBYTE)buf, &buflen);
		if (rv == ERROR_SUCCESS && type_code == REG_SZ)
		{
#ifdef UNICODE
			char intermediate_buf[ARRAY_SIZE(document_root_dir)];
			if (buflen > 0 && 0 < WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buf, -1, intermediate_buf, ARRAY_SIZE(document_root_dir), NULL, NULL))
			{
				intermediate_buf[ARRAY_SIZE(document_root_dir) - 1] = 0;
				strcpy(document_root_dir, intermediate_buf);
			}
#else
			buf[ARRAY_SIZE(document_root_dir) - 1] = 0;
			strcpy(document_root_dir, buf);
#endif
			// Make sure the DocumentRoot path is valid:
			{
				struct mgstat st;
				if (mg_stat(document_root_dir, &st) != 0 || !st.is_directory)
				{
					// Invalid root directory; use the current directory instead!
					getcwd(document_root_dir, ARRAY_SIZE(document_root_dir));
				}
				else
				{
					fail = FALSE;
				}
			}
		}
		RegCloseKey(hKey);
	}
	if (fail)
	{
		mg_strlcpy(document_root_dir, default_path, ARRAY_SIZE(document_root_dir));
	}
}

static void rememberDocumentRoot()
{
	int fail = TRUE;
	HKEY hKey;
	DWORD disposition = 0;
	LONG rv = RegCreateKeyEx(HKEY_CURRENT_USER, WEBSERVER_REGISTRY_KEY, 0, NULL, 0, KEY_WRITE | KEY_WOW64_32KEY, NULL, &hKey, &disposition);
	if (rv == ERROR_SUCCESS)
	{
		WCHAR buf[ARRAY_SIZE(document_root_dir)];
		if (0 < MultiByteToWideChar(CP_UTF8, 0, document_root_dir, -1, buf, ARRAY_SIZE(document_root_dir)))
		{
			// sizeof(buf) : https://msdn.microsoft.com/en-us/library/windows/desktop/ms724921(v=vs.85).aspx says: number of BYTES!
			rv = RegSetKeyValueW(hKey, NULL, _T("DocumentRoot"), REG_SZ, buf, sizeof(buf));
			if (rv == ERROR_SUCCESS)
			{
				fail = FALSE;
			}
		}
		RegCloseKey(hKey);
	}
	if (fail)
	{
		fail += 0;
	}
}

#else

void append_log(const char *msg, ...)
{
	va_list args;
	char *buf = NULL;
	const char *msgbuf = msg;

	va_start(args, msg);
	if (strchr(msg, '%'))
	{
		mg_vasprintf(NULL, &buf, 0, msg, args);
		msgbuf = buf;
	}
	va_end(args);
	fputs(msgbuf, stderr);
	free(buf);
}


struct rc_info
{
	unsigned int data_len;
	void *data;

	const void *id;
	const void *category;
	const char *mime;
};

static int load_internal_resource(struct rc_info *dst, struct mg_context *ctx, struct mg_connection *conn,
	const char *uri)
{
	*dst = { 0 };

	return 0;
}


static void recallDocumentRoot(const char *default_path)
{
}

static void rememberDocumentRoot()
{
}

#endif

void die(const char *fmt, ...)
{
  va_list ap;
  char msg[1024];

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

  fprintf(stderr, "Mongoose version %s (c) Sergey Lyubka, built %s\n",
          mg_version(), __DATE__);
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  mongoose -A <htpasswd_file> <realm> <user> <passwd>\n");
  fprintf(stderr, "  mongoose <config_file>\n");
  fprintf(stderr, "  mongoose [-option value ...]\n");
  fprintf(stderr, "\nOPTIONS:\n");

  names = mg_get_valid_option_names();
  for (i = 0; names[i] != NULL; i += MG_ENTRIES_PER_CONFIG_OPTION)
  {
    fprintf(stderr, "  %s%s %s (default: \"%s\")\n",
            (names[i][0] ? "-" : "  "),
            names[i], names[i + 1], names[i + 2] == NULL ? "" : names[i + 2]);
  }
  fprintf(stderr, "\nSee  http://code.google.com/p/mongoose/wiki/MongooseManual"
          " for more details.\n");
  fprintf(stderr, "Example:\n  mongoose -s cert.pem -p 80,443s -d no\n");
  exit(EXIT_FAILURE);
}

static void verify_document_root(const char *root) {
  struct mgstat st;
  char buf[PATH_MAX];

  getcwd(buf, sizeof(buf));
  if (mg_stat(root, &st) != 0 || !st.is_directory)
  {
    die("Invalid root directory: [%s]: %s; current directory = [%s]", root, mg_strerror(ERRNO), buf);
  }
}


static void set_option(char **options, const char *name, const char *value) {
  int i;

  if (mg_get_option_long_name(name))
  {
    name = mg_get_option_long_name(name);
  }

  for (i = 0; i < MAX_OPTIONS * 2; i += 2)
  {
    // replace option value when it was set before: command line overrules config file, which overrules global defaults.
    if (options[i] == NULL)
    {
      options[i] = mg_strdup(name);
      options[i + 1] = mg_strdup(value);
      break;
    }
    else if (strcmp(options[i], name) == 0)
    {
      free(options[i + 1]);
      options[i + 1] = mg_strdup(value);
      break;
    }
  }

  if (i > MAX_OPTIONS * 2 - 2)
  {
    die("Too many options specified");
  }
}

static void process_command_line_arguments(char *argv[], char **options)
{
  char line[MAX_CONF_FILE_LINE_SIZE], opt[sizeof(line)], val[sizeof(line)], *p;
  FILE *fp = NULL;
  size_t i;
  int line_no = 0;

  options[0] = NULL;

  // Should we use a config file ?
  if (argv[1] != NULL && argv[2] == NULL)
  {
    snprintf(config_file, sizeof(config_file), "%s", argv[1]);
  }
  else if ((p = strrchr(argv[0], DIRSEP)) == NULL)
  {
    // No command line flags specified. Look where binary lives
    snprintf(config_file, sizeof(config_file), "%s", CONFIG_FILE);
  }
  else
  {
    snprintf(config_file, sizeof(config_file), "%.*s%c%s",
             (int) (p - argv[0]), argv[0], DIRSEP, CONFIG_FILE);
  }

  fp = mg_fopen(config_file, "r");

  // If config file was set in command line and open failed, exit
  if (argv[1] != NULL && argv[2] == NULL && fp == NULL)
  {
    die("Cannot open config file %s: %s", config_file, mg_strerror(ERRNO));
  }

  // use the default values for starters (so that all options have a known reasonable value):
  for (i = 0; default_options[i]; i += 2)
  {
    set_option(options, default_options[i], default_options[i+1]);
  }

  // Load config file settings first
  if (fp != NULL)
  {
    append_log("Loading config file %s\n", config_file);

    // Loop over the lines in config file
    while (fgets(line, sizeof(line), fp) != NULL)
    {
      if (!line_no && !memcmp(line,"\xEF\xBB\xBF", 3))
      {
        // strip UTF-8 BOM
        p = line+3;
      }
      else
      {
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

      if (2 == sscanf(line, "%s %[^\r\n#]", opt, val))
      {
        set_option(options, opt, val);
        continue;
      }
      else
      {
        die("%s: line %d is invalid", config_file, line_no);
        break;
      }
    }

    (void) mg_fclose(fp);
  }

  // Now handle command line flags. They override config file / default settings.
  for (i = 1; argv[i] != NULL; i += 2)
  {
    if (argv[i][0] != '-' || argv[i + 1] == NULL)
    {
      show_usage_and_exit(ctx);
    }
    set_option(options, &argv[i][1], argv[i + 1]);
  }
}

static void init_server_name(void)
{
  char buf[PATH_MAX];

  snprintf(server_name, sizeof(server_name), "Mongoose web server v%s",
           mg_version());

  getcwd(buf, sizeof(buf));
  recallDocumentRoot(buf);
}

// example and test case for a callback
// this callback creates a statistics of request methods and the requested uris
// it is not meant as a feature but as a simple test case

struct t_stat
{
  const char * name;
  unsigned long getCount;
  unsigned long postCount;
  struct t_stat * next;
};

struct t_user_arg
{
  pthread_mutex_t mutex;
  struct t_stat * uris[0x10000];
};

unsigned short crc16(const void * data, size_t bitCount)
{
  unsigned short r = 0xFFFFu;
  size_t i;
  for (i = 0; i < bitCount; i++)
  {
    unsigned short b = ((unsigned char*)data)[i>>3];
    b >>= i & 0x7ul;
    r = ((r & 1u) != (b & 1u)) ? ((r>>1) ^ 0xA001u) : (r>>1);
  }
  r ^= 0xFFFFu;
  return r;
}

static int report_markdown_failure(struct mg_connection *conn, int is_inline_production, int response_code, const char *fmt, ...)
{
  va_list args;

  if (is_inline_production)
  {
    mg_printf(conn, "<h1 style=\"color: red;\">Error: %d - %s</h1>\n", response_code, mg_get_response_code_text(response_code));
    va_start(args, fmt);
    mg_vprintf(conn, fmt, args);
    va_end(args);
  }
  else
  {
    va_start(args, fmt);
    mg_vsend_http_error(conn, response_code, NULL, fmt, args);
    va_end(args);
  }
  return -1;
}


static int serve_a_markdown_page(struct mg_connection *conn, const struct mgstat *st, int is_inline_production)
{
#define SD_READ_UNIT 1024
#define SD_OUTPUT_UNIT 64

  const struct mg_request_info *ri = mg_get_request_info(conn);
  struct sd_buf *ib, *ob;
  int ret;
  unsigned int enabled_extensions = MKDEXT_TABLES | MKDEXT_FENCED_CODE | MKDEXT_EMAIL_FRIENDLY;
  unsigned int render_flags = 0; // HTML_SKIP_HTML | HTML_SKIP_STYLE | HTML_HARD_WRAP;

  struct sd_callbacks callbacks;
  struct html_renderopt options;
  struct sd_markdown *markdown;

  /* opening the file */
  FILE *in;

  MG_ASSERT(ri->phys_path);
  /* opening the file */
  in = mg_fopen(ri->phys_path, "r");
  if (!in)
  {
    return report_markdown_failure(conn, is_inline_production, 404, "Unable to open input file: [%s] %s", ri->uri, mg_strerror(errno));
  }

  /* reading everything */
  ib = sd_bufnew(SD_READ_UNIT);
  if (SD_BUF_OK != sd_bufgrow(ib, (size_t)st->size))
  {
    mg_fclose(in);
    sd_bufrelease(ib);
    return report_markdown_failure(conn, is_inline_production, 500, "Out of memory while loading Markdown input file: [%s]", ri->uri);
  }
  ret = (int)fread(ib->data, 1, ib->asize, in);
  if (ret > 0)
  {
    ib->size += ret;
    mg_fclose(in);
  }
  else
  {
    mg_fclose(in);
    sd_bufrelease(ib);
    return report_markdown_failure(conn, is_inline_production, 500, "Cannot read from input file: [%s] %s", ri->uri, mg_strerror(errno));
  }

  /* performing markdown parsing */
  ob = sd_bufnew(SD_OUTPUT_UNIT);

  sdhtml_renderer(&callbacks, &options, render_flags);
  markdown = sd_markdown_new(enabled_extensions, 16, &callbacks, &options);
  if (!markdown)
  {
    sd_bufrelease(ib);
    sd_bufrelease(ob);
    return report_markdown_failure(conn, is_inline_production, 500, "Out of memory while processing Markdown input file: [%s]", ri->uri);
  }
  sd_markdown_render(ob, ib->data, ib->size, markdown);
  sd_markdown_free(markdown);

  if (!is_inline_production)
  {
    /* write the appropriate headers */
    char date[64], lm[64], etag[64];
    time_t curtime = time(NULL);
    const char *hdr;
    int64_t cl, r1, r2;
    int n;

    mg_set_response_code(conn, 200);

    cl = ob->size;

#if 0
    // If Range: header specified, act accordingly
    r1 = r2 = 0;
    hdr = mg_get_header(conn, "Range");
    if (hdr != NULL && (n = parse_range_header(hdr, &r1, &r2)) > 0)
    {
      mg_set_response_code(conn, 206);
      (void) fseeko(fp, (off_t) r1, SEEK_SET);
      cl = n == 2 ? r2 - r1 + 1: cl - r1;
      mg_add_response_header(conn, 0, "Content-Range",
                         "bytes "
                         "%" PRId64 "-%"
                         PRId64 "/%" PRId64 "\r\n",
                         r1, r1 + cl - 1, stp->size);
    }
#endif

    // Prepare Etag, Date, Last-Modified headers. Must be in UTC, according to
    // http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.3
    mg_gmt_time_string(date, sizeof(date), &curtime);
    mg_gmt_time_string(lm, sizeof(lm), &st->mtime);
    (void) mg_snprintf(conn, etag, sizeof(etag), "%lx.%lx", (unsigned long) st->mtime, (unsigned long) st->size);

    mg_add_response_header(conn, 0, "Date", "%s", date);
    mg_add_response_header(conn, 0, "Last-Modified", "%s", lm);
    mg_add_response_header(conn, 0, "Etag", "\"%s\"", etag);
    mg_add_response_header(conn, 0, "Content-Type", "text/html; charset=utf-8");
    mg_add_response_header(conn, 0, "Content-Length", "%" PRId64, cl);
    // Connection: close is automatically added by mg_write_http_response_head()
    mg_write_http_response_head(conn, 0, NULL);

    ret = (int)cl;
    if (strcmp(ri->request_method, "HEAD") != 0)
    {
      ret = mg_write(conn, ob->data, (size_t)cl);
    }
  }
  else
  {
    ret = mg_write(conn, ob->data, ob->size);
  }

  /* cleanup */
  sd_bufrelease(ib);
  sd_bufrelease(ob);

  return ret;
}

static int send_requested_resource(struct mg_context *ctx, struct mg_connection *conn,
  const struct mg_request_info *request_info, struct t_user_arg * udata)
{
  // Send the resource matching the given name
  struct rc_info rc_spec = { 0 };
  if (load_internal_resource(&rc_spec, ctx, conn, request_info->uri))
  {
	  mg_add_response_header(conn, 0, "Content-Type", "%s", rc_spec.mime);
	  mg_add_response_header(conn, 0, "Cache-Control", "no-cache");
      mg_add_response_header(conn, 0, "Content-Length", "%u", (unsigned int)rc_spec.data_len);
      mg_write_http_response_head(conn, 200, NULL);

      if ((int)rc_spec.data_len != mg_write(conn, rc_spec.data, rc_spec.data_len))
      {
        mg_send_http_error(conn, 580, NULL, "not all data was written to the socket (len: %u)", (unsigned int)rc_spec.data_len); // internal error in our custom handler or client closed connection prematurely
      }

      return 1;
  }
  return 0;
}

/*
  Ths bit of code shows how one can go about providing something very much like
  IP-based and/or Name-based Virtual Hosting.

  When you have your local DNS (or hosts file for that matter) configured to
  point the 'localhost-9.lan' domain name at IP address 127.0.0.9 and then run
  mongoose on your localhost and visit
    http://127.0.0.2/
  for an example of IP-based Virtual Hosting, or
    http://localhost-9.lan/
  for an example of Host-based Virtual Hosting, you will see another website
  located in ./documentation: the mongoose documentation pages.
  If you visit
    http://127.0.0.1/
  or
    http://127.0.0.9/
  instead you will visit the website located in ./test/

  ---

  Off Topic: one can override other options on a per-connection / request basis
             as well. This applies to all options which' values are fetched by
             mongoose through the internal get_conn_option() call - grep
             mongoose.c for that one if you like.
*/
// typedef const char * (*mg_option_get_callback_t)(struct mg_context *ctx, struct mg_connection *conn, const char *name);
static const char *option_get_callback(struct mg_context *ctx, struct mg_connection *conn, const char *name)
{
  // check local IP for IP-based Virtual Hosting & switch DocumentRoot for the connection accordingly:
  if (conn && !strcmp("document_root", name))
  {
    const struct mg_request_info *request_info = mg_get_request_info(conn);

    static char docu_site_docroot[PATH_MAX] = "";

    /* IP-based Virtual Hosting */
    if (!request_info->local_ip.is_ip6 &&
         request_info->local_ip.ip_addr.v4[0] == 127 &&
         request_info->local_ip.ip_addr.v4[1] == 0 &&
         request_info->local_ip.ip_addr.v4[2] == 0 &&
         request_info->local_ip.ip_addr.v4[3] >= 2 /* 127.0.0.x where x >= 2 */)
    {
      /* 127.0.0.x where x >= 2 */

      // use the CTX-based get-option call so our recursive invocation
      // skips this bit of code as 'conn == NULL' then:
      mg_snprintf(NULL, docu_site_docroot, sizeof(docu_site_docroot), "%s/../localhost-%03u", mg_get_option(ctx, name), (unsigned int)request_info->local_ip.ip_addr.v4[3]);

      return docu_site_docroot;
    }
    /* Name-based Virtual Hosting */
    int prefix_len = mg_match_string("*.gov|*.lan", -1, mg_get_header(conn, "Host")); /* e.g. 'nameless.gov:8081' or 'fifi.lan:8081' */
    if (0 < prefix_len)
    {
      // use the CTX-based get-option call so our recursive invocation
      // skips this bit of code as 'conn == NULL' then:
      mg_snprintf(NULL, docu_site_docroot, sizeof(docu_site_docroot), "%s/../%.*s", mg_get_option(ctx, name), prefix_len, mg_get_header(conn, "Host"));

      return docu_site_docroot;
    }
  }
  return NULL; // let mongoose handle it by himself
}



static void *mongoose_callback(enum mg_event event, struct mg_connection *conn)
{
  struct mg_context *ctx = mg_get_context(conn);
  const struct mg_request_info *request_info = mg_get_request_info(conn);
  int i;
  struct t_user_arg * udata = (struct t_user_arg *)mg_get_user_data(ctx)->user_data;
  const char * uri;
  unsigned short crc;
  struct t_stat ** st;
  char content[1024];
  int content_length;

  if (event == MG_INIT0)
  {
	const char *root_dir = mg_get_conn_option(conn, "document_root");
	// translate the path to an absolute path when it's relative, e.g. '../server/':
	// we ONLY do this at startup time; any other directory specs are suspicious by design.
#if defined(_WIN32)
	char buf[MAX_PATH];
	DWORD pathlen = GetFullPathNameA(root_dir, MAX_PATH, buf, NULL);
	if (GetLastError() == ERROR_SUCCESS) {
	  // now we see this slightly hacky way of circumventing the design of the options list: set once, never touch again!
	  mg_set_option(ctx, "document_root", buf);
	  root_dir = mg_get_conn_option(conn, "document_root");
	}
	// else: let it fail downstream...
#endif

    verify_document_root(root_dir);
    return (void *)1;
  }
  if (event == MG_EXIT_MASTER && mg_get_stop_flag(ctx))
  {
    /*
     master thread stopped due to STOP signal given by somebody;
     this is a sure-fire way to detect if the STOP signal was issued,
     but it has the 'drawback' that by now, the master thread and
     probably quite a few of the client threads have terminated as
     well.
     If you don't mind about that, it's a fine way to detect the STOP
     with a minimum of fuss in an event-driven environment such as the
     Windows message loop.
    */
#if defined(_WIN32)
	PostMessage(app_hwnd, WM_SERVER_IS_STOPPING, 0, 0);
#endif
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
  }
#endif
  if (event == MG_EVENT_LOG)
  {
    DEBUG_TRACE(0x00010000, ("[%s] %s", request_info->log_severity, request_info->log_message));
    // we do not log 'HTTP RESPONSE 304' 'error' lines as those are very valid responses (304 = Not Modified) which should not pollute the log window.
    switch (request_info->status_code)
    {
    case 304:
      // do not log 'Not Modified' messages.
      break;

    default:
      append_log("[%s] %s\n", request_info->log_severity, request_info->log_message);
      break;
    }
    return (void *)1;
  }

  if (event == MG_SSI_INCLUDE_REQUEST || event == MG_NEW_REQUEST)
  {
    struct mgstat st;
    int file_found;

    MG_ASSERT(request_info->phys_path);
    file_found = (0 == mg_stat(request_info->phys_path, &st) && !st.is_directory);
    if (file_found)
    {
      // are we looking for HTML output of MarkDown file?
      if (mg_match_string("**.md$|**.mkd$|**.markdown$|**.wiki$", -1, request_info->phys_path) > 0)
      {
        serve_a_markdown_page(conn, &st, (event == MG_SSI_INCLUDE_REQUEST));
        return "";
      }
      return NULL; // let mongoose handle the default of 'file exists'...
    }
  }

  if (event == MG_HTTP_ERROR)
  {
	  // This callback currently only handles new requests
	  return NULL;
  }

  if (event != MG_NEW_REQUEST)
  {
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

  while (*st)
  {
    if (!strcmp((*st)->name, uri))
    {
      break;
    }
    else
    {
      st = &((*st)->next);
    }
  }
  if (*st == NULL)
  {
    uri = mg_strdup(uri);
    *st = (struct t_stat*) calloc(1, sizeof(struct t_stat));
    if (!st || !uri)
    {
      pthread_mutex_unlock(&udata->mutex);
      die("out of memory");
    }
    (*st)->name = uri;
    (*st)->next = 0;
  }
  if (!strcmp(request_info->request_method, "GET"))
  {
    (*st)->getCount++;
  }
  else if (!strcmp(request_info->request_method, "POST"))
  {
    (*st)->postCount++;
  }
  pthread_mutex_unlock(&udata->mutex);

  if (!strcmp(uri, "/_stat"))
  {
    mg_connection_must_close(conn);
    // Connection: close is automatically added by mg_write_http_response_head()
    mg_add_response_header(conn, 0, "Cache-Control", "no-cache");
    mg_add_response_header(conn, 0, "Content-Type", "text/html; charset=utf-8");
    mg_write_http_response_head(conn, 200, NULL);

    mg_printf(conn,
              "<html><head><title>HTTP server statistics</title>"
              "<style>th {text-align: left;}</style></head>"
              "<body><h1>HTTP server statistics</h1>\r\n");

    mg_printf(conn,
              "<p><pre><table border=\"1\" rules=\"all\">"
              "<tr><th>Resource</th>"
              "<th>GET</th><th>POST</th></tr>\r\n");

    pthread_mutex_lock(&udata->mutex);

    for (i = 0; i < sizeof(udata->uris) / sizeof(udata->uris[0]); i++)
    {
      st = &udata->uris[i];
      while (*st)
      {
        mg_printf(conn, "<tr><td>%s</td><td>%8u</td><td>%8u</td></tr>\r\n",
                  (*st)->name, (*st)->getCount, (*st)->postCount);
        st = &((*st)->next);
      }
    }
    pthread_mutex_unlock(&udata->mutex);

    mg_printf(conn, "</table></pre></p></body></html>\r\n");
    return (void *)1;
  }
  else if (!strcmp(uri, "/_echo"))
  {
    const char * contentLength = mg_get_header(conn, "Content-Length");

    mg_connection_must_close(conn);
  // Connection: close is automatically added by mg_write_http_response_head()
    mg_add_response_header(conn, 0, "Cache-Control", "no-cache");
    mg_add_response_header(conn, 0, "Content-Type", "text/plain; charset=utf-8");
    mg_write_http_response_head(conn, 200, NULL);

    mg_printf(conn, "Received headers:\r\n");
    for (i = 0; i < request_info->num_headers; i++)
    {
        mg_printf(conn, "Header[%d]: '%s' = '%s'\r\n",
                  i, request_info->http_headers[i].name, request_info->http_headers[i].value);
    }
    mg_printf(conn, "----- info bits ------\r\n");
    mg_printf(conn, "URL: [%s]\r\n", request_info->uri);
    mg_printf(conn, "Query: [%s]\r\n", request_info->query_string);
    mg_printf(conn, "Phys.Path: [%s]\r\n", request_info->phys_path);
    mg_printf(conn, "----- data? ------\r\n");

    if (!strcmp(request_info->request_method, "POST"))
    {
      long int dataSize = atol(contentLength);
#if 0
      int bufferSize = (dataSize > 1024 * 1024 ? 1024 * 1024 : (int)dataSize);
#else
      int bufferSize = (int)dataSize;
#endif
      long int gotSize = 0;
      int bufferFill = 0;
      char * data = (char*) ((dataSize > 0) ? malloc(bufferSize) : 0);
      if (data)
      {
        mg_set_non_blocking_mode(conn, 1);
        {
          const int tcpbuflen = 1 * 1024 * 1024;

          mg_setsockopt(conn, SOL_SOCKET, SO_RCVBUF, (const void *)&tcpbuflen, sizeof(tcpbuflen));
          mg_setsockopt(conn, SOL_SOCKET, SO_SNDBUF, (const void *)&tcpbuflen, sizeof(tcpbuflen));
        }

        while (gotSize < dataSize && !mg_get_stop_flag(ctx))
        {
          int gotNow = 0;
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
            mg_FD_SET(conn, &read_set, &max_fd);
            if (select(max_fd + 1, &read_set, NULL, NULL, &tv2) < 0)
            {
              // signal a fatal failure:
              // clear the handles sets to prevent 'surprises' from processing these a second time (below):
              FD_ZERO(&read_set);
              max_fd = -1;
              MG_ASSERT(!"Should never get here");
              mg_send_http_error(conn, 579, NULL, "select() failure"); // internal error in our custom handler
              break;
            }
            else
            {
              if (mg_FD_ISSET(conn, &read_set))
              {
                break;
              }
              max_fd = -1;
            }
          }

          if (max_fd >= 0)
          {
            long int len = dataSize - gotSize;
            if (len > bufferSize - bufferFill)
            {
              len = bufferSize - bufferFill;
            }
            gotNow = mg_read(conn, data + bufferFill, len);
            if (gotNow > 0)
            {
              bufferFill += gotNow;
              if (bufferFill == bufferSize && bufferSize != dataSize)
              {
                bufferFill = mg_write(conn, data, bufferSize);
                if (bufferFill < 0)
                {
                  mg_send_http_error(conn, 579, NULL, "POST /_echo: write error at dataSize=%lu, gotNow=%u, gotSize=%lu\n", dataSize, gotNow, gotSize);
                  break;
                }
                bufferFill = bufferSize - bufferFill;
              }
            }
          }

          if (gotNow == 0)
          {
            DEBUG_TRACE(0x00020000,
                        ("POST /_echo: ***CLOSE*** at dataSize=%lu, gotNow=%u, gotSize=%lu\n",
                         dataSize, gotNow, gotSize));
            break;
          }
          gotSize += gotNow;
        }
        mg_set_non_blocking_mode(conn, 0);
        //mg_write(conn, data, gotSize);
        if (bufferFill > 0 && mg_get_stop_flag(ctx) == 0)
        {
          int wlen = mg_write(conn, data, bufferFill);
          if (bufferFill != wlen)
          {
            mg_send_http_error(conn, 580, NULL, "POST /_echo: ***ERR*** at dataSize=%lu, gotSize=%lu, wlen=%d\n", dataSize, gotSize, wlen); // internal error in our custom handler
          }
        }
        free(data);
      }
    }
    else
    {
      mg_printf(conn, "%s", request_info->request_method);
    }

    return (void *)1;
  }
  else
  {
    struct mgstat fst;

    MG_ASSERT(request_info->phys_path);
    if (0 == mg_stat(request_info->phys_path, &fst))
    {
      return NULL; // let mongoose handle the default of 'file exists/directory listing'...
    }

    if (strstr(uri, "/restart"))
    {
      // send an info page
      content_length = mg_snprintf(conn, content, sizeof(content),
                                   "<html><body><h1>Restart in progress</h1>"
                                   "<p><a href=\"/\">Click here</a> to view "
                                   "the hello page again.");

      mg_connection_must_close(conn);

      //mg_set_response_code(conn, 200);
      mg_add_response_header(conn, 0, "Content-Length", "%d", content_length);
      mg_add_response_header(conn, 0, "Content-Type", "text/html");
      //mg_add_response_header(conn, 0, "Connection", "%s", mg_suggest_connection_header(conn)); -- not needed any longer
      mg_write_http_response_head(conn, 200, 0);

      mg_write(conn, content, content_length);

      // signal the server to stop & restart
      should_restart = 1;
      mg_signal_stop(mg_get_context(conn));

      // Mark as processed
      return "";
    }
    else if (strstr(request_info->uri, "/quit"))
    {
      // send an info page
      content_length = mg_snprintf(conn, content, sizeof(content),
                                   "<html><body><h1>Server shut down in progress</h1>");

      mg_connection_must_close(conn);

      //mg_set_response_code(conn, 200);
      mg_add_response_header(conn, 0, "Content-Length", "%d", content_length);
      mg_add_response_header(conn, 0, "Content-Type", "text/html");
      //mg_add_response_header(conn, 0, "Connection", "%s", mg_suggest_connection_header(conn)); -- not needed any longer
      mg_write_http_response_head(conn, 200, 0);

      mg_write(conn, content, content_length);

      // signal the server to stop
      should_restart = 0;
      mg_signal_stop(mg_get_context(conn));

      // Mark as processed
      return "";
    }
    else
#ifdef _WIN32
    if (send_requested_resource(ctx, conn, request_info, udata))
    {
      return (void *)1;
    }
    else
#endif
    {
      struct mg_mime_vec mime_vec;
      char ip_addr_strbuf[128];

      // allow default error processing chain:
      if (!strncmp(uri, "/error/", 7)) {
        return 0;
      }

      // default error processing chain for JS/CSS/JSON/LESS/MD/TXT/COFFEE/COFFEESCRIPT/FONT/SVG/PDF/AI/PS/JPG/PNG/GIF/AVI/MKV/MOV/etc. files,
      // i.e. handle all file requests which have a MIME type as 'standard' UNLESS the requested file is a HTML file.
      mg_get_mime_type(ctx, uri, NULL, &mime_vec);
      if (mime_vec.ptr && mime_vec.len && !mg_vec_matches_string(&mime_vec, "text/html"))
      {
        return 0; // let mongoose handle the default of 'file exists'...
      }
	  return 0; // let mongoose handle the default of 'file exists'...

      content_length = mg_snprintf(conn, content, sizeof(content),
                   "<html><body>"
                   "<h1>404 - File not found!</h1>"
                   "<p>Hello from mongoose! Your browser's IP address & port: %s : %d. You requested the file: '<code>%s</code>'."
                                   "<p><a href=\"/restart\">Click here</a> to restart "
                                   "the server."
                                   "<p><a href=\"/quit\">Click here</a> to stop "
                                   "the server.",
                   mg_sockaddr_to_string(ip_addr_strbuf, ARRAY_SIZE(ip_addr_strbuf), conn, TRUE),
                                   request_info->remote_port,
                   request_info->uri);    // <-- known issue: we echo user data back to them without sanitizing it first; we don't mind in this sample/test server!

      //mg_set_response_code(conn, 200); -- not needed any longer
      mg_add_response_header(conn, 0, "Content-Length", "%d", content_length);
      mg_add_response_header(conn, 0, "Content-Type", "text/html");
      //mg_add_response_header(conn, 0, "Connection", "%s", mg_suggest_connection_header(conn)); -- not needed any longer
      mg_write_http_response_head(conn, 200, 0);

      mg_write(conn, content, content_length);

      // Mark as processed
      return "";
    }
  }

  return NULL;
}

#if defined(_WIN32)

static void report_possible_vhosts(void)
{
  char hosts_path[PATH_MAX];
  char line[512];
  unsigned int ip_lsb;
  char domainname[128];
  const char *sysdir = getenv("WINDIR");
  FILE *hf;

  mg_snprintf(NULL, hosts_path, ARRAY_SIZE(hosts_path), "%s/system32/drivers/etc/hosts", sysdir);
  hf = mg_fopen(hosts_path, "r");
  if (!hf)
  {
    return;
  }
  while (fgets(line, sizeof(line), hf) != NULL)
  {
    if (sscanf(line, "127.0.0.%u %128[^# \r\n]", &ip_lsb, domainname) != 2)
    {
      continue;
    }

    // Only accept valid entries which point at 127.0.0.1 .. 127.0.0.254 (.255 is a broadcast address)
    if (strlen(domainname) == 0 || !strcmp(domainname, "localhost") || ip_lsb < 1 || ip_lsb > 254)
      continue;
    // Only accept .gov and .lan domins at 127.0.0.1; accept ANY domain at 127.0.0.2 .. 127.0.0.254
    // --> this ensures we skip most 'loop entries' which may be entered in the hosts file to prevent
    // browsers visiting those, e.g.
    //   127.0.0.1    nasty.ads.com
    if (ip_lsb == 1 && mg_match_string("*.gov$|*.lan$", -1, domainname) < 0)
      continue;

    append_log("\nPossible VHost: http://%s:%s/", domainname, mg_get_option(ctx, "listening_ports"));
  }

  // Close file
  (void) mg_fclose(hf);
}

static void report_server_started(void)
{
  char root_url[256];
  char ports[64];
  char *p;
  mg_strlcpy(ports, mg_get_option(ctx, "listening_ports"), ARRAY_SIZE(ports));
  p = ports + strcspn(ports, ",sp");
  p[0] = 0;
  mg_snprintf(NULL, root_url, ARRAY_SIZE(root_url), "Visit URL: http://localhost:%s/", ports);
  append_log("\nRestartable server %s started on port(s) %s with web root directory:\n  [%s]\nroot URL: %s\n\n",
             server_name, mg_get_option(ctx, "listening_ports"),
             mg_get_option(ctx, "document_root"),
             root_url + 11);

#if 0
  // TODO: clean up the next 'report / log' part:
  report_possible_vhosts();

  append_log("\nThis server supports both IP-based and name-based VirtualHosts, e.g.\n"
             "URL: http://hobbelt.gov:%s @ path: ../hobbelt.gov/\n"
             "URL: http://127.0.0.2:%s @ path: ../localhost-2/\n\n",
             ports, ports);
  // /TODO
#endif

  if (IsWindow(app_hwnd))
  {
    SetDlgItemTextA(app_hwnd, IDC_BUTTON_VISIT_URL, root_url);
    mg_strlcpy(server_url, root_url + 11, ARRAY_SIZE(server_url));
  }
}

static BOOL WINAPI mg_win32_break_handler(DWORD signal_type)
{
  switch(signal_type)
  {
  // Handle the CTRL-C signal.
  case CTRL_C_EVENT:
  // CTRL-CLOSE: confirm that the user wants to exit.
  case CTRL_CLOSE_EVENT:
  case CTRL_BREAK_EVENT:
    should_restart = 0;
    exit_flag = 1000 + signal_type;
    //mg_signal_stop(ctx);
    return TRUE;

  // Pass other signals to the next handler.
  case CTRL_LOGOFF_EVENT:
  case CTRL_SHUTDOWN_EVENT:
  default:
    should_restart = 0;
    return FALSE;
  }
}

#endif


static void start_mongoose(int argc, char *argv[])
{
  char *options[MAX_OPTIONS * 2] = { NULL };
  int i;
  struct mg_user_class_t userdef =
  {
    0,
    &mongoose_callback,
    0,
    0,
    option_get_callback
  };

  should_restart = 0;

  /* Edit passwords file if -A option is specified */
  if (argc > 1 && !strcmp(argv[1], "-A"))
  {
    if (argc != 6)
    {
      show_usage_and_exit(ctx);
    }
    exit(mg_modify_passwords_file(argv[2], argv[3], argv[4], argv[5]) ?
         EXIT_SUCCESS : EXIT_FAILURE);
  }

  /* Show usage if -h or --help options are specified */
  if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")))
  {
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
    if (!pUser_arg)
    {
        die("out of memory");
    }
    pthread_mutex_init(&pUser_arg->mutex, 0);
    userdef.user_data = pUser_arg;
  }

  /* Start Mongoose */
  ctx = mg_start(&userdef, (const char **)options);
  for (i = 0; options[i] != NULL; i++)
  {
    free(options[i]);
  }

  if (ctx == NULL)
  {
    die("Failed to start Mongoose. Maybe some options are "
        "assigned bad values?\nTry to run with '-e error_log.txt' "
        "and check error_log.txt for more information.");
  }
}

#if defined(_WIN32)
#if defined(MONGOOSE_AS_SERVICE)
static SERVICE_STATUS ss;
static SERVICE_STATUS_HANDLE hStatus;
static const char *service_magic_argument = "--";

static void WINAPI ControlHandler(DWORD code)
{
  if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN)
  {
    ss.dwWin32ExitCode = 0;
    ss.dwCurrentState = SERVICE_STOPPED;
  }
  SetServiceStatus(hStatus, &ss);
}

static void WINAPI ServiceMain(void)
{
  ss.dwServiceType = SERVICE_WIN32;
  ss.dwCurrentState = SERVICE_RUNNING;
  ss.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

  hStatus = RegisterServiceCtrlHandlerA(server_name, ControlHandler);
  SetServiceStatus(hStatus, &ss);

  while (ss.dwCurrentState == SERVICE_RUNNING)
  {
    mg_sleep(1000);
  }
  mg_stop(ctx);
  ctx = NULL;

  ss.dwCurrentState = SERVICE_STOPPED;
  ss.dwWin32ExitCode = (DWORD) -1;
  SetServiceStatus(hStatus, &ss);
}
#endif // MONGOOSE_AS_SERVICE

#define ID_TRAYICON        100
#define ID_QUIT            101
#define ID_EDIT_CONFIG     102
#define ID_SEPARATOR       103
#if defined(MONGOOSE_AS_SERVICE)
#define ID_INSTALL_SERVICE 104
#define ID_REMOVE_SERVICE  105
#endif // MONGOOSE_AS_SERVICE

static NOTIFYICONDATAA TrayIcon;

static void edit_config_file(struct mg_context *ctx)
{
  const char **names, *value;
  FILE *fp;
  int i;
  char cmd[200];

  // Create config file if it is not present yet
  if ((fp = mg_fopen(config_file, "r")) != NULL)
  {
    mg_fclose(fp);
  }
  else if ((fp = fopen(config_file, "a+")) != NULL)
  {
    fprintf(fp,
            "# Mongoose web server configuration file.\n"
            "# Lines starting with '#' and empty lines are ignored.\n"
            "# For detailed description of every option, visit\n"
            "# http://code.google.com/p/mongoose/wiki/MongooseManual\n\n");
    names = mg_get_valid_option_names();
    for (i = 0; names[i] != NULL; i += MG_ENTRIES_PER_CONFIG_OPTION)
    {
      value = mg_get_option(ctx, names[i + 1]);
      fprintf(fp, "# %s %s\n", names[i + 1], *value ? value : "<value>");
    }
    mg_fclose(fp);
  }

  snprintf(cmd, sizeof(cmd), "notepad.exe %s", config_file);
  WinExec(cmd, SW_SHOW);
}

static void show_error(void)
{
  char buf[256];
  FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, GetLastError(),
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                buf, sizeof(buf), NULL);
  MessageBoxA(NULL, buf, "Error", MB_OK);
}

static void ClientRectToScreen(HWND hWnd, LPRECT rc)
{
  POINT p1 = { rc->left, rc->top };
  POINT p2 = { rc->right, rc->bottom };
  ClientToScreen(hWnd, &p1);
  ClientToScreen(hWnd, &p2);
  rc->left = p1.x;
  rc->top = p1.y;
  rc->right = p2.x;
  rc->bottom = p2.y;
}

typedef struct
{
  int left;
  int right;
  int top;
  int bottom;
  int width;
  int height;
} OFFSETS;

#define MAX_CHILD_COUNT     31      // keep this one prime as it's used as the modulus for a simpl/fast hash too!

typedef struct
{
  unsigned int is_set_up : 1;
  DWORD control_index_map[MAX_CHILD_COUNT];
  OFFSETS controlOffsets[1 + MAX_CHILD_COUNT]; // slot 0 stores the dialog edges info
} dlgInfo_t;

static dlgInfo_t dlgInfo = { 0 };

static OFFSETS *getControlOffsets(DWORD id)
{
  int slot, i;
  MG_ASSERT(id != 0);
  for (i = 0; i < MAX_CHILD_COUNT; i++)
  {
    slot = (id + i) % MAX_CHILD_COUNT;
    if (dlgInfo.control_index_map[slot] == id)
    {
      return &dlgInfo.controlOffsets[slot];
    }
    else if (!dlgInfo.control_index_map[slot])
    {
      dlgInfo.control_index_map[slot] = id;
      return &dlgInfo.controlOffsets[slot];
    }
  }
  MG_ASSERT(!"Should never get here!");
  return NULL;
}

static void calculateOffsets(HWND hControl, LPCRECT parent_client_rc)
{
  RECT rc = { 0 };
  LONG ctrl_id = GetWindowLong(hControl, GWL_ID);
  OFFSETS *dst_rc = getControlOffsets(ctrl_id);
  BOOL rv = GetWindowRect(hControl, &rc);
  //OffsetRect(&rc, -parent_client_rc.left, -parent_client_rc.top);
  dst_rc->width = rc.right - rc.left;
  dst_rc->height = rc.bottom - rc.top;
  rc.top -= parent_client_rc->top;
  rc.left -= parent_client_rc->left;
  rc.right -= parent_client_rc->right;
  rc.bottom -= parent_client_rc->bottom;
  dst_rc->left = rc.left;
  dst_rc->right = rc.right;
  dst_rc->top = rc.top;
  dst_rc->bottom = rc.bottom;
}

typedef enum child_control_move_mode_t
{
  STICK_TO_TOP = 0x01,
  STICK_TO_BOTTOM = 0x02,
  STICK_TO_LEFT = 0x04,
  STICK_TO_RIGHT = 0x08,
  RESIZE_WIDTH = (STICK_TO_LEFT | STICK_TO_RIGHT),
  RESIZE_HEIGHT = (STICK_TO_TOP | STICK_TO_BOTTOM),
  RESIZE_BOTH = (RESIZE_WIDTH | RESIZE_HEIGHT),
} MOVE_MODE;

static BOOL MoveChildControl(HWND hControl, LPCRECT parent_client_rc, MOVE_MODE mode)
{
  int l, r, t, b, w, h;
  // Retrieve the child-window identifier. Use it to get at the matching OFFSETS struct in the meta store to help us resize the bugger.
  LONG ctrl_id = GetWindowLong(hControl, GWL_ID);
  OFFSETS *offsets = getControlOffsets(ctrl_id);

  switch ((int)mode)
  {
  default:
    // do nothing
    break;

  case STICK_TO_BOTTOM | STICK_TO_LEFT:
    l = offsets->left;
    t = parent_client_rc->bottom - parent_client_rc->top + offsets->bottom - offsets->height;
    w = offsets->width;
    h = offsets->height;
    MG_ASSERT(h > 0);
    MG_ASSERT(w > 0);
    MoveWindow(hControl, l, t, w, h, TRUE);
    break;

  case STICK_TO_BOTTOM | STICK_TO_RIGHT:
    l = parent_client_rc->right - parent_client_rc->left + offsets->right - offsets->width;
    t = parent_client_rc->bottom - parent_client_rc->top + offsets->bottom - offsets->height;
    w = offsets->width;
    h = offsets->height;
    MG_ASSERT(h > 0);
    MG_ASSERT(w > 0);
    MoveWindow(hControl, l, t, w, h, TRUE);
    break;

  case RESIZE_BOTH:
    l = offsets->left;
    r = parent_client_rc->right - parent_client_rc->left + offsets->right;
    t = offsets->top;
    b = parent_client_rc->bottom - parent_client_rc->top + offsets->bottom;
    w = r - l;
    h = b - t;
    MG_ASSERT(h > 0);
    MG_ASSERT(w > 0);
    MoveWindow(hControl, l, t, w, h, TRUE);
    break;

  case RESIZE_WIDTH:
  case RESIZE_WIDTH | STICK_TO_TOP:
    l = offsets->left;
    r = parent_client_rc->right - parent_client_rc->left + offsets->right;
    t = offsets->top;
    b = offsets->top + offsets->height;
    w = r - l;
    h = b - t;
    MG_ASSERT(h > 0);
    MG_ASSERT(w > 0);
    MoveWindow(hControl, l, t, w, h, TRUE);
    break;

  case RESIZE_HEIGHT:
  case RESIZE_HEIGHT | STICK_TO_LEFT:
    l = offsets->left;
    r = offsets->left + offsets->width;
    t = offsets->top;
    b = parent_client_rc->bottom - parent_client_rc->top + offsets->bottom;
    w = r - l;
    h = b - t;
    MG_ASSERT(h > 0);
    MG_ASSERT(w > 0);
    MoveWindow(hControl, l, t, w, h, TRUE);
    break;
  }
  return TRUE;
}

typedef struct
{
  HWND parent_hwnd;
  RECT parent_wrect;
  RECT parent_clrect;
} CalcInfoClosureData;

BOOL CALLBACK EnumControlsToCalculateOffsets(HWND hWndChild, LPARAM lParam)
{
  CalcInfoClosureData *meta = (CalcInfoClosureData *)lParam;

  // Retrieve the child-window identifier. Use it to check and, if necessary, re-assign a fresh ID to the control.
  // This reassign activity is required to ensure that *all* child controls have unique IDs, including the
  // IDC_STATIC ones!
  LONG idChild = GetWindowLong(hWndChild, GWL_ID);
  if (idChild == IDC_STATIC)
  {
    static int new_index = IDC_STATIC_START_ID;
    new_index++;
    SetWindowLong(hWndChild, GWL_ID, new_index);
    idChild = GetWindowLong(hWndChild, GWL_ID);
  }

  calculateOffsets(hWndChild, &meta->parent_clrect);

  return TRUE;
}

BOOL CALLBACK EnumControlsToResizeThem(HWND hWndChild, LPARAM lParam)
{
  CalcInfoClosureData *meta = (CalcInfoClosureData *)lParam;

  // Retrieve the child-window identifier. Use it to get at the matching OFFSETS struct in the meta store to help us resize the bugger.
  LONG idChild = GetWindowLong(hWndChild, GWL_ID);

  switch (idChild)
  {
  default:
    MoveChildControl(hWndChild, &meta->parent_clrect, STICK_TO_TOP | RESIZE_WIDTH);
    break;

  case IDC_STATIC_LOGO:
    MoveChildControl(hWndChild, &meta->parent_clrect, STICK_TO_TOP | STICK_TO_LEFT);
    break;

  case IDC_EDIT_WRAPPER:
  case IDC_RICHEDIT4LOG:
    MoveChildControl(hWndChild, &meta->parent_clrect, RESIZE_BOTH);
    break;

  case IDC_BUTTON_CLEAR_LOG:
    MoveChildControl(hWndChild, &meta->parent_clrect, STICK_TO_BOTTOM | STICK_TO_LEFT);
    break;

  case IDC_BUTTON_CREATE_VHOSTS_DIRS:
    MoveChildControl(hWndChild, &meta->parent_clrect, STICK_TO_BOTTOM | STICK_TO_RIGHT);
    break;
  }

  return TRUE;
}


#if defined(MONGOOSE_AS_SERVICE)
static int manage_service(int action)
{
  static const char *service_name = "Mongoose";
  SC_HANDLE hSCM = NULL, hService = NULL;
  SERVICE_DESCRIPTIONA descr = {server_name};
  char path[PATH_MAX + 20];  // Path to executable plus magic argument
  int success = 1;

  if ((hSCM = OpenSCManager(NULL, NULL, action == ID_INSTALL_SERVICE ?
                            GENERIC_WRITE : GENERIC_READ)) == NULL)
  {
    success = 0;
    show_error();
  }
  else if (action == ID_INSTALL_SERVICE)
  {
    GetModuleFileNameA(NULL, path, sizeof(path));
    strncat(path, " ", sizeof(path));
    strncat(path, service_magic_argument, sizeof(path));
    hService = CreateServiceA(hSCM, service_name, service_name,
                             SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                             SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                             path, NULL, NULL, NULL, NULL, NULL);
    if (hService)
    {
      ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, &descr);
    }
    else
    {
      show_error();
    }
  }
  else if (action == ID_REMOVE_SERVICE)
  {
    if ((hService = OpenServiceA(hSCM, service_name, DELETE)) == NULL ||
        !DeleteService(hService))
    {
      show_error();
    }
  }
  else if ((hService = OpenServiceA(hSCM, service_name,
                                     SERVICE_QUERY_STATUS)) == NULL)
  {
    success = 0;
  }

  CloseServiceHandle(hService);
  CloseServiceHandle(hSCM);

  return success;
}
#endif // MONGOOSE_AS_SERVICE

static BOOL CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wParam,
                                   LPARAM lParam)
{
#if defined(MONGOOSE_AS_SERVICE)
  static SERVICE_TABLE_ENTRYA service_table[] =
  {
    {server_name, (LPSERVICE_MAIN_FUNCTIONA) ServiceMain},
    {NULL, NULL}
  };
  int service_installed;
  char *service_argv[] = {__argv[0], NULL};
#endif // MONGOOSE_AS_SERVICE
  char buf[256];
  POINT pt;
  HMENU hMenu;
  //HWND hwndOwner;
  //RECT rcOwner, rcDlg, rc;
  NMHDR *nm;
  ENLINK *link;
  CHARRANGE cr;

  switch (msg)
  {
  case WM_INITDIALOG:
    app_hwnd = hWnd;

#if 0 // this is handled by the DM_REPOSITION message

    // Get the owner window and dialog box rectangles.
    if ((hwndOwner = GetParent(hWnd)) == NULL)
    {
        hwndOwner = GetDesktopWindow();
    }

    GetWindowRect(hwndOwner, &rcOwner);
    GetWindowRect(hWnd, &rcDlg);
    CopyRect(&rc, &rcOwner);

    // Offset the owner and dialog box rectangles so that right and bottom
    // values represent the width and height, and then offset the owner again
    // to discard space taken up by the dialog box.
    OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top);
    OffsetRect(&rc, -rc.left, -rc.top);
    OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom);

    // The new position is the sum of half the remaining space and the owner's
    // original position.
    SetWindowPos(hWnd,
                 HWND_TOP,
                 rcOwner.left + (rc.right / 2),
                 rcOwner.top + (rc.bottom / 2),
                 0, 0,          // Ignores size arguments.
                 SWP_NOSIZE);

    if (GetDlgCtrlID((HWND) wParam) != IDC_RICHEDIT4LOG)
    {
        SetFocus(GetDlgItem(hWnd, IDC_RICHEDIT4LOG));
        //return FALSE;
    }
#endif

    SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_SETEVENTMASK, 0, ENM_LINK);
    SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_AUTOURLDETECT, AURL_ENABLEURL | (edit_control_version >= 5 ? AURL_ENABLEEAURLS : 0), 0);
    SetWindowTextA(hWnd, server_name);
    PostMessage(hWnd, DM_REPOSITION, 0, 0);
    PostMessage(hWnd, WM_START_SERVER, 0, 0);
    return TRUE;

  case WM_SETFONT:
    return FALSE;

  case WM_CREATE:
    app_hwnd = hWnd;
    SendMessage(hWnd, WM_START_SERVER, 0, 0);
    break;

  case WM_START_SERVER:
    if (ctx == NULL) {
#if defined(MONGOOSE_AS_SERVICE)
      if (__argv[1] != NULL &&
          !strcmp(__argv[1], service_magic_argument))
      {
        PostMessage(hWnd, WM_RESTART_SERVER, 0, 0);
        StartServiceCtrlDispatcherA(service_table);
        exit(EXIT_SUCCESS);
      }
      else
      {
#else
      {
#endif // MONGOOSE_AS_SERVICE
        PostMessage(hWnd, WM_RESTART_SERVER, 0, 0);
      }
    }
    break;

  case WM_SIZE:
    if (wParam == SIZE_RESTORED)
    {
      CalcInfoClosureData meta = { 0 };
      meta.parent_hwnd = hWnd;

      // Get the client rect of the dialog itself to calculate the *relative* positions
      // of the controls inside.
      GetWindowRect(hWnd, &meta.parent_wrect);
      GetClientRect(hWnd, &meta.parent_clrect);
      ClientRectToScreen(hWnd, &meta.parent_clrect);

      if (!dlgInfo.is_set_up)
      {
        OFFSETS *dlgClientAreaOffsets = &dlgInfo.controlOffsets[0];
        dlgInfo.control_index_map[0] = 0xFFFFFFFFul;    // mark slot as allocated
        dlgClientAreaOffsets->left = meta.parent_clrect.left - meta.parent_wrect.left;
        dlgClientAreaOffsets->right = meta.parent_clrect.right - meta.parent_wrect.right;
        dlgClientAreaOffsets->top = meta.parent_clrect.top - meta.parent_wrect.top;
        dlgClientAreaOffsets->bottom = meta.parent_clrect.bottom - meta.parent_wrect.bottom;
        dlgClientAreaOffsets->width = dlgClientAreaOffsets->left - dlgClientAreaOffsets->right;
        dlgClientAreaOffsets->height = dlgClientAreaOffsets->top - dlgClientAreaOffsets->bottom;

        EnumChildWindows(hWnd, EnumControlsToCalculateOffsets, (LPARAM)&meta);

        dlgInfo.is_set_up = 1;
      }

      EnumChildWindows(hWnd, EnumControlsToResizeThem, (LPARAM)&meta);
    }
    return FALSE;

  case WM_SIZING:
    if (!dlgInfo.is_set_up)
    {
      return FALSE;
    }
    else
    {
      LPRECT wrc = (LPRECT)lParam;
      OFFSETS *dlgClientAreaOffsets = &dlgInfo.controlOffsets[0];
      OFFSETS *editControlOffsets = getControlOffsets(IDC_EDIT_WRAPPER);
      OFFSETS *clearButtonOffsets = getControlOffsets(IDC_BUTTON_CLEAR_LOG);
      OFFSETS *genDirsButtonOffsets = getControlOffsets(IDC_BUTTON_CREATE_VHOSTS_DIRS);
      int dlgBorderH = dlgClientAreaOffsets->height;
      int dlgBorderW = dlgClientAreaOffsets->width;
      int min_h = editControlOffsets->top - editControlOffsets->bottom + /* ~ 2 lines of text: */ 24;
      int min_w = clearButtonOffsets->left + clearButtonOffsets->width + genDirsButtonOffsets->width - genDirsButtonOffsets->right + /* gutter: */ 4;
      int w = wrc->right - wrc->left;
      int h = wrc->bottom - wrc->top;
      min_w += dlgBorderW;
      min_h += dlgBorderH;
      if (w < min_w)
      {
        wrc->right = wrc->left + min_w;
      }
      if (h < min_h)
      {
        wrc->bottom = wrc->top + min_h;
      }
    }
    return TRUE;

  case WM_COMMAND:
    switch (LOWORD(wParam))
    {
    case ID_QUIT:
      should_restart = 0;
      mg_stop(ctx);
      ctx = NULL;
      //Shell_NotifyIconA(NIM_DELETE, &TrayIcon);
      PostQuitMessage(EXIT_SUCCESS);
      break;

    case ID_EDIT_CONFIG:
      edit_config_file(ctx);
      break;

#if defined(MONGOOSE_AS_SERVICE)
    case ID_INSTALL_SERVICE:
    case ID_REMOVE_SERVICE:
      manage_service(LOWORD(wParam));
      break;
#endif // MONGOOSE_AS_SERVICE

    case IDC_BUTTON_VISIT_URL:
      ShellExecuteA(NULL, "open", server_url, NULL, NULL, SW_SHOWNORMAL);
      break;

	case IDC_BUTTON_CLEAR_LOG:
	  {
		// http://msdn.microsoft.com/en-us/library/windows/desktop/bb774195(v=vs.85).aspx
		//GETTEXTLENGTHEX tex = { GTL_DEFAULT, 1200 /* Unicode */ };
		//DWORD txtlen = SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_GETTEXTLENGTHEX, (WPARAM)&tex, 0);
		DWORD txtlen = GetWindowTextLength(GetDlgItem(hWnd, IDC_RICHEDIT4LOG));
		if (txtlen > 0)
		{
			// Throw away all the lines...
			cr.cpMin = 0;
			cr.cpMax = -1;
			SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_EXSETSEL, 0, (LPARAM)&cr);
			SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_REPLACESEL, FALSE, (LPARAM)_T(""));
			SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_HIDESELECTION, TRUE, 0);
			// and make sure the new text is visible: http://stackoverflow.com/questions/2208858/ensure-the-last-character-in-a-richedit-control-is-visible
			SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_SCROLLCARET, 0, 0);
		}
  	  }
	  return TRUE;

	case IDC_BUTTON_CREATE_VHOSTS_DIRS:
      // TODO
	  break;
	}
    break;

  case WM_NOTIFY:
    nm = (NMHDR *)lParam;
    switch (nm->code)
    {
    case EN_LINK:
      link = (ENLINK *)lParam;
      switch (link->msg)
      {
      case WM_LBUTTONDOWN:
      case WM_LBUTTONUP:
      case WM_LBUTTONDBLCLK:
        if (link->chrg.cpMax - link->chrg.cpMin < ARRAY_SIZE(buf))
        {
          DWORD len;
          TCHAR server_url[ARRAY_SIZE(buf)];
          SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_EXSETSEL, 0, (LPARAM)&link->chrg);
          len = SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_GETSELTEXT, FALSE, (LPARAM)server_url);
          server_url[len] = 0;
          // visit URL:
          ShellExecute(NULL, _T("open"), server_url, NULL, NULL, SW_SHOWNORMAL);
        }
        else
        {
          append_log("[error] Cannot start browser to point at URL in text due to buffer overflow.\n");
        }
        break;
      }
    }
    break;

  case WM_TRAY_ICON_HIT:
    switch (lParam)
    {
    case WM_RBUTTONUP:
    case WM_LBUTTONUP:
    case WM_LBUTTONDBLCLK:
      hMenu = CreatePopupMenu();
      AppendMenuA(hMenu, MF_STRING | MF_GRAYED, ID_SEPARATOR, server_name);
      AppendMenuA(hMenu, MF_SEPARATOR, ID_SEPARATOR, "");
#if defined(MONGOOSE_AS_SERVICE)
      service_installed = manage_service(0);
      snprintf(buf, sizeof(buf), "NT service: %s installed",
               service_installed ? "" : "not");
      AppendMenuA(hMenu, MF_STRING | MF_GRAYED, ID_SEPARATOR, buf);
      AppendMenuA(hMenu, MF_STRING | (service_installed ? MF_GRAYED : 0),
                 ID_INSTALL_SERVICE, "Install service");
      AppendMenuA(hMenu, MF_STRING | (!service_installed ? MF_GRAYED : 0),
                 ID_REMOVE_SERVICE, "Deinstall service");
      AppendMenuA(hMenu, MF_SEPARATOR, ID_SEPARATOR, "");
#endif // MONGOOSE_AS_SERVICE
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
    should_restart = 0;
    mg_stop(ctx);
    ctx = NULL;
    //Shell_NotifyIconA(NIM_DELETE, &TrayIcon);
    PostQuitMessage(EXIT_SUCCESS);

    DragAcceptFiles(hWnd, FALSE);
    DestroyWindow(hWnd);
    return TRUE;  // We've just sent our own quit message, with proper hwnd.

  case WM_DESTROY:
    if (hWnd == app_hwnd)
    {
      app_hwnd = NULL;
    }
    break;

  case WM_NCDESTROY:
    if (hWnd == app_hwnd)
    {
      app_hwnd = NULL;
    }
    break;

  case WM_DROPFILES:  // drag & drop functionality: when a file is dropped, its directory is used.
    {
      HDROP drop_handle = (HDROP)wParam;
      int filecount = DragQueryFile(drop_handle, 0xFFFFFFFF, NULL, 0);
      int i;
      char filepath[PATH_MAX + 1];
      struct mgstat st;

      for (i = 0; i < filecount; i++)
      {
        DragQueryFileA(drop_handle, i, filepath, ARRAY_SIZE(filepath));
        if (!mg_mk_fullpath(filepath, ARRAY_SIZE(filepath)) &&
            !mg_stat(filepath, &st))
        {
          append_log("[info] Dropped file/directory [%s]\n", filepath);
          if (!st.is_directory)
          {
            strrchr(filepath, '/')[0] = 0;
          }
          if (!mg_stat(filepath, &st) && st.is_directory)
          {
            mg_strlcpy(document_root_dir, filepath, ARRAY_SIZE(document_root_dir));
            append_log("[info] Dropped file/directory --> DocumentRoot = [%s]\n", document_root_dir);
			rememberDocumentRoot();
            should_restart = 1;
            mg_signal_stop(ctx);
            break;
          }
        }
      }
      DragFinish(drop_handle);
      return TRUE;
    }
    break;

  case WM_APPEND_LOG:
    {
      CHARFORMAT2 cf = {0};
      int pos;
      wchar_t *wbuf;
      size_t wbuf_len = strlen((const char *)lParam);
      wbuf_len++;
      wbuf_len *= 2;
      wbuf = (wchar_t *)malloc(wbuf_len);
      if (buf && MultiByteToWideChar(CP_UTF8, 0, (const char *)lParam, -1, wbuf, (int) wbuf_len))
      {
        for(;;)
        {
          // http://msdn.microsoft.com/en-us/library/windows/desktop/bb774195(v=vs.85).aspx
          //GETTEXTLENGTHEX tex = { GTL_DEFAULT, 1200 /* Unicode */ };
          //DWORD txtlen = SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_GETTEXTLENGTHEX, (WPARAM)&tex, 0);
          DWORD txtlen = GetWindowTextLength(GetDlgItem(hWnd, IDC_RICHEDIT4LOG));
          if (txtlen + wbuf_len/2 > 32000)
          {
            // Throw away the top lines until there's sufficient space...
            FINDTEXT ft = { { 0, -1 }, _T("\r") };
            cr.cpMin = 0;
            cr.cpMax = SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_FINDTEXT, FR_DOWN, (LPARAM)&ft) + 1;
            SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_EXSETSEL, 0, (LPARAM)&cr);
            SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_REPLACESEL, FALSE, (LPARAM)_T(""));
          }
          else
          {
            break;
          }
        }
        // select end of text:
        cr.cpMin = -1;
        cr.cpMax = -1;
        SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_EXSETSEL, 0, (LPARAM)&cr);
        // color severity sections RED:
        pos = 0;
        if (wbuf[pos] == '[')
        {
          for (pos = 1; wbuf[pos]; pos++)
          {
            if (wbuf[pos] == ']')
              break;
          }
        }
        if (pos > 0 && wbuf[pos] == ']')
        {
          wchar_t sentinel = wbuf[++pos];
          wbuf[pos] = 0;

          cf.cbSize = sizeof(cf);
          cf.dwMask = CFM_COLOR;
          cf.crTextColor = RGB(255,0,0);
          SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
          SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_REPLACESEL, 0, (LPARAM)wbuf);
          // and now write the remainder of the text:
          wbuf[pos] = sentinel;
          cr.cpMin = -1;
          cr.cpMax = -1;
          SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_EXSETSEL, 0, (LPARAM)&cr);
          cf.cbSize = sizeof(cf);
          cf.dwMask = CFM_COLOR;
          cf.crTextColor = RGB(0,0,0);
          SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
          SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_REPLACESEL, 0, (LPARAM)(wbuf + pos));
        }
        else
        {
          SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_REPLACESEL, 0, (LPARAM)wbuf);
        }
        SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_HIDESELECTION, TRUE, 0);
        // and make sure the new text is visible: http://stackoverflow.com/questions/2208858/ensure-the-last-character-in-a-richedit-control-is-visible
        SendDlgItemMessage(hWnd, IDC_RICHEDIT4LOG, EM_SCROLLCARET, 0, 0);
      }
      free(wbuf);
    }
    return TRUE;

  case WM_SERVER_IS_STOPPING:
    // check if we need to restart the server.
    if (should_restart)
    {
      mg_stop(ctx);
      ctx = NULL;
      append_log("Server stopped; will restart now.\n");

      PostMessage(hWnd, WM_RESTART_SERVER, 0, 0);
    }
    else
    {
      mg_stop(ctx);
      ctx = NULL;
      append_log("Server stopped.\n");

      //Shell_NotifyIconA(NIM_DELETE, &TrayIcon);
      PostQuitMessage(EXIT_SUCCESS);
    }
    return TRUE;

  case WM_RESTART_SERVER:
#if defined(MONGOOSE_AS_SERVICE)
    if (__argv[1] != NULL &&
      !strcmp(__argv[1], service_magic_argument))
    {
      start_mongoose(1, service_argv);
      report_server_started();
    }
    else
    {
#else
    {
#endif // MONGOOSE_AS_SERVICE
      start_mongoose(__argc, __argv);
      report_server_started();
    }
    break;
  }

#if 0
  // See also: http://stackoverflow.com/questions/11884021/c-why-this-window-title-gets-truncated
  // In our case, we get a clobbered window title in a Unicode build.
  if(IsWindowUnicode(hWnd))
    return DefWindowProcW(hWnd, msg, wParam, lParam);
  else
    return DefWindowProcA(hWnd, msg, wParam, lParam);
#else
  return FALSE;
#endif
}

HMODULE richedit_h = NULL;

// Here we attempt to load the latest RichEdit control from Microsoft
// and adjust our resource IDs accordingly as we cannot patch the
// resource class in any control defined through the resource compiler. :-(
HRESULT initRichEditControl(HINSTANCE hInst)
{
  HRESULT rv = E_UNEXPECTED;

  // Initialize RichEdit 4.1 .. 8.0 control
  richedit_h = LoadLibrary(_T("msftedit.dll"));
  // You can find out which version is loaded when you load msftedit.dll:
  if (richedit_h)
  {
    FARPROC f = GetProcAddress(richedit_h, "DllGetVersion");
    if (f)
    {
      typedef HRESULT CALLBACK DllGetVersion_f(DLLVERSIONINFO *pdvi);
      DllGetVersion_f *getV = (DllGetVersion_f *)f;
      DLLVERSIONINFO inf = { sizeof(DLLVERSIONINFO) };
      rv = getV(&inf);
      if (rv == S_OK)
      {
        edit_control_version = inf.dwMajorVersion;
      }
    }
  }
  // Initialize RichEdit 2.0 control
  if (richedit_h == NULL)
  {
    richedit_h = LoadLibrary(_T("RICHED20.DLL"));
    rv = S_OK;
    edit_control_version = 3;
  }
  if (richedit_h == NULL)
  {
    return E_NOTIMPL;
  }
  return rv;
}

// HRESULT initRichEditControl_Phase2(HINSTANCE hInst, HWND hWnd)
// {
//  HWND test_control = NULL;
//  HRESULT dwError = E_UNEXPECTED;

//  if (richedit_h != NULL && test_control == NULL) {
//    test_control = CreateWindowEx(WS_EX_CLIENTEDGE,
//      _T("RICHEDIT60W"),
//      _T("My Rich Edit"),
//      WS_BORDER | WS_CHILD | WS_VISIBLE | ES_MULTILINE,
//      2, 2,
//      200, 300,
//      hWnd,
//      0,
//      hInst,
//      NULL);
//    dwError = GetLastError();
//    if (dwError && dwError != ERROR_CANNOT_FIND_WND_CLASS) {
//      dwError += 0;
//    }
//    if (dwError == S_OK) {
//      IDC_RICHEDIT4LOG = IDC_RICHEDIT4LOG60;
//    }
//  }

//  if (richedit_h != NULL && test_control == NULL) {
//    test_control = CreateWindowEx(WS_EX_CLIENTEDGE,
//      _T("RICHEDIT50W"),
//      _T("My Rich Edit"),
//      WS_BORDER | WS_CHILD | WS_VISIBLE | ES_MULTILINE,
//      2, 2,
//      200, 300,
//      hWnd,
//      0,
//      hInst,
//      NULL);
//    dwError = GetLastError();
//    if (dwError && dwError != ERROR_CANNOT_FIND_WND_CLASS) {
//      dwError += 0;
//    }
//    if (dwError == S_OK) {
//      IDC_RICHEDIT4LOG = IDC_RICHEDIT4LOG60;
//    }
//  }

//  if (richedit_h != NULL && test_control == NULL) {
//    test_control = CreateWindowEx(WS_EX_CLIENTEDGE,
//      _T("RICHEDIT20W"),
//      _T("My Rich Edit 2"),
//      WS_BORDER | WS_CHILD | WS_VISIBLE | ES_MULTILINE,
//      2, 2,
//      200, 300,
//      hWnd,
//      0,
//      hInst,
//      NULL);
//    dwError = GetLastError();
//    if (dwError && dwError != ERROR_CANNOT_FIND_WND_CLASS) {
//      dwError += 0;
//    }
//    if (dwError == S_OK) {
//      IDC_RICHEDIT4LOG = IDC_RICHEDIT4LOG60;
//    }
//  }
//  if (test_control) {
//    DestroyWindow(test_control);
//  }
//  if (IDC_RICHEDIT4LOG) {
//    return S_OK;
//  }
//  return dwError;
// }

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmdline, int show)
{
  WNDCLASSA cls;
  HWND hWnd;
  MSG msg;
  HRESULT rv;

  //WM_SERVER_IS_STOPPING = RegisterWindowMessageA("mongoose_server_stopping");

  rv = initRichEditControl(hInst);
  if (rv != S_OK)
  {
    MessageBox(NULL, _T("Could not load the RichEdit control DLL."), _T("Error"), MB_OK | MB_ICONEXCLAMATION);
    return EXIT_FAILURE;
  }

  init_server_name();
  memset(&cls, 0, sizeof(cls));
  cls.lpfnWndProc = (WNDPROC) WindowProc;
  cls.hIcon = LoadIcon(NULL, IDI_APPLICATION);
  cls.lpszClassName = server_name;

  // As CreateDialog() will only succeed when we provide a resource which contains nothing but
  // valid control classes, we have one resource for every RichEdit version we may have loaded
  // earlier: here we discover whcihc RichEdit control is available for real:
  hWnd = CreateDialog(hInst, MAKEINTRESOURCE(IDD_FORMVIEW60), NULL, WindowProc);
  if (!hWnd)
  {
    edit_control_version = MG_MIN(6, edit_control_version);
    hWnd = CreateDialog(hInst, MAKEINTRESOURCE(IDD_FORMVIEW50), NULL, WindowProc);
  }
  if (!hWnd)
  {
    edit_control_version = MG_MIN(3, edit_control_version);
    hWnd = CreateDialog(hInst, MAKEINTRESOURCE(IDD_FORMVIEW20), NULL, WindowProc);
  }
  //rv = initRichEditControl_Phase2(hInst, hWnd);
  //if (rv != S_OK) ...
  if (!hWnd)
  {
    MessageBox(NULL, _T("Could not load the RichEdit control DLL."), _T("Error"), MB_OK | MB_ICONEXCLAMATION);
    return EXIT_FAILURE;
  }

  TrayIcon.cbSize = sizeof(TrayIcon);
  TrayIcon.uID = ID_TRAYICON;
  TrayIcon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
  TrayIcon.hIcon = (HICON)LoadImage(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON),
                                    IMAGE_ICON, 16, 16, 0);
  TrayIcon.hWnd = hWnd;
  snprintf(TrayIcon.szTip, sizeof(TrayIcon.szTip), "%s", server_name);
  TrayIcon.uCallbackMessage = WM_TRAY_ICON_HIT;
  Shell_NotifyIconA(NIM_ADD, &TrayIcon);

  ShowWindow(hWnd, SW_SHOW);

  DragAcceptFiles(hWnd, TRUE);

  while (GetMessage(&msg, hWnd, 0, 0) > 0)
  {
    if (!IsWindow(hWnd) || !IsDialogMessage(hWnd, &msg))
    {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
  }

  DragAcceptFiles(hWnd, FALSE);
  DestroyWindow(hWnd);

  Shell_NotifyIconA(NIM_DELETE, &TrayIcon);
  // HMODULE richedit_h = GetModuleHandle(_T("RICHED32.DLL"));
  FreeLibrary(richedit_h);

  // return the WM_QUIT value:
  return msg.wParam;
}
#else
int main(int argc, char *argv[])
{
  init_server_name();

  should_restart = 0;
  do
  {
    start_mongoose(argc, argv);

    printf("Restartable server %s started on port(s) %s with web root [%s]\n",
           server_name, mg_get_option(ctx, "listening_ports"),
           mg_get_option(ctx, "document_root"));
    while (exit_flag == 0 && !mg_get_stop_flag(ctx))
    {
      mg_sleep(100);
    }
    printf("Stopping on signal %d/%d, waiting for all threads to finish...",
          exit_flag, mg_get_stop_flag(ctx));
    fflush(stdout);
    mg_stop(ctx);
    ctx = NULL;
    printf("Server stopped.\n");
  } while (should_restart);

  mg_sleep(1000);
  printf("Server terminating now.\n");
  return EXIT_SUCCESS;
}
#endif /* _WIN32 */


static void srv_write_assert_to_logfile(struct mg_connection *conn, const char *expr, const char *filepath, unsigned int lineno)
{
  // Also write the assertion failure to the logfile, iff we're able to...
  if (conn)
  {
    const char *logfile = mg_get_default_error_logfile_path(conn);
    if (logfile)
    {
      FILE *fp = mg_fopen(logfile, "a+");
      if (fp != NULL)
      {
        flockfile(fp);
        fprintf(fp, "[assert] assertion failed: \"%s\" (%s @ line %u)\n", expr, filepath, lineno);
        fflush(fp);
        funlockfile(fp);
        mg_fclose(fp);
      }
    }
  }
}

void srv_signal_assert(const char *expr, const char *filepath, unsigned int lineno)
{
  struct mg_connection *conn = mg_get_fake_printf_conn(NULL);
  char msg[1024];

  mg_snprintf(conn, msg, sizeof(msg), "[assert] assertion failed: \"%s\" (%s @ line %u)\n", expr, filepath, lineno);

#if defined(_WIN32)
  MessageBoxA(NULL, msg, "Assertion Failure", MB_OK);
  error_dialog_shown_previously = 1;
#else
  fprintf(stderr, "%s\n", msg);
#endif

  // Also write the assertion failure to the logfile, iff we're able to...
  if (conn)
  {
    srv_write_assert_to_logfile(conn, expr, filepath, lineno);
  }

  // Assertion failures are fatal: attempt to abort/stop the server in a sane manner immediately:
  if (conn && mg_get_context(conn))
  {
    mg_signal_stop(mg_get_context(conn));
  }
  // die("Assertion failure");
  exit(EXIT_FAILURE);
}
