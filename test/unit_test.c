#include "mongoose_ex.c"

#define FATAL(str, line) do {                     \
  printf("Fail on line %d: [%s]\n", line, str);   \
  abort();                                        \
} while (0)
#define ASSERT(expr) do { if (!(expr)) FATAL(#expr, __LINE__); } while (0)

static void test_parse_http_request() {
  struct mg_request_info ri;
  char req1[] = "GET / HTTP/1.1\r\n\r\n";
  char req2[] = "BLAH / HTTP/1.1\r\n\r\n";
  char req3[] = "GET / HTTP/1.1\r\nBah\r\n";

  ASSERT(parse_http_request(req1, &ri) == 1);
  ASSERT(strcmp(ri.http_version, "1.1") == 0);
  ASSERT(ri.num_headers == 0);

  ASSERT(parse_http_request(req2, &ri) == 0);

  // TODO(lsm): Fix this. Bah is not a valid header.
  ASSERT(parse_http_request(req3, &ri) == 1);
  ASSERT(ri.num_headers == 1);
  ASSERT(strcmp(ri.http_headers[0].name, "Bah\r\n") == 0);

  // TODO(lsm): add more tests.
}

static void test_should_keep_alive(void) {
  struct mg_connection conn;
  struct mg_context ctx;
  char req1[] = "GET / HTTP/1.1\r\n\r\n";
  char req2[] = "GET / HTTP/1.0\r\n\r\n";
  char req3[] = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
  char req4[] = "GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n";

  memset(&conn, 0, sizeof(conn));
  memset(&ctx, 0, sizeof(ctx));
  conn.ctx = &ctx;
  parse_http_request(req1, &conn.request_info);
  conn.request_info.status_code = 200;

  ctx.config[ENABLE_KEEP_ALIVE] = "no";
  ASSERT(should_keep_alive(&conn) == 0);

  ctx.config[ENABLE_KEEP_ALIVE] = "yes";
  ASSERT(should_keep_alive(&conn) == 1);

  conn.must_close = 1;
  ASSERT(should_keep_alive(&conn) == 0);

  conn.must_close = 0;
  parse_http_request(req2, &conn.request_info);
  ASSERT(should_keep_alive(&conn) == 0);

  parse_http_request(req3, &conn.request_info);
  ASSERT(should_keep_alive(&conn) == 0);

  parse_http_request(req4, &conn.request_info);
  ASSERT(should_keep_alive(&conn) == 1);

  conn.request_info.status_code = 401;
  ASSERT(should_keep_alive(&conn) == 0);

  conn.request_info.status_code = 500;
  ASSERT(should_keep_alive(&conn) == 0);

  conn.request_info.status_code = 302;
  ASSERT(should_keep_alive(&conn) == 1);

  conn.request_info.status_code = 200;
  conn.must_close = 1;
  ASSERT(should_keep_alive(&conn) == 0);
}

static void test_match_prefix(void) {
  ASSERT(match_prefix("/api", 4, "/api") == 4);
  ASSERT(match_prefix("/a/", 3, "/a/b/c") == 3);
  ASSERT(match_prefix("/a/", 3, "/ab/c") == -1);
  ASSERT(match_prefix("/*/", 3, "/ab/c") == 4);
  ASSERT(match_prefix("**", 2, "/a/b/c") == 6);
  ASSERT(match_prefix("/*", 2, "/a/b/c") == 2);
  ASSERT(match_prefix("*/*", 3, "/a/b/c") == 2);
  ASSERT(match_prefix("**/", 3, "/a/b/c") == 5);
  ASSERT(match_prefix("**.foo|**.bar", 13, "a.bar") == 5);
  ASSERT(match_prefix("a|b|cd", 6, "cdef") == 2);
  ASSERT(match_prefix("a|b|c?", 6, "cdef") == 2);
  ASSERT(match_prefix("a|?|cd", 6, "cdef") == 1);
  ASSERT(match_prefix("/a/**.cgi", 9, "/foo/bar/x.cgi") == -1);
  ASSERT(match_prefix("/a/**.cgi", 9, "/a/bar/x.cgi") == 12);
  ASSERT(match_prefix("**/", 3, "/a/b/c") == 5);
  ASSERT(match_prefix("**/$", 4, "/a/b/c") == -1);
  ASSERT(match_prefix("**/$", 4, "/a/b/") == 5);
  ASSERT(match_prefix("$", 1, "") == 0);
  ASSERT(match_prefix("$", 1, "x") == -1);
  ASSERT(match_prefix("*$", 2, "x") == 1);
  ASSERT(match_prefix("/$", 2, "/") == 1);
  ASSERT(match_prefix("**/$", 4, "/a/b/c") == -1);
  ASSERT(match_prefix("**/$", 4, "/a/b/") == 5);
  ASSERT(match_prefix("*", 1, "/hello/") == 0);
  ASSERT(match_prefix("**.a$|**.b$", 11, "/a/b.b/") == -1);
  ASSERT(match_prefix("**.a$|**.b$", 11, "/a/b.b") == 6);
  ASSERT(match_prefix("**.a$|**.b$", 11, "/a/b.a") == 6);
}

static void test_remove_double_dots() {
  struct { char before[20], after[20]; } data[] = {
    {"////a", "/a"},
    {"/.....", "/."},
    {"/......", "/"},
    {"...", "..."},
    {"/...///", "/./"},
    {"/a...///", "/a.../"},
    {"/.x", "/.x"},
    {"/\\", "/"},    /* as we have cross-platform code/storage, we do NOT accept the '/' as part of any filename, even in UNIX! */
    {"/a\\", "/a\\"},
  };
  size_t i;

  for (i = 0; i < ARRAY_SIZE(data); i++) {
    //printf("[%s] -> [%s]\n", data[i].before, data[i].after);
    remove_double_dots_and_double_slashes(data[i].before);
    ASSERT(strcmp(data[i].before, data[i].after) == 0);
  }
}

static void test_IPaddr_parsing() {
    struct usa sa;
    struct vec v;
    struct socket s;

    memset(&sa, 0, sizeof(sa));
    ASSERT(!parse_ipvX_addr_string("example.com", 80, &sa));
    ASSERT(parse_ipvX_addr_string("10.11.12.13", 80, &sa));
    ASSERT(sa.u.sa.sa_family == AF_INET);
    ASSERT(sa.u.sa.sa_data[0] == 0);
    ASSERT(sa.u.sa.sa_data[1] == 80);
    ASSERT(sa.u.sa.sa_data[2] == 10);
    ASSERT(sa.u.sa.sa_data[3] == 11);
    ASSERT(sa.u.sa.sa_data[4] == 12);
    ASSERT(sa.u.sa.sa_data[5] == 13);

    memset(&s, 0, sizeof(s));
    memset(&v, 0, sizeof(v));
    v.ptr = "example.com:80";
    v.len = strlen(v.ptr);
    ASSERT(!parse_port_string(&v, &s));
    v.ptr = ":80";
    v.len = strlen(v.ptr);
    ASSERT(!parse_port_string(&v, &s));
    v.ptr = "80";
    v.len = strlen(v.ptr);
    ASSERT(parse_port_string(&v, &s));
    ASSERT(s.lsa.u.sin.sin_port == htons(80));
    ASSERT(!s.is_ssl);
    v.ptr = "443s";
    v.len = strlen(v.ptr);
    ASSERT(parse_port_string(&v, &s));
    ASSERT(s.lsa.u.sin.sin_port == htons(443));
    ASSERT(s.is_ssl);
    v.ptr = "10.11.12.13:80";
    v.len = strlen(v.ptr);
    ASSERT(parse_port_string(&v, &s));
    ASSERT(s.lsa.u.sa.sa_family == AF_INET);
    ASSERT(s.lsa.u.sa.sa_data[0] == 0);
    ASSERT(s.lsa.u.sa.sa_data[1] == 80);
    ASSERT(s.lsa.u.sa.sa_data[2] == 10);
    ASSERT(s.lsa.u.sa.sa_data[3] == 11);
    ASSERT(s.lsa.u.sa.sa_data[4] == 12);
    ASSERT(s.lsa.u.sa.sa_data[5] == 13);
    ASSERT(!s.is_ssl);

    v.ptr = "  20.21.22.23:280s,  ";
    v.len = strlen(v.ptr);
    ASSERT(parse_port_string(&v, &s));
    ASSERT(s.lsa.u.sa.sa_family == AF_INET);
    ASSERT(s.lsa.u.sa.sa_data[0] == 280 / 256);
    ASSERT(s.lsa.u.sa.sa_data[1] == 280 % 256);
    ASSERT(s.lsa.u.sa.sa_data[2] == 20);
    ASSERT(s.lsa.u.sa.sa_data[3] == 21);
    ASSERT(s.lsa.u.sa.sa_data[4] == 22);
    ASSERT(s.lsa.u.sa.sa_data[5] == 23);
    ASSERT(s.is_ssl);

    v.ptr = "[10.11.12.13]:180     ,    ";
    v.len = strlen(v.ptr);
    ASSERT(parse_port_string(&v, &s));
    ASSERT(s.lsa.u.sa.sa_family == AF_INET);
    ASSERT(s.lsa.u.sa.sa_data[0] == 0);
    ASSERT(s.lsa.u.sa.sa_data[1] == (char)180);
    ASSERT(s.lsa.u.sa.sa_data[2] == 10);
    ASSERT(s.lsa.u.sa.sa_data[3] == 11);
    ASSERT(s.lsa.u.sa.sa_data[4] == 12);
    ASSERT(s.lsa.u.sa.sa_data[5] == 13);
    ASSERT(!s.is_ssl);

    v.ptr = "80  ,  ";
    v.len = strlen(v.ptr);
    ASSERT(parse_port_string(&v, &s));
    ASSERT(s.lsa.u.sin.sin_port == htons(80));
    ASSERT(!s.is_ssl);
    v.ptr = "443s  ,  ";
    v.len = strlen(v.ptr);
    ASSERT(parse_port_string(&v, &s));
    ASSERT(s.lsa.u.sin.sin_port == htons(443));
    ASSERT(s.is_ssl);


    // TODO: test these:
    //  check_acl()
    //  parse_ipvX_addr_and_netmask()

}

static void test_logpath_fmt() {
    const char *path;
    char buf[512];
    char tinybuf[13];
    struct mg_context ctx = {0};
    struct mg_connection c = {0};
    c.ctx = &ctx;

    path = mg_get_logfile_path(tinybuf, sizeof(tinybuf), "%[U].long-blubber.log", &c, time(NULL));
    ASSERT(path);
    ASSERT(0 == strcmp(path, "_.long-blubb"));

    c.request_info.uri = "http://example.com/sample/page/tree?with-query=y&oh%20baby,%20oops!%20I%20did%20it%20again!";
    path = mg_get_logfile_path(tinybuf, sizeof(tinybuf), "%[U].long-blubber.log", &c, time(NULL));
    ASSERT(path);
    ASSERT(0 == strcmp(path, "http.example"));

    c.request_info.uri = "http://example.com/Oops.I.did.it.again....yeah....yeah....yeah....errr....ohhhhh....you shouldn't have.... Now let's see whether this bugger does da right thang for long URLs when we wanna have them as part of the logpath..........";
    path = mg_get_logfile_path(tinybuf, sizeof(tinybuf), "%Y/%[U]/%d/%m/blubber.log", &c, 1234567890);
    ASSERT(path);
    ASSERT(0 == strcmp(path, "_Y/http.exam"));

    c.request_info.uri = "http://example.com/Oops.I.did.it.again....yeah....yeah....yeah....errr....ohhhhh....you shouldn't have.... Now let's see whether this bugger does da right thang for long URLs when we wanna have them as part of the logpath..........";
    path = mg_get_logfile_path(tinybuf, sizeof(tinybuf), "%Y/%[Q]/%d/%m/blubber.log", &c, 1234567890);
    ASSERT(path);
    ASSERT(0 == strcmp(path, "_Y/_/_d/_m/b"));


    c.request_info.uri = NULL;
    path = mg_get_logfile_path(buf, sizeof(buf), "%[U].long-blubber.log", &c, time(NULL));
    ASSERT(path);
    ASSERT(0 == strcmp(path, "_.long-blubber.log"));

    c.request_info.uri = "http://example.com/sample/page/tree?with-query=y&oh%20baby,%20oops!%20I%20did%20it%20again!";
    path = mg_get_logfile_path(buf, sizeof(buf), "%[U].long-blubber.log", &c, time(NULL));
    ASSERT(path);
    ASSERT(0 == strcmp(path, "http.example.com.sample.page.tree.long-blubber.log"));

    c.request_info.uri = "http://example.com/Oops.I.did.it.again....yeah....yeah....yeah....errr....ohhhhh....you shouldn't have.... Now let's see whether this bugger does da right thang for long URLs when we wanna have them as part of the logpath..........";
    path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[U]/%d/%m/blubber.log", &c, 1234567890);
    ASSERT(path);
    ASSERT(0 == strcmp(path, "2009/http.example.com.Oops.I.did.it.again.yeah.yeah.396693b9/14/02/blubber.log"));

    c.request_info.uri = "http://example.com/Oops.I.did.it.again....yeah....yeah....yeah....errr....?&_&_&_&_&_ohhhhh....you shouldn't have.... Now let's see whether this bugger does da right thang for long URLs when we wanna have them as part of the logpath..........";
    path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[Q]/%d/%m/blubber.log", &c, 1234567890);
    ASSERT(path);
    ASSERT(0 == strcmp(path, "2009/__________ohhhhh.you_shouldn_t_have._Now_let_s_seed2d6cc07/14/02/blubber.log"));
}




static void test_header_processing()
{
    static const char *input = "HTTP/1.0 302 Found\r\n"
        "Location: http://www.google.nl/\r\n"
        "Cache-Control: private\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Set-Cookie: PREF=ID=f72f677fe44bc3d1:FF=0:TM=17777451416:LM=17777451416:S=SkqoabbgNkQJ-8ZZ; expires=Thu, 03-Apr-2014 08:23:36 GMT; path=/; domain=.google.com\r\n"
        "Set-Cookie: NID=58=zWkgbt1WtGE2ahsyDK_yNQDUaCaJ-3cWNNT-xMtBQyohMdaAtO9cHXaFZ23No4FfVXK-0jFVAVRUOiTy9KfmvHP1C0crTZjwWPIjORoR-kUqxXkf6MAxTR4hgPd8CzLF; expires=Wed, 03-Oct-2012 08:23:36 GMT; path=/; domain=.google.com; HttpOnly\r\n"
        "P3P: CP=\"This is not a P3P policy! See http://www.google.com/support/accounts/bin/answer.py?hl=en&answer=151657 for more info.\"\r\n"
        "Date: Tue, 03 Apr 2012 08:43:46 GMT\r\n"
        "Server: gws\r\n"
        "Content-Length: 218\r\n"
        "X-XSS-Protection: 1; mode=block\r\n"
        "X-Frame-Options: SAMEORIGIN\r\n"
        "\r\n"
        "<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\r\n"
        "<TITLE>302 Moved</TITLE></HEAD><BODY>\r\n"
        "<H1>302 Moved</H1>\r\n"
        "The document has moved\r\n"
        "<A HREF=\"http://www.google.nl/\">here</A>.\r\n"
        "</BODY></HTML>\r\n";

    char buf[8192];
    struct mg_context ctx = {0};
    struct mg_connection c = {0};
    int rv;
    char *p;
    const char *values[64];

    c.ctx = &ctx;

    strcpy(buf, input);

    rv = get_request_len(buf, (int)strlen(buf));
    ASSERT(rv > 0 && rv < (int)strlen(buf));
    ASSERT(strstr(buf + rv, "<HTML><HEAD>") == buf + rv);
    buf[rv] = 0;
    p = buf;
    parse_http_headers(&p, &c.request_info);
    ASSERT(p > buf);
    ASSERT(*p == 0);
    ASSERT(c.request_info.num_headers == 11);

    values[0] = mg_get_header(&c, "Set-Cookie");
    ASSERT(values[0]);

    rv = mg_get_headers(values, 64, &c, "Set-Cookie");
    ASSERT(rv == 2);
    ASSERT(values[0]);
    ASSERT(values[1]);
    ASSERT(!values[2]);

    rv = mg_get_headers(values, 2, &c, "Set-Cookie");
    ASSERT(rv == 2);
    ASSERT(values[0]);
    ASSERT(!values[1]);

    rv = mg_get_headers(values, 1, &c, "Set-Cookie");
    ASSERT(rv == 2);
    ASSERT(!values[0]);

    values[0] = mg_get_header(&c, "p3p");
    ASSERT(values[0]);

    values[0] = mg_get_header(&c, "NID");
    ASSERT(!values[0]);

    values[0] = mg_get_header(&c, "PREF");
    ASSERT(!values[0]);

    values[0] = mg_get_header(&c, "Cache-Control");
    ASSERT(values[0]);

    values[0] = mg_get_header(&c, "X-XSS-Protection");
    ASSERT(values[0]);

    rv = mg_get_headers(values, 64, &c, "Content-Type");
    ASSERT(values[0]);
    ASSERT(rv == 1);

    rv = mg_get_headers(values, 64, &c, "content-type");
    ASSERT(values[0]);
    ASSERT(rv == 1);

    rv = mg_get_headers(values, 64, &c, "CONTENT-TYPE");
    ASSERT(values[0]);
    ASSERT(rv == 1);
}





static void test_client_connect() {
    char buf[512];
    struct mg_context ctx = {0};
    struct mg_connection c = {0};
    struct mg_connection *g;
    int rv;

    c.ctx = &ctx;

    g = mg_connect(&c, "example.com", 80, 0);
    ASSERT(g);

    rv = mg_printf(g, "GET / HTTP/1.0\r\n\r\n");
    ASSERT(rv == 18);
    mg_shutdown(g, SHUT_WR);
    rv = mg_read(g, buf, sizeof(buf));
    ASSERT(rv > 0);
    mg_close_connection(g);
    free(g);


    g = mg_connect(&c, "google.com", 80, 1);
    ASSERT(!g);
    g = mg_connect(&c, "google.com", 80, 0);
    ASSERT(g);

    rv = mg_printf(g, "GET / HTTP/1.0\r\n\r\n");
    ASSERT(rv == 18);
    mg_shutdown(g, SHUT_WR);
    rv = mg_read(g, buf, sizeof(buf));
    ASSERT(rv > 0);
    mg_close_connection(g);
    //free(g);
}



int main(void) {
#if defined(_WIN32) && !defined(__SYMBIAN32__)
  InitializeCriticalSection(&global_log_file_lock.lock);
  global_log_file_lock.active = 1;
#if _WIN32_WINNT >= _WIN32_WINNT_NT4_SP3
  InitializeCriticalSectionAndSpinCount(&DisconnectExPtrCS, 1000);
#else
  InitializeCriticalSection(&DisconnectExPtrCS);
#endif
#endif

  test_match_prefix();
  test_remove_double_dots();
  test_IPaddr_parsing();
  test_logpath_fmt();
  test_header_processing();
  test_should_keep_alive();
  test_parse_http_request();

#if defined(_WIN32) && !defined(__SYMBIAN32__)
  {
    WSADATA data;
    WSAStartup(MAKEWORD(2,2), &data);
  }
#endif // _WIN32

  test_client_connect();
  return 0;
}
