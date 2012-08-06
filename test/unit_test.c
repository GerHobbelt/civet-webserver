#include "mongoose_ex.c"

#include <math.h>


#define FATAL(str, line)                                                    \
    do {                                                                    \
      printf("Fail on line %d: [%s]\n", line, str);                         \
      mg_signal_stop(ctx);                                                  \
      abort();                                                              \
    } while (0)

#define ASSERT(expr)                                                        \
    do {                                                                    \
      if (!(expr)) {                                                        \
        FATAL(#expr, __LINE__);                                             \
      }                                                                     \
    } while (0)

#define ASSERT_STREQ(str1, str2)                                            \
    do {                                                                    \
      if (strcmp(str1, str2)) {                                             \
        printf("Fail on line %d: strings not matching: "                    \
               "inp:\"%s\" != ref:\"%s\"\n",                                \
               __LINE__, str1, str2);                                       \
        mg_signal_stop(ctx);                                                \
        abort();                                                            \
      }                                                                     \
    } while (0)


static void test_MSVC_fix() {
  // when no assert fired in mg_freea(), we're good to go (see mongoose.c: crtdbg.h + malloc.h don't mesh 100% in MSVC2010)
  void *buf = mg_malloca(BUFSIZ);

  printf("=== TEST: %s ===\n", __func__);

  assert(buf);
  mg_freea(buf);
}

static void test_parse_http_request() {
  struct mg_context ctx_fake = {0};
  struct mg_context *ctx = &ctx_fake;
  struct mg_request_info ri;
  char req1[] = "GET / HTTP/1.1\r\n\r\n";
  char req2[] = "BLAH / HTTP/1.1\r\n\r\n";
  char req3[] = "GET / HTTP/1.1\r\nBah\r\n";

  printf("=== TEST: %s ===\n", __func__);

  ASSERT(parse_http_request(req1, &ri) == 1);
  ASSERT_STREQ(ri.http_version, "1.1");
  ASSERT(ri.num_headers == 0);

  ASSERT(parse_http_request(req2, &ri) == 0);

  // TODO(lsm): Fix this. Bah is not a valid header.
  ASSERT(parse_http_request(req3, &ri) == 1);
  ASSERT(ri.num_headers == 1);
  ASSERT_STREQ(ri.http_headers[0].name, "Bah\r\n");

  // TODO(lsm): add more tests.
}

static void test_should_keep_alive(void) {
  struct mg_context ctx_fake = {0};
  struct mg_context *ctx = &ctx_fake;
  struct mg_connection conn;
  char req1[] = "GET / HTTP/1.1\r\n\r\n";
  char req2[] = "GET / HTTP/1.0\r\n\r\n";
  char req3[] = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
  char req4[] = "GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n";

  printf("=== TEST: %s ===\n", __func__);

  memset(&conn, 0, sizeof(conn));
  conn.ctx = ctx;
  parse_http_request(req1, &conn.request_info);
  conn.request_info.status_code = 200;

  ctx->config[ENABLE_KEEP_ALIVE] = "no";
  ASSERT(should_keep_alive(&conn) == 0);

  ctx->config[ENABLE_KEEP_ALIVE] = "yes";
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
  struct mg_context ctx_fake = {0};
  struct mg_context *ctx = &ctx_fake;

  printf("=== TEST: %s ===\n", __func__);

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
  struct mg_context ctx_fake = {0};
  struct mg_context *ctx = &ctx_fake;

  printf("=== TEST: %s ===\n", __func__);

  for (i = 0; i < ARRAY_SIZE(data); i++) {
    //printf("[%s] -> [%s]\n", data[i].before, data[i].after);
    remove_double_dots_and_double_slashes(data[i].before);
    ASSERT_STREQ(data[i].before, data[i].after);
  }
}

static void test_IPaddr_parsing() {
  struct usa sa;
  struct vec v;
  struct socket s;
  struct mg_context ctx_fake = {0};
  struct mg_context *ctx = &ctx_fake;

  printf("=== TEST: %s ===\n", __func__);

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
  char *uri_input[] = {
    "http://example.com/Oops.I.did.it.again....yeah....yeah....yeah....errr....ohhhhh....you shouldn't have.... Now let's see whether this bugger does da right thang for long URLs when we wanna have them as part of the logpath..........",
    "http://example.com/Oops.I.did.it.again....yeah....yeah....yeah....errr....?&_&_&_&_&_ohhhhh....you shouldn't have.... Now let's see whether this bugger does da right thang for long URLs when we wanna have them as part of the logpath..........",
    "http://example.com/sample/page/tree?with-query=y&oh%20baby,%20oops!%20I%20did%20it%20again!"
  };
  const char *path;
  char buf[512];
  char tinybuf[13];
  struct mg_context ctx_fake = {0};
  struct mg_context *ctx = &ctx_fake;
  struct mg_connection c;

  printf("=== TEST: %s ===\n", __func__);

  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  path = mg_get_logfile_path(tinybuf, sizeof(tinybuf), "%[U].long-blubber.log", &c, time(NULL));
  ASSERT(path);
  ASSERT_STREQ(path, "_.long-blubb");

  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = uri_input[2];
  path = mg_get_logfile_path(tinybuf, sizeof(tinybuf), "%[U].long-blubber.log", &c, time(NULL));
  ASSERT(path);
  ASSERT_STREQ(path, "http.example");

  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = uri_input[0];
  path = mg_get_logfile_path(tinybuf, sizeof(tinybuf), "%Y/%[U]/%d/%m/blubber.log", &c, 1234567890);
  ASSERT(path);
  ASSERT_STREQ(path, "_Y/http.exam");

  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = uri_input[0];
  path = mg_get_logfile_path(tinybuf, sizeof(tinybuf), "%Y/%[Q]/%d/%m/blubber.log", &c, 1234567890);
  ASSERT(path);
  ASSERT_STREQ(path, "_Y/_/_d/_m/b");


  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = NULL;
  path = mg_get_logfile_path(buf, sizeof(buf), "%[U].long-blubber.log", &c, time(NULL));
  ASSERT(path);
  ASSERT_STREQ(path, "_.long-blubber.log");

  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = uri_input[2];
  path = mg_get_logfile_path(buf, sizeof(buf), "%[U].long-blubber.log", &c, time(NULL));
  ASSERT(path);
  ASSERT_STREQ(path, "http.example.com.sample.page.tree.long-blubber.log");

  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = uri_input[0];
  path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[U]/%d/%m/blubber.log", &c, 1234567890);
  ASSERT(path);
  ASSERT_STREQ(path, "2009/http.example.com.Oops.I.did.it.again.yeah.yeah.yeah.errr396693b9/14/02/blubber.log");

  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = uri_input[1];
  path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[Q]/%d/%m/blubber.log", &c, 1234567890);
  ASSERT(path);
  ASSERT_STREQ(path, "2009/_ohhhhh.you_shouldn_t_have._Now_let_s_see_whether_this_bd2d6cc07/14/02/blubber.log");

  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = uri_input[0];
  path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[Q]/%d/%m/blubber.log", &c, 1234567890);
  ASSERT(path);
  ASSERT_STREQ(path, "2009/_/14/02/blubber.log");

  // check the %[nX] numeric size parameter for %[Q/U] path formatters:

  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = uri_input[1];
  path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[20Q]/%d/%m/blubber.log", &c, 1234567890);
  ASSERT(path);
  ASSERT_STREQ(path, "2009/_ohhhhh.you_d2d6cc07/14/02/blubber.log");

  // invalid; ignore
  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = uri_input[1];
  path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[0Q]/%d/%m/blubber.log", &c, 1234567890);
  ASSERT(path);
  ASSERT_STREQ(path, "2009/_ohhhhh.you_shouldn_t_have._Now_let_s_see_whether_this_bd2d6cc07/14/02/blubber.log");

  // invalid, ignore
  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = uri_input[1];
  path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[-5Q]/%d/%m/blubber.log", &c, 1234567890);
  ASSERT(path);
  ASSERT_STREQ(path, "2009/_ohhhhh.you_shouldn_t_have._Now_let_s_see_whether_this_bd2d6cc07/14/02/blubber.log");

  // very tiny; crunch the hash
  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = uri_input[1];
  path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[4Q]/%d/%m/blubber.log", &c, 1234567890);
  ASSERT(path);
  ASSERT_STREQ(path, "2009/cc07/14/02/blubber.log");

  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = uri_input[1];
  path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[20U]/%d/%m/blubber.log", &c, 1234567890);
  ASSERT(path);
  ASSERT_STREQ(path, "2009/http.examplefa0ce5b0/14/02/blubber.log");

  // edge case; should not produce a hash
  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = uri_input[1];
  path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[56U]/%d/%m/blubber.log", &c, 1234567890);
  ASSERT(path);
  ASSERT_STREQ(path, "2009/http.example.com.Oops.I.did.it.again.yeah.yeah.yeah.errr/14/02/blubber.log");
  path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[55U]/%d/%m/blubber.log", &c, 1234567890);
  ASSERT(path);
  ASSERT_STREQ(path, "2009/http.example.com.Oops.I.did.it.again.yeah.yeah.fa0ce5b0/14/02/blubber.log");

  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = uri_input[1];
  path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[20U]/%d/%m/blubber.log", &c, 1234567890);
  ASSERT(path);
  ASSERT_STREQ(path, "2009/http.examplefa0ce5b0/14/02/blubber.log");

  // hash from raw; place at end of scrubbed uri component:
  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = uri_input[1];
  path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[20Q]/%d/%m/blubber.log", &c, 1234567890);
  ASSERT(path);
  ASSERT_STREQ(path, "2009/_ohhhhh.you_d2d6cc07/14/02/blubber.log");

  // IPv4 ports:
  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  c.request_info.uri = NULL;
  ASSERT(parse_ipvX_addr_string("10.11.12.13", 80, &c.client.lsa));
  ASSERT(parse_ipvX_addr_string("120.121.122.123", 180, &c.client.rsa));
  path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[C]/%[P]/%[s]/%[p]/%d/%m/blubber.log", &c, 1234567890);
  ASSERT(path);
  ASSERT_STREQ(path, "2009/120.121.122.123/180/10.11.12.13/80/14/02/blubber.log");



  // test illegal %[ formatters:
  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  path = mg_get_logfile_path(buf, sizeof(buf), "%[?].long-blubber.log", &c, time(NULL));
  ASSERT(path);
  ASSERT_STREQ(path, "![?].long-blubber.log"); // Note: we don't sanitize the template bits that originate in the server itself, and rightly so. Hence the '?' in here.

  memset(&c, 0, sizeof(c)); c.ctx = ctx;
  path = mg_get_logfile_path(buf, sizeof(buf), "%[bugger].%[-12345678901234567890boo].%[20~].long-blubber.log", &c, time(NULL));
  ASSERT(path);
  ASSERT_STREQ(path, "![bugger].![boo].![~].long-blubber.log");
}

/*
Fail on line 338: strings not matching: inp:"2009/http.example.com.Oops.I.did.it.again.yeah.yeah.yeah.errr/14/02/blubber.log" != ref:"2009/http.example.com.Oops.I.didfa0ce5b0/14/02/blubber.log"
Fail on line 341: strings not matching: inp:"2009/http.example.com.Oops.I.did.it.again.yeah.yeah.fa0ce5b0/14/02/blubber.log" != ref:"2009/http.example.com.Oops.I.didfa0ce5b0/14/02/blubber.log"
*/

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
  struct mg_context ctx_fake = {0};
  struct mg_context *ctx = &ctx_fake;
  struct mg_connection c = {0};
  int rv;
  char *p;
  const char *values[64];

  printf("=== TEST: %s ===\n", __func__);

  c.ctx = ctx;

  strcpy(buf, input);

  rv = get_request_len(buf, (int)strlen(buf));
  ASSERT(rv > 0 && rv < (int)strlen(buf));
  ASSERT(strstr(buf + rv, "<HTML><HEAD>") == buf + rv);
  buf[rv] = 0;
  p = buf;
  c.request_info.num_headers = parse_http_headers(&p, c.request_info.http_headers, ARRAY_SIZE(c.request_info.http_headers));
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



static void test_response_header_rw() {
  struct mg_context ctx_fake = {0};
  struct mg_context *ctx = &ctx_fake;
  struct mg_connection *conn;
  int rv;
  int i;
  double tag_add_idx, tag_rm_idx, tag_upd_idx;
  struct mg_header *hdr;

  const int bufsiz = 1380;

  printf("=== TEST: %s ===\n", __func__);

  conn = calloc(1, sizeof(*conn) + bufsiz * 2 + CHUNK_HEADER_BUFSIZ);
  ASSERT(conn != NULL);
  conn->ctx = ctx;
  conn->buf_size = bufsiz;
  conn->buf = (char *)(conn + 1);

  // add and remove a series of response headers:
  tag_add_idx = tag_rm_idx = tag_upd_idx = 0.0;
  for (i = 9 * 19; i > 0; i--)
  {
    char tagname[256];
    int old_hdrlen = conn->tx_headers_len;

    // add, update or delete?
    switch (i % 9)
    {
    default:
      tag_add_idx += 1.1;
      mg_snq0printf(conn, tagname, sizeof(tagname), "tag_name_%.0f", tag_add_idx);
      rv = mg_add_response_header(conn, 0, tagname, "V:%d", i);
      ASSERT(rv == 0);
      break;

    case 4:
      tag_rm_idx += 5.5;
    case 2:
      tag_rm_idx += 1.5;
      mg_snq0printf(conn, tagname, sizeof(tagname), "tag_name_%.0f", fmod(tag_rm_idx, tag_add_idx));
      rv = mg_remove_response_header(conn, tagname);
      ASSERT(rv >= 0);
      mg_snq0printf(conn, tagname, sizeof(tagname), "tag_name_%.0f", fmod(tag_rm_idx + 7, tag_add_idx));
      rv = mg_remove_response_header(conn, tagname);
      ASSERT(rv >= 0);
      break;

    case 3:
      tag_upd_idx += 2;
    case 1:
      tag_upd_idx += 39;
      tag_upd_idx = fmod(tag_upd_idx, tag_add_idx);
      // update tag
      mg_snq0printf(conn, tagname, sizeof(tagname), "tag_name_%.0f", tag_upd_idx);
      rv = mg_add_response_header(conn, 0, tagname, "V:UPDATE:%d", i);
      ASSERT(rv == 0);
      break;
    }

    // detect whether a significant 'compact' action took place:
    if (conn->tx_headers_len < old_hdrlen)
    {
      ASSERT(i == 82 || i == 37 || i == 15 || i == 6 || i == 3);
    }
  }

  // verify the result
  ASSERT(conn->request_info.num_response_headers == 61);

  // add headers to the very limit:
  rv = mg_add_response_header(conn, 0, "lim_1", "V:%d", --i);
  ASSERT(rv == 0);
  rv = mg_add_response_header(conn, 0, "lim_2", "V:%d", --i);
  ASSERT(rv == 0);
  rv = mg_add_response_header(conn, 0, "lim_3", "V:%d", --i);
  ASSERT(rv == 0);
  compact_tx_headers(conn);
  rv = mg_add_response_header(conn, 0, "lim_4", "V:%d", --i);
  ASSERT(rv == -1);
  ASSERT(conn->request_info.num_response_headers == 64);

  hdr = conn->request_info.response_headers;

  ASSERT_STREQ(hdr[0].name, "tag_name_4");
  ASSERT_STREQ(hdr[0].value, "V:UPDATE:145");
  ASSERT_STREQ(hdr[1].name, "tag_name_3");
  ASSERT_STREQ(hdr[1].value, "V:UPDATE:46");
  ASSERT_STREQ(hdr[2].name, "tag_name_7");
  ASSERT_STREQ(hdr[2].value, "V:162");
  ASSERT_STREQ(hdr[3].name, "tag_name_11");
  ASSERT_STREQ(hdr[3].value, "V:158");
  ASSERT_STREQ(hdr[4].name, "tag_name_0");
  ASSERT_STREQ(hdr[4].value, "V:UPDATE:55");
  ASSERT_STREQ(hdr[5].name, "tag_name_6");
  ASSERT_STREQ(hdr[5].value, "V:UPDATE:154");
  ASSERT_STREQ(hdr[6].name, "tag_name_14");
  ASSERT_STREQ(hdr[6].value, "V:UPDATE:147");
  ASSERT_STREQ(hdr[7].name, "tag_name_1");
  ASSERT_STREQ(hdr[7].value, "V:UPDATE:37");
  ASSERT_STREQ(hdr[8].name, "tag_name_15");
  ASSERT_STREQ(hdr[8].value, "V:UPDATE:93");
  ASSERT_STREQ(hdr[9].name, "tag_name_23");
  ASSERT_STREQ(hdr[9].value, "V:UPDATE:120");
  ASSERT_STREQ(hdr[10].name, "tag_name_29");
  ASSERT_STREQ(hdr[10].value, "V:UPDATE:102");
  ASSERT_STREQ(hdr[11].name, "tag_name_24");
  ASSERT_STREQ(hdr[11].value, "V:UPDATE:1");
  ASSERT_STREQ(hdr[12].name, "tag_name_5");
  ASSERT_STREQ(hdr[12].value, "V:UPDATE:91");
  ASSERT_STREQ(hdr[13].name, "tag_name_30");
  ASSERT_STREQ(hdr[13].value, "V:UPDATE:82");
  ASSERT_STREQ(hdr[14].name, "tag_name_59");
  ASSERT_STREQ(hdr[14].value, "V:78");
  ASSERT_STREQ(hdr[15].name, "tag_name_10");
  ASSERT_STREQ(hdr[15].value, "V:UPDATE:75");
  ASSERT_STREQ(hdr[16].name, "tag_name_62");
  ASSERT_STREQ(hdr[16].value, "V:72");
  ASSERT_STREQ(hdr[17].name, "tag_name_65");
  ASSERT_STREQ(hdr[17].value, "V:69");
  ASSERT_STREQ(hdr[18].name, "tag_name_66");
  ASSERT_STREQ(hdr[18].value, "V:68");
  ASSERT_STREQ(hdr[19].name, "tag_name_67");
  ASSERT_STREQ(hdr[19].value, "V:UPDATE:19");
  ASSERT_STREQ(hdr[20].name, "tag_name_68");
  ASSERT_STREQ(hdr[20].value, "V:62");
  ASSERT_STREQ(hdr[21].name, "tag_name_69");
  ASSERT_STREQ(hdr[21].value, "V:61");
  ASSERT_STREQ(hdr[22].name, "tag_name_70");
  ASSERT_STREQ(hdr[22].value, "V:60");
  ASSERT_STREQ(hdr[23].name, "tag_name_72");
  ASSERT_STREQ(hdr[23].value, "V:59");
  ASSERT_STREQ(hdr[24].name, "tag_name_33");
  ASSERT_STREQ(hdr[24].value, "V:UPDATE:57");
  ASSERT_STREQ(hdr[25].name, "tag_name_73");
  ASSERT_STREQ(hdr[25].value, "V:54");
  ASSERT_STREQ(hdr[26].name, "tag_name_74");
  ASSERT_STREQ(hdr[26].value, "V:53");
  ASSERT_STREQ(hdr[27].name, "tag_name_75");
  ASSERT_STREQ(hdr[27].value, "V:52");
  ASSERT_STREQ(hdr[28].name, "tag_name_76");
  ASSERT_STREQ(hdr[28].value, "V:51");
  ASSERT_STREQ(hdr[29].name, "tag_name_77");
  ASSERT_STREQ(hdr[29].value, "V:50");
  ASSERT_STREQ(hdr[30].name, "tag_name_41");
  ASSERT_STREQ(hdr[30].value, "V:UPDATE:48");
  ASSERT_STREQ(hdr[31].name, "tag_name_78");
  ASSERT_STREQ(hdr[31].value, "V:45");
  ASSERT_STREQ(hdr[32].name, "tag_name_79");
  ASSERT_STREQ(hdr[32].value, "V:44");
  ASSERT_STREQ(hdr[33].name, "tag_name_80");
  ASSERT_STREQ(hdr[33].value, "V:43");
  ASSERT_STREQ(hdr[34].name, "tag_name_81");
  ASSERT_STREQ(hdr[34].value, "V:UPDATE:28");
  ASSERT_STREQ(hdr[35].name, "tag_name_82");
  ASSERT_STREQ(hdr[35].value, "V:41");
  ASSERT_STREQ(hdr[36].name, "tag_name_44");
  ASSERT_STREQ(hdr[36].value, "V:UPDATE:39");
  ASSERT_STREQ(hdr[37].name, "tag_name_84");
  ASSERT_STREQ(hdr[37].value, "V:36");
  ASSERT_STREQ(hdr[38].name, "tag_name_85");
  ASSERT_STREQ(hdr[38].value, "V:35");
  ASSERT_STREQ(hdr[39].name, "tag_name_86");
  ASSERT_STREQ(hdr[39].value, "V:34");
  ASSERT_STREQ(hdr[40].name, "tag_name_87");
  ASSERT_STREQ(hdr[40].value, "V:33");
  ASSERT_STREQ(hdr[41].name, "tag_name_88");
  ASSERT_STREQ(hdr[41].value, "V:32");
  ASSERT_STREQ(hdr[42].name, "tag_name_42");
  ASSERT_STREQ(hdr[42].value, "V:UPDATE:30");
  ASSERT_STREQ(hdr[43].name, "tag_name_89");
  ASSERT_STREQ(hdr[43].value, "V:UPDATE:3");
  ASSERT_STREQ(hdr[44].name, "tag_name_90");
  ASSERT_STREQ(hdr[44].value, "V:26");
  ASSERT_STREQ(hdr[45].name, "tag_name_91");
  ASSERT_STREQ(hdr[45].value, "V:25");
  ASSERT_STREQ(hdr[46].name, "tag_name_92");
  ASSERT_STREQ(hdr[46].value, "V:24");
  ASSERT_STREQ(hdr[47].name, "tag_name_93");
  ASSERT_STREQ(hdr[47].value, "V:23");
  ASSERT_STREQ(hdr[48].name, "tag_name_28");
  ASSERT_STREQ(hdr[48].value, "V:UPDATE:21");
  ASSERT_STREQ(hdr[49].name, "tag_name_95");
  ASSERT_STREQ(hdr[49].value, "V:18");
  ASSERT_STREQ(hdr[50].name, "tag_name_96");
  ASSERT_STREQ(hdr[50].value, "V:17");
  ASSERT_STREQ(hdr[51].name, "tag_name_97");
  ASSERT_STREQ(hdr[51].value, "V:16");
  ASSERT_STREQ(hdr[52].name, "tag_name_98");
  ASSERT_STREQ(hdr[52].value, "V:15");
  ASSERT_STREQ(hdr[53].name, "tag_name_99");
  ASSERT_STREQ(hdr[53].value, "V:14");
  ASSERT_STREQ(hdr[54].name, "tag_name_9");
  ASSERT_STREQ(hdr[54].value, "V:UPDATE:12");
  ASSERT_STREQ(hdr[55].name, "tag_name_48");
  ASSERT_STREQ(hdr[55].value, "V:UPDATE:10");
  ASSERT_STREQ(hdr[56].name, "tag_name_100");
  ASSERT_STREQ(hdr[56].value, "V:9");
  ASSERT_STREQ(hdr[57].name, "tag_name_101");
  ASSERT_STREQ(hdr[57].value, "V:8");
  ASSERT_STREQ(hdr[58].name, "tag_name_102");
  ASSERT_STREQ(hdr[58].value, "V:7");
  ASSERT_STREQ(hdr[59].name, "tag_name_103");
  ASSERT_STREQ(hdr[59].value, "V:6");
  ASSERT_STREQ(hdr[60].name, "tag_name_104");
  ASSERT_STREQ(hdr[60].value, "V:5");
  ASSERT_STREQ(hdr[61].name, "lim_1");
  ASSERT_STREQ(hdr[61].value, "V:-1");
  ASSERT_STREQ(hdr[62].name, "lim_2");
  ASSERT_STREQ(hdr[62].value, "V:-2");
  ASSERT_STREQ(hdr[63].name, "lim_3");
  ASSERT_STREQ(hdr[63].value, "V:-3");


  // now set the request URI / query strings and cache those via header compact:
  ASSERT(0 == mg_cleanup_after_request(conn));

  rv = mg_add_response_header(conn, 0, "tag_1", "V:%d", --i);
  ASSERT(rv == 0);
  rv = mg_add_response_header(conn, 0, "tag_2", "V:%d", --i);
  ASSERT(rv == 0);
  rv = mg_add_response_header(conn, 0, "tag_3", "V:%d", --i);
  ASSERT(rv == 0);
  ASSERT(conn->tx_can_compact_hdrstore == 0);

  rv = mg_add_response_header(conn, 0, "tag_1", "V:blubber blab bloo ~ %d", --i);
  ASSERT(rv == 0);
  ASSERT(conn->request_info.num_response_headers == 3);
  ASSERT(conn->tx_can_compact_hdrstore == 1);
  ASSERT(conn->tx_headers_len == 65);

  conn->request_info.uri = "/oh-boy";
  conn->request_info.query_string = "what=shall&I=do.now";
  conn->tx_can_compact_hdrstore |= 2;
  rv = compact_tx_headers(conn);
  ASSERT(rv >= 0);
  ASSERT(conn->tx_headers_len == 87);
  ASSERT(conn->buf + bufsiz + CHUNK_HEADER_BUFSIZ == conn->request_info.uri);
  ASSERT_STREQ(conn->buf + bufsiz + CHUNK_HEADER_BUFSIZ, "/oh-boy");
  ASSERT(conn->buf + bufsiz + CHUNK_HEADER_BUFSIZ + 8 == conn->request_info.query_string);
  ASSERT_STREQ(conn->buf + bufsiz + CHUNK_HEADER_BUFSIZ + 8, "what=shall&I=do.now");

  hdr = conn->request_info.response_headers;

  ASSERT_STREQ(hdr[0].name, "tag_1");
  ASSERT_STREQ(hdr[0].value, "V:blubber blab bloo ~ -8");
  ASSERT_STREQ(hdr[1].name, "tag_2");
  ASSERT_STREQ(hdr[1].value, "V:-6");
  ASSERT_STREQ(hdr[2].name, "tag_3");
  ASSERT_STREQ(hdr[2].value, "V:-7");
}





static void test_client_connect() {
  char buf[512];
  struct mg_context ctx_fake = {0};
  struct mg_context *ctx = &ctx_fake;
  struct mg_connection *conn;
  struct mg_request_info *ri;
  int rv;
  const char *cookies[16];
  int cl;

  printf("=== TEST: %s ===\n", __func__);

  conn = mg_connect_to_host(ctx, "example.com", 80, MG_CONNECT_BASIC);
  ASSERT(conn);

  rv = mg_printf(conn, "GET / HTTP/1.0\r\n\r\n");
  ASSERT(rv == 18);
  mg_shutdown(conn, SHUT_WR);
  rv = mg_read(conn, buf, sizeof(buf));
  ASSERT(rv > 0);
  mg_close_connection(conn);
  //free(conn);


  conn = mg_connect_to_host(ctx, "google.com", 80, MG_CONNECT_USE_SSL);
  ASSERT(!conn);
  conn = mg_connect_to_host(ctx, "google.com", 80, MG_CONNECT_BASIC);
  ASSERT(conn);

  rv = mg_printf(conn, "GET / HTTP/1.0\r\n\r\n");
  ASSERT(rv == 18);
  mg_shutdown(conn, SHUT_WR);
  rv = mg_read(conn, buf, sizeof(buf));
  ASSERT(rv > 0);
  mg_close_connection(conn);
  //free(conn);


  // now with HTTP header support:
  ASSERT_STREQ(get_option(ctx, MAX_REQUEST_SIZE), "");
  conn = mg_connect_to_host(ctx, "www.google.com", 80, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
  ASSERT(!conn);

  // all options are empty
  ASSERT_STREQ(get_option(ctx, MAX_REQUEST_SIZE), "");
  // so we should set them up, just like one would've got when calling mg_start():
  ctx->config[MAX_REQUEST_SIZE] = "256";

  conn = mg_connect_to_host(ctx, "www.google.com", 80, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
  ASSERT(conn);

  ASSERT(0 == mg_add_tx_header(conn, 0, "Host", "www.google.com"));
  ASSERT(0 == mg_add_tx_header(conn, 0, "Connection", "close"));
  // set up the request the rude way: directly patch the request_info struct. Nasty!
  //
  // Setting us up cf. https://developers.google.com/custom-search/docs/xml_results?hl=en#WebSearch_Request_Format
  ri = mg_get_request_info(conn);
  ri->http_version = "1.1";
  ri->query_string = "q=mongoose&num=5&client=google-csbe&ie=utf8&oe=utf8&cx=00255077836266642015:u-scht7a-8i";
  ri->request_method = "GET";
  ri->uri = "/search";

  rv = mg_write_http_request_head(conn, NULL, NULL);
  ASSERT(rv == 153);
  // signal request phase done:
  mg_shutdown(conn, SHUT_WR);
  // fetch response, blocking I/O:
  //
  // but since this is a HTTP I/O savvy connection, we should first read the headers and parse them:
  rv = mg_read_http_response(conn);
  // google will spit back more than 256-1 header bytes in its response, so we'll get a buffer overrun:
  ASSERT(rv == 413);
  ASSERT(conn->request_len == 0);
  mg_close_connection(conn);



  // retry with a suitably large buffer:
  ctx->config[MAX_REQUEST_SIZE] = "2048";

  conn = mg_connect_to_host(ctx, "www.google.com", 80, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
  ASSERT(conn);

  ASSERT(0 == mg_add_tx_header(conn, 0, "Host", "www.google.com"));
  ASSERT(0 == mg_add_tx_header(conn, 0, "Connection", "close"));
  // set up the request the rude way: directly patch the request_info struct. Nasty!
  //
  // Setting us up cf. https://developers.google.com/custom-search/docs/xml_results?hl=en#WebSearch_Request_Format
  ri = mg_get_request_info(conn);
  ri->http_version = "1.1";
  ri->query_string = "q=mongoose&num=5&client=google-csbe&ie=utf8&oe=utf8&cx=00255077836266642015:u-scht7a-8i";
  ri->request_method = "GET";
  ri->uri = "/search";

  rv = mg_write_http_request_head(conn, NULL, NULL);
  ASSERT(rv == 153);
  // signal request phase done:
  mg_shutdown(conn, SHUT_WR);
  // fetch response, blocking I/O:
  //
  // but since this is a HTTP I/O savvy connection, we should first read the headers and parse them:
  rv = mg_read_http_response(conn);
  ASSERT(rv == 0);
  ASSERT(conn->request_len > 0);
  ASSERT(conn->request_len < 2048);
  ASSERT_STREQ(mg_get_header(conn, "Connection"), "close");
  ASSERT(mg_get_headers(cookies, ARRAY_SIZE(cookies), conn, "Set-Cookie") > 0);
  cl = atoi(mg_get_header(conn, "Content-Length"));
  ASSERT(cl > 0);

  // and now fetch the content:
  rv = mg_read(conn, buf, sizeof(buf));
  ASSERT(rv > 0);
  ASSERT(rv == cl);
  ASSERT(mg_get_request_info(conn));
  ASSERT(mg_get_request_info(conn)->status_code == 302 /* Moved */ );

  mg_close_connection(conn);
  //free(conn);



  // now with _full_ HTTP header support:
  conn = mg_connect_to_host(ctx, "www.google.com", 80, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
  ASSERT(conn);

  mg_add_tx_header(conn, 0, "Host", "www.google.com");
  mg_add_tx_header(conn, 0, "Connection", "close");
  // Setting us up cf. https://developers.google.com/custom-search/docs/xml_results?hl=en#WebSearch_Request_Format
  rv = mg_write_http_request_head(conn, "GET", "%s?%s", "/search", "q=mongoose&num=5&client=google-csbe&ie=utf8&oe=utf8&cx=00255077836266642015:u-scht7a-8i");
  ASSERT(rv == 153);
  // signal request phase done:
  mg_shutdown(conn, SHUT_WR);
  // fetch response, blocking I/O:
  //
  // but since this is a HTTP I/O savvy connection, we should first read the headers and parse them:
  rv = mg_read_http_response(conn);
  ASSERT(rv == 0);
  cl = atoi(mg_get_header(conn, "Content-Length"));
  ASSERT(cl > 0);
  ASSERT(mg_get_request_info(conn));
  ASSERT(mg_get_request_info(conn)->status_code == 302 /* Moved */ );

  // and now fetch the content:
  rv = mg_read(conn, buf, sizeof(buf));
  ASSERT(rv > 0);
  ASSERT(rv == cl);

  mg_close_connection(conn);
  //free(conn);



  // check whether the built-in Content-Length vs. Chunked I/O TX logic fires correctly:
  conn = mg_connect_to_host(ctx, "www.google.com", 80, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
  ASSERT(conn);

  ASSERT(0 == mg_add_tx_header(conn, 0, "Host", "www.google.com"));
  ASSERT(0 == mg_add_tx_header(conn, 0, "Connection", "keep-alive"));
  // set up the request the rude way: directly patch the request_info struct. Nasty!
  //
  // Setting us up cf. https://developers.google.com/custom-search/docs/xml_results?hl=en#WebSearch_Request_Format
  ri = mg_get_request_info(conn);
  ri->http_version = "1.1";
  ri->query_string = "q=mongoose&num=5&client=google-csbe&ie=utf8&oe=utf8&cx=00255077836266642015:u-scht7a-8i";
  ri->request_method = "GET";
  ri->uri = "/search";

  rv = mg_write_http_request_head(conn, NULL, NULL);
  ASSERT(mg_get_tx_header(conn, "Content-Length") == NULL);
  ASSERT_STREQ(mg_get_tx_header(conn, "Transfer-Encoding"), "chunked");
  ASSERT(mg_get_tx_mode(conn) == MG_IOMODE_CHUNKED_HEADER);
  ASSERT(mg_get_tx_chunk_no(conn) == 0);
  ASSERT(rv == 181);
  // signal request phase done:
  mg_shutdown(conn, SHUT_WR);
  ASSERT(mg_get_tx_mode(conn) == MG_IOMODE_CHUNKED_DATA);
  ASSERT(mg_get_tx_chunk_no(conn) == 1);

  // now try to write past the EOF! This should fire off an error message.
  rv = mg_printf(conn, "bugger!");
  ASSERT(rv == 0);

  // fetch response, blocking I/O:
  //
  // but since this is a HTTP I/O savvy connection, we should first read the headers and parse them:
  rv = mg_read_http_response(conn);
  ASSERT(rv == 0);
  ASSERT(conn->request_len > 0);
  ASSERT(conn->request_len < 2048);
  ASSERT_STREQ(mg_get_header(conn, "Connection"), "close");
  ASSERT(mg_get_headers(cookies, ARRAY_SIZE(cookies), conn, "Set-Cookie") > 0);
  cl = atoi(mg_get_header(conn, "Content-Length"));
  ASSERT(cl > 0);

  // and now fetch the content:
  rv = mg_read(conn, buf, sizeof(buf));
  ASSERT(rv > 0);
  ASSERT(rv == cl);
  ASSERT(mg_get_request_info(conn));
  ASSERT(mg_get_request_info(conn)->status_code == 302 /* Moved */ );

  mg_close_connection(conn);
  //free(conn);



  // check whether the built-in Content-Length vs. Chunked I/O TX logic fires correctly:
  conn = mg_connect_to_host(ctx, "www.google.com", 80, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
  ASSERT(conn);

  ASSERT(0 == mg_add_tx_header(conn, 0, "Host", "www.google.com"));
  ASSERT(0 == mg_add_tx_header(conn, 0, "Connection", "keep-alive"));
  
  // explicitly set chunked mode; the header writing logic should catch up:
  mg_set_tx_mode(conn, MG_IOMODE_CHUNKED_DATA);

  // set up the request the rude way: directly patch the request_info struct. Nasty!
  //
  // Setting us up cf. https://developers.google.com/custom-search/docs/xml_results?hl=en#WebSearch_Request_Format
  ri = mg_get_request_info(conn);
  ri->http_version = "1.1";
  ri->query_string = "q=mongoose&num=5&client=google-csbe&ie=utf8&oe=utf8&cx=00255077836266642015:u-scht7a-8i";
  ri->request_method = "GET";
  ri->uri = "/search";

  rv = mg_write_http_request_head(conn, NULL, NULL);
  ASSERT(mg_get_tx_header(conn, "Content-Length") == NULL);
  ASSERT_STREQ(mg_get_tx_header(conn, "Transfer-Encoding"), "chunked");
  ASSERT(mg_get_tx_mode(conn) == MG_IOMODE_CHUNKED_HEADER);
  ASSERT(mg_get_tx_chunk_no(conn) == 0);
  ASSERT(rv == 181);
  // signal request phase done:
  mg_shutdown(conn, SHUT_WR);
  ASSERT(mg_get_tx_mode(conn) == MG_IOMODE_CHUNKED_DATA);
  ASSERT(mg_get_tx_chunk_no(conn) == 1);
  // fetch response, blocking I/O:
  //
  // but since this is a HTTP I/O savvy connection, we should first read the headers and parse them:
  rv = mg_read_http_response(conn);
  ASSERT(rv == 0);
  ASSERT(conn->request_len > 0);
  ASSERT(conn->request_len < 2048);
  ASSERT_STREQ(mg_get_header(conn, "Connection"), "close");
  ASSERT(mg_get_headers(cookies, ARRAY_SIZE(cookies), conn, "Set-Cookie") > 0);
  cl = atoi(mg_get_header(conn, "Content-Length"));
  ASSERT(cl > 0);

  // and now fetch the content:
  rv = mg_read(conn, buf, sizeof(buf));
  ASSERT(rv > 0);
  ASSERT(rv == cl);
  ASSERT(mg_get_request_info(conn));
  ASSERT(mg_get_request_info(conn)->status_code == 302 /* Moved */ );

  mg_close_connection(conn);
  //free(conn);



  // check whether the built-in Content-Length vs. Chunked I/O TX logic fires correctly:
  conn = mg_connect_to_host(ctx, "www.google.com", 80, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
  ASSERT(conn);

  ASSERT(0 == mg_add_tx_header(conn, 0, "Host", "www.google.com"));
  ASSERT(0 == mg_add_tx_header(conn, 0, "Connection", "keep-alive"));
  // now with explicitly set content length: no chunked I/O!
  ASSERT(0 == mg_add_tx_header(conn, 0, "Content-Length", "%d", 0));
  // set up the request the rude way: directly patch the request_info struct. Nasty!
  //
  // Setting us up cf. https://developers.google.com/custom-search/docs/xml_results?hl=en#WebSearch_Request_Format
  ri = mg_get_request_info(conn);
  ri->http_version = "1.1";
  ri->query_string = "q=mongoose&num=5&client=google-csbe&ie=utf8&oe=utf8&cx=00255077836266642015:u-scht7a-8i";
  ri->request_method = "GET";
  ri->uri = "/search";

  rv = mg_write_http_request_head(conn, NULL, NULL);
  ASSERT(mg_get_tx_header(conn, "Transfer-Encoding") == NULL);
  ASSERT_STREQ(mg_get_tx_header(conn, "Content-Length"), "0");
  ASSERT(mg_get_tx_mode(conn) == MG_IOMODE_STANDARD);
  ASSERT(mg_get_tx_chunk_no(conn) == -1);
  ASSERT(rv == 172);
  // signal request phase done:
  mg_shutdown(conn, SHUT_WR);
  ASSERT(mg_get_tx_mode(conn) == MG_IOMODE_STANDARD);
  ASSERT(mg_get_tx_chunk_no(conn) == -1);
  // fetch response, blocking I/O:
  //
  // but since this is a HTTP I/O savvy connection, we should first read the headers and parse them:
  rv = mg_read_http_response(conn);
  ASSERT(rv == 0);
  ASSERT(conn->request_len > 0);
  ASSERT(conn->request_len < 2048);
  ASSERT_STREQ(mg_get_header(conn, "Connection"), "close");
  ASSERT(mg_get_headers(cookies, ARRAY_SIZE(cookies), conn, "Set-Cookie") > 0);
  cl = atoi(mg_get_header(conn, "Content-Length"));
  ASSERT(cl > 0);

  // and now fetch the content:
  rv = mg_read(conn, buf, sizeof(buf));
  ASSERT(rv > 0);
  ASSERT(rv == cl);
  ASSERT(mg_get_request_info(conn));
  ASSERT(mg_get_request_info(conn)->status_code == 302 /* Moved */ );

  mg_close_connection(conn);
  //free(conn);



  // check the new google search page at /cse
  conn = mg_connect_to_host(ctx, "www.google.com", 80, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
  ASSERT(conn);

  // http://www.google.com/cse?q=mongoose&num=5&client=google-csbe&ie=utf8&oe=utf8&cx=00255077836266642015:u-scht7a-8i
  mg_add_tx_header(conn, 0, "Host", "www.google.com");
  mg_add_tx_header(conn, 0, "Connection", "close");
  rv = mg_write_http_request_head(conn, "GET", "%s%s%s", "/cse", "?q=mongoose", "&num=5&client=google-csbe&ie=utf8&oe=utf8&cx=00255077836266642015:u-scht7a-8i");
  ASSERT(rv == 150);
  // signal request phase done:
  mg_shutdown(conn, SHUT_WR);
  // fetch response, blocking I/O:
  //
  // but since this is a HTTP I/O savvy connection, we should first read the headers and parse them:
  rv = mg_read_http_response(conn);
  ASSERT(rv == 0);
  ASSERT(mg_get_request_info(conn));
  ASSERT(mg_get_request_info(conn)->status_code == 404); // funny thing: google doesn't like this; sends a 404; see next for a 'valid' eqv. request: note the '&amp;' vs '&' down there
  ASSERT_STREQ(mg_get_request_info(conn)->http_version, "1.1");

  // and now fetch the content:
  for (;;) {
    int r = mg_read(conn, buf, sizeof(buf));

    if (r > 0)
      rv += r;
    else
      break;
  }
  ASSERT(rv > 0);
  //ASSERT(rv == cl);

  mg_close_connection(conn);
  //free(conn);



  // again: check the new google search page at /cse
  conn = mg_connect_to_host(ctx, "www.google.com", 80, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
  ASSERT(conn);

  // http://www.google.com/cse?q=mongoose&amp;num=5&amp;client=google-csbe&amp;ie=utf8&amp;oe=utf8&amp;cx=00255077836266642015:u-scht7a-8i
  mg_add_tx_header(conn, 0, "Host", "www.google.com");
  mg_add_tx_header(conn, 0, "Connection", "close");
  rv = mg_write_http_request_head(conn, "GET", "%s%s%s", "/cse", "?q=mongoose", "&amp;num=5&amp;client=google-csbe&amp;ie=utf8&amp;oe=utf8&amp;cx=00255077836266642015:u-scht7a-8i");
  ASSERT(rv == 170);
  // signal request phase done:
  mg_shutdown(conn, SHUT_WR);
  // fetch response, blocking I/O:
  //
  // but since this is a HTTP I/O savvy connection, we should first read the headers and parse them:
  rv = mg_read_http_response(conn);
  ASSERT(rv == 0);
  ASSERT(NULL == mg_get_header(conn, "Content-Length")); // google doesn't send a Content-Length with this one
  ASSERT(mg_get_request_info(conn));
  ASSERT(mg_get_request_info(conn)->status_code == 200);
  ASSERT_STREQ(mg_get_request_info(conn)->http_version, "1.1");

  // and now fetch the content:
  for (;;) {
    int r = mg_read(conn, buf, sizeof(buf));

    if (r > 0)
      rv += r;
    else
      break;
  }
  ASSERT(rv > 0);
  //ASSERT(rv == cl);

  mg_close_connection(conn);
  //free(conn);
}



static struct
{
  int connections_opened;
  int connections_served;
  int connections_closed_due_to_server_stop;
  int requests_sent;
  int requests_processed;
  int responses_sent;
  int responses_processed;
  int chunks_sent;
  int chunks_processed;
} chunky_request_counters;
static pthread_spinlock_t chunky_request_spinlock;

static void *chunky_server_callback(enum mg_event event, struct mg_connection *conn) {
  struct mg_request_info *request_info = mg_get_request_info(conn);
  struct mg_context *ctx = mg_get_context(conn);
  char content[1024];
  int content_length;

  if (event == MG_IDLE_MASTER)
    return 0;

  if (event == MG_INIT_CLIENT_CONN) {
    pthread_spin_lock(&chunky_request_spinlock);
    chunky_request_counters.connections_served++;
    pthread_spin_unlock(&chunky_request_spinlock);
    return 0;
  }

  if (event == MG_EXIT_CLIENT_CONN) {
    if (mg_get_stop_flag(ctx))
    {
      pthread_spin_lock(&chunky_request_spinlock);
      chunky_request_counters.connections_closed_due_to_server_stop++;
      pthread_spin_unlock(&chunky_request_spinlock);
    }

    return 0;
  }

  if (event == MG_NEW_REQUEST &&
      strstr(request_info->uri, "/chunky")) {
    int chunk_size;
    int chunk_count;
    int i, c;

    pthread_spin_lock(&chunky_request_spinlock);
    chunky_request_counters.requests_processed++;
    pthread_spin_unlock(&chunky_request_spinlock);

    if (mg_get_var(request_info->query_string, (size_t)-1, "chunk_size", content, sizeof(content), 0) > 0) {
      chunk_size = atoi(content);
    } else {
      chunk_size = 0;
    }
    if (mg_get_var(request_info->query_string, (size_t)-1, "count", content, sizeof(content), 0) > 0) {
      chunk_count = atoi(content);
    } else {
      chunk_count = 50;
    }

    mg_add_response_header(conn, 0, "Content-Length", "1234"); // fake; should be removed by the next one:
    // mongoose auto-detects TE when you set the proper header and use mg_write_http_response_head()
    mg_add_response_header(conn, 0, "Transfer-Encoding", "chunked");
    ASSERT(mg_get_response_header(conn, "Content-Length") == NULL);
    ASSERT_STREQ(mg_get_response_header(conn, "Transfer-Encoding"), "chunked");

    mg_add_response_header(conn, 0, "Content-Type", "text/html");
    ASSERT_STREQ(mg_suggest_connection_header(conn), "close");  // mongoose plays it safe as long as it doesn't know the Status Code yet!
    mg_set_response_code(conn, 200);
    ASSERT_STREQ(mg_suggest_connection_header(conn), "keep-alive");
    //mg_add_response_header(conn, 0, "Connection", "%s", mg_suggest_connection_header(conn)); -- not needed any longer

    // leading whitespace will be ignored:
    mg_add_response_header(conn, 0, "X-Mongoose-UnitTester", "%s%s", "   ", "Millennium Hand and Shrimp");

    i = mg_write_http_response_head(conn, 0, NULL);
    ASSERT(150 == i);
    ASSERT(mg_get_response_header(conn, "Content-Length") == NULL);
    ASSERT_STREQ(mg_get_response_header(conn, "Transfer-Encoding"), "chunked");

    // because we wish to test RX chunked reception, we set the chunk sizes explicitly for every chunk:
    mg_set_tx_next_chunk_size(conn, chunk_size);

    // any header added/changed AFTER the HEAD was written will be appended to the tail chunk
    mg_add_response_header(conn, 0, "X-Mongoose-UnitTester", "Buggerit!");

    // send a test page, in chunks
    mg_printf(conn,
              "<html><body><h1>Chunky page</h1>\n"
              "<p><a href=\"/chunky\">Click here</a> to get "
              "the chunky page again.</p>\n");

    do {
      // because we wish to test RX chunked reception, we set the chunk sizes explicitly for every chunk:
      mg_set_tx_next_chunk_size(conn, chunk_size);
      // you may call mg_set_tx_next_chunksize() as often as you like; it only takes effect when a new chunk is generated

      i = (int)mg_get_tx_remaining_chunk_size(conn);
      c = mg_get_tx_chunk_no(conn);

      // any header added/changed AFTER the HEAD was written will be appended to the tail chunk
      mg_add_response_header(conn, 0, "X-Mongoose-Chunky", "Alter-%d-of-%d", i, c);
      mg_add_response_header(conn, 0, "X-Mongoose-ChunkSizeTest", "%d", chunk_size);

      mg_printf(conn,
                "\n<pre>\n chunk #%d / %d, (size?: %d) remaining: %d \n</pre>\n"
                "<p>And this is some more lorem ipsum bla bla used as filler for the chunks...</p>\n",
                c, chunk_count, chunk_size, i);
    } while (c < chunk_count);

    i = (int)mg_get_tx_remaining_chunk_size(conn);
    c = mg_get_tx_chunk_no(conn);

    mg_printf(conn,
              "\n<pre>\n chunk #%d, remaining: %d \n</pre>\n"
              "<p><b>Now we've reached the end of our chunky page.</b></p>\n"
              "<blockquote><p><b>Note</b>: When you look at the page source,\n"
              "            you may see extra whitespace padding at the end\n"
              "            of the page to fill the last chunk (if the chunk size\n"
              "            was rather large and there was a lot 'remaining', that is).\n"
              "</p></blockquote>\n"
              "<hr><h1>Bye!</h1>\n",
              c, i);

    // pump out whitespace when the last explicit chunk wasn't entirely filled:
    i = (int)mg_get_tx_remaining_chunk_size(conn);
    mg_printf(conn, "%*s", i, "\n");

    pthread_spin_lock(&chunky_request_spinlock);
    chunky_request_counters.responses_sent++;
    pthread_spin_unlock(&chunky_request_spinlock);

    //DEBUG_TRACE(("test server callback: %s request serviced", request_info->uri));

    return (void *)1;
  } else if (event == MG_NEW_REQUEST) {
    content_length = mg_snprintf(conn, content, sizeof(content),
                                 "<html><body><p>Hello from mongoose! Remote port: %d."
                                 "<p><a href=\"/chunky\">Click here</a> to receive "
                                 "a Transfer-Encoding=chunked transmitted page from the server.",
                                 request_info->remote_port);

    mg_set_response_code(conn, 200);
    mg_add_response_header(conn, 0, "Content-Length", "%d", content_length);
    mg_add_response_header(conn, 0, "Content-Type", "text/html");
    mg_add_response_header(conn, 0, "Connection", "%s", mg_suggest_connection_header(conn));
    mg_write_http_response_head(conn, 0, NULL);

    mg_write(conn, content, content_length);

    // Mark as processed
    return (void *)1;
  } else {
    return NULL;
  }
}

static int gcl = 0;

static int chunky_write_chunk_header(struct mg_connection *conn, int64_t chunk_size, char *dstbuf, size_t dstbuf_size, char *chunk_extensions) {
  struct mg_context *ctx = mg_get_context(conn); 

  if (chunk_size == 0 && !conn->is_client_conn) {
	// This section is a special hack to force mongoose into the buffer overflow
	// edge condition, where mongoose MUST decide to 'shift' the buffered data
	// in order to load a full chunk header:
	// to accomplish this, our test code must DISABLE mongoose mg_write()
	// intelligence as we need to construct a single send() by hand to guarantee
	// that the other test thread (main loop) will pull() in this series of
	// chunks (headers + data) all at once: that is the only way to ensure that
	// the main thread MAY run into this buffer overflow edge condition in a
	// predictible fashion.

	// are we in a state where connexpects to send a chunk header?
    ASSERT(mg_get_tx_mode(conn) == MG_IOMODE_CHUNKED_HEADER); 
	// HACK:
	// make mg_write() think we're writing a chunk header. 
	// In actual fact, we're sending a whole bunch of 'em + data!
    ASSERT(conn->tx_chunk_header_sent == 2); 

	// construct a chunk header + data series large enough to flood the read/pull() buffer.
	if (01)
	{
		int flood_bufsiz = conn->buf_size * 4;
		char *flood_buf = (char *)malloc(flood_bufsiz + 512);
		int todo;
		int sn;
		char *p = flood_buf;
		int c = mg_get_tx_chunk_no(conn);

		ASSERT(flood_buf);
		for (todo = flood_bufsiz; ; )
		{
			// produce a semi-chaotic chunk size to maximize the chance to hit both edge cases:
			// 1) buffer overflow --> do_shift=1 for a regular chunk
			// 2) buffer overflow during tail (0-length) chunk header parsing --> do_shift=1 for the tail chunk
			//
			// Particularly #2 is EXTREMELY hard to hit, but it does happen and that code path
			// MAY contain bugs (it did before ;-) ); this code, together with the multiple runs
			// and sequenced requests has been created to maximally exercise the mongoose chunk I/O.
			int chunk_len = gcl /* gcl #1 */;

			pthread_spin_lock(&chunky_request_spinlock);
	        chunk_len += (chunky_request_counters.requests_sent * (256 - 18 + 24 /* gcl #2 */) + c) % 11;
		    pthread_spin_unlock(&chunky_request_spinlock);

			if (todo < chunk_len)
				break;

			sn = mg_snq0printf(conn, p, todo + 512, 
					((c % 3) == 2 ? 
					 "\r\n%x;mongoose-ext=oh-la-la-XXX;\r\ntodo=%7u %*s" : 
					 "\r\n%x\r\ntodo=%7u %*s"),
					chunk_len, 
					todo,
					chunk_len - 6 - 7, "B0rk?");
			ASSERT(sn > chunk_len);
			todo -= sn;
			p += sn;
			c++;
		  
			pthread_spin_lock(&chunky_request_spinlock);
		    chunky_request_counters.chunks_sent++;
		    pthread_spin_unlock(&chunky_request_spinlock);
		}
		sn = mg_write(conn, flood_buf, p - flood_buf);
		ASSERT(sn == p - flood_buf);
		free(flood_buf);

		conn->tx_chunk_count = c;
	}
	//conn->tx_chunk_header_sent = 0; 
	//conn->tx_remaining_chunksize = 0; 
  }

  // the regular test code, which adds chunk extensions to /some/ chunks:
  {
	  int c = mg_get_tx_chunk_no(conn);

	  pthread_spin_lock(&chunky_request_spinlock);
	  chunky_request_counters.chunks_sent++;
	  pthread_spin_unlock(&chunky_request_spinlock);

	  // generate some custom chunk extensions, semi-randomly, to make sure the decoder can cope as well!
	  if ((c % 3) == 2) {
		mg_snq0printf(conn, chunk_extensions, dstbuf_size - (chunk_extensions - dstbuf), "mongoose-ext=oh-la-la-%d", c);
	  }
  }

  return 0; // run default handler; we were just here to add extensions...
}

static int chunky_process_rx_chunk_header(struct mg_connection *conn, int64_t chunk_size, char *chunk_extensions, struct mg_header *chunk_headers, int header_count) {
  int c = mg_get_rx_chunk_no(conn);
  struct mg_context *ctx = mg_get_context(conn);

  pthread_spin_lock(&chunky_request_spinlock);
  chunky_request_counters.chunks_processed++;
  pthread_spin_unlock(&chunky_request_spinlock);

  // check the custom chunk extensions, to make sure the decoder can cope as well!
  if ((c % 3) == 2) {
    ASSERT(chunk_extensions != NULL);
    ASSERT(0 == strncmp(chunk_extensions, "mongoose-ext=oh-la-la-", 22));
  } else {
    ASSERT(chunk_extensions != NULL);
    ASSERT(*chunk_extensions == 0);
  }

  // test the parsed chunk trailers
  if (chunk_size == 0) {
    if (conn->is_client_conn) {
      int req_no, subreq_no;
      char nbuf[20];

      pthread_spin_lock(&chunky_request_spinlock);
      req_no = chunky_request_counters.requests_sent;
      pthread_spin_unlock(&chunky_request_spinlock);
      subreq_no = req_no - 1;
      subreq_no %= 8;

      ASSERT(header_count == 3);
      ASSERT_STREQ(chunk_headers[0].name, "X-Mongoose-UnitTester");
      ASSERT_STREQ(chunk_headers[0].value, "Buggerit!");
      ASSERT_STREQ(chunk_headers[1].name, "X-Mongoose-Chunky");
      //ASSERT_STREQ(chunk_headers[1].value, "Alter-0-of-10");
      ASSERT_STREQ(chunk_headers[2].name, "X-Mongoose-ChunkSizeTest");
      mg_snq0printf(conn, nbuf, sizeof(nbuf), "%d", (1 << subreq_no) * 16);
      ASSERT_STREQ(chunk_headers[2].value, nbuf); // 16, 32, ...
      switch (subreq_no) {
      default:
        ASSERT_STREQ(chunk_headers[1].value, "Alter-0-of-10");
        break;

      case 4:
        ASSERT_STREQ(chunk_headers[1].value, "Alter-208-of-10");
        break;

      case 5:
        ASSERT_STREQ(chunk_headers[1].value, "Alter-510-of-10");
        break;

      case 6:
        ASSERT_STREQ(chunk_headers[1].value, "Alter-910-of-10");
        break;

      case 7:
        ASSERT_STREQ(chunk_headers[1].value, "Alter-2002-of-10");
        break;
      }
    } else {
      int resp_no, subresp_no, get_w_hdr_no, run_no;
      char nbuf[20];

      pthread_spin_lock(&chunky_request_spinlock);
      resp_no = chunky_request_counters.responses_sent;
      pthread_spin_unlock(&chunky_request_spinlock);
      subresp_no = resp_no - 1;
      subresp_no %= 16;
      get_w_hdr_no = resp_no;
      get_w_hdr_no %= 5;
      run_no = resp_no - 1;
      run_no /= 16;

      if (subresp_no < 8) {
        if (get_w_hdr_no != 3) {
          ASSERT(header_count == 0);
        } else {
          ASSERT(header_count == 1);
          ASSERT_STREQ(chunk_headers[0].name, "X-Mongoose-Chunky-CLIENT");
          switch (subresp_no) {
          default:
            ASSERT(!"Should never get here");
            break;

          case 0:
            mg_snq0printf(conn, nbuf, sizeof(nbuf), "116, %d, 16", 16 - run_no);
            ASSERT_STREQ(chunk_headers[0].value, nbuf);
            break;

          case 1:
            mg_snq0printf(conn, nbuf, sizeof(nbuf), "116, %d, 32", 16 - run_no);
            ASSERT_STREQ(chunk_headers[0].value, nbuf);
            break;

          case 2:
            mg_snq0printf(conn, nbuf, sizeof(nbuf), "116, %d, 64", 16 - run_no);
            ASSERT_STREQ(chunk_headers[0].value, nbuf);
            break;

          case 3:
            mg_snq0printf(conn, nbuf, sizeof(nbuf), "117, %d, 128", 16 - run_no);
            ASSERT_STREQ(chunk_headers[0].value, nbuf);
            break;

          case 4:
            mg_snq0printf(conn, nbuf, sizeof(nbuf), "117, %d, 256", 16 - run_no);
            ASSERT_STREQ(chunk_headers[0].value, nbuf);
            break;

          case 5:
            mg_snq0printf(conn, nbuf, sizeof(nbuf), "117, %d, 512", 16 - run_no);
            ASSERT_STREQ(chunk_headers[0].value, nbuf);
            break;

          case 6:
            mg_snq0printf(conn, nbuf, sizeof(nbuf), "118, %d, 1024", 16 - run_no);
            ASSERT_STREQ(chunk_headers[0].value, nbuf);
            break;

          case 7:
            mg_snq0printf(conn, nbuf, sizeof(nbuf), "118, %d, 2048", 16 - run_no);
            ASSERT_STREQ(chunk_headers[0].value, nbuf);
            break;
          }
        }
      } else {
        ASSERT(header_count == 1);
        ASSERT_STREQ(chunk_headers[0].name, "X-Mongoose-Chunky-CLIENT");
        ASSERT_STREQ(chunk_headers[0].value, "Alter-3-of-18, 2048");
      }
    }
  }
  return 0;  // run default handler; we were just here to add extensions...
}

int test_chunked_transfer(void) {
  struct mg_context *ctx;
  /*
  The test server MUST run with 1 (ONE) thread, as the test code use a global chunk counter
  to assist in creating predictable, yet semi-random, chunk sizes.

  When running this code with multiple threads, the chunk counter will be updated by two
  threads when one connection shuts down while the other is established and used, producing
  fully unpredictable results.

  Using 1 client thread serializes the test process.
  */
  const char *options[] = {"listening_ports", "32156", "num_threads", "1", NULL};
  struct mg_user_class_t ucb = {
    NULL,
    chunky_server_callback
  };
  struct mg_connection *conn = NULL;
  char buf[4096];
  int rv;
  int prospect_chunk_size;
  int runs;

  printf("=== TEST: %s ===\n", __func__);

  pthread_spin_init(&chunky_request_spinlock, 0);
  memset(&chunky_request_counters, 0, sizeof(chunky_request_counters));

  ucb.write_chunk_header = chunky_write_chunk_header;
  ucb.process_rx_chunk_header = chunky_process_rx_chunk_header;

  ctx = mg_start(&ucb, options);
  if (!ctx)
    return -1;

  printf("Restartable server started on ports %s.\n",
         mg_get_option(ctx, "listening_ports"));

  printf("WARNING: multiple runs test the HTTP chunked I/O mode extensively; this may take a while.\n");

  for (runs = 16; runs > 0; runs--) {

    DEBUG_TRACE(("######### RUN: %d #############", runs));

    // open client connection to server and GET and POST chunked content
    conn = mg_connect_to_host(ctx, "localhost", 32156, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
    ASSERT(conn);
    rv = 0;

    pthread_spin_lock(&chunky_request_spinlock);
    chunky_request_counters.connections_opened++;
    pthread_spin_unlock(&chunky_request_spinlock);

    for (prospect_chunk_size = 16; prospect_chunk_size < 4096; prospect_chunk_size *= 2)
    {
      int add_chunkend_header = 0;
      mg_add_tx_header(conn, 0, "Host", "localhost");
      mg_add_tx_header(conn, 0, "Connection", "keep-alive");
      rv = mg_write_http_request_head(conn, "GET", "/chunky?count=%d&chunk_size=%d", 10, prospect_chunk_size);
      ASSERT(rv >= 88);
      ASSERT_STREQ(mg_get_tx_header(conn, "Connection"), "keep-alive");

      pthread_spin_lock(&chunky_request_spinlock);
      chunky_request_counters.requests_sent++;
      add_chunkend_header = (chunky_request_counters.requests_sent % 5 == 3);
      pthread_spin_unlock(&chunky_request_spinlock);

      if (add_chunkend_header) {
        mg_add_response_header(conn, 0, "X-Mongoose-Chunky-CLIENT", "%d, %d, %d", rv, runs, prospect_chunk_size);
      }

      // this one is optional here as we didn't send any data:
      // (It is mandatory though when you're transmitting in chunked transfer mode!)
      mg_flush(conn);
      // signal request phase done:
      //mg_shutdown(conn, SHUT_WR);

      // fetch response, blocking I/O:
      //
      // but since this is a HTTP I/O savvy connection, we should first read the headers and parse them:
      rv = mg_read_http_response(conn);
      if (rv == -2)
        break;
      ASSERT(rv == 0);
      ASSERT(NULL == mg_get_header(conn, "Content-Length")); // reply should NOT contain a Content-Length header!
      ASSERT(mg_get_request_info(conn));
      ASSERT(mg_get_request_info(conn)->status_code == 200);
      ASSERT_STREQ(mg_get_request_info(conn)->http_version, "1.1");
      ASSERT_STREQ(mg_get_header(conn, "Content-Type"), "text/html");
      // leading whitespace will be ignored:
      ASSERT_STREQ(mg_get_header(conn, "X-Mongoose-UnitTester"), "Millennium Hand and Shrimp");
      ASSERT_STREQ(mg_get_header(conn, "Connection"), "keep-alive");

      // and now fetch the content:
      for (;;) {
        int r = mg_read(conn, buf, sizeof(buf));

        if (r > 0)
          rv += r;
        else
          break;
      }
      ASSERT(rv > 0);
      //ASSERT(rv == cl);

      pthread_spin_lock(&chunky_request_spinlock);
      chunky_request_counters.responses_processed++;
      pthread_spin_unlock(&chunky_request_spinlock);

      // as we've got a kept-alive connection, we can send another request!
      ASSERT(0 == mg_cleanup_after_request(conn));
    }


    if (rv == -2) {
      mg_close_connection(conn);
      conn = NULL;
      continue;
    }


    // now do the same for POST requests: send chunked, receive another chunked stream:
    for (prospect_chunk_size = 16; prospect_chunk_size < 4096; prospect_chunk_size *= 2)
    {
      int i, c, chunk_size;
      int rx_state;
      int rcv_amount;

      mg_add_tx_header(conn, 0, "Host", "localhost");
      mg_add_tx_header(conn, 0, "Connection", "keep-alive");
      mg_add_response_header(conn, 0, "Content-Type", "text/plain");
      mg_add_response_header(conn, 0, "Transfer-Encoding", "%s", "chunked"); // '%s'? Just foolin' with ya. 'chunked' mode must be detected AFTER printf-formatting has been applied to value.
      rv = mg_write_http_request_head(conn, "POST", "/chunky?count=%d&chunk_size=%d", 10, prospect_chunk_size);
      ASSERT(rv >= 143);
      ASSERT_STREQ(mg_get_tx_header(conn, "Connection"), "keep-alive");

      pthread_spin_lock(&chunky_request_spinlock);
      chunky_request_counters.requests_sent++;
      pthread_spin_unlock(&chunky_request_spinlock);

      //----------------------------------------------------------------------------------------
      // WARNING:
      // We have the test server deliver a 'echo'-alike service, which starts responding
      // before the POST data is transmitted in its entirety.
      // We MUST interleave writing and reading from the connection as we'll otherwise run into
      // TCP buffer flooding issues (see also issue349 work) as the other side of the pipe needs
      // to read data from the pipe before it fills up, or you get yourself a case of deadlock
      // across a TCP connection.
      //
      // It is worrysome that the client needs to know how the server behaves, transmission-wise,
      // as mg_read_http_response() is a blocking operation. Of course we have 100% knowledge of
      // our test server here, but we should think this through in light of the Internet as our
      // scope/context, and then we'd quickly realize that we require a NON-BLOCKING means to
      // detect when the server actually started transmitting the response (not just the content,
      // but the entire response, response line and headers included).
      //
      // This is where the new mg_is_read_data_available() API comes in. It will check for
      // any incoming data, non-blocking and at minimal cost (one select() call) and should
      // always be used in your code before invoking mg_read() and friends in a client-side
      // connection setting.
      //----------------------------------------------------------------------------------------

      rx_state = 0;
      rcv_amount = 0;
      // now send our data, CHUNKED. When the initial chunk size runs out, we'll be using 'auto chunking' here.
      for (chunk_size = 1; chunk_size <= 2048; chunk_size *= 2)
      {
        // we set the chunk sizes explicitly for every chunk:
        mg_set_tx_next_chunk_size(conn, chunk_size);
        // you may call mg_set_tx_next_chunksize() as often as you like; it only takes effect when a new chunk is generated

        i = (int)mg_get_tx_remaining_chunk_size(conn);
        c = mg_get_tx_chunk_no(conn);

        // any header added/changed AFTER the HEAD was written will be appended to the tail chunk
        mg_add_response_header(conn, 0, "X-Mongoose-Chunky-CLIENT", "Alter-%d-of-%d, %d", i, c, chunk_size);

        mg_printf(conn,
                  "We're looking at chunk #%d here, (size?: %d) remaining: %d \n\n",
                  c, chunk_size, i);
        // for small chunk sizes, we'll have fallen back to 'auto chunking' around now: mg_get_tx_remaining_chunk_size(conn) --> 0
        i = (int)mg_get_tx_remaining_chunk_size(conn);
        c = mg_get_tx_chunk_no(conn);
        mg_printf(conn,
                  "chunk #%5d \n"
                  "padding: [%*s] \n",
                  c, - MG_MAX(1, i - 30), "xxx");

        if (mg_is_read_data_available(conn))
        {
          // fetch response, blocking I/O:
          //
          // but since this is a HTTP I/O savvy connection, we should first read the headers and parse them:
          switch (rx_state)
          {
          case 0:
            rv = mg_read_http_response(conn);
            ASSERT(rv == 0);
            ASSERT(NULL == mg_get_header(conn, "Content-Length")); // reply should NOT contain a Content-Length header!
            ASSERT(mg_get_request_info(conn));
            ASSERT(mg_get_request_info(conn)->status_code == 200);
            ASSERT_STREQ(mg_get_request_info(conn)->http_version, "1.1");
            ASSERT_STREQ(mg_get_header(conn, "Content-Type"), "text/html");
            // leading whitespace will be ignored:
            ASSERT_STREQ(mg_get_header(conn, "X-Mongoose-UnitTester"), "Millennium Hand and Shrimp");
            ASSERT_STREQ(mg_get_header(conn, "Connection"), "keep-alive");
            ASSERT_STREQ(mg_get_header(conn, "Transfer-Encoding"), "chunked");
            ASSERT(mg_get_rx_mode(conn) == MG_IOMODE_CHUNKED_HEADER);

            rx_state++;
            break;

          case 1:
            rv = mg_read(conn, buf, sizeof(buf));

            ASSERT(rv >= 0);
            rcv_amount += rv;
            break;

          default:
            ASSERT(!"should never get here");
            break;
          }
        }
      }

      // make sure we mark the chunked transmission as finished!
      rv = mg_flush(conn);
      if (rv > 0)
      {
        // the pending chunk hasn't been completely filled yet, which is an error.
        // Make sure we send the bytes we promised we'd send...
        i = (int)mg_get_tx_remaining_chunk_size(conn);
        c = mg_get_tx_chunk_no(conn);

        mg_printf(conn,
                  "chunk #%5d \n"
                  "padding: [%*s] \n",
                  c, - MG_MAX(1, chunk_size - 30), "xxx");
        i = (int)mg_get_tx_remaining_chunk_size(conn);
        if (i > 0)
          mg_printf(conn, "%*s", i, "Z");
        rv = mg_flush(conn);
        ASSERT(rv == 0);
      }
      // signal request phase done:
      //mg_shutdown(conn, SHUT_WR);


      // and now fetch the remaining content:
      do {
        switch (rx_state)
        {
        case 0:
          rv = mg_read_http_response(conn);
          ASSERT(rv == 0);
          ASSERT(NULL == mg_get_header(conn, "Content-Length")); // reply should NOT contain a Content-Length header!
          ASSERT(mg_get_request_info(conn));
          ASSERT(mg_get_request_info(conn)->status_code == 200);
          ASSERT_STREQ(mg_get_request_info(conn)->http_version, "1.1");
          ASSERT_STREQ(mg_get_header(conn, "Content-Type"), "text/html");
          // leading whitespace will be ignored:
          ASSERT_STREQ(mg_get_header(conn, "X-Mongoose-UnitTester"), "Millennium Hand and Shrimp");
          ASSERT_STREQ(mg_get_header(conn, "Connection"), "keep-alive");
          ASSERT_STREQ(mg_get_header(conn, "Transfer-Encoding"), "chunked");
          ASSERT(mg_get_rx_mode(conn) == MG_IOMODE_CHUNKED_HEADER);

          rv = 1;
          rx_state++;
          break;

        case 1:
          rv = mg_read(conn, buf, sizeof(buf));

          ASSERT(rv >= 0);
          rcv_amount += rv;
          break;

        default:
          ASSERT(!"should never get here");
          break;
        }
      } while (rv > 0);
      ASSERT(rv == 0);
      ASSERT(rcv_amount >= 0);

      pthread_spin_lock(&chunky_request_spinlock);
      chunky_request_counters.responses_processed++;
      pthread_spin_unlock(&chunky_request_spinlock);

      // as we've got a kept-alive connection, we can send another request!
      ASSERT(0 == mg_cleanup_after_request(conn));
    }


    mg_close_connection(conn);
    conn = NULL;
    //free(conn);
  }

  // allow all threads / connections on the server side to clean up by themselves:
  // wait for the linger timeout to trigger for any laggard.
  if (0)
  {
    const char *lv = mg_get_option(ctx, "socket_linger_timeout");
    int linger_timeout = atoi(lv ? lv : "1") * 1000;
    mg_sleep(MG_SELECT_TIMEOUT_MSECS * 4 + linger_timeout);
  }

  // now stop the server: done testing
  mg_stop(ctx);
  printf("Server stopped.\n");

  mg_sleep(1000);
  pthread_spin_destroy(&chunky_request_spinlock);

  ASSERT(chunky_request_counters.connections_opened == 16);
  ASSERT(chunky_request_counters.connections_served == 16);
  ASSERT(chunky_request_counters.requests_sent == 256);
  ASSERT(chunky_request_counters.requests_processed == 256);
  ASSERT(chunky_request_counters.responses_sent == 256);
  ASSERT(chunky_request_counters.responses_processed == 256);
  ASSERT(chunky_request_counters.chunks_sent >= 209);
  ASSERT(chunky_request_counters.chunks_processed == chunky_request_counters.chunks_sent);
  ASSERT(chunky_request_counters.connections_closed_due_to_server_stop >= 0);

  printf("Server terminating now.\n");
  return 0;
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

  test_MSVC_fix();

  test_match_prefix();
  test_remove_double_dots();
  test_IPaddr_parsing();
  test_logpath_fmt();
  test_header_processing();
  test_should_keep_alive();
  test_parse_http_request();
  test_response_header_rw();

#if defined(_WIN32) && !defined(__SYMBIAN32__)
  {
    WSADATA data;
    WSAStartup(MAKEWORD(2,2), &data);
  }
#endif // _WIN32

  test_client_connect();
  {
	  int gcl_best = 0;
	  int gcl_tbest = 0;
	  int hitc = 0;
	  int hittc = 0;
	  for (gcl = 18; ; gcl += 1) {
			pthread_spin_lock(&chunky_request_spinlock);
	        chunky_request_counters.requests_sent = 0;
		    pthread_spin_unlock(&chunky_request_spinlock);
		shift_hit = 0;
		shift_tail_hit = 0;
		test_chunked_transfer();
		if (shift_hit > hitc) {
			hitc = shift_hit;
			gcl_best = gcl;
		}
		if (shift_tail_hit > hittc) {
			hittc = shift_tail_hit;
			gcl_tbest = gcl;
		}
		printf("#######---------------------------------------- BEST GCL: %d / %d ~ %d / %d", gcl_best, gcl_tbest, hitc, hittc);
		fflush(stdout);
	  }
  }

  printf("\nAll tests have completed successfully.\n"
         "(Some error log messages may be visible. No worries, that's perfectly all right!)\n");

  return 0;
}
