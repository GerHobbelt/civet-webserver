#include "mongoose_ex.c"

static void test_match_prefix(void) {
  assert(match_prefix("/a/", 3, "/a/b/c") == 3);
  assert(match_prefix("/a/", 3, "/ab/c") == -1);
  assert(match_prefix("/*/", 3, "/ab/c") == 4);
  assert(match_prefix("**", 2, "/a/b/c") == 6);
  assert(match_prefix("/*", 2, "/a/b/c") == 2);
  assert(match_prefix("*/*", 3, "/a/b/c") == 2);
  assert(match_prefix("**/", 3, "/a/b/c") == 5);
  assert(match_prefix("**.foo|**.bar", 13, "a.bar") == 5);
  assert(match_prefix("a|b|cd", 6, "cdef") == 2);
  assert(match_prefix("a|b|c?", 6, "cdef") == 2);
  assert(match_prefix("a|?|cd", 6, "cdef") == 1);
  assert(match_prefix("/a/**.cgi", 9, "/foo/bar/x.cgi") == -1);
  assert(match_prefix("/a/**.cgi", 9, "/a/bar/x.cgi") == 12);
  assert(match_prefix("**/", 3, "/a/b/c") == 5);
  assert(match_prefix("**/$", 4, "/a/b/c") == -1);
  assert(match_prefix("**/$", 4, "/a/b/") == 5);
  assert(match_prefix("$", 1, "") == 0);
  assert(match_prefix("$", 1, "x") == -1);
  assert(match_prefix("*$", 2, "x") == 1);
  assert(match_prefix("/$", 2, "/") == 1);
  assert(match_prefix("**/$", 4, "/a/b/c") == -1);
  assert(match_prefix("**/$", 4, "/a/b/") == 5);
  assert(match_prefix("*", 1, "/hello/") == 0);
  assert(match_prefix("**.a$|**.b$", 11, "/a/b.b/") == -1);
  assert(match_prefix("**.a$|**.b$", 11, "/a/b.b") == 6);
  assert(match_prefix("**.a$|**.b$", 11, "/a/b.a") == 6);
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
    assert(strcmp(data[i].before, data[i].after) == 0);
  }
}

static void test_IPaddr_parsing() {
	struct usa sa;
	struct vec v;
	struct socket s;
	
	memset(&sa, 0, sizeof(sa));
	assert(!parse_ipvX_addr_string("example.com", 80, &sa));
	assert(parse_ipvX_addr_string("10.11.12.13", 80, &sa));
	assert(sa.u.sa.sa_family == AF_INET);
	assert(sa.u.sa.sa_data[0] == 0);
	assert(sa.u.sa.sa_data[1] == 80);
	assert(sa.u.sa.sa_data[2] == 10);
	assert(sa.u.sa.sa_data[3] == 11);
	assert(sa.u.sa.sa_data[4] == 12);
	assert(sa.u.sa.sa_data[5] == 13);

	memset(&s, 0, sizeof(s));
	memset(&v, 0, sizeof(v));
	v.ptr = "example.com:80";
	v.len = strlen(v.ptr);
	assert(!parse_port_string(&v, &s));
	v.ptr = ":80";
	v.len = strlen(v.ptr);
	assert(!parse_port_string(&v, &s));
	v.ptr = "80";
	v.len = strlen(v.ptr);
	assert(parse_port_string(&v, &s));
	assert(s.lsa.u.sin.sin_port == htons(80));
	assert(!s.is_ssl);
	v.ptr = "443s";
	v.len = strlen(v.ptr);
	assert(parse_port_string(&v, &s));
	assert(s.lsa.u.sin.sin_port == htons(443));
	assert(s.is_ssl);
	v.ptr = "10.11.12.13:80";
	v.len = strlen(v.ptr);
	assert(parse_port_string(&v, &s));
	assert(s.lsa.u.sa.sa_family == AF_INET);
	assert(s.lsa.u.sa.sa_data[0] == 0);
	assert(s.lsa.u.sa.sa_data[1] == 80);
	assert(s.lsa.u.sa.sa_data[2] == 10);
	assert(s.lsa.u.sa.sa_data[3] == 11);
	assert(s.lsa.u.sa.sa_data[4] == 12);
	assert(s.lsa.u.sa.sa_data[5] == 13);
	assert(!s.is_ssl);

	v.ptr = "  20.21.22.23:280s,  ";
	v.len = strlen(v.ptr);
	assert(parse_port_string(&v, &s));
	assert(s.lsa.u.sa.sa_family == AF_INET);
	assert(s.lsa.u.sa.sa_data[0] == 280 / 256);
	assert(s.lsa.u.sa.sa_data[1] == 280 % 256);
	assert(s.lsa.u.sa.sa_data[2] == 20);
	assert(s.lsa.u.sa.sa_data[3] == 21);
	assert(s.lsa.u.sa.sa_data[4] == 22);
	assert(s.lsa.u.sa.sa_data[5] == 23);
	assert(s.is_ssl);

	v.ptr = "[10.11.12.13]:180     ,    ";
	v.len = strlen(v.ptr);
	assert(parse_port_string(&v, &s));
	assert(s.lsa.u.sa.sa_family == AF_INET);
	assert(s.lsa.u.sa.sa_data[0] == 0);
	assert(s.lsa.u.sa.sa_data[1] == (char)180);
	assert(s.lsa.u.sa.sa_data[2] == 10);
	assert(s.lsa.u.sa.sa_data[3] == 11);
	assert(s.lsa.u.sa.sa_data[4] == 12);
	assert(s.lsa.u.sa.sa_data[5] == 13);
	assert(!s.is_ssl);

	v.ptr = "80  ,  ";
	v.len = strlen(v.ptr);
	assert(parse_port_string(&v, &s));
	assert(s.lsa.u.sin.sin_port == htons(80));
	assert(!s.is_ssl);
	v.ptr = "443s  ,  ";
	v.len = strlen(v.ptr);
	assert(parse_port_string(&v, &s));
	assert(s.lsa.u.sin.sin_port == htons(443));
	assert(s.is_ssl);


	// TODO: test these:
	//	check_acl()
	//	parse_ipvX_addr_and_netmask()

}

static void test_logpath_fmt() {
	const char *path;
	char buf[512];
	char tinybuf[13];
	struct mg_context ctx = {0};
	struct mg_connection c = {0};
	c.ctx = &ctx;

	path = mg_get_logfile_path(tinybuf, sizeof(tinybuf), "%[U].long-blubber.log", &c, time(NULL));
	assert(path);
	assert(0 == strcmp(path, "_.long-blubb"));

	c.request_info.uri = "http://example.com/sample/page/tree?with-query=y&oh%20baby,%20oops!%20I%20did%20it%20again!";
	path = mg_get_logfile_path(tinybuf, sizeof(tinybuf), "%[U].long-blubber.log", &c, time(NULL));
	assert(path);
	assert(0 == strcmp(path, "http.example"));

	c.request_info.uri = "http://example.com/Oops.I.did.it.again....yeah....yeah....yeah....errr....ohhhhh....you shouldn't have.... Now let's see whether this bugger does da right thang for long URLs when we wanna have them as part of the logpath..........";
	path = mg_get_logfile_path(tinybuf, sizeof(tinybuf), "%Y/%[U]/%d/%m/blubber.log", &c, 1234567890);
	assert(path);
	assert(0 == strcmp(path, "_Y/http.exam"));

	c.request_info.uri = "http://example.com/Oops.I.did.it.again....yeah....yeah....yeah....errr....ohhhhh....you shouldn't have.... Now let's see whether this bugger does da right thang for long URLs when we wanna have them as part of the logpath..........";
	path = mg_get_logfile_path(tinybuf, sizeof(tinybuf), "%Y/%[Q]/%d/%m/blubber.log", &c, 1234567890);
	assert(path);
	assert(0 == strcmp(path, "_Y/_/_d/_m/b"));


	c.request_info.uri = NULL;
	path = mg_get_logfile_path(buf, sizeof(buf), "%[U].long-blubber.log", &c, time(NULL));
	assert(path);
	assert(0 == strcmp(path, "_.long-blubber.log"));

	c.request_info.uri = "http://example.com/sample/page/tree?with-query=y&oh%20baby,%20oops!%20I%20did%20it%20again!";
	path = mg_get_logfile_path(buf, sizeof(buf), "%[U].long-blubber.log", &c, time(NULL));
	assert(path);
	assert(0 == strcmp(path, "http.example.com.sample.page.tree.long-blubber.log"));

	c.request_info.uri = "http://example.com/Oops.I.did.it.again....yeah....yeah....yeah....errr....ohhhhh....you shouldn't have.... Now let's see whether this bugger does da right thang for long URLs when we wanna have them as part of the logpath..........";
	path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[U]/%d/%m/blubber.log", &c, 1234567890);
	assert(path);
	assert(0 == strcmp(path, "2009/http.example.com.Oops.I.did.it.again.yeah.yeah.396693b9/14/02/blubber.log"));

	c.request_info.uri = "http://example.com/Oops.I.did.it.again....yeah....yeah....yeah....errr....?&_&_&_&_&_ohhhhh....you shouldn't have.... Now let's see whether this bugger does da right thang for long URLs when we wanna have them as part of the logpath..........";
	path = mg_get_logfile_path(buf, sizeof(buf), "%Y/%[Q]/%d/%m/blubber.log", &c, 1234567890);
	assert(path);
	assert(0 == strcmp(path, "2009/__________ohhhhh.you_shouldn_t_have._Now_let_s_seed2d6cc07/14/02/blubber.log"));
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

	p = buf;
	strcpy(buf, input);

	parse_http_headers(&p, &c.request_info);
	assert(p > buf);
	assert(strstr(p, "<HTML><HEAD>") == p);

	values[0] = mg_get_header(&c, "Set-Cookie");
	assert(values[0]);

	rv = mg_get_headers(values, 64, &c, "Set-Cookie");
	assert(rv == 2);
	assert(values[0]);
	assert(values[1]);
	assert(!values[2]);

	rv = mg_get_headers(values, 2, &c, "Set-Cookie");
	assert(rv == 1);
	assert(values[0]);
	assert(!values[1]);

	rv = mg_get_headers(values, 1, &c, "Set-Cookie");
	assert(rv == 0);
	assert(!values[0]);

	values[0] = mg_get_header(&c, "p3p");
	assert(values[0]);

	values[0] = mg_get_header(&c, "NID");
	assert(values[0]);

	values[0] = mg_get_header(&c, "PREF");
	assert(values[0]);

	values[0] = mg_get_header(&c, "Cache-Control");
	assert(values[0]);

	values[0] = mg_get_header(&c, "X-XSS-Protection");
	assert(values[0]);

	rv = mg_get_headers(values, 64, &c, "Content-Type");
}





static void test_client_connect() {
	char buf[512];
	struct mg_context ctx = {0};
	struct mg_connection c = {0};
	struct mg_connection *g;
	int rv;
	
	c.ctx = &ctx;

	g = mg_connect(&c, "example.com", 80, 0);
	assert(g);

	rv = mg_printf(g, "GET / HTTP/1.0\r\n\r\n");
	assert(rv == 18);
	mg_sleep(1000);
	rv = mg_pull(g, buf, sizeof(buf));
	assert(rv > 0);
	close_connection(g);
	free(g);


	g = mg_connect(&c, "google.com", 80, 1);
	assert(!g);
	g = mg_connect(&c, "google.com", 80, 0);
	assert(g);

	rv = mg_printf(g, "GET / HTTP/1.0\r\n\r\n");
	assert(rv == 18);
	mg_sleep(1000);
	rv = mg_pull(g, buf, sizeof(buf));
	assert(rv > 0);
	mg_close_connection(g);
	//free(g);
}



int main(void) {
  test_match_prefix();
  test_remove_double_dots();
  test_IPaddr_parsing();
  test_logpath_fmt();
  test_header_processing();

#if defined(_WIN32) && !defined(__SYMBIAN32__)
  {
	WSADATA data;
	WSAStartup(MAKEWORD(2,2), &data);
	InitializeCriticalSection(&traceCS);
  }
#endif // _WIN32

  test_client_connect();
  return 0;
}
