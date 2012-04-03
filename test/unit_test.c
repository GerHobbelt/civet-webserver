#include "mongoose.c"

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


int main(void) {
  test_match_prefix();
  test_remove_double_dots();
  test_IPaddr_parsing();
  test_logpath_fmt();
  return 0;
}
