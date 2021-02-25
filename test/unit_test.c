#define TEST_CHUNKING_SEARCH_OPT_TESTSETTING     1
//#define MG_BUF_LEN                             512

#include "mongoose_ex.c"

#include <math.h>

#define TAIL_CHUNK_HDR_FLOOD_ATTEMPT_MODULO     150   // <= 160
// first push all requests to the server asap, then go fetch their responses.
#define BLAST_ALL_REQUESTS_TO_SERVER_FIRST      0


static void fatal_exit(struct mg_context *ctx) {
  mg_signal_stop(ctx);
  abort();
}

#define FATAL(str, line)                                                    \
    do {                                                                    \
      printf("Fail on line %d: [%s]\n", line, str);                         \
      fatal_exit(ctx);                                                      \
    } while (0)

#define ASSERT(expr)                                                        \
    do {                                                                    \
      if (!(expr)) {                                                        \
        FATAL(#expr, __LINE__);                                             \
      }                                                                     \
    } while (0)

#define ASSERT_STREQ(str1, str2)                                            \
    do {                                                                    \
      if (!(str1) || !(str2) || strcmp(str1, str2)) {                       \
        printf("Fail on line %d: strings not matching: "                    \
               "inp:\"%s\" != ref:\"%s\"\n",                                \
               __LINE__, str1, str2);                                       \
        fatal_exit(ctx);                                                    \
      }                                                                     \
    } while (0)

#define ASSERT_STRPARTEQ(str, master)                                       \
    do {                                                                    \
	  int ml = (int)strlen(master);                                         \
      if (!(str) || strncmp(str, master, ml)) {                             \
        printf("Fail on line %d: string does not match head: "              \
               "inp:\"%s\" != head:\"%s\"\n",                               \
               __LINE__, str, master);                                      \
        fatal_exit(ctx);                                                    \
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
  char req4[] = "GET / HTTP/1.1\r\nA: foo bar\r\nB: bar\r\n baz\r\n\r\n";
  // as parse_http_request() will be fed NUL-terminated string which can have the terminating double CRLF damaged:
  char req5[] = "GET / HTTP/1.1\r\nA: foo bar\r\nB: bar\r\n\r";
  char req6[] = "GET / HTTP/1.1\r\nA: foo bar\r\nB: bar\r\n";
  char req7[] = "GET / HTTP/1.1\r\nA: foo bar\r\nB: bar\r";
  char req8[] = "GET / HTTP/1.1\r\nA: foo bar\r\nB: bar";
  char *req5_8[4];
  int i;

  req5_8[0] = req5;
  req5_8[1] = req6;
  req5_8[2] = req7;
  req5_8[3] = req8;

  printf("=== TEST: %s ===\n", __func__);

  ASSERT(parse_http_request(req1, &ri) == 0);
  ASSERT_STREQ(ri.http_version, "1.1");
  ASSERT(ri.num_headers == 0);

  ASSERT(parse_http_request(req2, &ri) == -1);
  ASSERT(parse_http_request(req3, &ri) == -1);

  // Header value may span multiple lines.
  ASSERT(parse_http_request(req4, &ri) == 0);
  ASSERT(ri.num_headers == 2);
  ASSERT_STREQ(ri.http_headers[0].name, "A");
  ASSERT_STREQ(ri.http_headers[0].value, "foo bar");
  ASSERT_STREQ(ri.http_headers[1].name, "B");
  ASSERT_STREQ(ri.http_headers[1].value, "bar baz"); // 'line continuation' cf. RFC2616 sec. 2.2: replaced by single SP space

  for (i = 0; i < ARRAY_SIZE(req5_8); i++) {
    ASSERT(parse_http_request(req5_8[i], &ri) == 0);
    ASSERT(ri.num_headers == 2);
    ASSERT_STREQ(ri.http_headers[0].name, "A");
    ASSERT_STREQ(ri.http_headers[0].value, "foo bar");
    ASSERT_STREQ(ri.http_headers[1].name, "B");
    ASSERT_STREQ(ri.http_headers[1].value, "bar");
    ASSERT_STREQ(ri.http_version, "1.1");
    ASSERT_STREQ(ri.uri, "/");
    ASSERT_STREQ(ri.query_string, "");
    ASSERT_STREQ(ri.request_method, "GET");
  }
}

static void test_http_hdr_value_unquoting(void) {
  struct mg_context ctx_fake = {0};
  struct mg_context *ctx = &ctx_fake;

  char *e = NULL;
  char *buf;
  char sep = 0;
  int rv;
  int tt, n;

  for (tt = 0; tt < 2; tt++) {
    char tv1[] = "boo";
    char tv2[] = "=boo";
    char tv3[] = "x\r\n \r\n";
    char tv4[] = "\"boo bongo \\\"bear\\\"\\\\\"\r\n";
    char tv5[] = "\"boo bongo \\\"bear\\\"\\\\\"\r\nbugger";
    char tv6[] = "a=b,c=d;e=f g=h";
    char tv7[] = "a=\"b\",c= \"d\"; e=\"f\" g=\"h\"";
    char tv8[] = "bar\r\n bar2 \r\n  ;    bar3\r\ndoo: dar\r\n \r\n \r\n da2\r\n\r";
    char tv9[] = "foo_min.1-2      \r\n\r";
    char tv10[] = "foo_min.1-2: bar\r\n bar2 \r\n  ;    bar3\r\ndoo: dar\r\n \r\n \r\n da2\r\n\r";
    // NOTE: CTL (\r\n etc.) chars are ALWAYS ILLEGAL as input to mg_unquote_header_value() as it expects its input
    //       to come from mg_extract_raw_http_header() or equivalent processes which already converted LWS to SP.
    char tv11[] = "\"bar\r\n bar2";
    char tv12[] = "\"bar\\\r\\\n bar2\"";
    char tv13[] = "$$foo##: \"bar \\\"bar2\\\"    \\ \\\\bar3 \" ,,  ,,  \" bar4 \",d=e,f=g \r\ndoo: \"dar   da2\"\r\n \r\ncoo:\"car\"";
    // erroneous cases:
    char tv14[] = "\"no terminating quote";
    char tv15[] = "\"escaped NUL is illegal, though RFC2616 sec. 2.2. says it isn't\\";
    char tv16[] = "\"no terminating quote\\\\";
    char tv17[] = "\"no terminating quote\\\"";
    char tv18[] = "\"illegal char in string: \x80";
    char tv19[] = "\"illegal char in string: \xFF";
    char tv20[] = "illegal-char-in-token-\x80";
    char tv21[] = "illegal-char-in-token-\xFF";
    char tv22[] = "no-escapes-in-token-\\x";
    char tv23[] = "illegal-char-in-token-\"";
    char tv24[] = "sep-at-end-of-token-@";
    char tv25[] = "sep-at-end-of-token[1]";
    char tv26[] = "sep-at-end-of-token{1}";
    char tv27[] = "sep-at-end-of-token(1)";
    char tv28[] = "sep-at-end-of-token<1>";

    char **end_ref = (tt ? &e : NULL);
    char *sep_ref = (tt ? &sep : NULL);

    buf = tv1;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    ASSERT(rv == 0);
    ASSERT_STREQ(buf, "boo");
    if (end_ref) {
      ASSERT(*end_ref == buf + 3);
      ASSERT(sep == 0);
      ASSERT(**end_ref == 0);
    }

    buf = tv2;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    if (end_ref) {
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "");
      ASSERT(*end_ref == buf);
      ASSERT(sep == '=');
      ASSERT(**end_ref == 0);

      buf = *end_ref + !!sep;
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "boo");
      ASSERT(sep == 0);
      ASSERT(**end_ref == 0);
    } else {
      ASSERT(rv == -1);
      ASSERT_STREQ(buf, "=boo");
    }

    buf = tv3;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    ASSERT(rv == 0);
    ASSERT_STREQ(buf, "x");
    if (end_ref) {
      ASSERT(*end_ref == buf + 1);
      ASSERT(sep == '\r');

      buf = *end_ref + !!sep;
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "");
      ASSERT(sep == '\n');
    }

    buf = tv4;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    ASSERT(rv == 0);
    ASSERT_STREQ(buf, "boo bongo \"bear\"\\");
    if (end_ref) {
      ASSERT(sep == '\r');
    }

    buf = tv5;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    if (end_ref) {
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "boo bongo \"bear\"\\");
      ASSERT(sep == '\r');
      ASSERT(**end_ref == '\r');

      buf = *end_ref + !!sep;
      buf += strspn(buf, "\r\n");
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT_STREQ(buf, "bugger");
      ASSERT(sep == 0);
    } else {
      ASSERT(rv == -1);
    }

    buf = tv6;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    if (end_ref) {
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "a");
      ASSERT(sep == '=');
      ASSERT(**end_ref == 0);

      for (n = 1; n < 8; n++) {
        buf = *end_ref + !!sep;
        rv = mg_unquote_header_value(buf, sep_ref, end_ref);
        ASSERT(rv == 0);
        ASSERT(buf[0] == 'a' + n);
        ASSERT(strlen(buf) == 1);
        ASSERT(n % 2 == 0 ? sep == '=' : n == 7 ? sep == 0 : !!strchr(",; ", sep));
      }
    } else {
      ASSERT(rv == -1);
    }

    buf = tv7;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    if (end_ref) {
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "a");
      ASSERT(sep == '=');
      ASSERT(**end_ref == 0);

      for (n = 1; n < 8; n++) {
        buf = *end_ref + !!sep;
        buf += strspn(buf, " \t\r\n");
        rv = mg_unquote_header_value(buf, sep_ref, end_ref);
        ASSERT(rv == 0);
        ASSERT(buf[0] == 'a' + n);
        ASSERT(strlen(buf) == 1);
        ASSERT(n % 2 == 0 ? sep == '=' : n == 7 ? sep == 0 : !!strchr(",; ", sep));
      }
    } else {
      ASSERT(rv == -1);
    }

    //char tv8[] = "bar\r\n bar2 \r\n  ;    bar3\r\ndoo: dar\r\n \r\n \r\n da2\r\n\r";
    buf = tv8;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    if (end_ref) {
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "bar");
      ASSERT(sep == '\r');
      ASSERT(**end_ref == 0);

      buf = *end_ref + !!sep;
      buf += strspn(buf, " \t\r\n");
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "bar2");
      ASSERT(sep == ' ');

      buf = *end_ref + !!sep;
      buf += strspn(buf, " \t\r\n");
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "");
      ASSERT(sep == ';');

      buf = *end_ref + !!sep;
      buf += strspn(buf, " \t\r\n");
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "bar3");
      ASSERT(sep == '\r');

      buf = *end_ref + !!sep;
      buf += strspn(buf, " \t\r\n");
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "doo");
      ASSERT(sep == ':');

      buf = *end_ref + !!sep;
      buf += strspn(buf, " \t\r\n");
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "dar");
      ASSERT(sep == '\r');

      buf = *end_ref + !!sep;
      buf += strspn(buf, " \t\r\n");
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "da2");
      ASSERT(sep == '\r');

      buf = *end_ref + !!sep;
      buf += strspn(buf, " \t\r\n");
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "");
      ASSERT(sep == 0);
    } else {
      ASSERT(rv == -1);
    }

    //char tv9[] = "foo_min.1-2      \r\n\r";
    buf = tv9;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    ASSERT(rv == 0);
    ASSERT_STREQ(buf, "foo_min.1-2");
    if (end_ref) {
      ASSERT(*end_ref == buf + 11);
      ASSERT(sep == ' ');
    }

    //char tv10[] = "foo_min.1-2: bar\r\n bar2 \r\n  ;    bar3\r\ndoo: dar\r\n \r\n \r\n da2\r\n\r";
    buf = tv10;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    if (end_ref) {
      ASSERT(rv == 0);
      ASSERT(*end_ref == buf + 11);
      ASSERT(sep == ':');

      buf = *end_ref + !!sep;
      buf += strspn(buf, " \t\r\n");
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "bar");
      ASSERT(sep == '\r');
    } else {
      ASSERT(rv == -1);
    }

    //char tv11[] = "\"bar\r\n bar2";
    buf = tv11;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    ASSERT(rv == -1);

    //char tv12[] = "\"bar\\\r\\\n bar2\"";
    buf = tv12;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    ASSERT(rv == 0);
    ASSERT_STREQ(buf, "bar\r\n bar2");
    if (end_ref) {
      ASSERT(sep == 0);
      ASSERT(**end_ref == 0);
    }

    //char tv13[] = "$$foo##: \"bar \\\"bar2\\\"    \\ \\\\bar3 \" ,,  ,,  \" bar4 \",d=e,f=g \r\ndoo: \"dar   da2\"\r\n \r\ncoo:\"car\"";
    buf = tv13;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    if (end_ref) {
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "$$foo##");
      ASSERT(sep == ':');

      buf = *end_ref + !!sep;
      buf += strspn(buf, " \t\r\n");
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "bar \"bar2\"     \\bar3 ");

      buf = *end_ref + !!sep;
      buf += strspn(buf, " \t\r\n");
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "");
      ASSERT(sep == ',');

      buf = *end_ref + !!sep;
      buf += strspn(buf, ", \t\r\n");
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, " bar4 ");
      ASSERT(sep == ',');

      buf = *end_ref + !!sep;
      buf += strspn(buf, " \t\r\n");
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "d");
      ASSERT(sep == '=');

      buf = *end_ref + !!sep;
      buf += strspn(buf, " \t\r\n");
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "e");
      ASSERT(sep == ',');

      buf = *end_ref + !!sep;
      buf += strspn(buf, "f=gdo: \t\r\n");  // skip f=g doo: string section
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "dar   da2");
      ASSERT(sep == '\r');
    } else {
      ASSERT(rv == -1);
    }

    buf = tv14;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    ASSERT(rv == -1);

    buf = tv15;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    ASSERT(rv == -1);

    buf = tv16;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    ASSERT(rv == -1);

    buf = tv17;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    ASSERT(rv == -1);

    buf = tv18;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    ASSERT(rv == -1);

    buf = tv19;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    ASSERT(rv == -1);

    buf = tv20;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    if (end_ref) {
      ASSERT(rv == 0);
      ASSERT(sep == '\x80');
      ASSERT(**end_ref == 0);
      ASSERT_STREQ(buf, "illegal-char-in-token-");
    } else {
      ASSERT(rv == -1);
    }

    buf = tv21;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    if (end_ref) {
      ASSERT(rv == 0);
      ASSERT(sep == '\xFF');
      ASSERT(**end_ref == 0);
      ASSERT_STREQ(buf, "illegal-char-in-token-");
    } else {
      ASSERT(rv == -1);
    }

    buf = tv22;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    if (end_ref) {
      ASSERT(rv == 0);
      ASSERT(sep == '\\');
      ASSERT(**end_ref == 0);
      ASSERT_STREQ(buf, "no-escapes-in-token-");
    } else {
      ASSERT(rv == -1);
    }

    buf = tv23;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    if (end_ref) {
      ASSERT(rv == 0);
      ASSERT(sep == '"');
      ASSERT(**end_ref == 0);
      ASSERT_STREQ(buf, "illegal-char-in-token-");
    } else {
      ASSERT(rv == -1);
    }

    buf = tv24;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    if (end_ref) {
      ASSERT(rv == 0);
      ASSERT(sep == '@');
      ASSERT(**end_ref == 0);
      ASSERT_STREQ(buf, "sep-at-end-of-token-");
    } else {
      ASSERT(rv == -1);
    }

    buf = tv25;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    if (end_ref) {
      ASSERT(rv == 0);
      ASSERT(sep == '[');
      ASSERT(**end_ref == 0);
      ASSERT_STREQ(buf, "sep-at-end-of-token");
    } else {
      ASSERT(rv == -1);
    }

    buf = tv26;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    if (end_ref) {
      ASSERT(rv == 0);
      ASSERT(sep == '{');
      ASSERT(**end_ref == 0);
      ASSERT_STREQ(buf, "sep-at-end-of-token");
    } else {
      ASSERT(rv == -1);
    }

    buf = tv27;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    if (end_ref) {
      ASSERT(rv == 0);
      ASSERT(sep == '(');
      ASSERT(**end_ref == 0);
      ASSERT_STREQ(buf, "sep-at-end-of-token");
    } else {
      ASSERT(rv == -1);
    }

    buf = tv28;
    rv = mg_unquote_header_value(buf, sep_ref, end_ref);
    if (end_ref) {
      ASSERT(rv == 0);
      ASSERT(sep == '<');
      ASSERT(**end_ref == 0);
      ASSERT_STREQ(buf, "sep-at-end-of-token");

      buf = *end_ref + !!sep;
      rv = mg_unquote_header_value(buf, sep_ref, end_ref);
      ASSERT(rv == 0);
      ASSERT_STREQ(buf, "1");
      ASSERT(sep == '>');
      ASSERT(**end_ref == 0);
    } else {
      ASSERT(rv == -1);
    }
  }
}

static void test_token_value_extractor(void) {
  struct mg_context ctx_fake = {0};
  struct mg_context *ctx = &ctx_fake;

  char tv1[] = "bla=boo\r\n";
  char tv2[] = "bla=boo\r\nbugger";
  // the next one is NOT a 'line continuation in the sense of RFC2616 as
  // mg_extract_token_qstring_value() REQUIRES such LWS to have been already
  // converted to SP by the caller before invocation:
  char tv3[] = "bla=boo\r\n bugger";
  char tv4[] = "bla=boo bugger";
  char tv5[] = "bla=boo bugger ";
  char tv6[] = "bla=boo bugger\r";
  char tv7[] = " \tbla =\r\n   boo  \r\nbugger";
  char tv8[] = " \tbla =\r\n   boo  \r\n  bugger";
  char tv9[] = " \tb-la.1 = \"boo bongo \\\"bear\\\"\\\\\"\r\nbugger";
  char tv10[] = "a=b,c=d;e=f g=h";
  char tv11[] = "a=b ,c=d ;e=f g=h";
  char tv12[] = "a=b, c=d; e=f g=h";
  char tv13[] = "a=b , c=d ; e=f g=h";
  char tv14[] = "a=b\n,\nc=d\n;\ne=f\ng=h";
  char tv15[] = "a=b\r\n,\r\nc=d\r\n;\r\ne=f\r\ng=h";
  char tv16[] = "a=b\r\n , \r\n c=d \r\n ; \r\ne=f\r\n\r\ng=h";
  char tv17[] = "a=\"b\",c= \"d\"; e=\"f\" g=\"h\"";
  // oddballs: \\ outside a string serves as a separator:
  char tv18[] = "a=b\\c=d?e=f/g=h";
  char tv19[] = "a=b@c=d[e=f]g=h";
  char tv20[] = "a=b(c=d)e=f{g=h}";
  char tv21[] = "a=b{c=d}e=f<g=h>";
  // yes, '=' is also a regular separator (RFC2616 sec 2.2)
  char tv22[] = "a=b<c=d>e=f=g=h=";

  // no-value cases:

  char tv30[] = "a=,c=;e=\r\ng=";
  char tv31[] = "a= ,c= ;e= \r\ng=";
  char tv32[] = "a=, c=; e= \r\n\r\n g="; // simple [\r\n ] would be detected as line continuation, hence [\r\n\r\n ]
  char tv33[] = "a= , c= ; e= \r\n \r\n\r\n g=";
  char tv34[] = "a=\n,\nc=\n;\ne=\ng=";
  char tv35[] = "a=\r\n,\r\nc=\r\n;\r\ne=\r\ng=";
  char tv36[] = "a=\r\n , \r\n c= \r\n ; \r\ne=\r\n\r\ng=";
  char tv37[] = "a=\"\",c= \"\"; e=\"\" g=\"\"";  // empty quoted-strings are NOT replaced by 'empty_string' as they are actually values!
  // oddballs: \\ outside a string serves as a separator:
  char tv38[] = "a=\\c=?e=/g=";
  char tv39[] = "a=@c=[e=]g=";
  char tv40[] = "a=(c=)e={g=}";
  char tv41[] = "a={c=}e=<g=>";
  // yes, '=' is also a regular separator (RFC2616 sec 2.2)
  char tv42[] = "a=<c=>e==g= \r\n";

  // faulty cases:

  // token=value: token cannot be quoted or contain escaped chars
  char tv50[] = "\"a\"=b";
  char tv51[] = "\\a=b";
  char tv52[] = "a\x80=b";
  char tv53[] = "\x80\x61=b";
  char tv54[] = "a=b\x80";
  char tv55[] = "a=\x80\x62";
  char tv56[] = "a=b\"c=d";
  char tv57[] = "a=b\"c\"=d";
  char tv58[] = "a=\"b+c+d";
  char tv59[] = "a?b";  // wrong separator
  char tv60[] = "a?=b";  // wrong separator

  char *value, *name, *e;
  char *buf;
  char sep;
  int rv, i, j;
  char *tv2_9[] = { tv2, tv3, tv4, tv5, tv6, tv7, tv8, tv9 };
  char *tv10_22[] = { tv10, tv11, tv12, tv13, tv14, tv15, tv16, tv17, tv18, tv19, tv20, tv21, tv22 };
  char *tv30_42[] = { tv30, tv31, tv32, tv33, tv34, tv35, tv36, tv37, tv38, tv39, tv40, tv41, tv42 };
  char *tv50e[] = { tv50, tv51, tv52, tv53, tv54, tv55, tv56, tv57, tv58, tv59, tv60 };
  name = value = NULL;
  buf = tv1;
  e = buf + strlen(buf);
  rv = mg_extract_token_qstring_value(&buf, &sep, &name, &value, NULL);
  ASSERT(rv == 0);
  ASSERT_STREQ(name, "bla");
  ASSERT_STREQ(value, "boo");
  ASSERT(sep == 0);
  ASSERT_STREQ(buf, "");
  ASSERT(buf == e);

  for (i = 0; i < ARRAY_SIZE(tv2_9); i++) {
    name = value = NULL;
    buf = tv2_9[i];
    rv = mg_extract_token_qstring_value(&buf, &sep, &name, &value, NULL);
    ASSERT(rv == 0);
    if (i == 7 /* tv9 */ ) {
      ASSERT_STREQ(name, "b-la.1");
      ASSERT_STREQ(value, "boo bongo \"bear\"\\");
    } else {
      ASSERT_STREQ(name, "bla");
      ASSERT_STREQ(value, "boo");
    }
    ASSERT(sep == ((i == 0 || i == 5 || i == 7) ? '\n' : ' '));
    name = value = NULL;
    buf += !!sep;
    ASSERT(strstr(buf, "bugger"));
    ASSERT(0 == strncmp(buf, "bugger", 6));
    rv = mg_extract_token_qstring_value(&buf, &sep, &name, &value, NULL);
    ASSERT(rv == -1);
    ASSERT(name == NULL);
    ASSERT(value == NULL);
    ASSERT(sep == ((i == 0 || i == 5 || i == 7) ? '\n' : ' '));
    ASSERT(0 == strncmp(buf, "bugger", 6));
  }

  for (i = 0; i < ARRAY_SIZE(tv10_22); i++) {
    buf = tv10_22[i];
    e = buf + strlen(buf);
    for (j = 0; j < 4; j++) {
      name = value = NULL;
      rv = mg_extract_token_qstring_value(&buf, &sep, &name, &value, NULL);
      ASSERT(rv == 0);
      ASSERT(*name == 'a' + 2 * j);
      ASSERT(*value == 'b' + 2 * j);
      ASSERT(!name[1]);
      ASSERT(!value[1]);
      ASSERT(sep == 0 || !!strchr("\n;, \\/?@()={}[]<>", sep));
      buf += !!sep;
    }
    ASSERT(sep == 0 || (i == 10 && sep == '}') || (i == 11 && sep == '>') || (i == 12 && sep == '='));
    ASSERT_STREQ(buf, "");
    ASSERT(buf == e);
  }

  for (i = 0; i < ARRAY_SIZE(tv30_42); i++) {
    buf = tv30_42[i];
    e = buf + strlen(buf);
    for (j = 0; j < 4; j++) {
      name = value = NULL;
      rv = mg_extract_token_qstring_value(&buf, &sep, &name, &value, "empty!");
      ASSERT(rv == 0);
      ASSERT(*name == 'a' + 2 * j);
      ASSERT(!name[1]);
      if (i == 7) {
        ASSERT_STREQ(value, "");
      } else {
        ASSERT_STREQ(value, "empty!");
      }
      ASSERT(sep == 0 || !!strchr("\n;, \\/?@()={}[]<>", sep));
      buf += !!sep;
    }
    ASSERT(sep == 0 || (i == 10 && sep == '}') || (i == 11 && sep == '>') || (i == 12 && sep == '='));
    ASSERT_STREQ(buf, "");
    ASSERT(buf == e);
  }

  for (i = 0; i < ARRAY_SIZE(tv50e); i++) {
    buf = tv50e[i];
    name = value = NULL;
    rv = mg_extract_token_qstring_value(&buf, &sep, &name, &value, NULL);
    ASSERT(rv == -1);
  }
}

static void test_http_header_extractor(void) {
  struct mg_context ctx_fake = {0};
  struct mg_context *ctx = &ctx_fake;

  char hdrs1[] = "foo: bar\r\ndoo    :dar   \r\ncoo:car\r\n";
  // now with 'line continuation'
  char hdrs2[] = "foo_min.1-2: bar\r\n bar2 \r\n  ;    bar3\r\ndoo: dar\r\n \r\n \r\n da2\r\n\r";
  // and quoted strings:
  char hdrs3[] = "$$foo##: \"bar\r\n \\\"bar2\\\"   \r\n  \\ \\\\bar3 \" ,,  ,,  \" bar4 \",d=e,f=g \r\ndoo: \"dar\r\n \r\n \r\n da2\"\r\n \r\ncoo:\"car\"";

  char *e;
  struct mg_header hdrs[64];
  char *buf;
  int rv;

  // implicitly tests mg_extract_raw_http_header():
  memset(hdrs, 0, sizeof(hdrs));
  buf = hdrs1;
  e = buf + strlen(buf);
  rv = parse_http_headers(&buf, hdrs, ARRAY_SIZE(hdrs));
  ASSERT(rv == 3);
  ASSERT_STREQ(hdrs[0].name, "foo");
  ASSERT_STREQ(hdrs[0].value, "bar");
  ASSERT_STREQ(hdrs[1].name, "doo");
  ASSERT_STREQ(hdrs[1].value, "dar");
  ASSERT_STREQ(hdrs[2].name, "coo");
  ASSERT_STREQ(hdrs[2].value, "car");
  ASSERT_STREQ(buf, "");
  ASSERT(buf == e);

  memset(hdrs, 0, sizeof(hdrs));
  buf = hdrs2;
  e = buf + strlen(buf);
  rv = parse_http_headers(&buf, hdrs, ARRAY_SIZE(hdrs));
  ASSERT(rv == 2);
  ASSERT_STREQ(hdrs[0].name, "foo_min.1-2");
  ASSERT_STREQ(hdrs[0].value, "bar bar2 ; bar3");
  ASSERT_STREQ(hdrs[1].name, "doo");
  ASSERT_STREQ(hdrs[1].value, "dar da2");
  ASSERT_STREQ(buf, "");
  ASSERT(buf == e);

  memset(hdrs, 0, sizeof(hdrs));
  buf = hdrs3;
  e = buf + strlen(buf);
  rv = parse_http_headers(&buf, hdrs, ARRAY_SIZE(hdrs));
  ASSERT(rv == 3);
  ASSERT_STREQ(hdrs[0].name, "$$foo##");
  ASSERT_STREQ(hdrs[0].value, "\"bar \\\"bar2\\\"    \\ \\\\bar3 \" ,, ,, \" bar4 \",d=e,f=g");
  ASSERT_STREQ(hdrs[1].name, "doo");
  ASSERT_STREQ(hdrs[1].value, "\"dar da2\"");
  ASSERT_STREQ(hdrs[2].name, "coo");
  ASSERT_STREQ(hdrs[2].value, "\"car\"");
  ASSERT_STREQ(buf, "");
  ASSERT(buf == e);
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
  ASSERT(parse_http_request(req1, &conn.request_info) == 0);
  conn.request_info.status_code = 200;

  ctx->config[ENABLE_KEEP_ALIVE] = "no";
  ASSERT(should_keep_alive(&conn) == 0);

  ctx->config[ENABLE_KEEP_ALIVE] = "yes";
  ASSERT(should_keep_alive(&conn) == 1);

  conn.must_close = 1;
  ASSERT(should_keep_alive(&conn) == 0);

  conn.must_close = 0;
  ASSERT(parse_http_request(req2, &conn.request_info) == 0);
  ASSERT(should_keep_alive(&conn) == 0);

  ASSERT(parse_http_request(req3, &conn.request_info) == 0);
  ASSERT(should_keep_alive(&conn) == 0);

  ASSERT(parse_http_request(req4, &conn.request_info) == 0);
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

  ASSERT(match_string("/api", 4, "/api") == 4);
  ASSERT(match_string("/a/", 3, "/a/b/c") == 3);
  ASSERT(match_string("/a/", 3, "/ab/c") == -1);
  ASSERT(match_string("/*/", 3, "/ab/c") == 4);
  ASSERT(match_string("**", 2, "/a/b/c") == 6);
  ASSERT(match_string("/*", 2, "/a/b/c") == 2);
  ASSERT(match_string("*/*", 3, "/a/b/c") == 2);
  ASSERT(match_string("**/", 3, "/a/b/c") == 5);
  ASSERT(match_string("**.foo|**.bar", 13, "a.bar") == 5);
  ASSERT(match_string("a|b|cd", 6, "cdef") == 2);
  ASSERT(match_string("a|b|c?", 6, "cdef") == 2);
  ASSERT(match_string("a|?|cd", 6, "cdef") == 1);
  ASSERT(match_string("/a/**.cgi", 9, "/foo/bar/x.cgi") == -1);
  ASSERT(match_string("/a/**.cgi", 9, "/a/bar/x.cgi") == 12);
  ASSERT(match_string("**/", 3, "/a/b/c") == 5);
  ASSERT(match_string("**/$", 4, "/a/b/c") == -1);
  ASSERT(match_string("**/$", 4, "/a/b/") == 5);
  ASSERT(match_string("$", 1, "") == 0);
  ASSERT(match_string("$", 1, "x") == -1);
  ASSERT(match_string("*$", 2, "x") == 1);
  ASSERT(match_string("/$", 2, "/") == 1);
  ASSERT(match_string("**/$", 4, "/a/b/c") == -1);
  ASSERT(match_string("**/$", 4, "/a/b/") == 5);
  ASSERT(match_string("*", 1, "/hello/") == 0);
  ASSERT(match_string("**.a$|**.b$", 11, "/a/b.b/") == -1);
  ASSERT(match_string("**.a$|**.b$", 11, "/a/b.b") == 6);
  ASSERT(match_string("**.a$|**.b$", 11, "/a/b.a") == 6);
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
  ASSERT((unsigned char)s.lsa.u.sa.sa_data[1] == (unsigned char)180);
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
  // fail due to HTTP/xxx head not being skipped: that is not a header!
  c.request_info.num_headers = parse_http_headers(&p, c.request_info.http_headers, ARRAY_SIZE(c.request_info.http_headers));
  ASSERT(p == buf);
  ASSERT(c.request_info.num_headers == -1);

  strcpy(buf, input);
  rv = get_request_len(buf, (int)strlen(buf));
  ASSERT(rv > 0 && rv < (int)strlen(buf));
  ASSERT(strstr(buf + rv, "<HTML><HEAD>") == buf + rv);
  buf[rv] = 0;
  p = buf;
  p += strcspn(p, "\r\n");
  p += strspn(p, "\r\n");
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
  // mark connection as being 'in header transmission/preparation mode':
  conn->num_bytes_sent = -1;
  ASSERT(!mg_have_headers_been_sent(conn));

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
  ASSERT_STREQ(conn->request_info.uri, "/oh-boy");
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


static const char *fetch_data = "hello world!\n";
static void *fetch_callback(enum mg_event event,
                           struct mg_connection *conn) {
  const struct mg_request_info *request_info = mg_get_request_info(conn);
  if (event == MG_NEW_REQUEST && !strcmp(request_info->uri, "/data")) {
    mg_add_response_header(conn, 0, "Content-Length", "%d", (int) strlen(fetch_data));
    mg_add_response_header(conn, 0, "Content-Type", "text/plain; charset=utf-8");
    mg_write_http_response_head(conn, 200, NULL);

    mg_printf(conn, "%s", fetch_data);
    return "";
  } else if (event == MG_EVENT_LOG) {
    printf("%s\n", request_info->log_message);
  }

  return NULL;
}

static void test_mg_fetch(void) {
  static const char *options[] = {
    "document_root", ".",
    "listening_ports", "33796",
    NULL,
  };
  char buf2[2000];
  int length;
  struct mg_context *ctx;
  struct mg_connection *conn = NULL;
  const struct mg_request_info *ri;
  const char *tmp_file = "temporary_file_name_for_unit_test.txt";
  struct mgstat st;
  FILE *fp;
  struct mg_user_class_t ucb = {
    NULL,
    fetch_callback
  };

  ASSERT((ctx = mg_start(&ucb, options)) != NULL);

  // Failed fetch, pass invalid URL
  ASSERT(mg_fetch(ctx, "localhost", tmp_file, NULL) == NULL);
  ASSERT(mg_fetch(ctx, "localhost:33796", tmp_file,
                  &conn) == NULL);
  ASSERT(conn == NULL);
  ASSERT(mg_fetch(ctx, "http://$$$.$$$", tmp_file,
                  &conn) == NULL);
  ASSERT(conn == NULL);

  // Failed fetch, pass invalid file name
  fp = mg_fetch(ctx, "http://localhost:33796/data",
                  "/this/file/must/not/exist/ever",
                  &conn);
  ASSERT(fp == NULL);
  ASSERT(conn != NULL);
  ri = mg_get_request_info(conn);
  ASSERT(ri->num_headers == 3);
  ASSERT_STREQ(ri->request_method, "GET");
  ASSERT_STREQ(ri->http_version, "1.1");
  ASSERT_STREQ(ri->uri, "/data");
  ASSERT(ri->status_code == 200);
  ASSERT_STREQ(ri->status_custom_description, "OK");
  mg_close_connection(conn);
  conn = NULL;

  // Successful fetch
  fp = mg_fetch(ctx, "http://localhost:33796/data", tmp_file, NULL);
  ASSERT(fp != NULL);

  // Successful fetch, keeping the connection but NOT keep-alive!
  fp = mg_fetch(ctx, "http://localhost:33796/data", tmp_file, &conn);
  ASSERT(fp != NULL);
  ASSERT(conn != NULL);
  ri = mg_get_request_info(conn);
  ASSERT(ri->num_headers == 3);
  ASSERT_STREQ(ri->request_method, "GET");
  ASSERT_STREQ(ri->http_version, "1.1");
  ASSERT_STREQ(ri->uri, "/data");
  ASSERT(ri->status_code == 200);
  ASSERT_STREQ(ri->status_custom_description, "OK");
  ASSERT((length = ftell(fp)) == (int) strlen(fetch_data));
  fseek(fp, 0, SEEK_SET);
  ASSERT(fread(buf2, 1, length, fp) == (size_t) length);
  ASSERT(memcmp(buf2, fetch_data, length) == 0);
  fclose(fp);
  mg_close_connection(conn);
  conn = NULL;

  // Fetch big file, mongoose.c
#if defined(_MSC_VER)
  if (mg_stat("mongoose.c", &st) && !mg_stat("../../mongoose.c", &st)) {
    // copy mongoose.c to project directory
    int mongoose_c_copied = CopyFileA("../../mongoose.c", "mongoose.c", TRUE);
#endif
  fp = mg_fetch(ctx, "http://localhost:33796/mongoose.c", tmp_file, &conn);
  ASSERT(fp != NULL);
  ASSERT(conn != NULL);
  ri = mg_get_request_info(conn);
  ASSERT(mg_stat("mongoose.c", &st) == 0);
  ASSERT(st.size == ftell(fp));
  ASSERT(ri->num_headers == 3);
  ASSERT_STREQ(ri->request_method, "GET");
  ASSERT_STREQ(ri->http_version, "1.1");
  ASSERT_STREQ(ri->uri, "/mongoose.c");
  ASSERT(ri->status_code == 200);
  ASSERT_STREQ(ri->status_custom_description, "OK");
  fclose(fp);
  mg_close_connection(conn);
  conn = NULL;
#if defined(_MSC_VER)
    // remove copy of mongoose.c from project directory
    if (mongoose_c_copied)
      mg_remove("mongoose.c");
  }
#endif

  mg_remove(tmp_file);
  mg_stop(ctx);
}



static int test_client_connect_expect_error = 0;

static void *test_client_event_handler(enum mg_event event, struct mg_connection *conn) {
  const struct mg_request_info *ri = mg_get_request_info(conn);

  if (event == MG_EVENT_LOG) {
    if (test_client_connect_expect_error == 1) {
      const char *emsg = ri->log_message;
      if (strstr(emsg, "content data bytes beyond the END of a chunked transfer")) {
        test_client_connect_expect_error = 0;
        fprintf(stderr, "### EXPECTED error! This is part of the test suite! ###\n");
      }
    }
  }
  return 0;
}


static void test_client_connect() {
  char buf[512];
  struct mg_context ctx_fake = {0};
  struct mg_context *ctx = &ctx_fake;
  struct mg_connection *conn;
  struct mg_request_info *ri4m;
  int rv;
  const char *cookies[16];
  int cl;

  ctx_fake.user_functions.user_callback = test_client_event_handler;
  test_client_connect_expect_error = 0;

  printf("=== TEST: %s ===\n", __func__);

  conn = mg_connect(ctx, "example.com", 80, MG_CONNECT_BASIC);
  ASSERT(conn);

  rv = mg_printf(conn, "GET / HTTP/1.0\r\n\r\n");
  ASSERT(rv == 18);
  mg_shutdown(conn, SHUT_WR);
  rv = mg_read(conn, buf, sizeof(buf));
  ASSERT(rv > 0);
  mg_close_connection(conn);
  //free(conn);


  conn = mg_connect(ctx, "google.com", 80, MG_CONNECT_USE_SSL);
  ASSERT(!conn);
  conn = mg_connect(ctx, "google.com", 80, MG_CONNECT_BASIC);
  ASSERT(conn);

  rv = mg_printf(conn, "GET / HTTP/1.0\r\n\r\n");
  ASSERT(rv == 18);
  mg_shutdown(conn, SHUT_WR);
  rv = mg_read(conn, buf, sizeof(buf));
  ASSERT(rv > 0);
  mg_close_connection(conn);
  //free(conn);


  // now with HTTP header support:
  conn = mg_connect(ctx, "www.google.com", 80, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
  ASSERT(conn);

  ASSERT(0 == mg_add_tx_header(conn, 0, "Host", "www.google.com"));
  ASSERT(0 == mg_add_tx_header(conn, 0, "Connection", "close"));
  // set up the request the rude way: directly patch the request_info struct. Nasty!
  //
  // Setting us up cf. https://developers.google.com/custom-search/docs/xml_results?hl=en#WebSearch_Request_Format
  ri4m = (struct mg_request_info *)mg_get_request_info(conn);
  ri4m->http_version = "1.1";
  ri4m->query_string = "q=mongoose&num=5&client=google-csbe&ie=utf8&oe=utf8&cx=00255077836266642015:u-scht7a-8i";
  ri4m->request_method = "GET";
  ri4m->uri = "/search";

  rv = mg_write_http_request_head(conn, NULL, NULL);
  ASSERT(rv == 153);
  // signal request phase done:
  mg_shutdown(conn, SHUT_WR);
  // fetch response, blocking I/O:
  //
  // but since this is a HTTP I/O savvy connection, we should first read the headers and parse them:
  rv = mg_read_http_response_head(conn);
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
  conn = mg_connect(ctx, "www.google.com", 80, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
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
  rv = mg_read_http_response_head(conn);
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
  conn = mg_connect(ctx, "www.google.com", 80, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
  ASSERT(conn);

  ASSERT(0 == mg_add_tx_header(conn, 0, "Host", "www.google.com"));
  ASSERT(0 == mg_add_tx_header(conn, 0, "Connection", "keep-alive"));
  // set up the request the rude way: directly patch the request_info struct. Nasty!
  //
  // Setting us up cf. https://developers.google.com/custom-search/docs/xml_results?hl=en#WebSearch_Request_Format
  ri4m = (struct mg_request_info *)mg_get_request_info(conn);
  ri4m->http_version = "1.1";
  ri4m->query_string = "q=mongoose&num=5&client=google-csbe&ie=utf8&oe=utf8&cx=00255077836266642015:u-scht7a-8i";
  ri4m->request_method = "GET";
  ri4m->uri = "/search";

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
  test_client_connect_expect_error = 1;
  rv = mg_printf(conn, "bugger!");
  ASSERT(rv == 0);
  ASSERT(test_client_connect_expect_error == 0);

  // fetch response, blocking I/O:
  //
  // but since this is a HTTP I/O savvy connection, we should first read the headers and parse them:
  rv = mg_read_http_response_head(conn);
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
  conn = mg_connect(ctx, "www.google.com", 80, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
  ASSERT(conn);

  ASSERT(0 == mg_add_tx_header(conn, 0, "Host", "www.google.com"));
  ASSERT(0 == mg_add_tx_header(conn, 0, "Connection", "keep-alive"));

  // explicitly set chunked mode; the header writing logic should catch up:
  mg_set_tx_mode(conn, MG_IOMODE_CHUNKED_DATA);

  // set up the request the rude way: directly patch the request_info struct. Nasty!
  //
  // Setting us up cf. https://developers.google.com/custom-search/docs/xml_results?hl=en#WebSearch_Request_Format
  ri4m = (struct mg_request_info *)mg_get_request_info(conn);
  ri4m->http_version = "1.1";
  ri4m->query_string = "q=mongoose&num=5&client=google-csbe&ie=utf8&oe=utf8&cx=00255077836266642015:u-scht7a-8i";
  ri4m->request_method = "GET";
  ri4m->uri = "/search";

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
  rv = mg_read_http_response_head(conn);
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
  conn = mg_connect(ctx, "www.google.com", 80, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
  ASSERT(conn);

  ASSERT(0 == mg_add_tx_header(conn, 0, "Host", "www.google.com"));
  ASSERT(0 == mg_add_tx_header(conn, 0, "Connection", "keep-alive"));
  // now with explicitly set content length: no chunked I/O!
  ASSERT(0 == mg_add_tx_header(conn, 0, "Content-Length", "%d", 0));
  // set up the request the rude way: directly patch the request_info struct. Nasty!
  //
  // Setting us up cf. https://developers.google.com/custom-search/docs/xml_results?hl=en#WebSearch_Request_Format
  ri4m = (struct mg_request_info *)mg_get_request_info(conn);
  ri4m->http_version = "1.1";
  ri4m->query_string = "q=mongoose&num=5&client=google-csbe&ie=utf8&oe=utf8&cx=00255077836266642015:u-scht7a-8i";
  ri4m->request_method = "GET";
  ri4m->uri = "/search";

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
  rv = mg_read_http_response_head(conn);
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
  conn = mg_connect(ctx, "www.google.com", 80, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
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
  rv = mg_read_http_response_head(conn);
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
  conn = mg_connect(ctx, "www.google.com", 80, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
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
  rv = mg_read_http_response_head(conn);
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




static void *test_local_client_event_handler(enum mg_event event, struct mg_connection *conn) {
  const struct mg_request_info *ri = mg_get_request_info(conn);

  if (event == MG_EVENT_LOG) {
    if (test_client_connect_expect_error == 1) {
      const char *emsg = ri->log_message;
      test_client_connect_expect_error = 0;
      fprintf(stderr, "### EXPECTED error! This is part of the test suite! ###\n");
    }
  }
  return 0;
}

static int test_server_connect_expect_error = 0;

static void *test_local_server_event_handler(enum mg_event event, struct mg_connection *conn) {
  const struct mg_request_info *ri = mg_get_request_info(conn);

  if (event == MG_EVENT_LOG) {
    if (test_server_connect_expect_error == 1) {
      const char *emsg = ri->log_message;
      test_server_connect_expect_error = 0;
      fprintf(stderr, "### EXPECTED error! This is part of the test suite! ###\n");
    }
  }
  return 0;
}

static void test_local_client_connect() {
  char buf[MG_BUF_LEN];
  char *d, *e;
  struct mg_context ctx_client = {0};
  struct mg_context *ctx;
  struct mg_connection *conn;
  struct mg_request_info *ri4m;
  const struct mg_request_info *ri;
  int rv;

  static const char *options[] = {
    "document_root", ".",
    "listening_ports", "33797",
    NULL,
  };
  const char *tmp_file = "temporary_file_name_for_unit_test.txt";
  struct mg_user_class_t ucb = {
    NULL,
    test_local_server_event_handler
  };

  ASSERT((ctx = mg_start(&ucb, options)) != NULL);

  ctx_client.user_functions.user_callback = test_local_client_event_handler;
  test_client_connect_expect_error = 0;
  test_server_connect_expect_error = 0;

  printf("=== TEST: %s ===\n", __func__);

  conn = mg_connect(&ctx_client, "localhost", 33797, MG_CONNECT_BASIC);
  ASSERT(conn);

  rv = mg_printf(conn, "GET / HTTP/1.0\r\n\r\n");
  ASSERT(rv == 18);
  // half-close to signal server we're done sending the request
  ASSERT(0 == mg_shutdown(conn, SHUT_WR));

  rv = mg_read(conn, buf, sizeof(buf));
  ASSERT(rv > 0);
  ASSERT_STRPARTEQ(buf, "HTTP/1.0 200 OK\r\n");
  mg_close_connection(conn);



  // now with HTTP header support:
  conn = mg_connect(&ctx_client, "localhost", 33797, MG_CONNECT_HTTP_IO);
  ASSERT(conn);

  //rv = mg_printf(conn, "GET /test/hello.txt HTTP/1.0\r\n\r\n");
  mg_set_http_version(conn, "1.0");
  rv = mg_write_http_request_head(conn, "GET", "/test/hello.txt");
  ASSERT(rv > 0);
  mg_shutdown(conn, SHUT_WR);

  // must fail as we can't be in chunked transfer mode
  ASSERT(-1 == mg_add_tx_header(conn, 0, "Connection", "close"));  

  rv = mg_read_http_response_head(conn);
  ASSERT(rv == 0);

  rv = mg_read(conn, buf, sizeof(buf));
  ASSERT(rv >= 0);

  ri = mg_get_request_info(conn);
  ASSERT(ri->status_code == 404);
  mg_close_connection(conn);




#if 0
  // when Content-Length isn't specified and we're not 
  // in chunked transfer mode (HTTP/1.1 only), then mg_read()
  // behaves as a single recv(), i.e. it does NOT strive
  // to fill the entire buf[] by waiting a long time.
  // This was done as a safeguard against bad/odd peer behaviour.
  // 
  d = buf;
  e = buf + sizeof(buf);
  do {
    rv = mg_read(conn, d, e - d);
    ASSERT(rv >= 0);
  while (e > d && rv > 0);
#endif

  // cleanup
  mg_stop(ctx);
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
  const struct mg_request_info *request_info = mg_get_request_info(conn);
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

    if (mg_get_var(request_info->query_string, (size_t)-1, "chunk_size", content, sizeof(content), 1) > 0) {
      chunk_size = atoi(content);
    } else {
      chunk_size = 0;
    }
    if (mg_get_var(request_info->query_string, (size_t)-1, "count", content, sizeof(content), 1) > 0) {
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

    DEBUG_TRACE(0x00010000,
                ("test server callback: %s request serviced",
                 request_info->uri));

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

static int gcl[3] = {0};

typedef struct test_conn_user_data {
  int req_id;
} test_conn_user_data_t;

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
        int chunk_len = gcl[0];

        pthread_spin_lock(&chunky_request_spinlock);
        chunk_len += (chunky_request_counters.responses_sent * (256 + gcl[1]) + c) % gcl[2];
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
      test_conn_user_data_t *ud;

      ud = (test_conn_user_data_t *)conn->request_info.req_user_data;
      ASSERT(ud);
      req_no = ud->req_id;
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
          ASSERT(header_count == ARRAY_SIZE(conn->request_info.response_headers) - 6 + 1);
          ASSERT_STREQ(chunk_headers[0].name, "X-Mongoose-Chunky-CLIENT");
          switch (subresp_no) {
          default:
            ASSERT(!"Should never get here");
            break;

          case 0:
            mg_snq0printf(conn, nbuf, sizeof(nbuf), "131, %d, 16", 16 - run_no);
            ASSERT_STREQ(chunk_headers[0].value, nbuf);
            break;

          case 1:
            mg_snq0printf(conn, nbuf, sizeof(nbuf), "131, %d, 32", 16 - run_no);
            ASSERT_STREQ(chunk_headers[0].value, nbuf);
            break;

          case 2:
            mg_snq0printf(conn, nbuf, sizeof(nbuf), "131, %d, 64", 16 - run_no);
            ASSERT_STREQ(chunk_headers[0].value, nbuf);
            break;

          case 3:
            mg_snq0printf(conn, nbuf, sizeof(nbuf), "132, %d, 128", 16 - run_no);
            ASSERT_STREQ(chunk_headers[0].value, nbuf);
            break;

          case 4:
            mg_snq0printf(conn, nbuf, sizeof(nbuf), "132, %d, 256", 16 - run_no);
            ASSERT_STREQ(chunk_headers[0].value, nbuf);
            break;

          case 5:
            mg_snq0printf(conn, nbuf, sizeof(nbuf), "132, %d, 512", 16 - run_no);
            ASSERT_STREQ(chunk_headers[0].value, nbuf);
            break;

          case 6:
            mg_snq0printf(conn, nbuf, sizeof(nbuf), "133, %d, 1024", 16 - run_no);
            ASSERT_STREQ(chunk_headers[0].value, nbuf);
            break;

          case 7:
            mg_snq0printf(conn, nbuf, sizeof(nbuf), "133, %d, 2048", 16 - run_no);
            ASSERT_STREQ(chunk_headers[0].value, nbuf);
            break;
          }
        }
      } else {
        ASSERT(header_count == ARRAY_SIZE(conn->request_info.response_headers) - 6 + 1);
        ASSERT_STREQ(chunk_headers[0].name, "X-Mongoose-Chunky-CLIENT");
        ASSERT_STREQ(chunk_headers[0].value, "Alter-3-of-18, 2048");
      }
    }
  }
  return 0;  // run default handler; we were just here to add extensions...
}

static void fixup_tcp_buffers_for_large_send_chunks(struct mg_connection *conn) {
  struct mg_context *ctx;
  // see what the OS default is, then increase that for this connection when it's
  // smaller than the expected largest send() tail headers' chunk:
  int tx_tcpbuflen = 0, rx_tcpbuflen = 0;
  size_t tx_varsize = sizeof(int), rx_varsize = sizeof(int);

  ctx = mg_get_context(conn);

  ASSERT(0 == mg_getsockopt(conn, SOL_SOCKET, SO_RCVBUF, &rx_tcpbuflen, &rx_varsize));
  ASSERT(0 == mg_getsockopt(conn, SOL_SOCKET, SO_SNDBUF, &tx_tcpbuflen, &tx_varsize));

  if (tx_tcpbuflen < conn->buf_size + CHUNK_HEADER_BUFSIZ) {
    tx_tcpbuflen = conn->buf_size + CHUNK_HEADER_BUFSIZ;
    ASSERT(0 == mg_setsockopt(conn, SOL_SOCKET, SO_SNDBUF, &tx_tcpbuflen, sizeof(tx_tcpbuflen)));
  }
  if (rx_tcpbuflen < conn->buf_size + CHUNK_HEADER_BUFSIZ) {
    rx_tcpbuflen = conn->buf_size + CHUNK_HEADER_BUFSIZ;
    ASSERT(0 == mg_setsockopt(conn, SOL_SOCKET, SO_RCVBUF, &rx_tcpbuflen, sizeof(rx_tcpbuflen)));
  }
}

int test_chunked_transfer(int round) {
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

  if (round == 1)
    printf("=== TEST: %s ===\n", __func__);

  pthread_spin_init(&chunky_request_spinlock, 0);
  memset(&chunky_request_counters, 0, sizeof(chunky_request_counters));

  ucb.write_chunk_header = chunky_write_chunk_header;
  ucb.process_rx_chunk_header = chunky_process_rx_chunk_header;

  ctx = mg_start(&ucb, options);
  if (!ctx)
    return -1;

  if (round == 1) {
    printf("Restartable server started on ports %s.\n",
           mg_get_option(ctx, "listening_ports"));
  } else {
    printf(".");
  }

  for (runs = 16; runs > 0; runs--) {
    test_conn_user_data_t ud = {0};

    DEBUG_TRACE(0x00020000, ("##### RUN: %d #####", runs));

    // open client connection to server and GET and POST chunked content
    conn = mg_connect(ctx, "localhost", 32156, MG_CONNECT_BASIC | MG_CONNECT_HTTP_IO);
    ASSERT(conn);
    rv = 0;

    pthread_spin_lock(&chunky_request_spinlock);
    chunky_request_counters.connections_opened++;
    ud.req_id = chunky_request_counters.requests_sent;
    pthread_spin_unlock(&chunky_request_spinlock);

    mg_set_request_user_data(conn, &ud);

    /*
    When you expect to send large chunks at once, such as we are when we send a large number
    of headers (and consequently large bytecount) in the tail chunk, you MUST increase
    the internal TCP stack send buffer to ensure that you do not suffer from deadlock
    when both parties (such as in this testclient and built-in test server) MAY send these
    large numbers of bytes without the option of them emptying their receive buffers
    at the same time.

    You may observe this deadlock cause happen without the SO_SNDBUF + SO_RCVBUF adjustment below
    as we must account for both testclient and testserver sending large header blocks in
    their tail chunks; we only 'cope' with that by adjusting at the client side here, i.e.
    SO_RCVBUF increase is meant to cope with the expected large incoming tail block from the
    testserver.

    (At later revision will include these adjustments as an option for mongoose proper.)
    */
    fixup_tcp_buffers_for_large_send_chunks(conn);

    for (prospect_chunk_size = 16; prospect_chunk_size < 4096; prospect_chunk_size *= 2)
    {
      int add_chunkend_header = 0;
      int req_sent_count;

      mg_add_tx_header(conn, 0, "Host", "localhost");
      mg_add_tx_header(conn, 0, "Connection", "keep-alive");

      pthread_spin_lock(&chunky_request_spinlock);
      req_sent_count = ++chunky_request_counters.requests_sent;
      pthread_spin_unlock(&chunky_request_spinlock);
      add_chunkend_header = (req_sent_count % 5 == 3);

      rv = mg_write_http_request_head(conn, "GET", "/chunky?count=%d&chunk_size=%d&sent_count=%03u", 10, prospect_chunk_size, req_sent_count % 1000);
      ASSERT(rv >= 100);
      ASSERT_STREQ(mg_get_tx_header(conn, "Connection"), "keep-alive");

      if (add_chunkend_header) {
        int hi;

        mg_add_response_header(conn, 0, "X-Mongoose-Chunky-CLIENT", "%d, %d, %d", rv, runs, prospect_chunk_size);

        // help trigger edge case 2 by pumping out a huge tail chunk header section:
        for (hi = 6; hi < (int)ARRAY_SIZE(conn->request_info.response_headers); hi++) {
          ASSERT(0 == mg_add_response_header(conn, 1, "X-Mongoose-Chunky-CLIENT-FloodTest", "%d; %d; %d; \"bugger-it and still no cocktail under the bridge! %*s!\"",
                                             hi, runs, prospect_chunk_size, req_sent_count % TAIL_CHUNK_HDR_FLOOD_ATTEMPT_MODULO, "ugh"));
        }
      }

      // this one is optional here as we didn't send any data:
      // (It is mandatory though when you're transmitting in chunked transfer mode!)
      mg_flush(conn);
      // signal request phase done:
      //mg_shutdown(conn, SHUT_WR);

#if BLAST_ALL_REQUESTS_TO_SERVER_FIRST
      // as we've got a kept-alive connection, we can send another request!
      ASSERT(0 == mg_cleanup_after_request(conn));
    }

    for (prospect_chunk_size = 16; prospect_chunk_size < 4096; prospect_chunk_size *= 2)
    {
#endif
      ud.req_id++;

      // fetch response, blocking I/O:
      //
      // but since this is a HTTP I/O savvy connection, we should first read the headers and parse them:
      rv = mg_read_http_response_head(conn);
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
      int i, c, chunk_size, hi;
      int rx_state;
      int rcv_amount;
      int req_sent_count;

      mg_add_tx_header(conn, 0, "Host", "localhost");
      mg_add_tx_header(conn, 0, "Connection", "keep-alive");
      mg_add_response_header(conn, 0, "Content-Type", "text/plain");
      mg_add_response_header(conn, 0, "Transfer-Encoding", "%s", "chunked"); // '%s'? Just foolin' with ya. 'chunked' mode must be detected AFTER printf-formatting has been applied to value.

      pthread_spin_lock(&chunky_request_spinlock);
      req_sent_count = ++chunky_request_counters.requests_sent;
      pthread_spin_unlock(&chunky_request_spinlock);

      rv = mg_write_http_request_head(conn, "POST", "/chunky?count=%d&chunk_size=%d&sent_count=%03u", 10, prospect_chunk_size, req_sent_count % 1000);
      ASSERT(rv >= 158);
      ASSERT_STREQ(mg_get_tx_header(conn, "Connection"), "keep-alive");

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
      // as mg_read_http_response_head() is a blocking operation. Of course we have 100% knowledge of
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
            ud.req_id++;

            rv = mg_read_http_response_head(conn);
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

      // help trigger edge case 2 by pumping out a huge tail chunk header section:
      for (hi = 6; hi < (int)ARRAY_SIZE(conn->request_info.response_headers); hi++) {
        ASSERT(0 == mg_add_response_header(conn, 1, "X-Mongoose-Chunky-CLIENT-FloodTest", "%d; %d; %d; \"bugger-it and still no cocktail under the bridge! %*s!\"",
                                           hi, runs, prospect_chunk_size, req_sent_count % TAIL_CHUNK_HDR_FLOOD_ATTEMPT_MODULO, "ugh"));
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
          ud.req_id++;

          rv = mg_read_http_response_head(conn);
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

//  if (round == 1)
//    printf("Server stopped.\n");

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

//  if (round == 1)
//  printf("Server terminating now.\n");
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

#if MG_DEBUG_TRACING
  *mg_trace_level() = 0x00021501;
#endif

  test_MSVC_fix();

  test_match_prefix();
  test_remove_double_dots();
  test_IPaddr_parsing();
  test_logpath_fmt();
  test_http_hdr_value_unquoting();
  test_token_value_extractor();
  test_http_header_extractor();
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
  test_local_client_connect();
  test_mg_fetch();

  /*
  semi-random testing of the chunked transfer I/O logic: the edge cases are easily seen
  yet very / extremely hard to trigger using static analysis/prediction: as the edge
  cases depend on network behaviour and internal behaviour of the TCP stack to
  'fill those buffers just right' to tickle the edge case, their occurrence is semi-random
  in practice.

  To counter this in testing, we construct a parameterized test, which' parameters are then
  randomized within heuristically determined ranges on each run, while the data collected
  in those test runs is used to check whether the edge cases have been triggered and how
  often this has happened.
  Particularly the second edge case is extremely hard to trigger, depending on your
  protocol stack/OS and other uncontrolled external factors, so many runs may be required
  to observe a trigger there.

  The collected cases are the ones which have shown to trigger either or both edge cases
  for particular hardware significantly more often than others and are hence included
  as 'presets' for the first number of runs in order to maximize our chances of success
  in a short period of time.
  */
  {
    int gcl_best[3] = {0};
    int gcl_tbest[3] = {0};
    int hitc = 0;
    int hittc = 0;
    int round;
    int total_hitc = 0;
    int total_hittc = 0;
    const int presets[][3] =
    {
      { 111,3548,132 },
      { 134,19718,98 },
      { 140,30333,126 },
      { 155,27753,36 }, // tail hits ~ / 8 ~ / 39
      { 155,28297,21 }, // tail hits ~ / 9 ~ / 80
      { 156,1869,115 },
      { 159,27529,31 },
      { 18,13458,21 },
      { 18,19169,27 },
      { 18,3788,130 },
      { 21,32729,10 },
      { 22,6995,5 },
      { 24,11840,19 },
      { 31,9514,12 },
      { 32,15141,14 },
      { 34,19718,48 },
      { 34,3035,43 },
      { 41,24084,7 },
      { 46,29358,15 },
      { 58,8942,17 },
      { 59,18467,37 },
      { 60,12382,24 },
      { 60,26439,6 },
      { 65,21726,24 },
    };

    printf("WARNING: multiple runs test the HTTP chunked I/O mode extensively;\n"
           "         this may take a while. The HTTP chunk transfer test code\n"
           "         attempts to include two important 'edge conditions' in the\n"
           "         tests, but hitting these is dependent on network conditions\n"
           "         i.e. hits occur semi-randomly. This code runs until both\n"
           "         edge conditions have been hit at least 100 times.\n");

    for (round = 1; total_hittc < 100; round++) {
      int improved = 0;

      pthread_spin_lock(&chunky_request_spinlock);
      chunky_request_counters.responses_sent = 0;
      pthread_spin_unlock(&chunky_request_spinlock);

      if (round < ARRAY_SIZE(presets)) {
        printf("@");
        fflush(stdout);
        gcl[0] = presets[round][0];
        gcl[1] = presets[round][1];
        gcl[2] = presets[round][2];
      } else {
        gcl[0] = 18 + rand() % 150;
        gcl[1] = 0 + rand();
        gcl[2] = 3 + rand() % 150;
      }

      shift_hit = 0;
      shift_tail_hit = 0;

      test_chunked_transfer(round);

      if (shift_hit > hitc) {
        hitc = shift_hit;
        memcpy(gcl_best, gcl, sizeof(gcl));
        improved = 1;
      }
      if (shift_tail_hit > hittc) {
        hittc = shift_tail_hit;
        memcpy(gcl_tbest, gcl, sizeof(gcl));
        improved = 1;
      }

      total_hitc += shift_hit;
      total_hittc += shift_tail_hit;

      if (improved) {
        FILE *lf = fopen("gcl-best.log", "a");
        if (lf) {
          fprintf(lf, "  { %d,%d,%d }, // hits ~ %d ~ %d\n",
                gcl_best[0], gcl_best[1], gcl_best[2],
                hitc,
                total_hitc);
          fprintf(lf, "  { %d,%d,%d }, // tail hits ~ / %d ~ / %d\n",
                gcl_tbest[0], gcl_tbest[1], gcl_tbest[2],
                hittc,
                total_hittc);
          fclose(lf);
        }
        printf("\n#######--------- BEST GCL: %d.%d.%d / %d.%d.%d ~ %d / %d ~ %d / %d\n",
               gcl_best[0], gcl_best[1], gcl_best[2],
               gcl_tbest[0], gcl_tbest[1], gcl_tbest[2],
               hitc, hittc,
               total_hitc, total_hittc);
        fflush(stdout);
      }
    }
  }

  printf("\nAll tests have completed successfully.\n"
         "(Some error log messages may be visible. No worries, that's perfectly all right!)\n");

  return 0;
}
