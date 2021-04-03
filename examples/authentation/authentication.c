
#include "civetweb_ex.h"  // mg_get_headers(), mg_match_string()


/*
 * Cookie based authentication
 * taken from http://en.wikipedia.org/wiki/HTTP_cookie#Authentication
 *
 * 1. The user inserts his or her username and password in the text fields
 *    of a login page and sends them to the server;
 * 2. The server receives the username and password and checks them; if
 *    correct, it sends back a page confirming that login has been successful
 *    together with a cookie containing a random session ID that coincides with
 *    a session stored in a database. This cookie is usually made valid for
 *    only the current browser session, however it may also be set to expire at
 *    a future date. The random session ID is then provided on future visits
 *    and provides a way for the server to uniquely identify the browser and
 *    confirm that the browser already has an authenticated user.
 * 3. Every time the user requests a page from the server, the browser
 *    automatically sends the cookie back to the server; the server compares
 *    the cookie with the stored ones; if a match is found, the server knows
 *    which user has requested that page.
 */

static int
login_page(struct mg_connection *conn)
{
    char        name[100], pass[100], uri[100];
    const char  *cookies[20];
    const struct mg_request_info *ri = mg_get_request_info(conn);
    const char  *qs = ri->query_string;
    size_t       qslen = strlen(qs); // query_string ~ "" when no query string was specified in the request

    mg_get_var(qs, qslen, "name", name, ARRAY_SIZE(name), 1);
    mg_get_var(qs, qslen, "pass", pass, ARRAY_SIZE(pass), 1);
    mg_get_headers(cookies, ARRAY_SIZE(cookies), conn, "Cookie");

    /*
     * Here user name and password must be checked against some
     * database - this is step 2 from the algorithm described above.
     * This is an example, so hardcode name and password to be
     * admin/admin, and if this is so, set "allow=yes" cookie and
     * redirect back to the page where we have been redirected to login.
     */
    if (strcmp(name, "admin") == 0 && strcmp(pass, "admin") == 0) {
        const char  **cookie;
        for (cookie = &cookies[0]; *cookie; cookie++)
        {
            if (*cookie == NULL || sscanf(*cookie, "uri=%99s", uri) != 1)
            {
                (void) strcpy(uri, "/");
                break;
            }
        }
        /* Set allow=yes cookie, which is expected by authorize() */
        mg_printf(conn, "HTTP/1.1 301 Moved Permanently\r\n"
            "Location: %s\r\n"
            "Set-Cookie: allow=yes; Path=/;\r\n\r\n", uri);
        mg_mark_end_of_header_transmission(conn);
    } else {
        /* Print login page */
        mg_printf(conn, "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: allow=no; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;\r\n" /* destroy cookie if it exists already */
            "content-Type: text/html\r\n\r\n");
        mg_mark_end_of_header_transmission(conn);
        mg_printf(conn, ""
            "Please login (enter admin/admin to pass)<br>"
            "<form method=post>"
            "Name: <input type=text name=name></input><br/>"
            "Password: <input type=password name=pass></input><br/>"
            "<input type=submit value=Login></input>"
            "</form>");
    }
    return 1;
}

static int
authorize(struct mg_connection *conn)
{
    const char *cookies[20];
    const char *cookie = NULL;
    int i;
    const struct mg_request_info *ri = mg_get_request_info(conn);

    mg_get_headers(cookies, ARRAY_SIZE(cookies), conn, "Cookie");
    for (i = 0; cookies[i]; i++)
    {
        if (strstr(cookies[i], "allow=") != NULL)
        {
            cookie = cookies[i];
            break;
        }
    }

    if (!strcmp(ri->uri, "/login")) {
        /* Always authorize accesses to the login page */
        return 0;
    } else if (cookie != NULL && strstr(cookie, "allow=yes") != NULL) {
        /* Valid cookie is present, authorize */
        return 0;
    } else {
        /* Not authorized. Redirect to the login page */
        mg_printf(conn, "HTTP/1.1 301 Moved Permanently\r\n"
            "Set-Cookie: uri=%s;\r\n"
            "Location: /login\r\n\r\n", ri->uri);
        mg_mark_end_of_header_transmission(conn);
    }
    return 1;
}

static const struct srv_pages_config {
    enum mg_event event;
    const char *uri;
    int (*func)(struct mg_connection *conn);
} srv_pages_config[] = {
    {MG_NEW_REQUEST, "/login$", &login_page},
    {MG_NEW_REQUEST, "/**", &authorize},
    {0, NULL, NULL}
};

static void *callback(enum mg_event event,
        struct mg_connection *conn)
{
    int i;
    const struct mg_request_info *ri = mg_get_request_info(conn);

    for (i = 0; srv_pages_config[i].uri != NULL; i++)
    {
        if (event == srv_pages_config[i].event &&
            (event == MG_HTTP_ERROR ||
            -1 < mg_match_string(srv_pages_config[i].uri, -1, ri->uri)))
        {
            if (srv_pages_config[i].func(conn) != 0)
                return "processed";
        }
    }

    return NULL;
}

int
main(void)
{
    struct mg_context *ctx;
    const char *options[] = {"listening_ports", "8080"};
    const struct mg_user_class_t ucb = {
        NULL,      // Arbitrary user-defined data
        callback   // User-defined callback function
    };

    ctx = mg_start(&ucb, options);
    while (!mg_get_stop_flag(ctx)) {
        mg_sleep(10);
    }
    mg_stop(ctx);
    return 0;
}
