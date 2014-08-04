
Overview
=====

Civetweb is small and easy to use web server.
It may be embedded into C/C++ host applications or used as a stand-alone
server. See `Embedding.md` for information on embedding civetweb into
host applications.

The stand-alone server is self-contained, and does not require any external
software to run. Some Windows users may need to install the
[Visual C++ Redistributable](http://www.microsoft.com/en-us/download/details.aspx?id=30679).

Installation
----

On Windows, UNIX and Mac, the civetweb stand-alone executable may be started
from the command line.
Running `civetweb` in a terminal, optionally followed by configuration parameters
(`civetweb [OPTIONS]`) or a configuration file name (`civetweb [config_file_name]`),
starts the web server.

For UNIX and Mac, civetweb does not detach from the terminal.
Pressing `Ctrl-C` keys will stop the server.

On Windows, civetweb iconifies itself to the system tray icon when started.
Right-click on the icon pops up a menu, where it is possible to stop
civetweb, or configure it, or install it as Windows service.

When started without options, the server exposes the local directory at
[http](http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol) port 8080.
Thus, the easiest way to share a folder on Windows is to copy `civetweb.exe`
to this folder, double-click the exe, and launch a browser at
[http://localhost:8080](http://localhost:8080). Note that 'localhost' should
be changed to a machine's name if a folder is accessed from other computer.

When started, civetweb first searches for the configuration file.
If configuration file is specified explicitly in the command line, i.e.
`civetweb path_to_config_file`, then specified configuration file is used.
Otherwise, civetweb would search for file `civetweb.conf` in the same directory
the executable is located, and use it. This configuration file is optional.

The configuration file is a sequence of lines, each line containing one
command line argument name and the corresponding value.
Empty lines, and lines beginning with `#`, are ignored.
Here is the example of `civetweb.conf` file:

    document_root c:\www
    listening_ports 80,443s
    ssl_certificate c:\civetweb\ssl_cert.pem

When a configuration file is used, additional command line arguments may
override the configuration file settings.
All command line arguments must start with `-`.

For example: The above `civetweb.conf` file is used, and civetweb started as
`civetweb -document_root D:\web`. Then the `D:\web` directory will be served
as document root, because command line options take priority over the
configuration file. The configuration options section below provides a good
overview of the Civetweb features.

Note that configuration options on the command line must start with `-`,
but their names are the same as in the config file. All option names are
listed in the next section. Thus, the following two setups are equivalent:

    # Using command line arguments
    $ civetweb -listening_ports 1234 -document_root /var/www

    # Using config file
    $ cat civetweb.conf
    listening_ports 1234
    document_root /var/www
    $ civetweb

Civetweb can also be used to modify `.htpasswd` passwords files:

    civetweb -A <htpasswd_file> <realm> <user> <passwd>

Unlike other web servers, civetweb does not require CGI scripts to be located
in a special directory. CGI scripts can be anywhere. CGI (and SSI) files are
recognized by the file name pattern. Civetweb uses shell-like glob
patterns. Pattern match starts at the beginning of the string, so essentially
patterns are prefix patterns. Syntax is as follows:

     **      Matches everything
     *       Matches everything but slash character, '/'
     ?       Matches any character
     $       Matches the end of the string
     |       Matches if pattern on the left side or the right side matches.

All other characters in the pattern match themselves. Examples:

    **.cgi$      Any string that ends with .cgi
    /foo         Any string that begins with /foo
    **a$|**b$    Any string that ends with a or b

# Configuration Options

Below is a list of configuration options understood by Civetweb.
Every option is followed by it's default value. If a default value is not
present, then the default is empty.

### cgi\_pattern `**.cgi$|**.pl$|**.php$`
All files that match `cgi_pattern` are treated as CGI files. Default pattern
allows CGI files be anywhere. To restrict CGIs to a certain directory,
use `/path/to/cgi-bin/**.cgi` as pattern. Note that the full file path is
matched against the pattern, not the URI.

### cgi\_environment
Extra environment variables to be passed to the CGI script in
addition to standard ones. The list must be comma-separated list
of name=value pairs, like this: `VARIABLE1=VALUE1,VARIABLE2=VALUE2`.

### put\_delete\_auth\_file
Passwords file for PUT and DELETE requests. Without password file, it will not
be possible to, PUT new files to the server or DELETE existing ones. PUT and
DELETE requests might still be handled by Lua scripts and CGI paged.

### cgi\_interpreter
Path to an executable to use as CGI interpreter for __all__ CGI scripts
regardless of the script file extension. If this option is not set (which is
the default), Civetweb looks at first line of a CGI script,
[shebang line](http://en.wikipedia.org/wiki/Shebang_(Unix\)), for an
interpreter (not only on Linux and Mac but also for Windows).

For example, if both PHP and Perl CGIs are used, then
`#!/path/to/php-cgi.exe` and `#!/path/to/perl.exe` must be first lines of the
respective CGI scripts. Note that paths should be either full file paths,
or file paths relative to the current working directory of the civetweb
server. If civetweb is started by mouse double-click on Windows, the current
working directory is the directory where the civetweb executable is located.

If all CGIs use the same interpreter, for example they are all PHP, it is
more efficient to set `cgi_interpreter` to the path to `php-cgi.exe`.
The  shebang line in the CGI scripts can be omitted in this case.
Note that PHP scripts must use `php-cgi.exe` as executable, not `php.exe`.

### protect\_uri
Comma separated list of URI=PATH pairs, specifying that given
URIs must be protected with password files specified by PATH.
All Paths must be full file paths.

### authentication_domain `mydomain.com`
Authorization realm used for HTTP digest authentication. This domain is
used in the encoding of the `.htpasswd` authorization files as well.
Changing the domain retroactively will render the existing passwords useless.

### ssi\_pattern `**.shtml$|**.shtm$`
All files that match `ssi_pattern` are treated as Server Side Includes (SSI).

SSI is a simple interpreted server-side scripting language which is most
commonly used to include the contents of another file into a web page.
It can be useful when it is desirable to include a common piece
of code throughout a website, for example, headers and footers.

In order for a webpage to recognize an SSI-enabled HTML file, the filename
should end with a special extension, by default the extension should be
either `.shtml` or `.shtm`. These extentions may be changed using the
`ssi_pattern` option.

Unknown SSI directives are silently ignored by civetweb. Currently, two SSI
directives are supported, `<!--#include ...>` and
`<!--#exec "command">`. Note that the `<!--#include ...>` directive supports
three path specifications:

    <!--#include virtual="path">  Path is relative to web server root
    <!--#include abspath="path">  Path is absolute or relative to
                                  web server working dir
    <!--#include file="path">,    Path is relative to current document
    <!--#include "path">

The `include` directive may be used to include the contents of a file or the
result of running a CGI script. The `exec` directive is used to execute a
command on a server, and show the output that would have been printed to
stdout (the terminal window) otherwise. Example:

    <!--#exec "ls -l" -->

For more information on Server Side Includes, take a look at the Wikipedia:
[Server Side Includes](http://en.wikipedia.org/wiki/Server_Side_Includes)

### throttle
Limit download speed for clients.  `throttle` is a comma-separated
list of key=value pairs, where key could be:

    *                   limit speed for all connections
    x.x.x.x/mask        limit speed for specified subnet
    uri_prefix_pattern  limit speed for given URIs

The value is a floating-point number of bytes per second, optionally
followed by a `k` or `m` character, meaning kilobytes and
megabytes respectively. A limit of 0 means unlimited rate. The
last matching rule wins. Examples:

    *=1k,10.0.0.0/8=0   limit all accesses to 1 kilobyte per second,
                        but give connections the from 10.0.0.0/8 subnet
                        unlimited speed

    /downloads/=5k      limit accesses to all URIs in `/downloads/` to
                        5 kilobytes per second. All other accesses are unlimited

### access\_log\_file
Path to a file for access logs. Either full path, or relative to the current
working directory. If absent (default), then accesses are not logged.

### enable\_directory\_listing `yes`
Enable directory listing, either `yes` or `no`.

### error\_log\_file
Path to a file for error logs. Either full path, or relative to the current
working directory. If absent (default), then errors are not logged.

### global\_auth\_file
Path to a global passwords file, either full path or relative to the current
working directory. If set, per-directory `.htpasswd` files are ignored,
and all requests are authorized against that file.

The file has to include the realm set through `authentication_domain` and the
password in digest format:

    user:realm:digest
    test:test.com:ce0220efc2dd2fad6185e1f1af5a4327

Password files may be generated using `civetweb -A` as explained above, or
online tools e.g. [this generator](http://www.askapache.com/online-tools/htpasswd-generator).

### index\_files `index.xhtml,index.html,index.htm,index.cgi,index.shtml,index.php`
Comma-separated list of files to be treated as directory index files.
If more than one matching file is present in a directory, the one listed to the left
is used as a directory index.

In case built-in Lua support has been enabled, `index.lp,index.lsp,index.lua`
are additional default index files, ordered before `index.cgi`.

### enable\_keep\_alive `no`
Enable connection keep alive, either `yes` or `no`.

Experimental feature. Allows clients to reuse TCP connection for subsequent
HTTP requests, which improves performance.
For this to work when using request handlers it is important to add the
correct Content-Length HTTP header for each request. If this is forgotten the
client will time out.

### access\_control\_list
An Access Control List (ACL) allows restrictions to be put on the list of IP
addresses which have access to the web server. In the case of the Civetweb
web server, the ACL is a comma separated list of IP subnets, where each
subnet is pre-pended by either a `-` or a `+` sign. A plus sign means allow,
where a minus sign means deny. If a subnet mask is omitted, such as `-1.2.3.4`,
this means to deny only that single IP address.

Subnet masks may vary from 0 to 32, inclusive. The default setting is to allow
all accesses. On each request the full list is traversed, and
the last match wins. Examples:

    -0.0.0.0/0,+192.168/16    deny all accesses, only allow 192.168/16 subnet

To learn more about subnet masks, see the
[Wikipedia page on Subnetwork](http://en.wikipedia.org/wiki/Subnetwork).

### extra\_mime\_types
Extra mime types, in tha form `extension1=type1,exten-sion2=type2,...`.
See the [Wikipedia page on Internet media types](http://en.wikipedia.org/wiki/Internet_media_type).
Extension must include a leading dot. Example:
`.cpp=plain/text,.java=plain/text`

### listening\_ports `8080`
Comma-separated list of ports to listen on. If the port is SSL, a
letter `s` must be appended, for example, `80,443s` will open
port 80 and port 443, and connections on port 443 will be SSL-ed.
For non-SSL ports, it is allowed to append letter `r`, meaning 'redirect'.
Redirect ports will redirect all their traffic to the first configured
SSL port. For example, if `listening_ports` is `80r,443s`, then all
HTTP traffic coming at port 80 will be redirected to HTTPS port 443.

It is possible to specify an IP address to bind to. In this case,
an IP address and a colon must be pre-pended to the port number.
For example, to bind to a loopback interface on port 80 and to
all interfaces on HTTPS port 443, use `127.0.0.1:80,443s`.

### document\_root `.`
A directory to serve. By default, the current workubg directory is served.
The current directory is commonly referenced as dot (`.`).

### ssl\_certificate
Path to the SSL certificate file. This option is only required when at least
one of the `listening\_ports` is SSL. The file must be in PEM format,
and it must have both, private key and certificate, see for example
[ssl_cert.pem](https://github.com/bel2125/civetweb/blob/master/resources/ssl_cert.pem)
A description how to create a certificate can be found in doc/OpenSSL.md

### num\_threads `50`
Number of worker threads. Civetweb handles each incoming connection in a
separate thread. Therefore, the value of this option is effectively the number
of concurrent HTTP connections Civetweb can handle.

### run\_as\_user
Switch to given user credentials after startup. Usually, this option is
required when civetweb needs to bind on privileged ports on UNIX. To do
that, civetweb needs to be started as root. From a security point of view,
running as root is not advisable, therefore this option can be used to drop
privileges. Example:

    civetweb -listening_ports 80 -run_as_user webserver

### url\_rewrite\_patterns
Comma-separated list of URL rewrites in the form of
`uri_pattern=file_or_directory_path`. When Civetweb receives any request,
it constructs the file name to show by combining `document_root` and the URI.
However, if the rewrite option is used and `uri_pattern` matches the
requested URI, then `document_root` is ignored. Instead,
`file_or_directory_path` is used, which should be a full path name or
a path relative to the web server's current working directory. Note that
`uri_pattern`, as all civetweb patterns, is a prefix pattern.

This makes it possible to serve many directories outside from `document_root`,
redirect all requests to scripts, and do other tricky things. For example,
to redirect all accesses to `.doc` files to a special script, do:

    civetweb -url_rewrite_patterns **.doc$=/path/to/cgi-bin/handle_doc.cgi

Or, to imitate support for user home directories, do:

    civetweb -url_rewrite_patterns /~joe/=/home/joe/,/~bill=/home/bill/

### hide\_files\_patterns
A pattern for the files to hide. Files that match the pattern will not
show up in directory listing and return `404 Not Found` if requested. Pattern
must be for a file name only, not including directory names. Example:

    civetweb -hide_files_patterns secret.txt|*.hide

### request\_timeout\_ms `30000`
Timeout for network read and network write operations, in milliseconds.
If a client intends to keep long-running connection, either increase this
value or (better) use keep-alive messages.

### lua\_preload\_file
This configuration option can be used to specify a Lua script file, which
is executed before the actual web page script (Lua script, Lua server page
or Lua websocket). It can be used to modify the Lua environment of all web
page scripts, e.g., by loading additional libraries or defining functions
required by all scripts.
It may be used to achieve backward compatibility by defining obsolete
functions as well.

### lua\_script\_pattern `"**.lua$`
A pattern for files that are interpreted as Lua scripts by the server.
In contrast to Lua server pages, Lua scripts use plain Lua syntax.
An example can be found in the test directory.

### lua\_server\_page\_pattern `**.lp$|**.lsp$`
Files matching this pattern are treated as Lua server pages.
In contrast to Lua scripts, the content of a Lua server pages is delivered
directly to the client. Lua script parts are delimited from the standard
content by including them between <? and ?> tags.
An example can be found in the test directory.

### websocket\_root
In case civetweb is built with Lua and websocket support, Lua scripts may
be used for websockets as well. Since websockets use a different URL scheme
(ws, wss) than other http pages (http, https), the Lua scripts used for
websockets may also be served from a different directory. By default,
the document_root is used as websocket_root as well.

### access\_control\_allow\_origin
Access-Control-Allow-Origin header field, used for cross-origin resource
sharing (CORS).
See the [Wikipedia page on CORS](http://en.wikipedia.org/wiki/Cross-origin_resource_sharing).

### error\_pages
This option may be used to specify a directory for user defined error pages.
The error pages may be specified for an individual http status code (e.g.,
404 - page requested by the client not found), a group of http status codes
(e.g., 4xx - all client errors) or all errors. The corresponding error pages
must be called error404.ext, error4xx.ext or error.ext, whereas the file
extention may be one of the extentions specified for the index_files option.
See the [Wikipedia page on HTTP status codes](http://en.wikipedia.org/wiki/HTTP_status_code).

### decode\_url `yes`
URL encoded request strings are decoded in the server, unless it is disabled
by setting this option to `no`.

# Lua Scripts and Lua Server Pages
Pre-built Windows and Mac civetweb binaries have built-in Lua scripting
support as well as support for Lua Server Pages.

Lua scripts (default extension: *.lua) use plain Lua syntax.
The body of the script file is not sent directly to the client,
the Lua script must send header and content of the web page by calling
the function mg.write(text).

Lua Server Pages (default extensions: *.lsp, *.lp) are html pages containing
script elements similar to PHP, using the Lua programming language instead of
PHP. Lua script elements must be enclosed in `<?  ?>` blocks, and can appear
anywhere on the page. Furthermore, Lua Server Pages offer the opportunity to
insert the content of a variable by enclosing the Lua variable name in
`<?=  ?>` blocks, similar to PHP.
For example, to print the current weekday name and the URI of the current
page, one can write:

    <p>
      <span>Today is:</span>
      <? mg.write(os.date("%A")) ?>
    </p>
    <p>
      URI is <?=mg.request_info.uri?>
    </p>

Lua is known for it's speed and small size. Civetweb currently uses Lua
version 5.2.3. The documentation for it can be found in the
[Lua 5.2 reference manual](http://www.lua.org/manual/5.2/).


Note that this example uses function `mg.write()`, which sends data to the
web client. Using `mg.write()` is the way to generate web content from inside
Lua code. In addition to `mg.write()`, all standard Lua library functions
are accessible from the Lua code (please check the reference manual for
details). Information on the request is available in the `mg.request_info`
object, like the request method, all HTTP headers, etcetera.

[page2.lua](https://github.com/bel2125/civetweb/blob/master/test/page2.lua)
is an example for a plain Lua script.

[page2.lp](https://github.com/bel2125/civetweb/blob/master/test/page2.lp)
is an example for a Lua Server Page.

Both examples show the content of the `mg.request_info` object as the page
content. Please refer to `struct mg_request_info` definition in
[civetweb.h](https://github.com/bel2125/civetweb/blob/master/include/civetweb.h)
to see additional information on the elements of the `mg.request_info` object.

Civetweb also provides access to the [SQlite3 database](http://www.sqlite.org/)
through the [LuaSQLite3 interface](http://lua.sqlite.org/index.cgi/doc/tip/doc/lsqlite3.wiki)
in Lua. Examples are given in
[page.lua](https://github.com/bel2125/civetweb/blob/master/test/page.lua) and
[page.lp](https://github.com/bel2125/civetweb/blob/master/test/page.lp).


Civetweb exports the following functions to Lua:

mg (table):

    mg.read()                  -- reads a chunk from POST data, returns it as a string
    mg.write(str)              -- writes string to the client
    mg.include(path)           -- sources another Lua file
    mg.redirect(uri)           -- internal redirect to a given URI
    mg.onerror(msg)            -- error handler, can be overridden
    mg.version                 -- a string that holds Civetweb version
    mg.document_root           -- a string that holds the document root directory
    mg.auth_domain             -- a string that holds the HTTP authentication domain
    mg.get_var(str, varname)   -- extract variable from (query) string
    mg.get_cookie(str, cookie) -- extract cookie from a string
    mg.get_mime_type(filename) -- get MIME type of a file
    mg.send_file(filename)     -- send a file, including MIME type
    mg.url_encode(str)         -- URL encode a string
    mg.url_decode(str)         -- URL decode a string
    mg.base64_encode(str)      -- BASE64 encode a string
    mg.base64_decode(str)      -- BASE64 decode a string
    mg.md5(str)                -- return the MD5 hash of a string
    mg.keep_alive(bool)        -- allow/forbid to use http keep-alive for this request
    mg.request_info            -- a table with the following request information
         .remote_addr          -- IP address of the client as string
         .remote_port          -- remote port number
         .server_port          -- server port number
         .request_method       -- HTTP method (e.g.: GET, POST)
         .http_version         -- HTTP protocol version (e.g.: 1.1)
         .uri                  -- resource name
         .query_string         -- query string if present, nil otherwise
         .script_name          -- name of the Lua script
         .https                -- true if accessed by https://, false otherwise
         .remote_user          -- user name if authenticated, nil otherwise

connect (function):

    -- Connect to the remote TCP server. This function is an implementation
    -- of simple socket interface. It returns a socket object with three
    -- methods: send, recv, close, which are synchronous (blocking).
    -- connect() throws an exception on connection error.
    connect(host, port, use_ssl)

    -- Example of using connect() interface:
    local host = 'code.google.com'  -- IP address or domain name
    local ok, sock = pcall(connect, host, 80, 1)
    if ok then
      sock:send('GET /p/civetweb/ HTTP/1.0\r\n' ..
                'Host: ' .. host .. '\r\n\r\n')
      local reply = sock:recv()
      sock:close()
      -- reply now contains the web page https://code.google.com/p/civetweb
    end


**IMPORTANT: Civetweb does not send HTTP headers for Lua pages. Therefore,
every Lua Page must begin with a HTTP reply line and headers**, like this:

    <? print('HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n') ?>
    <html><body>
      ... the rest of the web page ...

To serve a Lua Page, civetweb creates a Lua context. That context is used for
all Lua blocks within the page. That means, all Lua blocks on the same page
share the same context. If one block defines a variable, for example, that
variable is visible in all block that follow.

## Websockets for Lua
Civetweb offers support for websockets in Lua as well. In contrast to plain
Lua scripts and Lua server pages, Lua websocket scripts are shared by all clients.

Lua websocket scripts must define a few functions:
    open(arg)    -- callback to accept or reject a connection
    ready(arg)   -- called after a connection has been established
    data(arg)    -- called when the server receives data from the client
    close(arg)   -- called when a websocket connection is closed
All function are called with one argument of type table with at least one field
"client" to identify the client. When "open" is called, the argument table additionally
contains the "request_info" table as defined above. For the "data" handler, an
additional field "data" is available. The functions "open", "ready" and "data"
must return true in order to keep the connetion open.

Lua websocket pages do support single shot (timeout) and interval timers.

An example is shown in
[websocket.lua](https://github.com/bel2125/civetweb/blob/master/test/websocket.lua).


# Common Problems
- PHP doesn't work - getting empty page, or 'File not found' error. The
  reason for that is wrong paths to the interpreter. Remember that with PHP,
  the correct interpreter is `php-cgi.exe` (`php-cgi` on UNIX).
  Solution: specify the full path to the PHP interpreter, e.g.:
    `civetweb -cgi_interpreter /full/path/to/php-cgi`

- Civetweb fails to start. If Civetweb exits immediately when started, this
  usually indicates a syntax error in the configuration file
  (named `civetweb.conf` by default) or the command-line arguments.
  Syntax checking is omitted from Civetweb to keep its size low. However,
  the Manual should be of help. Note: the syntax changes from time to time,
  so updating the config file might be necessary after executable update.

- Embedding with OpenSSL on Windows might fail because of calling convention.
  To force Civetweb to use `__stdcall` convention, add `/Gz` compilation
  flag in Visual Studio compiler.

