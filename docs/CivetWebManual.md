# Describes all configurable options

<pre>
civetweb(1)               BSD General Commands Manual              civetweb(1)

NAME
     civetweb -- lightweight web server

SYNOPSIS
     civetweb [config_file] [OPTIONS]
     civetweb -A htpasswd_file domain_name user_name password

DESCRIPTION
     civetweb is small, fast and easy to use web server with CGI, SSL, MD5
     authorization, and basic SSI support.

     civetweb does not detach from terminal, and uses current working direc-
     tory as the web root, unless -r option is specified.  It is possible to
     specify multiple ports to listen on. For example, to make civetweb listen
     on HTTP port 80 and HTTPS port 443, one should start it as: civetweb -s
     cert.pem -p 80,443s

     Unlike other web servers, civetweb does not require CGI scripts be put in
     a special directory. CGI scripts can be anywhere. CGI (and SSI) files are
     recognized by the file name pattern.  civetweb uses shell-like glob pat-
     terns with the following syntax:
     **      Matches everything
     *       Matches everything but slash character, '/'
     ?       Matches any character
     $       Matches the end of the string
     |       Matches if pattern on the left side or the right side matches.
             Pattern on the left side is matched first
     All other characters in the pattern match themselves.

     If no arguments are given, civetweb searches for a configuration file
     called "civetweb.conf" in the same directory where civetweb binary is
     located. Alternatively, a file name could be specified in the command
     line. Format of the configuration file is the same as for the command
     line options except that each option must be specified on a separate
     line, leading dashes for option names must be omitted.  Lines beginning
     with '#' and empty lines are ignored.

OPTIONS
     -A htpasswd_file domain_name user_name password
             Add/edit user's password in the passwords file. Deleting users
             can be done with any text editor. Functionality is similar to
             Apache's htdigest utility.

     -C cgi_pattern
             All files that fully match cgi_pattern are treated as CGI.
             Default pattern allows CGI files be anywhere. To restrict CGIs to
             certain directory, use e.g. "-C /cgi-bin/**.cgi".  Default:
             "**.cgi$|**.pl$|**.php$"

     -E cgi_environment
             Extra environment variables to be passed to the CGI script in
             addition to standard ones. The list must be comma-separated list
             of X=Y pairs, like this: "VARIABLE1=VALUE1,VARIABLE2=VALUE2".
             Default: ""

     -G put_delete_passwords_file
             PUT and DELETE passwords file. This must be specified if PUT or
             DELETE methods are used. Default: ""

     -I cgi_interpreter
             Use cgi_interpreter as a CGI interpreter for all CGI scripts
             regardless script extension.  CivetWeb decides which interpreter
             to use by looking at the first line of a CGI script.  Default:
             "".

     -M max_request_size
             Maximum HTTP request size in bytes. Default: "16384"

     -P protect_uri
             Comma separated list of URI=PATH pairs, specifying that given
             URIs must be protected with respected password files. Default: ""

     -R authentication_domain
             Authorization realm. Default: "mydomain.com"

     -S ssi_pattern
             All files that fully match ssi_pattern are treated as SSI.
             Unknown SSI directives are silently ignored. Currently, two SSI
             directives are supported, "include" and "exec".  Default:
             "**.shtml$|**.shtm$"

     -a access_log_file
             Access log file. Default: "", no logging is done.

     -d enable_directory_listing
             Enable/disable directory listing. Default: "yes"

     -e error_log_file
             Error log file. Default: "", no errors are logged.

     -g global_passwords_file
             Location of a global passwords file. If set, per-directory
             .htpasswd files are ignored, and all requests must be authorised
             against that file.  Default: ""

     -i index_files
             Comma-separated list of files to be treated as directory index
             files.  Default: "index.html,index.htm,index.cgi"

     -l access_control_list
             Specify access control list (ACL). ACL is a comma separated list
             of IP subnets, each subnet is prepended by '-' or '+' sign. Plus
             means allow, minus means deny. If subnet mask is omitted, like
             "-1.2.3.4", then it means single IP address. Mask may vary from 0
             to 32 inclusive. On each request, full list is traversed, and
             last match wins. Default setting is to allow all. For example, to
             allow only 192.168/16 subnet to connect, run "civetweb
             -0.0.0.0/0,+192.168/16".  Default: ""

     -m extra_mime_types
             Extra mime types to recognize, in form "extension1=type1,exten-
             sion2=type2,...". Extension must include dot.  Example: "civetweb
             -m .cpp=plain/text,.java=plain/text". Default: ""

     -p listening_ports
             Comma-separated list of ports to listen on. If the port is SSL, a
             letter 's' must be appeneded, for example, "-p 80,443s" will open
             port 80 and port 443, and connections on port 443 will be SSL-ed.
             It is possible to specify an IP address to bind to. In this case,
             an IP address and a colon must be prepended to the port number.
             For example, to bind to a loopback interface on port 80 and to
             all interfaces on HTTPS port 443, use "civetweb -p
             127.0.0.1:80,443s". Default: "8080"

     -r document_root
             Location of the WWW root directory. Default: "."

     -s ssl_certificate
             Location of SSL certificate file. Default: ""

     -t num_threads
             Number of worker threads to start. Default: "10"

     -u run_as_user
             Switch to given user's credentials after startup. Default: ""

     -w url_rewrite_patterns
             Comma-separated list of URL rewrites in the form of "pattern=sub-
             stitution,..." If the "pattern" matches some prefix of the
             requested URL, then matched prefix gets substituted with "substi-
             tution".  For example, "-w /config=/etc,**.doc|**.rtf=/cgi-
             bin/handle_doc.cgi" will serve all URLs that start with "/config"
             from the "/etc" directory, and call handle_doc.cgi script for
             .doc and .rtf file requests. If some pattern matches, no further
             matching/substitution is performed (first matching pattern wins).
             Default: ""

EMBEDDING
     civetweb was designed to be embeddable into C/C++ applications. Since the
     source code is contained in single C file, it is fairly easy to embed it
     and follow the updates. Please refer to http://code.google.com/p/civetweb
     for details.

EXAMPLES
     civetweb -r /var/www -s /etc/cert.pem -p 8080,8043s
             Start serving files from /var/www. Listen on port 8080 for HTTP,
             and 8043 for HTTPS connections.  Use /etc/cert.pem as SSL cer-
             tificate file.

     civetweb -l -0.0.0.0/0,+10.0.0.0/8,+1.2.3.4
             Deny connections from everywhere, allow only IP address 1.2.3.4
             and all IP addresses from 10.0.0.0/8 subnet to connect.

     civetweb -w **=/my/script.cgi
             Invoke /my/script.cgi for every incoming request, regardless of
             the URL.

COPYRIGHT
     civetweb is licensed under the terms of the MIT license.

AUTHOR
     Sergey Lyubka <valenok@gmail.com>.

                                 Mar 10, 2012
</pre>