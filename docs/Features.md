# Descriptions of CivetWeb Features

Below you will find a description of several of the features included in the CivetWeb web server.  Along with the description, most also contain a simple usage of the feature being described.<br/>

## Table of Contents

### SSI Support

*Server Side Includes* (SSI) is a simple interpreted server-side scripting language which is most commonly used to include the contents of a file into a web page. It can be useful when it is desirable to include a common piece of code throughout a website.

Some of the ways in which Sever Side Includes may be used include:
  * Including the contents of a file (html, txt, etc) into a web page
  * Include the result of running a CGI script
  * Executing a program, script, or shell command on the server

In order for a webpage to recognize an SSI-enabled HTML file, the filename should end with a special extension.  As stated in the CivetWeb manual, the default for the CivetWeb web server is either *shtml* or *shtm*. 

CivetWeb supports two SSI directives, "*_include_*" and "*_exec_*". The "include" directive may be used to include the contents of a file or the result of running a CGI script. When using "*_include_*", you must use either the "*_virtual_*" or "*_file_*" variable when specifying the path to the file or script. The "*_virtual_*" variable specifies the target relative to the web root.  The "*_file_*" variable specifies the target relative to the directory of the current file. Two examples of including a file called "test.c", located in a sub-directory (test) of the web root:

{{{
<!--#include file="test.c" -->

<!--#include virtual="test/test.c" -->
}}}

The second directive supported, "*_exec_*", is used to execute a program, script, or shell command on the server. An example of executing the "*ls* *-l*" command:

{{{
<!--#exec "ls -l" -->
}}}

For more information on Server Side Includes, take a look at the Wikipedia entry: [http://en.wikipedia.org/wiki/Server_Side_Includes Server Side Includes - Wikipedia]

----

### ACL Support

*An Access Control List* (ACL) allows restrictions to be put on the list of IP addresses which have access to the web server. In the case of the CivetWeb web server, the ACL is a comma separated list of IP subnets, where each subnet is prepended by either a ‘-’ or a ‘+’ sign. A plus sign means allow, where a minus sign means deny. If a subnet mask is omitted, such as “-1.2.3.4”, this means to deny only that single IP address.

Subnet masks may vary from 0 to 32, inclusive. The default setting is to allow all, and on each request the full list is traversed - where the last match wins.

The ACL can be specified either at runtime, using the *-l* option, or by using “*l*" in the config file. For example, to allow only the *192.168.0.0/16* subnet to connect, you would run the following command:

{{{
./civetweb -l -0.0.0.0/0,+192.168.0.0/16
}}}

The ACL can also be set in the web server config file.  Using the example above, the config file line would be:

{{{
l	-0.0.0.0/0,+192.168.0.0/16
}}}

To learn more about subnet masks, see the [http://en.wikipedia.org/wiki/Subnetwork Wikipedia page on Subnetwork ], or [http://wiki.xtronics.com/index.php/IP_Subnet_Masks IP Subnet Masks by Transtronics].

----

### Alias Support

Similar to Apache’s mod_alias, using aliases allows a mapping to be created between URLs and file system paths. This mapping allows content which is not under the web server Document Root to be served as part of the web document tree. In other words, URLs beginning with the url-path will be mapped to local files beginning with the directory-path.

In the CivetWeb web server, this can be done two ways:

  * Aliases can be set at runtime by using the -w option to specify url_rewrite_patterns
  * Aliases can be set in the config file

In the following examples, suppose we wanted to map our local video directory (*/home/user/Videos*) to the URL "*/videos*", and we wanted to map our pictures directory (*/home/user/Pictures*) to the URL "*/pictures*".

Using the first option (setting the aliases at runtime), would look similar to the following.  

{{{
./civetweb -w /videos=/home/user/Videos,/pictures=/home/user/Pictures
}}}

To test if the newly set-up aliases are working correctly, point your web browser to one of the two URLs, where you should see a directory listing of the local files.

{{{
http://<your-web-server-address>/pictures
http://<your-web-server-address>/videos
}}}

If this doesn’t work, double check that your paths are correct in your alias definitions and that everything is spelled correctly. Aliases should be able to be created for any drive physically attached to your computer.

----

### CGI Support

Using *CGI* (Common Gateway Interface), a web server can communicate with other types of programs running on the server. Because the CivetWeb web server by itself is only able to deal with HTML files, it can “pass off” scripts written in other languages to their specific interpreter, thus allowing the functionality of many CGI languages to be used. Some of the possible languages include: PHP, Perl, ASP, ASP.NET, Python, Ruby on Rails, and C.

To configure CivetWeb to process CGI scripts in a given language, the interpreter for that language must be installed on the server. As an example, we’ll walk through how you would enable PHP to be used with the CivetWeb web server.

The first thing you need to do is download and install PHP if it is not currently installed on your server. The PHP source can be downloaded from the following location: [http://www.php.net/downloads.php]. To build and install PHP with the Autoconf system, run the following commands:

{{{
./configure
make
sudo make install
}}}

On OS X, for example, this will place the “*php-cgi*" program in the "*/usr/local/bin*" directory. Steps will be similar for other operating systems. Now that the PHP CGI interpreter is installed, let CivetWeb know where it is located. This can be done in two ways (as most options can) and be set at runtime using the -I option, or by adding a similar line to the configuration file. The -C option can also be set, which defines which extensions are treated as CGI scripts. Setting these option at runtime, CivetWeb would be started as follows:

{{{
./civetweb -C cgi,php -I /usr/local/bin/php-cgi
}}}

After starting the web server, you can test if PHP is working by browsing to any PHP file which is located under your web server root directory.

----

### Directory Listing

Directory listing can be enabled or disabled in the CivetWeb Web Server either at runtime using the *-d* option, or through the config file using the "*d*" variable.  By default, directory listing is turned on. Examples of turning off directory listing are shown below:

{{{
./civetweb -d no      [ Runtime ]
d    no               [ Config File ]
}}}

If directory listing is turned off and a user attempts to view a directory, they will see a message similar to the following:

{{{
Error 403: Directory Listing Denied
Directory listing denied
}}}

----

### Default Index File List

The user may set the list of default index files for the CivetWeb Web Server using the “*-i*" option at runtime or the “*i*" variable in the config file. To set the list of default index files at runtime, start the web server similar to the following:

{{{
./civetweb -i index.html,index.htm,index.php,index.cgi
}}}

To set the list from the config file, use a line similar to the one below.

{{{
i    index.html,index.htm,index.php,index.cgi
}}}

Since it is possible to define a list of default index pages, the CivetWeb Web Server will use the first default file that it finds in the list that exists in the web directory as the index page it shows to the user.  

Using the above lists as an example, if there is both an index.html and index.htm file in the root of the web server, index.html will be used because it comes first in the default file list and therefore has a higher priority than index.htm.

----

### Securing URIs and Directories

CivetWeb allows you to secure URIs and directories under your server web root. This is beneficial when you desire to protect specific directories and limit access to specific users.

#### Setting the Authentication Domain

The authentication domain is the area of a website which will be secured. This is the first thing that needs to be done, and can be set using the *-R* (or *authentication_domain*) option at runtime or in the config file. For example, the following sets the authentication domain to “localhost”:

Set at runtime:
{{{
./civetweb -R localhost
}}}

Set in the config file:
{{{
authentication_domain    localhost
}}}

#### Creating the .htpasswd File

The second thing that needs to be done is that a *.htpasswd* file needs to be created to hold the username and password of the users who will be allowed to enter the restricted URI or directory. To create a .htpasswd file, the civetweb application may be used with the *-A* option. The *-A* option allows usernames and passwords to be added or modified within a given .htpasswd file. Deleting users can be done through a normal text editor and functionality is similar to that of Apache’s htdigest utility. To create a .htpasswd file in the root directory of the web server with the username “admin” and the password “pass”, execute the following command from the web root.

{{{
 ./civetweb -A ./.htpasswd localhost admin pass
}}}

This will create the corresponding .htpasswd file in the root directory of the web server.  

#### Protecting Specific URIs or Directories

Now that an authentication domain has been defined and a .htpasswd file has been created, use the *-P* (or *protect_uri*) option at runtime or in the config file to specify which directories and URIs are to be protected. This option is a comma separated list of *URI=path* pairs specifying that the given URI must be protected with the associated password file.

To protect a directory called *secure_area*, the following command would be used:

Set at runtime:
{{{
./civetweb -P /secure_area=./.htpasswd
}}}

Set in the config file:
{{{
protect_uri    /secure_area=./.htpasswd
}}}

#### Setting the Global Passwords File

It’s possible to set a global passwords file in the CivetWeb web server.  If this is set, all per-directory .htpasswd files will be ignored and all requests will be authorized through this global .htpasswd file.  To set this, use the *-g* (or *global_passwords_file*) option at runtime or in the config file:

Set at runtime:

{{{
./civetweb -g ./.htpasswd
}}}

Set in the config file:

{{{
global_passwords_file    ./.htpasswd
}}}
