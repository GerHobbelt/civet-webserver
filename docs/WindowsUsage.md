# Windows installation, and typical usage on Windows platform

## Installing and configuring CivetWeb on Windows 

Sections: <wiki:toc max_depth== >

*Note: Please put your comments in the proper Wiki. Problems must
be posted at [http://code.google.com/p/civetweb/issues/list Bugs],
comments involving Linux, etc., should go in the proper Wiki.*

### Important instructions for installing version 2.9 as a Windows Service

{{{
WARNING!

Installing and uninstalling civetweb may destroy important  files,
even if they have nothing directly to  do  with  civetweb.  Follow
these instructions carefully to avoid data loss.

Assume that "root" is your server root directory, containing files
such as CGI interpreters, their configuration files, any files  to
be served by civetweb in the root  directory  "/",  documentation,
log files, etc. Your actual file  layout  may  be  different  from
this, but let's  just  assume  this  layout  for  simplicity.  The
important point here is that we don't want to lose  any  of  these
files.

When installing a new version of civetweb, it is a  good  idea  to
uninstall the previous version, especially if it was running as  a
Windows Service. When doing this, be sure to  save  any  important
files, such as the civetweb configuration file.

To install civetweb:

1. Create an empty root\civetweb folder. NEVER keep any useful
	files in folder "civetweb" other than as instructed here.
2. Copy civetweb-2.9.install.exe into "civetweb".
3. Run civetweb-2.9.install.exe to install civetweb into that
	folder. Be very careful not to install civetweb into "root",
	only "civetweb".
4. After installation, copy your real civetweb.conf from "root"
	into "civetweb", overwriting the sample civetweb.conf file
	that was part of the installation.
5. Restart service "civetweb-2.9". You can do that with system
	program 'services.msc' or just a 'restart.cmd' file
	containing these lines:

@echo off
Net stop "CivetWeb 2.9"
Net start "CivetWeb 2.9"

6. If your civetweb.conf file is correct, civetweb is now
	running and ready to serve Web requests. Caution: civetweb
	does not detect most errors in civetweb.conf (it may exit
	silently), so some experimentation may be necessary.


To uninstall civetweb:

1. Copy civetweb.conf and anything else important back to "root" folder.
2. Run root\civetweb\uninstall.exe.
3. Note: the entire civetweb subfolder will be deleted!
}}}

### Installing and configuring CivetWeb on Windows in general 

To install CivetWeb on Windows, download and run the CivetWeb [http://code.google.com/p/civetweb/downloads/list installer]. By default, the installer tries to setup CivetWeb as [http://en.wikipedia.org/wiki/Windows_service Windows service] to start automatically when Windows starts. Administrator privileges are required for that. Alternatively, this can be disabled by unchecking appropriate checkbox on the installer's first page. In this case, CivetWeb can be started as Windows console application.

After CivetWeb is installed, you can start your browser and type in the address http://127.0.0.1 . This is the address of your own machine. You must see the content of disk C:.

An installer creates shortcuts in the Start menu, most important ones are "Edit config",  "Start service" and "Stop service". These are needed when you want to change the default configuration. "Edit config" starts up an editor, where you can tweak any option. Most important options are:
   *  *root* - where your HTML files live. By default, it is set to "C:\", change it to the directory you want.
   *  *cgi_interp* - this must be a full path to the CGI interpreter program. If you use Perl for your CGI files, or PHP, or anything else - please put the full path to `perl.exe`, or `php-cgi.exe`, or whatever you are using as CGI interpreter. <font color=" red">*PHP NOTE!*</font> For PHP 5.x and older, the correct CGI interpreter is `php-cgi.exe`, not `php.exe`.

In the configuration file, all blank lines and lines that begin with '#' symbol, are ignored. The rest of the lines must start with valid option name, followed by any number of whitespace characters, followed by an option value. If the configuration option is not set, the default value is used. All valid option names, with their default values, are described in CivetWebManual, in the OPTIONS section. 

Any time you change the configuration by changing option values, saving and closing the config file, CivetWeb must be restarted to re-read the changes. This can be done by stopping the service, and starting it again, via the Start menu shortcuts.

If you have Windows firewall running, it may block web connections to your machine. This means that while you can access your web pages from the machine that runs CivetWeb, you may not access them from other computers. To allow web connections to the machine, go to the control panel, windows firewall, add exception, add port, TCP port 80 and TCP port 443.

## Advanced usage

   * Installing CivetWeb is not necessary for make it work. `civetweb.exe` is self-sufficient executable file. Installation procedure does not copy any DLLs or write into registry; it merely unpacks files into a directory and registers a Windows service. If you wish to share some files really quickly, just copy `civetweb.exe` into the directory you wish to share, and double-click it. This will run CivetWeb in console mode, on port 8080. Point your browser to http://your_machine:8080 to see shared files. 
   * Setting *cgi_interp* option is not the only way of running CGI scripts. You can leave this option unset. In this case, the first line of your CGI script must be `#!c:\full\path\to\cgi_interpreter`. This allows to run CGI scripts with different CGI interpreters, for example, Perl, PHP, at the same time.
   * It is possible to restrict access to the web server to certain machines only. To do that, set *acl* option this way: `acl -0.0.0.0/0,+machine1,+machine2`, where `machine1`, `machine2` are IP addresses of the machines allowed to connect.
   * It is possible to protect certain folders with password. To do that, you have to create passwords file in that folder. Start command prompt, run following commands:
{{{
c:\civetweb-2.1\civetweb.exe -A c:\folder\to\protect\.htpasswd mydomain.com user1 password1
c:\civetweb-2.1\civetweb.exe -A c:\folder\to\protect\.htpasswd mydomain.com user2 password2
...
}}}
   * Sometimes it is needed to protect all folders with same passwords file, so for any request authentication will be required. This is done by creating a single passwords file, and setting *auth_gpass* option. Run "Edit config", set "auth_gpass C:\global_passwords.txt", save and exit. Stop and start CivetWeb service. Start command prompt, run following commands:
{{{
c:\civetweb-2.1\civetweb.exe -A C:\global_passwords.txt mydomain.com user1 password1
c:\civetweb-2.1\civetweb.exe -A C:\global_passwords.txt mydomain.com user2 password2
...
}}}

## How To Set Up PHP

One of the great things about the CivetWeb server is that it is
easy to set up the server-side language *PHP* for use either
locally (at IP address `127.0.0.1`, which is usually named
`localhost` in the local DNS file `HOSTS`), as a LAN subnet
Intranet server, or as a WAN (external Internet) Webserver. (Note:
CivetWeb is probably not suitable for use as a high-volume
Webserver such as Apache or IIS. One reason is that it runs PHP as
a CGI interpreter, which means that it reloads the PHP executable
to serve each PHP page. Of course, this overhead is no problem for
local server-based applications.)

You can write an entire multimedia and/or database application in
PHP, then run it on any computer under Linux or Windows, or run it
from removable media such as CDs, DVDs, and USB Flash Drives.

Here are some basic instructions on how to set up PHP under
CivetWeb on current versions of Windows (some modifications would
be needed for Linux):

 * Choose a folder to be your server root and home to CivetWeb and PHP.

 * Either install CivetWeb as a Service (recommended) or run civetweb.exe.

 * Download any recent version of the PHP binaries for Windows from http://PHP.net. You need the basic PHP executable files php5.dll and php-cgi.exe; copy them to your root folder. If you want to use a database, copy its PHP extension file, such as php_sqlite3.dll (which I recommend for its small size and high speed), to your root folder as well.

 * Create the text file `php.ini` from the default php.ini distributed with the PHP Windows binaries. Consider making the following changes:

{{{
short_open_tag = On (to use "<? ?>" instead of "<?php ?>")
max_execution_time = 15
max_input_time = 10
memory_limit = 16M
display_errors = On (turn Off after debugging)
display_startup_errors = On (turn Off after debugging)
log_errors = Off
html_errors = Off
magic_quotes_gpc = Off
extension_dir = "C:\root" (change to your root path)
;extension=php_sqlite3.dll (put extension DLLs in your root)
;extension=php_mysql.dll
date.timezone=US/Eastern (Change to your time zone)
   (You can find a list of time zone names in the following PHP program:
  http://bluequartz.org/svn/5100R/tags/raq550_OSS_1_0/ui/palette/libPhp/uifc/TimeZone.php)
}}}

 * Create the text file `civetweb.conf` containing your desired server settings. For PHP, be sure to include:

{{{
(Warning--2.8 syntax)
cgi_interp      php-cgi.exe
cgi_ext         php
}}}

 * For testing and debugging, create the text file `info.php` containing:

{{{
<?php
phpinfo();
?>

(Note that the function call "phpinfo()" generates all the needed
HTML for the information page it generates, so nothing else should
go in "info.php".)
}}}

 * Don't forget to create a default file such as `index.html` or `index.php`, an error handling file such as `error.php`, and a home icon file `favicon.ico` for your server.
