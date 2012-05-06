#!/usr/bin/lua5.1

-- Every CGI script that returns any valid JSON object will work in the test.
-- In case you do not have not yet used CGI, you may want to use this script which is written in Lua.
-- You may download an interpreter from http://luabinaries.sourceforge.net/download.html, extract it
-- to some folder in your search path (the path of the webserver or /usr/bin on Linux), and add the
-- line   I lua5.1.exe   to your .conf file.



resp = "{";

method = os.getenv("REQUEST_METHOD")
uri = os.getenv("REQUEST_URI");
query = os.getenv("QUERY_STRING");
len = os.getenv("CONTENT_LENGTH");

if method then
  resp = resp .. '"method" : "' .. method .. '", ';
end
if uri then
  resp = resp .. '"uri" : "' .. uri .. '", ';
end
if query then
  resp = resp .. '"query" : "' .. query .. '", ';
end
if len then
  resp = resp .. '"len" : "' .. len .. '", ';
end

resp = resp .. '"time" : "' .. os.date() .. '" ';

resp = resp .. "}";



print "Connection: close"
--print "Connection: keep-alive"

print "Status: 200 OK"
print "Content-Type: text/html; charset=utf-8"
print "Cache-Control: no-cache"
--print ("Content-Length: " .. resp:len())
print ""

print (resp)


-- Store the POST data to a file
if (method == "POST") then  
  myFile = io.open("data" .. query:sub(4) .. ".txt", "wb");  
  myFile:write(resp)
  myFile:write("\r\n\r\n")
  data = io.read(len)
  myFile:write(data)
  myFile:close()
end


