# Full Web application example

*<font color="red">Draft document, work in progress</font>*

## Introduction 

Generally, there are three ways of writing web apps:
   * Generating HTML pages on the server side: write static HTML and implant a logic directly in the HTML markup.  Technologies like PHP or ASP are doing that. For example, PHP web page is an HTML with <?php > elements embedded inside. When a web page is requested, web server replaces the content of <?php> with the result of execution of that content by the PHP interpreter.
   * Generating HTML pages on the server side entirely programmatically. CGI programs and embedded web servers doing that.
   * Generating HTML pages on the client side dynamically by Javascript and using Ajax to get data from the server.

I believe the third way is most clean, efficient and effective because it allows to keep business logic entirely decoupled from the GUI. Business logic and GUI thus could be tested, deployed and updated separately.

I will fully explain the application architecture and an implementation of simple using CivetWeb web server.

## Application architecture 

### Web app with no authentication 

If web application does not require users to authenticate, the architecture may look like this:  http://docs.google.com/drawings/pub?id=1Ougc6ppxd-0dMhJkIgV0Iws2JwUVtZktL_qHWZtlZeM&w=720&h=540&dummy=x.png

Event flow looks like this:
   # Browser loads HTML and Javascript files from the frontend
   # Javascript code when loaded starts to talk AJAX to the backend, constructing dynamic content

In this case, frontend and backend could be physically separated. For example, frontend can be at http://frontend.some-site.com in Sweden, and backend could be at http://backend.some-other-site.com in Ireland (in such case, JSONP AJAX calls should be implemented cause XMLHttp does not allow cross-domain calls).

### Web app with authentication 

If authentication is required, things become more complicated. Users should not be allowed to get static content unless they are authenticated. Simplistic frontend would not work, because it will always give back requested files if user knows the URL. Therefore, frontend must be able to check whether user is authenticated. If user is authenticated, then frontend gives back whatever is requested. If not, then it asks user to authenticate by redirecting to the login server. 

http://docs.google.com/drawings/pub?id=1r9Qia49ND54SHaCa7xmRkNJAXQUu3YZRYR8IklpQDHQ&w=720&h=540&dummy=pic.png

Usual solution is using authentication cookies:
    # Browser requests http://frontend/index.html
    # Web server checks whether certain cookie is set
    # If cookie is set, request is served
    # If cookie is not set, redirection is sent back to http://login
    # Web page on http://login asks for username and pass
    # User submits username and pass
    # Login server checks them, sets the authentication cookie and redirects back to http://frontend/index.html
    # Browser re-requests index.html - going back to step 2, but the cookie is set now
    # All subsequent queries to http://frontend will have authentication cookie set and will be served
    # When static content is loaded, Javascript code starts to make AJAX requests to the backend
    # The backend does the same authentication checks

In this scenario, frontend must be configurable to make a redirect based on cookie. Modern web servers are able to do that, for example Apache with mod_rewrite functionality. So, all three components can be separated: frontend can live in New Zealand, login service provided by a third party company in Switzerland, and backend can be in Austria. 

### Web app with authentication, our example 

For the sake of simplicity, in my example I combine all three servers -- frontend, backend and login -- into one, CivetWeb based. To make clear logical distinction between the components, static content will live at URLs that start with `/static/` prefix, backend requests will have `/ajax/` prefix, and authentication requests will start with `/auth` prefix. And here's the diagram:

http://docs.google.com/drawings/pub?id=1nDBp_V5U953yZzOHLvMwcnXSYIbUQJrnS80dqbHn4Po&w=720&h=560&pic=x.png

## Our example: chat server 

We build very simple chat server, where users can login, send messages and see messages from the other users. It will be single common chat room. 

To run an example, [http://code.google.com/p/civetweb/source/checkout checkout CivetWeb code], go to the `examples/web_app` directory and run `make`.  Start your browser and point your browser at http://127.0.0.1:8080/

There is a live version running at [TODO]

The following sections discuss implementation details of each subsystem.

### Authentication 

### Administration panel 

### Chat interface 

## Conclusion 

