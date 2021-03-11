# Phase-Deploy

This is a list of common problems encountered when configuring Mongoose 

## Introduction 

Once Mongoose has been successfully installed (very simple if you choose the Standalone executable, more complicated if you choose the Windows Service version), all pages will be served successfully, some pages will be served, no pages will be served, or Mongoose may just exit immediately (2.9) with a strange error message.

This document will eventually list all the problems that users find, with solutions.

## Common errors 

  * *Mongoose fails to start:* If Mongoose exits immediately when run, this usually indicates a syntax error in the configuration file (named `mongoose.conf` by default) or the command-line arguments. Syntax checking is omitted from Mongoose to keep its size low. However, the Manual should be of help. Note: the syntax changed dramatically between releases 2.8 and 2.9. Rewriting configuration directives will be necessary; you cannot use 2.8 directives with the 2.9 executable file.

  * *No input file specified:* A Web page containing only "No input file specified." is possible when Mongoose calls the PHP interpreter to preprocess the page. It means that PHP has failed to find a file. This normally can't happen, since Mongoose looks for the file first and reports file not found (404) without calling the interpreter if Mongoose cannot find the file. However, if you include a `doc_root` directive in `PHP.ini`, telling the interpreter a specific directory for files, you will most likely get this message. The fix is to comment out the directive.