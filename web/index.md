# Tinyweb
<div style="text-align: center;"><iframe src="gad.html" frameborder="0" scrolling="no" style="border: 1px solid gray; padding: 0; overflow:hidden; scrolling: no; top:0; left: 0; width: 100%;" onload="this.style.height=(this.contentWindow.document.body.scrollHeight+5)+'px';"></iframe></div>

## Origins

Tinyweb came from [https://github.com/shenfeng/tiny-web-server](https://github.com/shenfeng/tiny-web-server "original tinyweb server") repository.

And the current repository is: [https://github.com/cyd01/tinyweb](https://github.com/cyd01/tinyweb "The new tinyweb server")

## Contents

Tinyweb is a very light HTTP web server written in C.
Here are the original features:

* Basic MIME mapping
* Very basic directory listing
* Low resource usage
* sendfile(2)
* Support Accept-Ranges: bytes (for in browser MP4 playing)
* concurrency by pre-fork

And the new features recently added:

* Default index file
* 302 redirect for directory
* Expect: 100-continue
* DELETE, GET, HEAD, POST and PUT methods
* Basic Auth for PUT and DELETE method
* Light virtual host feature
* Very light dynamic script integration (scripts are *.sh)
* Docker image (https://hub.docker.com/r/cyd01/tinyweb/)
