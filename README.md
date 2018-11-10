
# Tinyweb

## Origins

Tinyweb came from [https://github.com/shenfeng/tiny-web-server](https://github.com/shenfeng/tiny-web-server "tinyweb server") repository.

## Contents

Tinyweb is a very light HTTP web server written in C.
Here are the original features:

* Basic MIME mapping
* Very basic directory listing
* Low resource usage
* sendfile(2)
* Support Accept-Ranges: bytes (for in browser MP4 playing)
* concurrency by pre-fork

And the new features recentrly added:

* Default index file
* 302 redirect for directory
* DELETE, GET, HEAD and PUT methods
* Very light dynamic script integration (scripts are *.sh)
* Dockerfile

## How to compile

### Cygwin

```bash
gcc -o tinyweb tinyweb.c
```

### Linux

```bash
gcc -o tinyweb tinyweb.c -DSENDFILE_H
```
