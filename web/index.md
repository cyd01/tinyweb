
# Tinyweb

## Origins

Tinyweb came from [https://github.com/shenfeng/tiny-web-server](https://github.com/shenfeng/tiny-web-server "tinyweb server") repository.

## How to compile

### Cygwin

```bash
gcc -o tinyweb tinyweb.c
```

### Linux

```bash
gcc -o tinyweb tinyweb.c -DSENDFILE_H
```
