# How to compile

## Cygwin

```bash
gcc -o tinyweb tinyweb.c -DNO_SENDFILE
```

## MinGW32

```bash
gcc -o tinyweb tinyweb.c -DNO_SENDFILE -DWIN32 -lwsock32 /c/windows/system32/kernel32.dll
```

## Linux

```bash
gcc -o tinyweb tinyweb.c
```
