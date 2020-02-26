# Usage

```bash
Usage: tinyweb [-h] [-v] [[directory] port]
        -h: print this help message
        -v: verbose mode

Configuration variables:
- TINYWEB_DIR: home directory [.]
- TINYWEB_PORT: listening port [9999]
- TINYWEB_CMD: external scripts command []
- TINYWEB_CAT: external cat command [cat]
- TINYWEB_AUTH: Basic authent for PUT and DELETE
- TINYWEB_DEBUG: unable debug mode
```

* Default directory is ```.```.
* Default port is ```9999```.

> Remark concerning Windows version

Default scripts engine on Windows is **CMD.EXE**. It accepts **.BAT** files only.  
To run dynamic scripts on Windows, the easiest is to run **tinyweb** into a Unix-like environment such as [busybox](https://frippery.org/busybox/).  
Then it is necessary to tell **tinyweb** about the new default engine by setting the variable **TINYWEB_CMD** to **busybox bash**:

    busybox.exe bash -c "export TINYWEB_CMD='busybox bash' ; tinyweb.exe"
