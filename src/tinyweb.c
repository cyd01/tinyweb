#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define random rand
#else
#include <arpa/inet.h>          /* inet_ntoa */
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

#ifndef NO_SENDFILE
#include <sys/sendfile.h>
#endif

#ifndef TCP_CORK
#define TCP_CORK 3
#endif

#define LISTENQ  1024  /* second argument to listen() */
#define MAXLINE 1024   /* max length of a line */
#define RIO_BUFSIZE 1024

typedef struct {
    int rio_fd;                 /* descriptor for this buf */
    int rio_cnt;                /* unread byte in this buf */
    char *rio_bufptr;           /* next unread byte in this buf */
    char rio_buf[RIO_BUFSIZE];  /* internal buffer */
} rio_t;

/* Simplifies calls to bind(), connect(), and accept() */
typedef struct sockaddr SA;

typedef struct {
    char method[10];
    char uri[512];
    char filename[512];
    off_t offset;              /* for support Range */
    size_t end;
    size_t length;
    char query[512];
    char auth[50];
    char type[50];
    char host[50];
    size_t bodylen;
    char body[MAXLINE];
} http_request;

typedef struct {
    const char *extension;
    const char *mime_type;
} mime_map;

mime_map meme_types [] = {
    {".htm", "text/html"},
    {".html", "text/html"},
    {".css", "text/css"},
    {".js", "text/javascript"},
    {".gif", "image/gif"},
    {".jpeg", "image/jpeg"},
    {".jpg", "image/jpeg"},
    {".png", "image/png"},
    {".ico", "image/x-icon"},
    {".svg", "image/svg+xml"},
    {".pdf", "application/pdf"},
    {".mp3", "audio/mpeg"},
    {".mp4", "video/mp4"},
    {".xml", "text/xml"},
    {".yaml", "text/x-yaml"},
    {".yml", "text/x-yaml"},
    {NULL, NULL},
};

//char *default_mime_type = "text/plain";
char *default_mime_type = "application/octet-stream";

char *default_index_file = "index.html";

char *server_software = "Tinyweb 1.0";

char tmp_dir[256]="." ;

int nb_forks = 10 ;

char *dynamic_shell = "" ;

void rio_readinitb(rio_t *rp, int fd){
    rp->rio_fd = fd;
    rp->rio_cnt = 0;
    rp->rio_bufptr = rp->rio_buf;
}

ssize_t writen(int fd, void *usrbuf, size_t n){
    size_t nleft = n;
    ssize_t nwritten;
    char *bufp = usrbuf;

    while (nleft > 0){
#ifdef WIN32
	if ((nwritten = send(fd, bufp, nleft, 0)) <= 0){
#else
        if ((nwritten = write(fd, bufp, nleft)) <= 0){
#endif
            if (errno == EINTR)  /* interrupted by sig handler return */
                nwritten = 0;    /* and call write() again */
            else
                return -1;       /* errorno set by write() */
        }
        nleft -= nwritten;
        bufp += nwritten;
    }
    return n;
}


/*
 * rio_read - This is a wrapper for the Unix read() function that
 *    transfers min(n, rio_cnt) bytes from an internal buffer to a user
 *    buffer, where n is the number of bytes requested by the user and
 *    rio_cnt is the number of unread bytes in the internal buffer. On
 *    entry, rio_read() refills the internal buffer via a call to
 *    read() if the internal buffer is empty.
 */
/* $begin rio_read */
static ssize_t rio_read(rio_t *rp, char *usrbuf, size_t n){
    int cnt;
    while (rp->rio_cnt <= 0){  /* refill if buf is empty */
#ifdef WIN32
	rp->rio_cnt = recv(rp->rio_fd, rp->rio_buf, sizeof(rp->rio_buf), 0);
#else
        rp->rio_cnt = read(rp->rio_fd, rp->rio_buf, sizeof(rp->rio_buf));
#endif	    
        if (rp->rio_cnt < 0) {
	    //if (errno == EBADF ) printf("Bad file descriptor !\n");
            if (errno != EINTR) /* interrupted by sig handler return */
                return -1;
        }
        else if (rp->rio_cnt == 0)  /* EOF */
            return 0;
        else {
            rp->rio_bufptr = rp->rio_buf; /* reset buffer ptr */
		//printf("==>%s<==\n",rp->rio_buf);
	}
    }

    /* Copy min(n, rp->rio_cnt) bytes from internal buf to user buf */
    cnt = n;
    if (rp->rio_cnt < n)
        cnt = rp->rio_cnt;
    memcpy(usrbuf, rp->rio_bufptr, cnt);
    rp->rio_bufptr += cnt;
    rp->rio_cnt -= cnt;
    return cnt;
}

/*
 * rio_readlineb - robustly read a text line (buffered)
 */
ssize_t rio_readlineb(rio_t *rp, void *usrbuf, size_t maxlen){
    int n, rc;
    char c, *bufp = usrbuf;

    for (n = 1; n < maxlen; n++){
        if ((rc = rio_read(rp, &c, 1)) == 1){
            *bufp++ = c;
            if (c == '\n')
                break;
        } else if (rc == 0){
            if (n == 1)
                return 0; /* EOF, no data read */
            else
                break;    /* EOF, some data was read */
        } else
            return -1;    /* error */
    }
    *bufp = 0;
    return n;
}

/* The  stristr()  function  finds the first occurrence of the substring needle in
   the string haystack, ignores  the  case  of  both arguments.*/
char* stristr( const char* str1, const char* str2 ) {
    const char* p1 = str1 ;
    const char* p2 = str2 ;
    const char* r = *p2 == 0 ? str1 : 0 ;

    while( *p1 != 0 && *p2 != 0 ) {
        if( tolower( (unsigned char)*p1 ) == tolower( (unsigned char)*p2 ) ) {
            if( r == 0 ) { r = p1 ; }
            p2++ ;
	} else {
	    p2 = str2 ;
            if( r != 0 ) { p1 = r + 1 ; }
	    if( tolower( (unsigned char)*p1 ) == tolower( (unsigned char)*p2 ) ) {
                r = p1 ;
                p2++ ;
	    } else { r = 0 ; }
	}
	p1++ ;
    }
    return *p2 == 0 ? (char*)r : 0 ;
}

void format_size(char* buf, struct stat *stat){
    if(S_ISDIR(stat->st_mode)){
        sprintf(buf, "%s", "[DIR]");
    } else {
        off_t size = stat->st_size;
        if(size < 1024){
            sprintf(buf, "%lu", size);
        } else if (size < 1024 * 1024){
            sprintf(buf, "%.1fK", (double)size / 1024);
        } else if (size < 1024 * 1024 * 1024){
            sprintf(buf, "%.1fM", (double)size / 1024 / 1024);
        } else {
            sprintf(buf, "%.1fG", (double)size / 1024 / 1024 / 1024);
        }
    }
}

#ifdef WIN32
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#define BUFSIZE MAX_PATH
DWORD GetFinalPathNameByHandleA(HANDLE hFile,LPSTR  lpszFilePath,DWORD  cchFilePath,DWORD  dwFlags);
int getfilename(HANDLE hFile, char* filename, int size) {
	return GetFinalPathNameByHandleA(hFile,filename,size,0) ;
}
DIR *fdopendir(int fd) {
	char filename[512];
	getfilename( (void*)_get_osfhandle(fd),filename,512);
	return opendir(filename);
}
int openat(int fd, const char *pathname, int flags) {
	char filename[512];
	getfilename( (void*)_get_osfhandle(fd),filename,512);
	if( (pathname[0]!='/') && (filename[strlen(filename)-1]!='/') ) { strcat(filename,"/"); }
	strcat( filename, pathname ) ;
	return open(filename,flags);
}
#endif

void handle_directory_redirect(int out_fd, char *filename, char *redirect) {
	char buf[MAXLINE];
	sprintf(buf, "HTTP/1.1 302 Found\r\nLocation: ");
	if( (filename[0]!='.')&&(filename[0]!='/') ) { strcat(buf,"/" ); }
	if( strcmp(filename,".") ) { strcat(buf, filename); }
	strcat(buf, redirect);
	strcat(buf, "\r\n\r\n");
	writen(out_fd, buf, strlen(buf));
}

void handle_directory_request(int out_fd, int dir_fd, char *filename){
    char buf[MAXLINE], m_time[32], size[16];
    struct stat statbuf;
    sprintf(buf, "HTTP/1.1 200 OK\r\n%s%s%s%s%s",
            "Content-Type: text/html\r\n\r\n",
            "<html><head><style>",
            "body{font-family: monospace; font-size: 13px;}",
            "td {padding: 1.5px 6px;}",
            "</style></head><body><table>\n");
    writen(out_fd, buf, strlen(buf));
    DIR *d = (DIR*)fdopendir(dir_fd);
    struct dirent *dp;
    int ffd;
    while ((dp = readdir(d)) != NULL){
        if(!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..")){
            continue;
        }
        if ((ffd = openat(dir_fd, dp->d_name, O_RDONLY)) == -1){
            perror(dp->d_name);
            continue;
        }
        fstat(ffd, &statbuf);
        strftime(m_time, sizeof(m_time),
                 "%Y-%m-%d %H:%M", localtime(&statbuf.st_mtime));
        format_size(size, &statbuf);
        if(S_ISREG(statbuf.st_mode) || S_ISDIR(statbuf.st_mode)){
            char *d = S_ISDIR(statbuf.st_mode) ? "/" : "";
            sprintf(buf, "<tr><td><a href=\"%s%s\">%s%s</a></td><td>%s</td><td>%s</td></tr>\n",
                    dp->d_name, d, dp->d_name, d, m_time, size);
            writen(out_fd, buf, strlen(buf));
        }
        close(ffd);
    }
    sprintf(buf, "</table></body></html>");
    writen(out_fd, buf, strlen(buf));
    closedir(d);
}

static const char* get_mime_type(char *filename){
    char *dot = strrchr(filename, '.');
    if(dot){ // strrchar Locate last occurrence of character in string
        mime_map *map = meme_types;
        while(map->extension){
            if(strcmp(map->extension, dot) == 0){
                return map->mime_type;
            }
            map++;
        }
    }
    return default_mime_type;
}


int open_listenfd(int port){
    int listenfd, optval=1;
    struct sockaddr_in serveraddr;

    /* Create a socket descriptor */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

#ifndef WIN32
    /* Eliminates "Address already in use" error from bind. */
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
                   (const void *)&optval , sizeof(int)) < 0)
        return -1;

    // 6 is TCP's protocol number
    // enable this, much faster : 4000 req/s -> 17000 req/s
    if (setsockopt(listenfd, 6, TCP_CORK,
                   (const void *)&optval , sizeof(int)) < 0)
        return -1;
#endif

    /* Listenfd will be an endpoint for all requests to port
       on any IP address for this host */
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short)port);
    
    if (bind(listenfd, (SA *)&serveraddr, sizeof(serveraddr)) < 0)
        return -1;

    /* Make it a listening socket ready to accept connection requests */
    if (listen(listenfd, LISTENQ) < 0)
        return -1;
    return listenfd;
}

void url_decode(char* src, char* dest, int max) {
    char *p = src;
    char code[3] = { 0 };
    while(*p && --max) {
        if(*p == '%') {
            memcpy(code, ++p, 2);
            *dest++ = (char)strtoul(code, NULL, 16);
            p += 2;
        } else {
            *dest++ = *p++;
        }
    }
    *dest = '\0';
}

void parse_request(int fd, http_request *req){
    rio_t rio;
    char buf[MAXLINE], method[MAXLINE], uri[MAXLINE];
    req->offset = 0;
    req->end = 0;              /* default */
    req->query[0] = '\0';
    req->uri[0] = '\0';
    req->host[0] = '\0';
    req->auth[0] = '\0';
    req->type[0] = '\0';
    req->length = 0;
    req->bodylen=0;
    req->body[0] = '\0';
    
 
    rio_readinitb(&rio, fd);
    rio_readlineb(&rio, buf, MAXLINE);
    sscanf(buf, "%s %s", method, uri); /* version is not cared */
    strcpy(req->method, method);
    /* read all */
    while(buf[0] != '\n' && buf[1] != '\n') { /* \n || \r\n */
        rio_readlineb(&rio, buf, MAXLINE);
        //if(buf[0] == 'R' && buf[1] == 'a' && buf[2] == 'n'){
	if( stristr(buf,"Range: ")==buf ) {
            sscanf(buf, "Range: bytes=%lu-%lu", &req->offset, &req->end);
            // Range: [start, end]
            if( req->end != 0) req->end ++;
	} else if( stristr(buf,"Host: ")==buf ) {
	    sscanf(buf+6, "%s", &(req->host[0]) );
	} else if( stristr(buf, "Content-length: ")==buf ) {
	    sscanf(buf+16, "%lu", &req->length );
	} else if( stristr(buf, "Authorization: ")==buf ) {
	    sscanf(buf+15, "%[a-zA-Z0-9=+/ ]", &(req->auth[0]) );
	} else if( stristr(buf, "Content-type: ")==buf ) {
	    sscanf(buf+14, "%s", &(req->type[0]) );
	} else if( stristr(buf, "Expect: 100-continue")==buf ) {
	  writen(fd, "HTTP/1.1 100 Continue\r\n\r\n", 25);
	}
    }
    if( rio.rio_cnt>0 ) {
	    req->bodylen=rio.rio_cnt;
	    memcpy(req->body,rio.rio_bufptr,rio.rio_cnt);
    }
    if( uri[0]!='/' ) { uri[0]='/'; url_decode(uri, (req->uri)+1, MAXLINE); } 
    else { url_decode(uri, req->uri, MAXLINE); }
    int i;
    for (i = 0; i < strlen(req->uri); i++) { if( req->uri[i]=='?' ) { req->uri[i]='\0'; break; } }
    char* filename = uri;
    if(uri[0] == '/'){
        filename = uri + 1;
        int length = strlen(filename);
        if (length == 0){
            filename = ".";
        } else {
	    for (i = 0; i < length; ++ i) {
                if (filename[i] == '?') {
		    url_decode(filename+i+1 , req->query, MAXLINE);
                    filename[i] = '\0';
                    break;
                }
            }
        }
    }
    url_decode(filename, req->filename, MAXLINE);
}


void log_access(int status, struct sockaddr_in *c_addr, http_request *req){
    printf("%s:%d %d - %s %s/%s (%lu) ? %s\n", inet_ntoa(c_addr->sin_addr),
           ntohs(c_addr->sin_port), status, req->method, req->host, req->filename, req->length, req->query);
}

void client_error(int fd, int status, char *msg, char *headers, char *longmsg){
    char buf[MAXLINE];
    sprintf(buf, "HTTP/1.1 %d %s\r\n", status, msg);
    if(headers!=NULL) if(strlen(headers)>0) { sprintf(buf + strlen(buf), "%s", headers); }
    if( status==204 ) {
	sprintf(buf + strlen(buf), "Content-length: 0\r\n\r\n");
    } else {
	if( (longmsg!=NULL) && (strlen(longmsg)>0) ){
	    sprintf(buf + strlen(buf),
                "Content-length: %lu\r\n\r\n", strlen(longmsg));
	    sprintf(buf + strlen(buf), "%s", longmsg);
	} else { sprintf(buf + strlen(buf), "Content-length: 0\r\n\r\n");}
    }
    writen(fd, buf, strlen(buf));
}

char *psttemp=NULL;
char * mmktemp(char *template) {
	if(psttemp!=NULL) { free(psttemp); } psttemp=NULL;
	psttemp=(char*)malloc(256);psttemp[0]='\0';
	sprintf(psttemp,"%s/%s%ld",tmp_dir,template,random());
	return psttemp;
}

int write_file(int fd, http_request *req, char * filename) {
    char buf[512];
    int put_fd, n;
    ssize_t size=0;
    if( (put_fd = open(filename, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR ))==-1 ) {
	return 500;
    } else {
	if( req->bodylen>0 ) { write(put_fd,req->body,req->bodylen) ; } /* Is there some data into buffer */
	fd_set fds;
	struct timeval timeout; timeout.tv_sec=2; timeout.tv_usec=0;
	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	if( select(fd+1, &fds, 0, 0, &timeout)==1 ) { /* there is data available into socket */
#ifdef WIN32
	    while( (n=recv(fd,buf,512,0))>0 ) {
#else
	    while( (n=read(fd,buf,512))>0 ) {
#endif
		write(put_fd,buf,n);
		size+=n;
		if( select(fd+1, &fds, 0, 0, &timeout)!=1 ) break;
	    }
	    printf("Writing %ld bytes into %s\n",size,req->filename);
	    close(put_fd);
	    return 200;
	} else {
	    close(put_fd);
	    return 400;
	}
	close(put_fd);
    }
    return 500;
}

#ifndef WIN32
#define READ   0
#define WRITE  1
FILE * popen2(const char * command, const char * type, int * pid) {
    pid_t child_pid;
    int fd[2];
    pipe(fd);

    if((child_pid = fork()) == -1) {
	perror("fork");
        exit(1);
    }

    /* child process */
    if (child_pid == 0) {
        if (type == "r") {
            close(fd[READ]);    //Close the READ end of the pipe since the child's fd is write-only
            dup2(fd[WRITE], 1); //Redirect stdout to pipe
        } else {
            close(fd[WRITE]);    //Close the WRITE end of the pipe since the child's fd is read-only
            dup2(fd[READ], 0);   //Redirect stdin to pipe
        }

        setpgid(child_pid, child_pid); //Needed so negative PIDs can kill children of /bin/sh
        //execl("/bin/sh", "/bin/sh", "-c", command.c_str(), NULL);
	execl("/bin/sh", "/bin/sh", "-c", command, "2>&1", NULL);
        exit(0);
    } else {
        if (type == "r") {
            close(fd[WRITE]); //Close the WRITE end of the pipe since parent's fd is read-only
        } else {
            close(fd[READ]); //Close the READ end of the pipe since parent's fd is write-only
        }
    }

    *pid = child_pid;

    if (type == "r") {
        return fdopen(fd[READ], "r");
    }

    return fdopen(fd[WRITE], "w");
}

int pclose2(FILE * fp, pid_t pid) {
    int stat;

    kill(-pid, 9);
    fclose(fp);
    while (waitpid(pid, &stat, 0) == -1) {
        if (errno != EINTR) {
            stat = -1;
            break;
        }
    }
    return stat;
}
#endif

#define BUF_SIZE 512
int serve_dynamic(int out_fd, http_request *req ) {
/*# Exemple de shell dynamic
#!/bin/bash
echo "Content-type: text/plain"
echo
echo "On est dans un shell: "
echo "QUERY_STRING=${QUERY_STRING}"
echo "REQUEST_METHOD=${REQUEST_METHOD}"
echo "REQUEST_URI=${REQUEST_URI}"
echo "DOCUMENT_ROOT=${DOCUMENT_ROOT}"
echo "HTTP_HOST=${HTTP_HOST}"
echo "SCRIPT_FILENAME=${SCRIPT_FILENAME}"
echo "SERVER_SOFTWARE=${SERVER_SOFTWARE}"
echo "SCRIPT_NAME=${SCRIPT_NAME}"
echo "CONTENT_LENGTH=${CONTENT_LENGTH}"
echo "CONTENT_TYPE=${CONTENT_TYPE}"
*/
	char cmd[1024];
	char cwd[PATH_MAX];
	char buf[BUF_SIZE];
	FILE *fp ;
	int ret = 200 ;
	int pid;
	
	getcwd(cwd, sizeof(cwd));
	
	if( strlen(req->query)>0 ) { setenv("QUERY_STRING", req->query, 1); }
	if( strlen(req->method)>0 ) { setenv("REQUEST_METHOD", req->method, 1); }
	setenv("DOCUMENT_ROOT", cwd, 1);
	if( strlen(req->auth)>0 ) { setenv("HTTP_AUTHORIZATION", req->auth, 1); }
	if( strlen(req->host)>0 ) { setenv("HTTP_HOST", req->host, 1); }
	sprintf(cmd, "/%s", req->filename );
	if( strlen(req->filename)>0 ) { setenv("REQUEST_URI", cmd, 1); }
	sprintf(cmd, "%s/%s", cwd, req->filename );
	setenv("SCRIPT_FILENAME", cmd, 1);
	setenv("SERVER_SOFTWARE", server_software, 1);
	setenv("CONTENT_TYPE", req->type, 1);
	sprintf(buf,"%lu",req->length);
	setenv("CONTENT_LENGTH", buf, 1);
	setenv("SCRIPT_NAME", req->uri, 1);

	char * tmpfilename=NULL;
	if( !strcmp(req->method,"POST") && (req->bodylen>0) ) {
		//tmpfilename = tmpnam(NULL) ;
		tmpfilename = mmktemp("tinyweb") ;
		if( tmpfilename!=NULL ) {
			int r = write_file(out_fd, req, tmpfilename);
			switch(r) {
				case 500: client_error(out_fd, 500, "Internal server error", NULL, "Unable to create temporary file.");
#ifdef WIN32
				closesocket(out_fd);
#else
				close(out_fd); 
#endif
				return 500; break;
			}
			//sprintf(cmd, "cat %s |%s \"%s/%s\" 2>&1", tmpfilename, dynamic_shell, cwd, req->filename) ;
			sprintf(cmd, "cat %s | \"%s/%s\"", tmpfilename, cwd, req->filename) ;
		} else { 
			client_error(out_fd, 500, "Internal server error", NULL, "Unable to get temporary filename."); 
#ifdef WIN32
			closesocket(out_fd);
#else
			close(out_fd);
#endif
			return 500; 
		}
	} else {
		//sprintf(cmd, "%s \"%s/%s\" 2>&1", dynamic_shell, cwd, req->filename) ;
		sprintf(cmd, "\"%s/%s\"", cwd, req->filename) ;
	}


#ifdef WIN32
	fp = popen(cmd,"r");
	printf("running command %s\n",cmd);
#else
	fp = popen2(cmd,"r",&pid) ; printf("starting process %d\n",pid);
	printf("running command [/bin/sh -c] %s\n",cmd);
#endif
	
	int nb_read;
	if( fp!=NULL ) {
		if( !fgets(buf, BUF_SIZE, fp) ) {
			strcpy(buf,"HTTP/1.1 500 Internal server error\r\n"); 
			writen(out_fd, buf, strlen(buf));
			ret = 500 ;
		} else {
			if( stristr(buf,"Status:")==buf ) {
				writen(out_fd, "HTTP/1.1 ", 9);
				int i=8;
				while( buf[i]==' ' ) { i++; }
				writen(out_fd, buf+i, strlen(buf+i));
				ret = atoi(buf+i);
			} else {
				strcpy(buf,"HTTP/1.1 200 OK\r\n"); 
			}
			writen(out_fd, buf, strlen(buf));
			while( (nb_read=fread(buf,1,BUF_SIZE,fp))>0 )  {
				if( writen(out_fd, buf, nb_read)!=nb_read ) break ;
				fsync(out_fd);
				if( nb_read!=BUF_SIZE ) break;
			}
		}
	} else {
		strcpy(buf,"HTTP/1.1 500 Internal Server Error\r\n\r\nInternal Server Error");
		writen(out_fd, buf, strlen(buf));
		ret = 500 ;
	}
	if( tmpfilename!=NULL ) { unlink(tmpfilename) ;}
	
#ifdef WIN32
	pclose(fp) ;
#else
	printf("killing process %d\n",pid) ; pclose2(fp,pid) ;
#endif
	
	unsetenv("QUERY_STRING");
	unsetenv("REQUEST_METHOD");
	unsetenv("DOCUMENT_ROOT");
	unsetenv("HTTP_AUTHORIZATION");
	unsetenv("HTTP_HOST");
	unsetenv("REQUEST_URI");
	unsetenv("SCRIPT_FILENAME");
	unsetenv("SERVER_SOFTWARE");
	unsetenv("CONTENT_TYPE");
	unsetenv("CONTENT_LENGTH");
	unsetenv("SCRIPT_NAME");
#ifdef WIN32
	closesocket(out_fd);
#else
	close(out_fd);
#endif
	return ret ;
}

void serve_static_get(int out_fd, int in_fd, http_request *req,
                  size_t total_size, time_t last_change_time) {
    char buf[256];
    if (req->offset > 0){
        sprintf(buf, "HTTP/1.1 206 Partial\r\n");
        sprintf(buf + strlen(buf), "Content-Range: bytes %lu-%lu/%lu\r\n",
                req->offset, req->end, total_size);
    } else {
        sprintf(buf, "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\n");
    }
    char date[100];
    strftime(date, 100, "%a, %d %b %Y %H:%M:%S %Z", localtime(&(last_change_time)));
    sprintf(buf + strlen(buf), "Last-Modified: %s\r\n", date);

    time_t current_time = time(0) ;
    strftime(date, 100, "%a, %d %b %Y %H:%M:%S %Z", localtime(&(current_time)));
    sprintf(buf + strlen(buf), "Date: %s\r\n", date);
    
    sprintf(buf + strlen(buf), "Cache-Control: no-cache\r\nExpires: 0\r\n");
    // sprintf(buf + strlen(buf), "Cache-Control: public, max-age=315360000\r\nExpires: Thu, 31 Dec 2037 23:55:55 GMT\r\n");

    sprintf(buf + strlen(buf), "Content-type: %s\r\n",
            get_mime_type(req->filename));

    if( strcmp(req->method,"HEAD") ) {
	sprintf(buf + strlen(buf), "Content-length: %lu\r\n\r\n",
            req->end - req->offset);

	writen(out_fd, buf, strlen(buf));
	off_t offset = req->offset; /* copy */
	while(offset < req->end){
#ifndef NO_SENDFILE
		if(sendfile(out_fd, in_fd, &offset, req->end - req->offset) <= 0) {
			break;
		}
#else
		int n;

		while( (n=read(in_fd,buf,256))>0 ) {
#ifdef WIN32
			send(out_fd,buf,n,0);
#else
			write(out_fd,buf,n);
#endif
			if(n!=256) break ;
		}
#endif
		printf("offset: %d \n\n", (int)offset);
		
#ifdef WIN32
		closesocket(out_fd);
#else
		close(out_fd);
#endif
		break;
	}
    } else {
	    sprintf(buf + strlen(buf), "\r\n" ) ;
	    writen(out_fd, buf, strlen(buf));
#ifdef WIN32
		closesocket(out_fd);
#else
	    close(out_fd);
#endif
    }
}

void serve_static_put(int out_fd, http_request *req) { // curl -X PUT -H "Expect:" http://localhost:9996/1.txt --upload-file 1.txt
	int r = write_file( out_fd, req, req->filename ) ;
	switch( r ) {
		case 200: client_error(out_fd, 200, "OK", NULL, "File created"); break;
		case 400: client_error(out_fd, 400, "Bad request", NULL, "No data found");break;
		case 500: 
		default: client_error(out_fd, 500, "Internal server error", NULL, "Internal server error: unable to create file");
	
	}
#ifdef WIN32
	closesocket(out_fd);
#else
	close(out_fd);
#endif
}

void serve_static(int out_fd, int in_fd, http_request *req,
                  size_t total_size, time_t last_change_time) {
    if( !strcmp(req->method,"HEAD") || !strcmp(req->method,"GET") || !strcmp(req->method,"POST") ) {
	serve_static_get(out_fd, in_fd, req, total_size, last_change_time) ;
    } else if( !strcmp(req->method,"DELETE") ) {
	close( in_fd ) ;
	if( remove( req->filename )==0 ) {
	    printf("File %s removed !\n",req->filename);
	    client_error(out_fd, 204, "No content", NULL, NULL);
	} else {
	    client_error(out_fd, 500, "Internal server error", NULL, "Internal server error: unable to remove file");
	}
    } else if( !strcmp(req->method,"OPTIONS") ) {
	client_error(out_fd, 200, "OK", "Allow: DELETE, GET, HEAD, OPTIONS, POST, PUT, TRACE\r\n", NULL);
    } else if( !strcmp(req->method,"PUT") ) {
	serve_static_put(out_fd, req) ;
    } else if( !strcmp(req->method,"TRACE") ) {
	client_error(out_fd, 405, "Method not allowed", "Allow: DELETE, GET, HEAD, OPTIONS, POST, PUT, TRACE\r\n", "Method not allowed");
    } else {
	client_error(out_fd, 405, "Method not allowed", "Allow: DELETE, GET, HEAD, OPTIONS, POST, PUT, TRACE\r\n", "Method not allowed");
    }
}

int index_file_found(char *directory) {
	char buf[1024];
	int fd, ret=0 ;
	if( directory[strlen(directory)-1]!='/' ) {
		sprintf(buf, "%s/%s", directory, default_index_file);
	} else {
		sprintf(buf, "%s%s", directory, default_index_file);
	}
	fd = open(buf, O_RDONLY, 0);
	if( fd>0 ){
		struct stat sbuf;
		fstat(fd, &sbuf);
		if(S_ISREG(sbuf.st_mode)){
			ret=1;
		}
		close(fd);
	}
	return ret ;
}

void process(int fd, struct sockaddr_in *clientaddr){
    printf("accept request, fd is %d, pid is %d\n", fd, getpid());
    http_request req;
    parse_request(fd, &req);
	
    printf("request filename: %s\n", req.filename);

    struct stat sbuf;
    int status = 200, ffd = open(req.filename, O_RDONLY, 0);
    if( !strcmp(req.method,"PUT") ) {
	serve_static_put(fd, &req) ;
    } else if( ffd<=0 ) {
        status = 404;
        char *msg = "File not found";
        client_error(fd, status, "Not found", NULL, msg);
    } else {
        fstat(ffd, &sbuf);
        if(S_ISREG(sbuf.st_mode)){
            if (req.end == 0){
                req.end = sbuf.st_size;
            }
            if (req.offset > 0){
                status = 206;
            }
            if( !strcmp(req.filename+strlen(req.filename)-3,".sh") ) {
		status = serve_dynamic(fd, &req);
	    } else {
		serve_static(fd, ffd, &req, sbuf.st_size, sbuf.st_ctime);
	    }
        } else if(S_ISDIR(sbuf.st_mode)){
	    if( (req.filename[strlen(req.filename)-1]!='/')&&(req.filename[strlen(req.filename)-1]!='.') ) {
		status = 302;
		handle_directory_redirect(fd, req.filename, "/");
	    } else if( index_file_found(req.filename) ) {
		status = 302;
		handle_directory_redirect(fd, req.filename, default_index_file);
	    } else {
		status = 200;
		handle_directory_request(fd, ffd, req.filename);
	    }
        } else {
            status = 400;
            char *msg = "Unknow Error";
            client_error(fd, status, "Error", NULL, msg);
        }
    }
    close(ffd);
    log_access(status, clientaddr, &req);
}

struct adresseIP { unsigned char i1; unsigned char i2; unsigned char i3; unsigned char i4; } ;
int server_main(char *path, int default_port) {
	int listenfd,
	    connfd;
	struct sockaddr_in clientaddr;
	socklen_t clientlen = sizeof clientaddr;

	if(chdir(path) != 0) {
                perror(path);
                exit(1);
	}
	printf("parent pid is %d\n",getpid());
	listenfd = open_listenfd(default_port);
	if (listenfd > 0) {
		char buf[256];
		path = getcwd(buf, 256);
		printf("listen on port %d, scan directory %s, fd is %d\n", default_port, path, listenfd);
	} else {
		perror("ERROR");
		exit(listenfd);
	}
	
#ifndef WIN32
	// Ignore SIGPIPE signal, so if browser cancels the request, it
	// won't kill the whole process.
	signal(SIGPIPE, SIG_IGN);
	int i;
	if( nb_forks>0 )
	for(i = 0; i < 10; i++) {
		int pid = fork();
		if (pid == 0) {         //  child
			while(1) {
				connfd = accept(listenfd, (SA *)&clientaddr, &clientlen);
				process(connfd, &clientaddr);
				close(connfd);
			}
		} else if (pid > 0) {   //  parent
			printf("child pid is %d\n", pid);
		} else {
			perror("fork");
		}
	}
#endif
	while(1){
		connfd = accept(listenfd, (SA *)&clientaddr, &clientlen);
		struct adresseIP * adIP = (struct adresseIP*) &( clientaddr.sin_addr.s_addr ) ;
		printf("accept connexion from %d.%d.%d.%d:%d\n",adIP->i1,adIP->i2,adIP->i3,adIP->i4,ntohs(clientaddr.sin_port));
		process(connfd, &clientaddr);
#ifdef WIN32
		closesocket(connfd);
#else		
		close(connfd);
#endif
	}
	return 0 ;
}

void usage( char *progname ) {
	printf("Usage: %s [-h] [[directory] port]\n",progname);
	printf("Configuration variables:\n");
	printf("- TINYWEB_DIR: home directory [.]\n");
	printf("- TINYWEB_PORT: listening port [9999]\n");
#ifndef WIN32
	printf("- TINYWEB_NBPROCESS: number of concurrent processes [10]\n");
#endif
	printf("- TINYWEB_CMD: external scripts command []\n");
}

int main(int argc, char** argv){
    int default_port = 9999;
    char buf[256];
    char *path = getcwd(buf, 256);

    if( getenv("TINYWEB_PORT")!=NULL ) { default_port = atoi(getenv("TINYWEB_PORT")) ; if( (default_port<1)||(default_port>65535) ) {default_port = 9999;}  }
    if( getenv("TINYWEB_DIR")!=NULL ) { path = getenv("TINYWEB_DIR") ; }
    if( getenv("TINYWEB_NBPROCESS")!=NULL ) { nb_forks=atoi(getenv("TINYWEB_NBPROCESS")); if(nb_forks<0) nb_forks=0;  }
    if( getenv("TINYWEB_CMD")!=NULL ) { dynamic_shell=(char*)malloc(strlen(getenv("TINYWEB_CMD"))+1);strcpy(dynamic_shell,getenv("TINYWEB_CMD"));strcat(dynamic_shell," "); }
	    
    if( getenv("TMPDIR")!=NULL ) { strcpy(tmp_dir, getenv("TMPDIR")); }
    else if( getenv("TEMP")!=NULL ) { strcpy(tmp_dir, getenv("TEMP")); }
    else if( getenv("TMP")!=NULL ) { strcpy(tmp_dir, getenv("TMP")); }
    
    if(chdir(path) != 0) {
        perror(path);
        exit(1);
    }

    if(argc == 2) {
	if( !strcmp(argv[1],"-h") ) { usage(argv[0]); exit(0); }
        if(argv[1][0] >= '0' && argv[1][0] <= '9') {
            default_port = atoi(argv[1]);
        } else {
            path = argv[1];
            if(chdir(argv[1]) != 0) {
                perror(argv[1]);
                exit(1);
            }
        }
    } else if (argc == 3) {
        default_port = atoi(argv[2]);
        path = argv[1];
        if(chdir(argv[1]) != 0) {
            perror(argv[1]);
            exit(1);
        }
    }
#ifdef WIN32
WSADATA wsaData;
if( WSAStartup(MAKEWORD(2,2), &wsaData) ) {
    printf("Unable to start winsock!\n");
    return EXIT_FAILURE ; }
#endif
    return server_main( path, default_port ) ;
}

/*
# Linux
gcc -o tinyweb tinyweb.c

# Cygwin
gcc -o tinyweb tinyweb.c -DNO_SENDFILE

# MinGW
gcc -o tinyweb.exe tinyweb.c -DNO_SENDFILE -DWIN32 -lwsock32 /c/windows/system32/kernel32.dll

echo '<html><head><title>It works!</title></head><body>It works!</body></html>' > index.html

*/
