#include <arpa/inet.h>          /* inet_ntoa */
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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
    char filename[512];
    off_t offset;              /* for support Range */
    size_t end;
    char query[512];
    char host[512];
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

int nb_forks = 10 ;

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
        if ((nwritten = write(fd, bufp, nleft)) <= 0){
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

        rp->rio_cnt = read(rp->rio_fd, rp->rio_buf,
                           sizeof(rp->rio_buf));
        if (rp->rio_cnt < 0){
            if (errno != EINTR) /* interrupted by sig handler return */
                return -1;
        }
        else if (rp->rio_cnt == 0)  /* EOF */
            return 0;
        else
            rp->rio_bufptr = rp->rio_buf; /* reset buffer ptr */
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
    DIR *d = fdopendir(dir_fd);
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

    /* Eliminates "Address already in use" error from bind. */
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
                   (const void *)&optval , sizeof(int)) < 0)
        return -1;

    // 6 is TCP's protocol number
    // enable this, much faster : 4000 req/s -> 17000 req/s
    if (setsockopt(listenfd, 6, TCP_CORK,
                   (const void *)&optval , sizeof(int)) < 0)
        return -1;

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
    req->query[0] = '\0' ;
    req->host[0] = '\0' ;

    rio_readinitb(&rio, fd);
    rio_readlineb(&rio, buf, MAXLINE);
    sscanf(buf, "%s %s", method, uri); /* version is not cared */
    strcpy(req->method, method);
    /* read all */
    while(buf[0] != '\n' && buf[1] != '\n') { /* \n || \r\n */
        rio_readlineb(&rio, buf, MAXLINE);
        if(buf[0] == 'R' && buf[1] == 'a' && buf[2] == 'n'){
            sscanf(buf, "Range: bytes=%lu-%lu", &req->offset, &req->end);
            // Range: [start, end]
            if( req->end != 0) req->end ++;
        } else if(buf[0] == 'H' && buf[1] == 'o' && buf[2] == 's' && buf[3] == 't' && buf[4] == ':') { // Host:
	    sscanf(buf, "Host: %s", &req->host);
	}
    }
    char* filename = uri;
    if(uri[0] == '/'){
        filename = uri + 1;
        int length = strlen(filename);
        if (length == 0){
            filename = ".";
        } else {
	    int i;
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
    printf("%s:%d %d - %s %s ? %s\n", inet_ntoa(c_addr->sin_addr),
           ntohs(c_addr->sin_port), status, req->method, req->filename, req->query);
}

void client_error(int fd, int status, char *msg, char *longmsg){
    char buf[MAXLINE];
    sprintf(buf, "HTTP/1.1 %d %s\r\n", status, msg);
    sprintf(buf + strlen(buf),
            "Content-length: %lu\r\n\r\n", strlen(longmsg));
    sprintf(buf + strlen(buf), "%s", longmsg);
    writen(fd, buf, strlen(buf));
}

void serve_dynamic(int out_fd, http_request *req ) {
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
*/
	char cmd[1024];
	char cwd[PATH_MAX];
	getcwd(cwd, sizeof(cwd));
	
	if( strlen(req->query)>0 ) { setenv("QUERY_STRING", req->query, 1); }
	if( strlen(req->method)>0 ) { setenv("REQUEST_METHOD", req->method, 1); }
	setenv("DOCUMENT_ROOT", cwd, 1);
	if( strlen(req->host)>0 ) { setenv("HTTP_HOST", req->host, 1); }
	sprintf(cmd, "/%s", req->filename );
	if( strlen(req->filename)>0 ) { setenv("REQUEST_URI", cmd, 1); }
	sprintf(cmd, "%s/%s", cwd, req->filename );
	setenv("SCRIPT_FILENAME", cmd, 1);
	setenv("SERVER_SOFTWARE", server_software, 1);
	
	sprintf(cmd, "\"%s/%s\" 2>&1", cwd, req->filename);
	printf("running command /bin/sh -c %s\n",cmd);
	
	FILE *fp = popen(cmd,"r");
	char buf[512];
	int nb_read;
	if( fp!=NULL ) {
		strcpy(buf,"HTTP/1.1 200 OK\r\n"); writen(out_fd, buf, strlen(buf));
		while( (nb_read=fread(buf,1,512,fp))>0 )  {
			writen(out_fd, buf, nb_read);
			if( nb_read!=512 ) break;
		}
	} else {
		strcpy(buf,"HTTP/1.1 500 Internal Server Error\r\n\r\nInternal Server Error"); 
		writen(out_fd, buf, strlen(buf));
	}
	
	pclose(fp);
	unsetenv("QUERY_STRING");
	unsetenv("REQUEST_METHOD");
	unsetenv("DOCUMENT_ROOT");
	unsetenv("HTTP_HOST");
	unsetenv("REQUEST_URI");
	unsetenv("SCRIPT_FILENAME");
	unsetenv("SERVER_SOFTWARE");
}

void serve_static(int out_fd, int in_fd, http_request *req,
                  size_t total_size, time_t last_change_time) {
    char buf[256];
    if (req->offset > 0){
        sprintf(buf, "HTTP/1.1 206 Partial\r\n");
        sprintf(buf + strlen(buf), "Content-Range: bytes %lu-%lu/%lu\r\n",
                req->offset, req->end, total_size);
    } else {
        sprintf(buf, "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\n");
    }
    char date[35];
    strftime(date, 35, "%a, %d %b %Y %H:%M:%S %Z", localtime(&(last_change_time)));
    sprintf(buf + strlen(buf), "Last-Modified: %s\r\n", date);

    time_t current_time = time(0) ;
    strftime(date, 35, "%a, %d %b %Y %H:%M:%S %Z", localtime(&(current_time)));
    sprintf(buf + strlen(buf), "Date: %s\r\n", date);
    
    sprintf(buf + strlen(buf), "Cache-Control: no-cache\r\nExpires: 0\r\n");
    // sprintf(buf + strlen(buf), "Cache-Control: public, max-age=315360000\r\nExpires: Thu, 31 Dec 2037 23:55:55 GMT\r\n");

    sprintf(buf + strlen(buf), "Content-length: %lu\r\n",
            req->end - req->offset);
    sprintf(buf + strlen(buf), "Content-type: %s\r\n\r\n",
            get_mime_type(req->filename));

    writen(out_fd, buf, strlen(buf));
    off_t offset = req->offset; /* copy */
    while(offset < req->end){
        if(sendfile(out_fd, in_fd, &offset, req->end - req->offset) <= 0) {
            break;
        }
        printf("offset: %d \n\n", (int)offset);
        close(out_fd);
        break;
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
    if(ffd <= 0){
        status = 404;
        char *msg = "File not found";
        client_error(fd, status, "Not found", msg);
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
		serve_dynamic(fd, &req);
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
            client_error(fd, status, "Error", msg);
        }
        close(ffd);
    }
    log_access(status, clientaddr, &req);
}
int server_main(char *path, int default_port) {
	int listenfd,
	    connfd;
	struct sockaddr_in clientaddr;
	socklen_t clientlen = sizeof clientaddr;

	if(chdir(path) != 0) {
                perror(path);
                exit(1);
	}
	listenfd = open_listenfd(default_port);
	if (listenfd > 0) {
		printf("listen on port %d, scan directory %s, fd is %d\n", default_port, path, listenfd);
	} else {
		perror("ERROR");
		exit(listenfd);
	}
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

	while(1){
		connfd = accept(listenfd, (SA *)&clientaddr, &clientlen);
		process(connfd, &clientaddr);
		close(connfd);
	}
	return 0 ;
}

int main(int argc, char** argv){
    int default_port = 9999;
    char buf[256];
    char *path = getcwd(buf, 256);
    
    if( getenv("TINYWEB_PORT")!=NULL ) { default_port = atoi(getenv("TINYWEB_PORT")) ; if( (default_port<1)||(default_port>65535) ) {default_port = 9999;}  }
    if( getenv("TINYWEB_DIR")!=NULL ) { path = getenv("TINYWEB_DIR") ; }
    if(chdir(path) != 0) {
        perror(path);
        exit(1);
    }
    if(argc == 2) {
	if( !strcmp(argv[1],"-h") ) { printf("Usage %s [[directory] port]\n",argv[0]); exit(0); }
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

    return server_main( path, default_port ) ;
}

/*

gcc -o tinyweb tinyweb.c

echo '<html><head><title>It works!</title></head><body>It works!</body></html>' > index.html

*/

