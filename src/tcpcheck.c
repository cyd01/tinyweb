#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <fcntl.h>
#include <errno.h>

static void usage(void) { fprintf(stderr,"tcpcheck: [-h] [-l] [-t timeout] [-v] [host:]port\n" ); }
int verbose = 0 ;

int conn_nonb(struct sockaddr_in sa, int sock, int timeout) {
    int flags = 0, error = 0, ret = 0;
    fd_set  rset, wset;
    socklen_t   len = sizeof(error);
    struct timeval  ts;
    
    ts.tv_sec = timeout;
    
    //clear out descriptor sets for select
    //add socket to the descriptor sets
    FD_ZERO(&rset);
    FD_SET(sock, &rset);
    wset = rset;    //structure assignment ok
    
    //set socket nonblocking flag
    if( (flags = fcntl(sock, F_GETFL, 0)) < 0) {
	if( verbose ) fprintf(stderr, "fcntl error\n" );
	return 61;
    }
    
    if(fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
	if( verbose ) fprintf(stderr, "fcntl error\n" );
	return 62;
    }
    
    //initiate non-blocking connect
    if( (ret = connect(sock, (struct sockaddr *)&sa, 16)) < 0 )
        if (errno != EINPROGRESS) {
	    if( verbose ) fprintf(stderr, "Connection refused\n" );
            return 111;
        }

    if(ret == 0)    //then connect succeeded right away
        goto done;
    
    //we are waiting for connect to complete now
    if( (ret = select(sock + 1, &rset, &wset, NULL, (timeout) ? &ts : NULL)) < 0) {
	if( verbose ) fprintf(stderr, "select error\n" );
        return 21;
    }
    if(ret == 0) {   //we had a timeout
        errno = ETIMEDOUT;
        if( verbose ) fprintf(stderr,"Timeout\n");
	return 9 ;
    }

    //we had a positivite return so a descriptor is ready
    if(FD_ISSET(sock, &rset) || FD_ISSET(sock, &wset)) {
        if(getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
		if( verbose ) fprintf(stderr, "getsockopt error\n" );
		return 22;
   	}
    } else
        return -1;

    if(error) {  //check if we had a socket error
	errno = error;
	if( verbose ) { 
		if( error==ECONNREFUSED ) {
			fprintf(stderr, "Connection refused\n" ) ;
		} else {
			fprintf(stderr, "socket error\n" ) ;
		}
	}
	    
        return error ;
    }
    
done:
    //put socket back in blocking mode
    if(fcntl(sock, F_SETFL, flags) < 0) {
	if( verbose ) fprintf(stderr, "fcntl error\n" );
	return 63;
    }

    if( verbose ) { printf("Connected\n") ; }
    return 0 ;
}

int main(int argc, char *argv[]) {
    int return_code = 0 ;
    int timeout = 2 ;
   
    char * hostname = "localhost" ;
    int PORT = 80 ;
	
	if( argc==1 ) { usage() ; return 1 ; }
	int opt;
	while ((opt = getopt(argc, argv, "hlvt:")) != -1) {
		switch (opt) {
		case 'l':
			break;
		case 'v':
			verbose=1;
			break;
		case 't':
			timeout = atoi(optarg) ;
			break;
		case 'h':
		default: 
			usage();
			return 1;
		}
	}
	if (optind >= argc) { usage() ; return 1 ; } 
	else {
		char *pst ;
		if( (pst=strstr(argv[optind],":")) == NULL ) {
			PORT = atoi( argv[optind] ) ;
		} else {
			PORT=atoi( pst+1 ) ;
			hostname = (char*) malloc( strlen(argv[optind])+1 ) ;
			strcpy( hostname, argv[optind] ) ;
			pst = strstr(hostname,":") ;
			pst[0]='\0';
		}
		if( PORT <= 0 ) PORT = 80 ;
	}

	
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
	
   if( verbose ) { printf("Connecting to %s:%d\n",hostname,PORT); }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
	if( verbose ) fprintf(stderr,"ERROR opening socket\n");
	return_code = 2 ;
	exit( return_code ) ;
    }

    server = gethostbyname(hostname) ;
    if (server == NULL) {
        if( verbose ) fprintf(stderr, "Unknown host %s.\n", hostname);
	return_code = 22 ;
    } else {
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, 
	(char *)&serv_addr.sin_addr.s_addr,
	server->h_length);
	serv_addr.sin_port = htons(PORT) ;
	    
	    return_code = conn_nonb(serv_addr, sockfd, 2) ;
    }

    close(sockfd);
    return return_code ;
}




/*
cd VPS/docker/tinyweb/

clear ; docker run -it -v $(pwd):/tmp/gcc cyd01/alpinegcc gcc -o /tmp/gcc/tcpcheck /tmp/gcc/tcpcheck.c


docker run --rm --name alpinegcc -v $(pwd):/tmp/gcc cyd01/alpinegcc /tmp/gcc/tcpcheck -v www.google.fr:80 ;echo $?

docker run --rm --name alpinegcc -v $(pwd):/tmp/gcc cyd01/alpinegcc /tmp/gcc/tcpcheck -v www.google.fr:801 ;echo $?

docker run --rm --name alpinegcc -v $(pwd):/tmp/gcc cyd01/alpinegcc /tmp/gcc/tcpcheck -v www.dgfsdfgds.fr:80 ;echo $?
*/
