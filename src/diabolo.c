// static compilation: gcc -static -o diabolo diabolo.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#define PORT 1667
#define BUFFER_SIZE 1024
#define TIMEOUT_SECONDS 5

void handle_client(int client_socket) {
    fd_set readfds;
    struct timeval timeout;
    char buffer[BUFFER_SIZE];
    int max_fd, activity;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(client_socket, &readfds);
        max_fd = client_socket;

        timeout.tv_sec = TIMEOUT_SECONDS;
        timeout.tv_usec = 0;

        activity = select(max_fd + 1, &readfds, NULL, NULL, &timeout);

        if (activity < 0) {
            perror("select");
            break;
        } else if (activity == 0) {
            // Timeout: no data received within the time limit
            printf("Timeout: no data received.\n");
            break;
        } else {
            if (FD_ISSET(client_socket, &readfds)) {
                ssize_t bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
                if (bytes_read <= 0) {
                    // Error or connection closed
                    break;
                }
                buffer[bytes_read] = '\0';
                printf("Request received: %s\n", buffer);

                 // Get current date and time
                time_t now;
                time(&now);
                char *time_str = ctime(&now);
                time_str[strlen(time_str)-1]='\0';

                // Minimal HTTP response
                char response[BUFFER_SIZE];
                snprintf(response, sizeof(response),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain; charset=utf-8\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "I'm DIABOLO, I'm waiting for Zéphyrin with my master SATANAS, and it is '%s'", time_str);
                
                send(client_socket, response, strlen(response), 0);
                break;
            }
        }
    }

    close(client_socket);
    exit(0);
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    // Listen
    if (listen(server_socket, 5) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server started on port %d...\n", PORT);
    unsigned long int nb=0;

    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("accept");
            continue;
        }

        // Print client IP address
        nb++;
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        printf("New client %ld from %s\n", nb, client_ip);

        // Fork to handle client
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(client_socket);
            continue;
        } else if (pid == 0) {
            // Child process: handle client
            close(server_socket);
            handle_client(client_socket);
        } else {
            // Parent process: close client socket
            close(client_socket);
        }
    }

    close(server_socket);
    return 0;
}
