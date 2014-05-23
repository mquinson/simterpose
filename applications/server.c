#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/timeb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>

#define SERV_PORT 2227

int main(int argc, char **argv)
{

  if (argc < 3) {
    fprintf(stderr, "usage: %s amount_of_messages message_size \n", argv[0]);
    return EXIT_FAILURE;
  }

  int messages_count = atoi(argv[1]);
  int message_size = atoi(argv[2]);

  int serverSocket;
  char *buff = malloc(message_size);
  u_short port;
  int res;
  int client_socket;

  if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Server: error socket");
    exit(1);
  }

  struct sockaddr_in *serv_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
  memset((char *) serv_addr, (char) 0, sizeof(struct sockaddr_in));

  port = SERV_PORT;
  serv_addr->sin_family = AF_INET;
  serv_addr->sin_port = htons(port);
  serv_addr->sin_addr.s_addr = htonl(INADDR_ANY);


  int on = 1;
  if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
    perror("Server: error setsockopt");
    exit(1);
  }


  if (getsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &on, &on) < 0) {
    perror("Server: error getsockopt");
    exit(1);
  }

  if (bind(serverSocket, (struct sockaddr *) serv_addr, sizeof(struct sockaddr_in)) < 0) {
    perror("Server: error bind");
    exit(1);
  }
  if (listen(serverSocket, SOMAXCONN) < 0) {
    perror("Server: error listen");
    exit(1);
  }
  fprintf(stderr, "Server: Waiting for incoming requests\n");
  int clilen = sizeof(struct sockaddr_in);
  struct sockaddr_in *cli_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));

  if ((client_socket = accept(serverSocket, (struct sockaddr *) cli_addr, (socklen_t *) & clilen)) < 0) {
    perror("Server: error accepting real message");
    exit(1);
  }

  int ia = 0;
  for (ia = 0; ia < messages_count; ++ia) {
    int length = message_size;
    while (length > 0) {
      res = recv(client_socket, buff, length, 0);
      if (res == -1) {
        fprintf(stderr, "Server: error while receiving message #%d: %s\n", ia, strerror(errno));
        exit(1);
      }
      length -= res;
      //    printf("Server : recv %d (left %d)\n", res, length);
    }
    fprintf(stderr, "Server: Message received: %s", buff);
    sprintf(buff, "answer #%d",ia);
    res = send(client_socket, buff, message_size, 0);
    if (res == -1) {
      perror("Server: erreur envoi 2");
      exit(1);
    }
  }
  shutdown(client_socket, 2);
  close(client_socket);

  return 0;
}
