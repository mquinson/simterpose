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

#define SERV_PORT 2227

//#define BUFFER_SIZE 1024


int main(int argc, char **argv)
{

  if (argc < 2) {
    fprintf(stderr, "usage: %s buffer_size \n", argv[0]);
    return EXIT_FAILURE;
  }

  int buffer_size = atoi(argv[1]);

  int serverSocket;
  char *buff = malloc(buffer_size);
  u_short port;
  int res;
  int client_socket;

  if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("error socket");
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
    perror("error setsockopt");
    exit(1);
  }

  if (getsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &on, &on) < 0) {
    perror("error getsockopt");
    exit(1);
  }

  if (bind(serverSocket, (struct sockaddr *) serv_addr, sizeof(struct sockaddr_in)) < 0) {
    perror("error bind");
    exit(1);
  }
  if (listen(serverSocket, SOMAXCONN) < 0) {
    perror("error listen");
    exit(1);
  }
  printf("Attente demande de connexion\n");
  int clilen = sizeof(struct sockaddr_in);
  struct sockaddr_in *cli_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));


  if ((client_socket = accept(serverSocket, (struct sockaddr *) cli_addr, (socklen_t *) & clilen)) < 0) {
    perror("error accept");
    exit(1);
  }
  struct iovec iov[1];
  struct msghdr msg;


  iov[0].iov_base = buff;
  iov[0].iov_len = buffer_size;

  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  msg.msg_name = NULL;
  msg.msg_namelen = 0;


  res = recvmsg(client_socket, &msg, 0);
  if (res == -1) {
    perror("erreur réception server");
    exit(1);
  }
  printf("Recevive %d bytes : Message reçu du client %s\n", res, buff);

  return 0;
}
