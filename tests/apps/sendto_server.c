/* sendto_server -- A server listening to sendto_client using sendto/recvfrom   */
/*           Its only merit is to constitute a test case for simterpose         */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SERV_PORT 2227

#define BUFFER_SIZE 1024


int main()
{
   int serverSocket;
  char *buff = (char *) malloc(BUFFER_SIZE);
  u_short port;
  int res;
  int client_socket;

  if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Error socket");
    exit(1);
  } 

  struct sockaddr_in *serv_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
  memset((char *) serv_addr, (char) 0, sizeof(struct sockaddr_in));


  port = SERV_PORT;
  serv_addr->sin_family = AF_INET;
  serv_addr->sin_port = htons(port);
  serv_addr->sin_addr.s_addr = INADDR_ANY;

  int on = 1;
  if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
    perror("Error setsockopt");
    exit(1);
  }



  /* if (getsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &on, &on) < 0) { */
  /*   perror("Error getsockopt"); */
  /*   exit(1); */
  /* } */


  
  if (bind(serverSocket, (struct sockaddr *) serv_addr, sizeof(struct sockaddr_in)) < 0) {
    perror("Error bind");
    exit(1);
  }
  
  if (listen(serverSocket, SOMAXCONN) < 0) {
    perror("Error listen");
    exit(1);
  }
  fprintf(stderr, "Waiting for connexion\n");
  
  socklen_t clilen = sizeof(struct sockaddr_in);
  struct sockaddr_in cli_addr;

  if ((client_socket = accept(serverSocket, (struct sockaddr *) &cli_addr, (socklen_t *) &clilen)) < 0) {
    perror("Error accept");
    exit(1);
  }
  
  struct in_addr in = { cli_addr.sin_addr.s_addr };
  fprintf(stderr, "Here %d %s\n", cli_addr.sin_addr.s_addr, inet_ntoa(in));
  fprintf(stderr, "Connect to client  %s:%d\n", inet_ntoa(in), ntohs(cli_addr.sin_port));

  int ia;
  for (ia = 0; ia < 5; ++ia){
    res = recvfrom(client_socket, buff, BUFFER_SIZE, 0, (struct sockaddr *) &cli_addr, (socklen_t *) & clilen);
    if (res == -1) {
      perror("Error server reception");
      exit(1);
    }
    fprintf(stderr, "Receive message #%d from client: \"%s\"\n", ia, buff);
  }

  shutdown(client_socket, SHUT_RDWR);
   close(client_socket);
  
  return 0;
}
