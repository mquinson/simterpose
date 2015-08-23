/* msg_server -- A simple server listening to msg_client using sendmsg/recvmsg */
/*               Its only merit is to constitute a test case for simterpose  */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>

int main(int argc, char **argv)
{

  if (argc < 4) {
    fprintf(stderr, "Usage: %s port msg_count msg_size\n", argv[0]);
    return EXIT_FAILURE;
  }

  u_short port = atoi(argv[1]);
  int msg_count = atoi(argv[2]);
  int msg_size;

 if (atoi(argv[3])>0){
    msg_size = atoi(argv[3]);
  }
  else
    msg_size = 128;
  char* buff = (char*) malloc(msg_size * sizeof(char));

  fprintf(stderr, "Server starting on port %d: #msg: %d; size: %d \n", port, msg_count, msg_size);

  int serverSocket;
  int res;
  int client_socket;
  
  if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Server: error socket");
    exit(1);
  }

  struct sockaddr_in *serv_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
  memset((char *) serv_addr, (char) 0, sizeof(struct sockaddr_in));

  serv_addr->sin_family = AF_INET;
  serv_addr->sin_port = htons(port);
  serv_addr->sin_addr.s_addr = htonl(INADDR_ANY);


  int on = 1;
  if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
    perror("Server: error setsockopt");
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
    perror("Server: error accepting real connection");
    exit(1);
  }
  struct iovec iov[1];
  struct msghdr msg;
  int msg_number = 0;
  for (msg_number = 0; msg_number < msg_count; ++msg_number) {
    iov[0].iov_base = buff;
    iov[0].iov_len = msg_size;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    res = recvmsg(client_socket, &msg, 0);
    if (res == -1) {
      fprintf(stderr, "Server: error while receiving message #%d \"%s\"\n", msg_number, strerror(errno));
      exit(1);
    }
    /* fprintf(stderr, "Receive message #%d of %d bytes: \"%s\" \n", msg_number, res, buff); */
  }

  shutdown(client_socket, 2);
  close(client_socket);

  return 0;
}
