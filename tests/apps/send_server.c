/* send_server -- A simple server listening to send_client using send/recv   */
/*                Its only merit is to constitute a test case for simterpose */

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
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>

int main(int argc, char **argv)
{

  if (argc < 4) {
    fprintf(stderr, "usage: %s port msg_count msg_size \n", argv[0]);
    return EXIT_FAILURE;
  }

  int server_port = atoi(argv[1]);
  int msg_count = atoi(argv[2]);
  int msg_size = atoi(argv[3]);

  fprintf(stderr, "Server starting on port %d: #msg: %d; size: %d \n", server_port, msg_count, msg_size);
  struct timeval * ti = (struct timeval * ) malloc(sizeof(struct timeval));
  gettimeofday(ti, NULL);
  printf("[%d] Time with gettimeofday: %lld %lld\n", getpid(), (long long) ti->tv_sec,  (long long) ti->tv_usec);
  char * ti_s = (char *) malloc(sizeof(char));
  ti_s = ctime(&ti->tv_sec);
  char * ti_us = (char *) malloc(sizeof(char));
  ti_us = ctime(&ti->tv_usec);
  printf("[%d] Time with gettimeofday in char: %s %s\n", getpid(), ti_s, ti_us);

  int serverSocket;
  char *buff = (char *) malloc(msg_size);
  char *expected = (char *) malloc(msg_size);
  u_short port;
  int res;
  int client_socket;

  if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Server: error socket");
    exit(1);
  }

  struct sockaddr_in *serv_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
  memset((char *) serv_addr, (char) 0, sizeof(struct sockaddr_in));

  port = server_port;
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
    perror("Server: error accepting real message");
    exit(1);
  }

  int msg_number = 0;
  for (msg_number = 0; msg_number < msg_count; ++msg_number) {
    sprintf(expected, "This is the message #%d produced on the client.", msg_number);

    int length = msg_size;
    while (length > 0) {
      res = recv(client_socket, buff, length, 0);
      if (res == -1) {
        fprintf(stderr, "Server: error while receiving message #%d: %s\n", msg_number, strerror(errno));
        exit(1);
      }
      length -= res;
    }
    if (strcmp(buff, expected)) {
      fprintf(stderr, "Server: received message does not match at step %d (got: %s)\n", msg_number, buff);
      exit(1);
    }
    fprintf(stderr, "Server: reception of message #%d was successful\n", msg_number);

    sprintf(buff, "This is the answer #%d, from the server.", msg_number);
    res = send(client_socket, buff, msg_size, 0);
    if (res == -1) {
      perror("Server: error sending answer");
      exit(1);
    }
  }
  shutdown(client_socket, 2);
  close(client_socket);

  
  gettimeofday(ti, NULL);
  printf("[%d] Time with gettimeofday: %lld %lld\n", getpid(), (long long) ti->tv_sec,  (long long) ti->tv_usec);
  ti_s = ctime(&ti->tv_sec);
  ti_us = ctime(&ti->tv_usec);
  printf("[%d] Time with gettimeofday in char: %s %s\n", getpid(), ti_s, ti_us);
  fprintf(stderr, "Server exiting after %d msgs\n", msg_count);
  
  return 0;
}
