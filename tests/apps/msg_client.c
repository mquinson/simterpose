/* msg_client -- A simple client talking to msg_server using sendmsg/recvmsg */
/*                Its only merit is to constitute a test case for simterpose */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.           */

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
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>


int main(int argc, char **argv)
{

  if (argc < 5) {
    fprintf(stderr, "usage: %s IP port msg_count msg_size\n", argv[0]);
    return EXIT_FAILURE;
  }

  char *IP = argv[1];
  u_short port = atoi(argv[2]);
  int msg_count = atoi(argv[3]);
  int buffer_size = atoi(argv[4]);

  struct timespec tvcl;
  clock_gettime(CLOCK_REALTIME, &tvcl);
  fprintf(stderr, "msg_client starting: #msg: %d; (time: %d; clock_gettime: %f)\n",
          msg_count, (int)time(NULL), tvcl.tv_sec + tvcl.tv_nsec / 1000000000.0);

  int clientSocket;
  int res;
  char buff[buffer_size];
  strcpy(buff, "Message from client ");
  struct hostent *serverHostEnt;


  if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("error socket");
    exit(1);
  }
  struct sockaddr_in cli_addr;
  memset(&cli_addr, 0, sizeof(struct sockaddr_in));
  serverHostEnt = gethostbyname(IP);
  memcpy(&(cli_addr.sin_addr), serverHostEnt->h_addr, serverHostEnt->h_length);
  cli_addr.sin_family = AF_INET;
  cli_addr.sin_port = htons(port);

  if (connect(clientSocket, (struct sockaddr *) &cli_addr, sizeof(cli_addr)) < 0) {
    printf("msg_client: cannot connect to the server: %s\n", strerror(errno));
    exit(1);
  }

  fprintf(stderr, "msg_client: connected to the server %s:%d\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
  struct iovec iov[1];
  struct msghdr msg;

  int msg_number = 0;

  for (msg_number = 0; msg_number < msg_count; ++msg_number) {

    memset(&msg, 0, sizeof(struct msghdr));
    sprintf(buff, "This is the message #%d produced on the client.", msg_number);

    iov[0].iov_base = buff;
    iov[0].iov_len = strlen(buff) + 1;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;


    res = sendmsg(clientSocket, &msg, 0);

    if (res == -1) {
      perror("erreur envoi client");
      exit(1);
    }
    fprintf(stderr, "Client: sent message #%d\n", msg_number);

  }
  shutdown(clientSocket, 2);
  close(clientSocket);

  struct timespec end_tvcl;
  clock_gettime(CLOCK_REALTIME, &end_tvcl);
  fprintf(stderr, "OK: Client exiting after %d messages (time: %d; clock_gettime: %f)\n",
          msg_count, (int)time(NULL), end_tvcl.tv_sec + end_tvcl.tv_nsec / 1000000000.0);

  return 0;
}
