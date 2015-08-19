/* sendto_client -- A client talking to sendto_server using sendto/recvfromv */
/*        Its only merit is to constitute a test case for simterpose         */

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
#include <arpa/inet.h>
#include <netdb.h>
#include <arpa/inet.h>

int main(int argc, char** argv)
{
  int clientSocket;
  u_short port = atoi(argv[2]);
  int nb_msg = atoi(argv[3]);
  int buffer_size;
  int res;

  if (atoi(argv[4])>0)
    buffer_size = atoi(argv[4]);
  else
    buffer_size = 128;
  char* buff = (char*) malloc(buffer_size * sizeof(char));
  memset(buff, 65, (buffer_size-1)*sizeof(char));
  buff[buffer_size] = '\0';

  /* long host_addr; */
  /* strcpy(buff, "Message from client"); */
  struct hostent *serverHostEnt;

  if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Error socket");
    exit(1);
  }

  struct sockaddr_in cli_addr;
  memset(&cli_addr, 0, sizeof(struct sockaddr_in));
  /* host_addr = inet_addr("162.32.43.1"); */       /*162.32.43.1 */
  serverHostEnt = gethostbyname("162.32.43.1");
  memcpy(&(cli_addr.sin_addr), serverHostEnt->h_addr, serverHostEnt->h_length);
  
  cli_addr.sin_family = AF_INET;
  cli_addr.sin_port = htons(port);
  
  if (connect(clientSocket, (struct sockaddr *) &cli_addr, sizeof(cli_addr)) < 0) {
    fprintf(stderr, "Connection demand failed\n");
    exit(0);
  }
  
  fprintf(stderr, "Connect to server %s:%d\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
  
  int msg_count;
  
  for (msg_count = 0; msg_count < nb_msg; ++msg_count) {
    size_t len = strlen(buff) + 1;
    res = sendto(clientSocket, buff, len, 0, (struct sockaddr *) &cli_addr, sizeof(struct sockaddr_in));

    if (res == -1) {
      perror("Error send client");
      exit(1);
    }
    /* fprintf(stderr, "Client: Message send #%d \"%s\"\n", msg_count, buff); */
  }
  shutdown(clientSocket, SHUT_RDWR);
  close(clientSocket);
  
  return 0;
}
