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

#define SERV_PORT 2227

#define BUFFER_SIZE 1024

int main()
{
  int clientSocket = 0;
  u_short port = 0;
  int res = 0;
  char buff[BUFFER_SIZE] = {0};
  strcpy(buff, "Message from client \n ");
  int server_socket = 0;
  long host_addr = 0;
  struct hostent *serverHostEnt;

  if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Error socket");
    exit(1);
  } 

  struct sockaddr_in cli_addr;
  memset(&cli_addr, 0, sizeof(struct sockaddr_in));
  host_addr = inet_addr("162.32.43.1");       /*162.32.43.1 */
  serverHostEnt = gethostbyname("162.32.43.1");
  memcpy(&(cli_addr.sin_addr), serverHostEnt->h_addr, serverHostEnt->h_length);
  port = SERV_PORT;
  cli_addr.sin_family = AF_INET;
  cli_addr.sin_port = htons(port);

  if (connect(clientSocket, (struct sockaddr *) &cli_addr, sizeof(cli_addr)) < 0) {
    fprintf(stderr, "Connection demand failed\n");
    exit(0);
  }
  
  fprintf(stderr, "Connect to server %s:%d\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
  
  int ia;
  
  for (ia = 0; ia < 5; ++ia) {
    res = sendto(clientSocket, buff, strlen(buff) + 1, 0, (struct sockaddr *) &cli_addr, sizeof(struct sockaddr_in));

    if (res == -1) {
      perror("Error send client");
      exit(1);
    }
    fprintf(stderr, "Message send #%d from client\n", ia, buff);
  }
  
  return 0;
}
