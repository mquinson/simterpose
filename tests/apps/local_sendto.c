/* local_sendto -- A simple client/server communication using sendto/recvfrom */
/* It is used to test the application on the machine only not with Simterpose */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>

int sendto_client(char* IP, u_short port, int nb_msg, int buff_length){
  int clientSocket;
  int buffer_size;
  int res;

  if (buff_length>0)
    buffer_size = buff_length;
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
  serverHostEnt = gethostbyname(IP);
  memcpy(&(cli_addr.sin_addr), serverHostEnt->h_addr, serverHostEnt->h_length);
  
  cli_addr.sin_family = AF_INET;
  cli_addr.sin_port = htons(port);
  
  if (connect(clientSocket, (struct sockaddr *) &cli_addr, sizeof(cli_addr)) < 0) {
    fprintf(stderr, "Connection demand failed\n");
    exit(0);
  }
  
  /* fprintf(stderr, "Connect to server %s:%d\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port)); */
  
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


/*_____________________________________________________________________________________*/
int recv_server(u_short port, int nb_msg, int buff_length){
  int serverSocket;
  int client_socket;
  int buffer_size;
  if (buff_length>0){
    buffer_size = buff_length;
  }
  else
    buffer_size = 128;
  char* buff = (char*) malloc(buffer_size * sizeof(char));
  int res;

  
  if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Error socket");
    exit(1);
  }

  struct sockaddr_in *serv_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
  memset((char *) serv_addr, (char) 0, sizeof(struct sockaddr_in));

  serv_addr->sin_family = AF_INET;
  serv_addr->sin_port = htons(port);
  serv_addr->sin_addr.s_addr = INADDR_ANY;

  socklen_t on = 1;
  if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
    perror("Error setsockopt");
    exit(1);
  }

  if (getsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &on, &on) < 0) {
    perror("Error getsockopt");
    exit(1);
  }
  
  if (bind(serverSocket, (struct sockaddr *) serv_addr, sizeof(struct sockaddr_in)) < 0) {
    perror("Error bind");
    exit(1);
  }
  
  if (listen(serverSocket, SOMAXCONN) < 0) {
    perror("Error listen");
    exit(1);
  }
  /* fprintf(stderr, "Waiting for connexion\n"); */
  
  socklen_t clilen = sizeof(struct sockaddr_in);
  struct sockaddr_in cli_addr;

  if ((client_socket = accept(serverSocket, (struct sockaddr *) &cli_addr, (socklen_t *) &clilen)) < 0) {
    perror("Error accept");
    exit(1);
  }
  
  struct in_addr in = { cli_addr.sin_addr.s_addr };
  /* fprintf(stderr, "Here %d %s\n", cli_addr.sin_addr.s_addr, inet_ntoa(in)); */
  /* fprintf(stderr, "Connect to client  %s:%d\n", inet_ntoa(in), ntohs(cli_addr.sin_port)); */

  int msg_count;
  for (msg_count = 0; msg_count < nb_msg; ++msg_count){
    res = recvfrom(client_socket, buff, buffer_size, 0, (struct sockaddr *) &cli_addr, (socklen_t *) & clilen);
    if (res == -1) {
      perror("Error server reception");
      exit(1);
    }
    /* fprintf(stderr, "Receive message #%d of %d bytes: \"%s\"\n", msg_count, res, buff); */
  }

  shutdown(client_socket, SHUT_RDWR);
  close(client_socket);
  
  return 0;
}

/*_____________________________________________________________________________________*/
int main(int argc, char** argv){
 
  if (argc < 5){
    printf("arguments are missing\n");
    return -1;
  }

  pid_t child_1, child_2;
  if((child_1 = fork()) == 0){
    recv_server(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
    return 0;
  }
    
  if((child_2 = fork()) == 0){
    sendto_client(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
    return 0;
  }

  waitpid(child_1, NULL, 0);
  waitpid(child_2, NULL, 0);
  
  struct tms clock_buf;
  times(&clock_buf);
  
  printf("User CPU time %li \n", clock_buf.tms_utime + clock_buf.tms_cutime);
  printf("System CPU time %li \n", clock_buf.tms_stime + clock_buf.tms_cstime);
  printf("Total CPU time %li \n", clock_buf.tms_utime + clock_buf.tms_cutime + clock_buf.tms_stime + clock_buf.tms_cstime);

  return 0;
}
