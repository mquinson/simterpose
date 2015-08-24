/* local_sendmsg -- A simple client/server communication using sendmsg/recvmsg */
/*  It is used to test the application on the machine only not with Simterpose */

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
#include <errno.h>

int sendmsg_client(char* IP, u_short port, int nb_msg, int buff_length){

  int buffer_size;  
  int clientSocket;
  int res;

  if (buff_length>0)
    buffer_size = buff_length;
  else
    buffer_size = 128;
  char* buff = (char*) malloc(buffer_size * sizeof(char));
  memset(buff, 65, (buffer_size-1)*sizeof(char));
  buff[buffer_size] = '\0';

  /* fprintf(stderr, "Client starting: #msg: %d; size:%d (the server is on %s:%d) \n", nb_msg, buffer_size, IP, port); */
 
  /* strcpy(buff, "Message from client "); */
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
    perror("Client cannot connect to the server\n");
    exit(1);
  }

  /* fprintf(stderr, "Connected to the server %s:%d\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port)); */
  struct iovec iov[1];
  struct msghdr msg;

  int msg_number = 0;

  for (msg_number = 0; msg_number < nb_msg; ++msg_number) {
    memset(&msg, 0, sizeof(struct msghdr));
    /* sprintf(buff, "This is the message #%d produced on the client.", msg_number); */
   
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
    /* fprintf(stderr, "Client: Message send #%d\n", msg_number); */

  }
  
  shutdown(clientSocket, 2);
  close(clientSocket);
 
  /* fprintf(stderr, "Client exiting after %d msgs \n", nb_msg); */
  
  return 0;
}


/*_____________________________________________________________________________________*/
int recvmsg_server(u_short port, int nb_msg, int buff_length){

  int msg_size;

 if (buff_length>0){
    msg_size = buff_length;
  }
  else
    msg_size = 128;
  char* buff = (char*) malloc(msg_size * sizeof(char));

  /* fprintf(stderr, "Server starting on port %d: #msg: %d; size: %d \n", port, nb_msg, msg_size); */

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
  /* fprintf(stderr, "Server: Waiting for incoming requests\n"); */

  int clilen = sizeof(struct sockaddr_in);
  struct sockaddr_in *cli_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));

  if ((client_socket = accept(serverSocket, (struct sockaddr *) cli_addr, (socklen_t *) & clilen)) < 0) {
    perror("Server: error accepting real connection");
    exit(1);
  }
  struct iovec iov[1];
  struct msghdr msg;
  int msg_number = 0;
  for (msg_number = 0; msg_number < nb_msg; ++msg_number) {
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

/*_____________________________________________________________________________________*/
int main(int argc, char** argv){
 
  if (argc < 5){
    printf("arguments are missing\n");
    return -1;
  }

  pid_t child_1, child_2;
  if((child_1 = fork()) == 0){
    recvmsg_server(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
    return 0;
  }
    
  if((child_2 = fork()) == 0){
    sendmsg_client(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
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
