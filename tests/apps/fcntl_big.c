/* fcntl syscall over little file */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */
/* Author Louisa Bessad */

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
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#define SERV_PORT 2227

#define BUFFER_SIZE 1024


int main()
{
  int fd = open("text_big.txt", O_RDONLY);
  printf("valuer de fd %d\n", fd);
  int flags;

  flags =   fcntl(fd, F_GETFD, 0);
  printf("value of flags %d\n", flags);
  flags = fcntl(fd, F_SETFD, O_RDWR | O_NONBLOCK);
  printf("value of flags %d after SETFL\n", flags);

  int fd_dup;
  fd_dup = fcntl(fd, F_DUPFD, 10);
  printf("valeur of fd_dup %d\n", fd_dup);

  int status_flags;

  flags =   fcntl(fd, F_GETFL, 0);
  printf("value of status flags %d\n", status_flags);
  flags = fcntl(fd, F_SETFL, O_RDWR | O_NONBLOCK);
  printf("value of status flags %d after SETFL\n", status_flags);

  struct flock * lock = (struct flock *) malloc(sizeof(struct flock));
  lock->l_type = F_RDLCK;
  lock->l_whence = SEEK_SET;
  lock->l_start = 0;
  lock->l_len = 15;
  lock->l_pid = getpid();
  int ret;
  ret = fcntl(fd, F_SETLK, lock); 
  printf("valeur de retour de setlk %d \n", ret);
  ret = fcntl(fd, F_GETLK, lock);
  printf("valeur de retour de getlk %d \n", ret);
  free(lock);

  ret = fcntl(fd, F_GETOWN);
  printf("valeur de recpteur de signaux %d \n", ret);
  ret = fcntl(fd, F_SETOWN, getpid());
  printf("valeur de recpteur de signaux %d \n", ret);

  return 0;
}
