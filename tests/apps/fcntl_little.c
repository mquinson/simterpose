/* fcntl syscall test over little file */
/* Some weird things occur with the two last series of test*/

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */
/* Author Louisa Bessad */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>

int main()
{
 
  int fd = open("apps/test_little.txt", O_RDWR);
    
  fcntl(fd, F_GETFD);
  fcntl(fd, F_SETFD, FD_CLOEXEC);
  fcntl(fd, F_GETFD);

  int fd_dup;
  fd_dup = fcntl(fd, F_DUPFD, 10);
  fcntl(fd_dup, F_GETFD);
  fcntl(fd_dup, F_SETFD, FD_CLOEXEC);
  fcntl(fd_dup, F_GETFD);

  fd_dup = fcntl(fd, F_DUPFD_CLOEXEC, 10);
  fcntl(fd_dup, F_GETFD);

  fcntl(fd, F_GETFL);
  fcntl(fd, F_SETFL, O_RDONLY);
  fcntl(fd, F_SETFL, O_APPEND);
  fcntl(fd, F_GETFL);

  struct flock * lock = (struct flock *) malloc(sizeof(struct flock));
  lock->l_type = F_RDLCK;
  lock->l_whence = SEEK_SET;
  lock->l_start = 0;
  lock->l_len = 15;
  lock->l_pid = getpid();

  fcntl(fd, F_GETLK, lock);
  lock->l_type = F_RDLCK;
  fcntl(fd, F_SETLK, lock);
  fcntl(fd, F_GETLK, lock);
  free(lock);

  fcntl(fd, F_GETOWN);
  fcntl(fd, F_SETOWN, getpid());
  fcntl(fd, F_GETOWN);

  close(fd);
  close(fd_dup);
  
  return 0;
}
