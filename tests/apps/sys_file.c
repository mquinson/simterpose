/* sysfile syscall test */
/* Some weird things occur with the two last series of test*/

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */
/* Author Louisa Bessad */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

int main()
{
  int fd = open("apps/toto", O_RDWR);
  creat("apps/test.txt", S_IRWXU);

  /* dup2(fd, 15); */
  dup(fd);
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

  /* int fd_dup_sys = dup(fd); */
  dup2(fd, fd_dup);
  /* dup2(fd, fd_dup_sys); */

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
  
  write(fd, "abcdefge", 8);
  
  char * buf = (char *) malloc(8*sizeof(char));
  lseek(fd, 0, SEEK_SET);
  read(fd, buf, 8);

  lseek(fd, 150, SEEK_CUR);

  close(fd);
  close(fd_dup);
  
  return 0;
}
