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
  struct timeval * ti = (struct timeval * ) malloc(sizeof(struct timeval));
  gettimeofday(ti, NULL);
  printf("Time with gettimeofday: %lld %lld\n", (long long) ti->tv_sec,  (long long) ti->tv_usec);
  char * ti_s = (char *) malloc(sizeof(char));
  ti_s = ctime(&ti->tv_sec);
  char * ti_us = (char *) malloc(sizeof(char));
  ti_us = ctime(&ti->tv_usec);
  printf("Time with gettimeofday in char: %s %s\n", ti_s, ti_us);

  int fd = open("apps/toto", O_RDWR);
  int fd_creat = creat("apps/test.txt", S_IRWXU);

  /* dup2(fd, 15); */
  dup(fd);

  int flags;
  flags = fcntl(fd, F_GETFD);
  /* printf("F_GETFD: Value of FD_CLOEXEC %d for fd %d\n", flags, fd); */
  flags = fcntl(fd, F_SETFD, FD_CLOEXEC);
  /* printf("F_SETFD: Return value %d  for fd %d\n", flags, fd); */
  flags = fcntl(fd, F_GETFD);
  /* printf("F_GETFD: Value of FD_CLOEXEC %d for fd %d\n", flags, fd); */
  /* printf("----------------------------------------\n"); */

  int fd_dup;
  fd_dup = fcntl(fd, F_DUPFD, 10);
  /* printf("F_DUPFD: Value of fd_dup %d  for fd %d\n", fd_dup, fd); */
  flags = fcntl(fd_dup, F_GETFD);
  /* printf("F_GETFD: Value of FD_CLOEXEC %d for fd %d\n", flags, fd_dup); */
  flags = fcntl(fd_dup, F_SETFD, FD_CLOEXEC);
  /* printf("F_SETFD: Return value %d  for fd %d\n", flags, fd); */
  flags = fcntl(fd_dup, F_GETFD);
  /* printf("F_GETFD: Value of FD_CLOEXEC %d for fd %d\n", flags, fd); */
  /* printf("----------------------------------------\n"); */


  fd_dup = fcntl(fd, F_DUPFD_CLOEXEC, 10);
  /* printf("F_DUPFD_CLOEXEC: Value of fd_dup %d for fd %d\n", fd_dup, fd); */
  flags = fcntl(fd_dup, F_GETFD);
  /* printf("F_GETFD: Value of FD_CLOEXEC %d for fd %d\n", flags, fd_dup); */
  /* printf("----------------------------------------\n"); */

  int ret;
  /* int fd_dup_sys = dup(fd); */
  /* printf("fd_dup %d\n", fd_dup_sys); */
  ret = dup2(fd, fd_dup);
  /* ret = dup2(fd, fd_dup_sys); */
  /* printf("ret dup %d\n", ret); */

  int status_flags;
  status_flags =  fcntl(fd, F_GETFL);
  /* printf("F_GETFL: Value of status flags %d for fd %d\n", status_flags, fd); */
  status_flags = fcntl(fd, F_SETFL, O_RDONLY);
  /* printf("F_SETFL: Return value %d  for fd %d\n", status_flags, fd); */
  status_flags = fcntl(fd, F_SETFL, O_APPEND);
  /* printf("F_SETFL: Return value %d  for fd %d\n", status_flags, fd); */
  status_flags =  fcntl(fd, F_GETFL);
  /* printf("F_GETFL: Value of status flags %d for fd %d\n", status_flags, fd); */
  /* printf("----------------------------------------\n"); */

  struct flock * lock = (struct flock *) malloc(sizeof(struct flock));
  lock->l_type = F_RDLCK;
  lock->l_whence = SEEK_SET;
  lock->l_start = 0;
  lock->l_len = 15;
  lock->l_pid = getpid();

  /* int ret; */
  ret = fcntl(fd, F_GETLK, lock);
  /* printf("F_GETLK: Return value %d for fd %d \n", ret, fd); */
  lock->l_type = F_RDLCK;
  ret = fcntl(fd, F_SETLK, lock);
  /* printf("F_SETLK: Return value %d  for fd %d \n", ret, fd); */
  ret = fcntl(fd, F_GETLK, lock);
  /* printf("F_GETLK: Return value %d for fd %d \n", ret, fd); */
  free(lock);

  /* printf("----------------------------------------\n"); */
  /* printf("valeur cmd %d\n", F_GETOWN); */
  ret = fcntl(fd, F_GETOWN);
  /* printf("F_GETOWN: ID of signals' receptor %d for fd %d \n", ret, fd); */
  ret = fcntl(fd, F_SETOWN, getpid());
  /* printf("F_SETOWN: Return value %d for fd %d \n", ret, fd); */
  ret = fcntl(fd, F_GETOWN);
  /* printf("F_GETOWN: ID of signals' receptor %d for fd %d \n", ret, fd); */

  /* printf("----------------------------------------\n"); */
  ret = write(fd, "abcdefge", 8);
  printf("[%d] write(%d, abcdefge, 8) = %d\n", getpid(), fd, ret);
  char * buf = (char *) malloc(8*sizeof(char));
  ret = lseek(fd, 0, SEEK_SET);
  ret = read(fd, buf, 8);
  printf("[%d] read(%d, %s, 8) = %d\n", getpid(), fd, buf, ret);

  /* printf("----------------------------------------\n"); */
  ret = lseek(fd, 150, SEEK_CUR);

  ret = close(fd);
  ret = close(fd_dup);

  gettimeofday(ti, NULL);
  printf("Time with gettimeofday: %lld %lld\n", (long long) ti->tv_sec,  (long long) ti->tv_usec);

  ti_s = ctime(&ti->tv_sec);
  ti_us = ctime(&ti->tv_usec);
  printf("Time with gettimeofday in char: %s %s\n", ti_s, ti_us);

  struct timespec *tp = (struct timespec *) malloc(sizeof(struct timespec));
  clock_gettime(CLOCK_REALTIME, tp);
  printf("Time with clock_gettime: %d %ld\n", tp->tv_sec, tp->tv_nsec);
  
  return 0;
}
