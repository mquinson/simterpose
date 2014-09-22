#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


int main()
{

  struct pollfd fich[3] = { {0, POLLIN | POLLPRI, 0}, {0, POLLIN | POLLPRI | POLLOUT, 0}, {0, POLLIN, 0} };

  int res;

  fich[0].fd = open("../applications/fork.c", O_RDONLY);
  fich[1].fd = open("../applications/server.c", O_RDWR);
  fich[2].fd = open("../applications/server.c", O_WRONLY);

  res = poll(NULL, 3, 2500);



}
