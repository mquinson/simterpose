#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main()
{

  int i;
  int n = 3;
  for (i = 0; i < n; i++) {
    printf("Appel fork n°%d\n", i + 1);
    if (fork() == 0) {
      printf("Message du fils numéro %d\n", i + 1);
      exit(0);
    }
  }
  for (i = 0; i < n; i++) {
    wait(NULL);
  }
}
