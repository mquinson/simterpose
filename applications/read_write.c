#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(){

  char *buff=malloc(512);
  int f=open("./file_rw","O_RDWR");
  fgets(buff,512,stdin);
  write(f,buff,512);
  close(f);

}
