#include <stdio.h>
#include <sys/types.h> 
#include <unistd.h> 

int main(){ 

  dup(0);
  int current_uid = getuid();

  if (setuid(0)){ 
    perror("setuid"); 
    return 1; 
  } 
  
  // Je suis maintenant root!
  printf("My UID is: %d. My GID is: %d\n", getuid(), getgid());
  system("/usr/bin/id"); 

  // Est temps de redescendre à des privilèges d'utilisateur ordinaire
  setuid(current_uid);
  printf("My UID is: %d. My GID is: %d\n", getuid(), getgid()); 
  system("/usr/bin/id"); 
  
  return 0; 
  
}  
