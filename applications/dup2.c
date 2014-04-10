#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#define BUFSIZE 20

void fonc_mail(){
  int fd[2];
  int status;
  pipe(fd);
  char bufout[BUFSIZE] = "bou ";
  char bufin[BUFSIZE];
  if(fork()>0){  
    write(fd[1],bufout, BUFSIZE);
    close(fd[0]); 
  }else{
    dup2(fd[0],0);
    close(fd[1]);
    if(fork()>0){
      execlp("mail","mail","-s","bou", "marion.guthmuller@loria.fr",NULL);
    }else{
      wait(&status);
    }
  }
}

int main(){
  struct sigaction sig, old;
  sig.sa_handler=fonc_mail;
  sigaction(SIGALRM,&sig,&old);
  alarm(3);
  pause();
}
