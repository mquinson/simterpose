#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/timeb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>


#define SERV_PORT 2227

//#define BUFFER_SIZE 1000

#define IP "162.32.43.1"
//#define IP "127.0.0.1"

int main(int argc, char** argv){

  if (argc < 3) {
    fprintf(stderr, "usage: %s number_of_loops buffer_size \n", argv[0]);
    return EXIT_FAILURE;
  }

  int number_of_loops = atoi(argv[1]);
  int buffer_size = atoi(argv[2]);

  int clientSocket;
  u_short port;
  int res;
  char *buff=malloc(buffer_size);
  int server_socket;
  long host_addr;
  struct hostent *serverHostEnt;


  if((clientSocket = socket(AF_INET,SOCK_STREAM,0)) < 0){
    perror("Client : error socket 1");
    exit(1);
  }else{
    
    struct sockaddr_in cli_addr;
    memset(&cli_addr,0,sizeof(struct sockaddr_in));
    host_addr=inet_addr(IP);
    serverHostEnt=gethostbyname(IP);
    memcpy(&(cli_addr.sin_addr),serverHostEnt->h_addr,serverHostEnt->h_length);
    port=SERV_PORT;
    cli_addr.sin_family=AF_INET;
    cli_addr.sin_port=htons(port);

    if(connect(clientSocket,(struct sockaddr *)&cli_addr,sizeof(cli_addr))<0){
      printf("Client : echec demande de connexion 1\n");
      exit(0);
    }else{
      printf("Client : Connexion avec le serveur établie 1\n");
      // while(1){
	//fgets(buff,512,stdin);

      res=send(clientSocket,"message envoye par client\n",buffer_size,0);
      if(res==-1){
	  perror("Client : erreur envoi 1");
	  exit(1);
      }else{
          int length = buffer_size;
          while(length > 0)
          {
            res = recv(clientSocket,buff,length,0);
            if(res==-1){
              perror("Client : erreur réception 1 ");
              exit(1);
            }
            length -= res;
            printf("Client : Message reçu : recv %d (left %d)\n", res, length);
          }
      }
      //}
      shutdown(clientSocket,2);
      close(clientSocket);
    }

  }
  
  if((clientSocket = socket(AF_INET,SOCK_STREAM,0)) < 0){
    perror("Client : error socket 2");
    exit(1);
  }else{
    struct timeval begin;
    struct timespec tvcl;
    struct sockaddr_in cli_addr;
    memset(&cli_addr,0,sizeof(struct sockaddr_in));
    host_addr=inet_addr(IP);
    serverHostEnt=gethostbyname(IP);
    memcpy(&(cli_addr.sin_addr),serverHostEnt->h_addr,serverHostEnt->h_length);
    port=SERV_PORT;
    cli_addr.sin_family=AF_INET;
    cli_addr.sin_port=htons(port);
    
    if(connect(clientSocket,(struct sockaddr *)&cli_addr,sizeof(cli_addr))<0){
      printf("Client : echec demande de connexion 2\n");
      exit(0);
    }else{
    //  printf("Client : Connexion avec le serveur établie\n");
      // while(1){
        //fgets(buff,512,stdin);
      int ia = 0;

      /*   gettimeofday(&begin, NULL); 
      printf("\ngettimeofday du client: %f\n",begin.tv_sec + begin.tv_usec/1000000.0);
      printf("time du client: %d \n",time(NULL));
      clock_gettime(NULL, &tvcl); 
      printf("clock_gettime du client : %f\n\n",tvcl.tv_sec + tvcl.tv_nsec/1000000000.0);*/

      for(ia=0; ia < number_of_loops ; ++ia)
      {
        res=send(clientSocket,buff,buffer_size,0);
        if(res==-1){
          perror("Client : erreur envoi 2");
          exit(1);
        }else{
          int length = buffer_size;
          while(length > 0)
          {
            //printf("New receive waited\n");
            res = recv(clientSocket,buff,length,0);
            if(res==-1){
              printf("Client : loop %d \n",ia);
              perror("Client : erreur réception 2 ");
              exit(1);
            }
            length -= res;
            printf("Client : Message reçu : recv %d (left %d)\n", res, length);
          }
        }
      //  printf("Client : reçu\n");
      }
      //}
       shutdown(clientSocket,2);
       close(clientSocket);
    }
    
    }

  return 0;
}
