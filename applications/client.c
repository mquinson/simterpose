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
#include <errno.h>


#define SERV_PORT 2227

#define BUFFER_SIZE 100000

int main(){

  int clientSocket;
  u_short port;
  int res;
  char *buff=malloc(BUFFER_SIZE);
  int server_socket;
  long host_addr;
  struct hostent *serverHostEnt;


  if((clientSocket = socket(AF_INET,SOCK_STREAM,0)) < 0){
    perror("error socket");
    exit(1);
  }else{
    
    struct sockaddr_in cli_addr;
    memset(&cli_addr,0,sizeof(struct sockaddr_in));
    host_addr=inet_addr("127.0.0.1");/*162.32.43.1*/
    serverHostEnt=gethostbyname("127.0.0.1");
    memcpy(&(cli_addr.sin_addr),serverHostEnt->h_addr,serverHostEnt->h_length);
    port=SERV_PORT;
    cli_addr.sin_family=AF_INET;
    cli_addr.sin_port=htons(port);

    if(connect(clientSocket,(struct sockaddr *)&cli_addr,sizeof(cli_addr))<0){
      printf("%s : echec demande de connexion\n", strerror(errno));
      exit(0);
    }else{
      printf("Connexion avec le serveur établie\n");
      // while(1){
	//fgets(buff,512,stdin);
      res=send(clientSocket,buff,BUFFER_SIZE,0);
	int i=0;
	int j;
	for(i=0; i<2000000 ; ++i)
	{
	  j=i*(i%14);
	  --j;
	}
	if(res==-1){
	  perror("erreur envoi client");
	  exit(1);
	}else{
	  res=recv(clientSocket,buff,BUFFER_SIZE,0);
	  if(res==-1){
	    perror("erreur reception client");
	    exit(1);
	  }else{
	    printf("Message reçu : %s",buff);
	  }
	}
	//}
//       shutdown(clientSocket,2);
//       close(clientSocket);
    }

  }
  
  if((clientSocket = socket(AF_INET,SOCK_STREAM,0)) < 0){
    perror("error socket");
    exit(1);
  }else{
    
    struct sockaddr_in cli_addr;
    memset(&cli_addr,0,sizeof(struct sockaddr_in));
    host_addr=inet_addr("162.32.43.1");
    serverHostEnt=gethostbyname("162.32.43.1");
    memcpy(&(cli_addr.sin_addr),serverHostEnt->h_addr,serverHostEnt->h_length);
    port=SERV_PORT;
    cli_addr.sin_family=AF_INET;
    cli_addr.sin_port=htons(port);
    
    if(connect(clientSocket,(struct sockaddr *)&cli_addr,sizeof(cli_addr))<0){
      printf("%s : echec demande de connexion\n", strerror(errno));
      exit(0);
    }else{
      printf("Connexion avec le serveur établie\n");
      // while(1){
        //fgets(buff,512,stdin);
      res=send(clientSocket,buff,BUFFER_SIZE,0);
      int i=0;
      int j;
      for(i=0; i<2000000 ; ++i)
      {
        j=i*(i%14);
        --j;
      }
      if(res==-1){
        perror("erreur envoi client");
        exit(1);
      }else{
        res=recv(clientSocket,buff,BUFFER_SIZE,0);
        if(res==-1){
          perror("erreur reception client");
          exit(1);
        }else{
          printf("Message reçu : %s",buff);
        }
      }
      //}
//       shutdown(clientSocket,2);
//       close(clientSocket);
    }
    
  }

  return 0;
}
