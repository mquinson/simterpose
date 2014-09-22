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


#define SERV_PORT 2222

int main(int argc, char *argv[])
{

  int clientSocket;
  u_short port;
  int res;
  char *buff = malloc(512);
  int server_socket;
  long host_addr;
  struct hostent *serverHostEnt;
  char *prog = malloc(512);
  int nb_exe = 0;
  int size_mess = 0;
  int status;

  if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("error socket");
    exit(1);
  } else {

    struct sockaddr_in cli_addr;
    memset(&cli_addr, 0, sizeof(struct sockaddr_in));
    host_addr = inet_addr("127.0.0.1");
    serverHostEnt = gethostbyname("127.0.0.1");
    memcpy(&(cli_addr.sin_addr), serverHostEnt->h_addr, serverHostEnt->h_length);
    port = SERV_PORT;
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_port = htons(port);

    if (connect(clientSocket, (struct sockaddr *) &cli_addr, sizeof(cli_addr)) < 0) {
      printf("echec demande de connexion\n");
      exit(1);
    }
    printf("Connexion avec le serveur établie\n");
    nb_exe = atoi(argv[1]);     //nb exec
    printf("Nombre d'executions : %d\n", nb_exe);
    size_mess = atoi(argv[2]);  // taille mess retour
    printf("Taille message retour : %d\n", size_mess);
    // execution prog
    int pid = fork();
    if (pid == 0) {
      int i;
      for (i = 0; i < nb_exe; i++) {
        if (fork() == 0) {
          if (execl("../applications/chess_advanced", "../applications/chess_advanced", NULL) == -1) {
            perror("execl");
            exit(1);
          }
        } else {
          wait(&status);
        }
      }
    } else {
      waitpid(pid, NULL, 0);
      res = send(clientSocket, "Calcul complet terminé !", size_mess, 0);
      if (res == -1) {
        perror("erreur envoi client");
        exit(1);
      }
    }

  }

}
