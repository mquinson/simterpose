#include "parser.h" /* for launcher proc desc*/

void init_all_process()
{
  //on lance le launcher
  //et on le bloque avant qu'il exécute
  //on écrit ensuite sur le file le nombre de process à lancer
  //et on écrit le premier processus à lancer
  
  //pour 0 .. nb_process dans launcher_procdesc
    //Tant que le launcher ne fait pas de fork
      //s'il fait pas un fork on le relance
      //sinon on crée le processus et on passe au suivant
    //on écrit le prochain nom de processus
    //on relance le launcher
  
}