#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) 
{
  FILE *f1, *f2;	
  char buff1[100];
  char buff2[100];
  int var = 0;
  int line = 0; 
  
  if (argc < 3) {
    fprintf(stderr, "usage: %s file1 file2 \n", argv[0]);
    exit(0);
  }

    f1 = fopen(argv[1],  "r" );
  if (f1 == NULL) {
    printf("Can't open %s for reading\n", argv[1]);
    exit(0);
  }
    f2 = fopen(argv[2],  "r" ) ;
  if (f2 == NULL) {
    printf("Can't open %s for reading\n", argv[2]);
    exit(0);
  }
  
  while (((fgets(buff1, 100, f1)) && (fgets(buff2, 100, f2))) != NULL) {
    ++line;
    var = strcmp(buff1, buff2);           
      if (var != 0){
        printf("Difference on line %i.\n", line);	      
	fclose(f1);
	fclose(f2);
	exit(0);
      }
      
  }
  
  printf("Same files\n"); 
  fclose(f1);
  fclose(f2);

  return(0);
 }


