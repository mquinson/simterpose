#include <stdio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/time.h>

int main(){
	
	printf("temps début: ");
	struct timeval begin;
	gettimeofday(&begin, NULL); 
	printf("%ld\n",begin.tv_sec + begin.tv_usec/1000000.0);

	int i;
	for(i=0; i<1000000; i++){
	}
		
	printf("\n temps fin: ");
	struct timeval end;
	gettimeofday(&end, NULL); 
	printf("%ld\n",end.tv_sec + end.tv_usec/1000000.0);

	double elapsed = (end.tv_sec - begin.tv_sec) + 
              ((end.tv_usec - begin.tv_usec)/1000000.0);
	printf("Différence: %f secondes \n",elapsed);
}
