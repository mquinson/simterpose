#include <stdio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/time.h>
//%rax	System call		%rdi			%rsi
// 96	sys_gettimeofday	struct timeval *tv	struct timezone *tz	

int main(){
	
	printf("temps début:");
	struct timeval begin;
	gettimeofday(&begin, NULL); 
	printf("%f\n",begin.tv_sec + begin.tv_usec/1000000.0);

	
	int i;
	for(i=0; i<1000000; i++){
	}

	printf("\n temps fin: ");
	struct timeval end;
	gettimeofday(&end, NULL); 
	printf("%f\n",end.tv_sec + end.tv_usec/1000000.0);


	double elapsed = (end.tv_sec - begin.tv_sec) + 
              ((end.tv_usec - begin.tv_usec)/1000000.0);
	printf("\nDifférence: %f secondes \n",elapsed);
}
