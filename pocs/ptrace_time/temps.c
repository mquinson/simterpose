#include <stdio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/time.h>
//%rax	System call		%rdi			%rsi
// 96	sys_gettimeofday	struct timeval *tv	struct timezone *tz	

int main(){
	
	printf("temps début (gettimeofday):");
	struct timeval begin;
	gettimeofday(&begin, NULL); 
	printf("%f\n\n",begin.tv_sec + begin.tv_usec/1000000.0);


	printf("temps début  (time) : %d \n\n",time(NULL));

	struct timespec tvcl;
	clock_gettime(NULL, &tvcl); 
	printf("temps début  (clock_gettime) : %f\n\n",tvcl.tv_sec + tvcl.tv_nsec/1000000000.0);
	
	int i;
	for(i=0; i<1000000; i++){
	}

	printf("\n temps fin (gettimeofday): ");
	struct timeval end;
	gettimeofday(&end, NULL); 
	printf("%f\n\n",end.tv_sec + end.tv_usec/1000000.0);
	
	printf("temps fin  (time) : %d \n\n",time(NULL));

	struct timespec tvcl_end;
	clock_gettime(NULL, &tvcl_end); 
	printf("temps fin (clock_gettime) : %f\n\n",tvcl_end.tv_sec + tvcl_end.tv_nsec/1000000000.0);


	double elapsed = (end.tv_sec - begin.tv_sec) + 
              ((end.tv_usec - begin.tv_usec)/1000000.0);
	printf("\nDifférence (gettimeofday): %f secondes \n",elapsed);

	double elapsed_clock = (tvcl_end.tv_sec - tvcl.tv_sec) + 
              ((tvcl_end.tv_nsec - tvcl.tv_nsec)/1000000000.0);
	printf("\nDifférence (clock): %f secondes \n",elapsed_clock);
}
