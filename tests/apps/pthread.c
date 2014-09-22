#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

void *hello(void *arg)
{

  int *id = (int *) arg;
  printf("%d : hello world \n", *id);
  dup(*id);
  pthread_exit(NULL);

}

int main()
{

  pthread_t threads[3];
  int id[3] = { 1, 2, 3 };
  int i;
  int n = 10;

  for (i = 0; i < n; i++) {
    printf("Crée thread %d\n", i + 1);
    pthread_create(&threads[i], NULL, hello, (void *) &id[i]);
  }
  for (i = 0; i < n; i++) {
    pthread_join(threads[i], NULL);
  }
  pthread_exit(NULL);


}
