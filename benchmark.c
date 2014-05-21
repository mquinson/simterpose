#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "xbt/log.h"

#include "calc_times_proc.h"

#define NOMBRE_BOUCLE 10000000
#define OPERATION_PER_LOOP 4

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(BENCHMARK, ST, "benchmark log");


int start_benchmark(float *flop_per_sec, float *ms_per_flop)
{
  srand(time(NULL));
  init_cputime();
  long long int times[3];
  long long int result;
  pid_t pid = getpid();
  XBT_DEBUG("Starting benchmark for %d", pid);

  if (!ask_time(pid, times)) {
    long long int initialTime = times[1] + times[2];
    int i;
    float a = rand() % 20;
    float b = rand() % 40;
    float c = rand() % 47;
    for (i = NOMBRE_BOUCLE; i >= 0; --i) {
      b = (float) (a * c);
      b = (float) (a + c);
      b = (float) (a - b);
      b = (float) (a / c);
    }
    ask_time(pid, times);
    result = (times[1] + times[2]) - initialTime;
    XBT_DEBUG("Duration of benchmark : %lld", result);

    *ms_per_flop = ((float) result) / (NOMBRE_BOUCLE * OPERATION_PER_LOOP);
    *flop_per_sec = (1000000.) / (*ms_per_flop);

    XBT_DEBUG("Result for benchmark : %f -> (%f flops)", *ms_per_flop, *flop_per_sec);

  } else {
    XBT_DEBUG("Unable to have system time");

    return -1;
  }


  finish_cputime();

  return EXIT_SUCCESS;
}


//#define MATRIX_SIZE 100

int benchmark_matrix_product(float *flop_per_sec, float *ms_per_flop)
{
  srand(time(NULL));
  int matrixSize = rand() % 20 + 500;

  int i, j;


  float **matrix1 = malloc(sizeof(float *) * matrixSize);
  float **matrix2 = malloc(sizeof(float *) * matrixSize);
  float **matrix_result = malloc(sizeof(float *) * matrixSize);

  for (i = 0; i < matrixSize; ++i) {
    matrix1[i] = malloc(sizeof(float) * matrixSize);
    matrix2[i] = malloc(sizeof(float) * matrixSize);
    matrix_result[i] = malloc(sizeof(float) * matrixSize);
    for (j = 0; j < matrixSize; ++j) {
      matrix1[i][j] = rand() % 20;
      matrix2[i][j] = rand() % 20;
      matrix_result[i][j] = rand() % 20;
    }
  }

  long long int times[3];
  long long int result;

  pid_t pid = getpid();

  init_cputime();

  if (!ask_time(pid, times)) {
    long long int initialTime = times[1] + times[2];
    int i_result, j_result;

    for (j_result = 0; j_result < matrixSize; ++j_result) {
      for (i_result = 0; i_result < matrixSize; ++i_result) {
        for (i = 0; i < matrixSize; ++i) {
          matrix_result[j_result][i_result] =
              matrix_result[i_result][j_result] + matrix1[i_result][i] * matrix2[i][j_result];
        }
      }
    }


    ask_time(pid, times);
    result = (times[1] + times[2]) - initialTime;
    XBT_DEBUG("Duration of benchmark : %lld", result);

    *ms_per_flop = ((float) result) / (2. * matrixSize * matrixSize * matrixSize);
    *flop_per_sec = (1000000.) / (*ms_per_flop);

    XBT_DEBUG("Result for benchmark : %f -> (%f flops)", *ms_per_flop, *flop_per_sec);

  }

  finish_cputime();

  return EXIT_SUCCESS;
}
