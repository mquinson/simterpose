#include <stdlib.h>

//#define DEBUG

#include "benchmark.h"

int main(int argc, char** argv)
{
  float flops_per_sec, micros_per_flop;
  start_benchmark(&flops_per_sec, &micros_per_flop);
  
  benchmark_matrix_product(&flops_per_sec, &micros_per_flop);
  
  
  return EXIT_SUCCESS;
}