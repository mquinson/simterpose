#ifndef INCLUDE_BENCHMARK_H
#define INCLUDE_BENCHMARK_H

/*Be carefull, benchmark do is own init and finish cputime, so dont use it between an init and a finish cputime*/
int start_benchmark(float *flop_per_sec, float *micro_s_per_flop);

int benchmark_matrix_product(float *flop_per_sec, float* ms_per_flop);

#endif