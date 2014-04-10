/*  Copyright (c) 2006, Philip Busch <broesel@studcs.uni-sb.de>
 *  All rights reserved.
 *
 *  congruence-free NxN-size queens problem solver (recursive backtracking)
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   - Neither the name of the author nor the names of its contributors may
 *     be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */


/*  Board positions are stored in an int array, where i and a[i] specify the
 *  x- and y-coordinates of queen i.
 *  The code which unifies the solution set will run much faster if the
 *  solution set is represented as a data structure with better seek times
 *  (array, tree, whatever); a linked list is probably the most braindead
 *  approach...
 *
 *  Output may look like this (for a 12x12 board):
 *
 *  congruence-free NxN-size queens problem solver (recursive backtracking)
 *  >>> solving queensproblem:
 *      14200 solutions with 10945856 tries
 *  >>> unifying solution set (approximated cardinality: 1775)
 *      progress: 100.000%  1787/1787
 *      unique solutions: 1787
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>


// linked list node
typedef struct node_l node_l;
struct node_l {
	node_l *next;
	void *data;
};


// prepend node
int list_push(node_l **x, void *data)
{
	node_l *n = NULL;

	assert(x != NULL);

	if((n = (node_l *)malloc(sizeof(node_l))) == NULL) {
		return(-1);
	} else {
		n->data = data;
		n->next = *x;

		*x = n;
		return(0);
	}
}

// compute size
size_t list_size(const node_l *x)
{
	size_t s = 0;

	for(; x != NULL; s++, x = x->next);
	return(s);
}

// remove first node
void *list_pop(node_l **x)
{
	node_l *n = NULL;
	void *data;

	assert(x != NULL);

	if(*x == NULL)
		return(NULL);

	n = *x;
	*x  = n->next;
	data = n->data;
	free(n);

	return(data);
}

// remove Nth node
void *list_remove(node_l **x, int pos)
{
	node_l *current = *x;
	node_l *next = NULL;
	void *data;

	assert(x != NULL);

	if(pos < 0)
	        return(NULL);

	if(*x == NULL)
	        return(NULL);

	if(pos == 0)
	        return(list_pop(x));

	while(--pos) {
		current = current->next;
	}

	if((next = current->next) == NULL)
	        return(NULL);

	data = next->data;
	current->next = next->next;

	free(next);
	return(data);
}

// check for conflicting queens
int board_conflict(int cboard[], int col)
{
	int i;
	
	for(i = 0; i < col; i++) {
		if((cboard[i] == cboard[col])               // same row
		|| (cboard[i] + i == cboard[col] + col)    // same diag
		|| (cboard[i] - i == cboard[col] - col)) { // same diag
		        return(1);
		}
	}
	return(0);
}

// print whole board
void board_print(int cboard[], int size)
{
	int i = 0;
	
	for(; i < size; i++) {
		printf("%i", cboard[i]);
	}
	printf("\n");
}

// compare two boards (0 on equality, -1 otherwise)
int board_comp(int cboardA[], int cboardB[], int size)
{
	int i = 0;

	for(; i < size; i++)
		if(cboardA[i] != cboardB[i])
		        return(-1);

	return(0);
}

// rotate board by 90 degrees
void board_rotate(int dest[], const int src[], int size)
{
	int board[size];
	int i = 0;
	
	for(i = 0; i < size; i++) {
		board[(size-1) - src[i]] = i;
	}

	for(i = 0; i < size; i++) {
		dest[i] = board[i];
	}
}

// mirror board at main diagonal
void board_mirror(int dest[], const int src[], int size)
{
	int i;

	for(i = 0; i < size; i++) {
		dest[src[i]] = i;
	}

}

// print solution set
void sol_print(node_l *s, int size)
{
	while(s != NULL) {
		board_print(s->data, size);
		s = s->next;
	}
}

// remove solution cboard from solution set _s (when unifying)
int sol_remove(node_l **s, int cboard[], int size)
{
	node_l *n = NULL;
	int i = 0;

	assert(s != NULL);
	
	n = *s;
	while(n != NULL) {
		if(board_comp(cboard, n->data, size) == 0) {
			list_remove(s, i);
			return(1);
		}
		i++;
		n = n->next;
	}
	return(0);
}

// remove solutions with rotation congruence from solution set _s
void sol_remove_rotation(node_l **s, int cboard[], int size)
{
	int tmp_board[size];
	int i = 0;

	for(i = 0; i < size; i++)
	        tmp_board[i] = cboard[i];

	for(i = 0; i < 3; i++) {
		board_rotate(tmp_board, tmp_board, size);

		if(board_comp(cboard, tmp_board, size) != 0)
			sol_remove(s, tmp_board, size);
	}
}

// remove solutions with mirror congruence from solution set _s
void sol_remove_mirrors(node_l **s, int cboard[], int size)
{
	int tmp_board[size];

	board_mirror(tmp_board, cboard, size);

	if(board_comp(cboard, tmp_board, size) != 0)
	        sol_remove(s, tmp_board, size);

	sol_remove_rotation(s, tmp_board, size);
}

// store a solution in the solution set _s
int sol_store(node_l **s, int cboard[], int size)
{
	int *cb = NULL;
	int i = 0;

	if((cb = (int *)malloc(sizeof(int) * size)) != NULL) {
		for(i = 0; i < size; i++) {
			cb[i] = cboard[i];
		}
		return(list_push(s, (void *)cb));
	}
	return(-1);
}

// unify solution set _s
void sol_unique(node_l **s, int size)
{
	int tmp_board[size];
	node_l *n = NULL;
	double exp;
	int i = 0;
	size_t sz;

	if(s == NULL)
	        return;

	n = *s;
	sz = list_size(n);
	exp = sz / 7.999;

	printf(">>> unifying solution set (approximated cardinality: %d)\n", (int)exp);

	while(n != NULL) {
		sol_remove_rotation(s, n->data, size);
		sol_remove_mirrors(s, n->data, size);
//		printf("    progress: %02.3f%%\t%i/%i\r", 100.0 * (double)i / exp, i, list_size(*s));
		n = n->next;
		i++;
	}
	
	sz = list_size(*s);
	printf("    progress: %02.3f%%\t%i/%i\t\t\r", 100., sz, sz);

	printf("\n    unique solutions: %i\n", list_size(*s));
}

// no comment
node_l *solve_queensproblem(int size)
{
	int cboard[size];
	int col = 0;
	int solutions = 0;
	int tries     = 0;
	int i = 0;
	node_l *sol = NULL;
	
	// initialize checkerboard
	for(; i < size; i++)
	        cboard[i] = 0;

	printf(">>> solving queensproblem:\n");

	for(;;) {
		if(cboard[col] > size-1) {    // no valid options left, go back
			cboard[col] = 0;
			if(col == 0) break;
			col -= 1;
			cboard[col]++;
		} else if(!board_conflict(cboard, col)) {            // advance
			if(col == size-1) {
				solutions++;
				sol_store(&sol, cboard, size);
				cboard[col]++;
			} else {
				col += 1;
			}
		} else {                             // retry at current column
			cboard[col]++;
		}

		tries++;
	}

	printf("    %i solutions with %i tries\n", solutions, tries);

	return(sol);
}

int main(int argc, char *argv[])
{
	node_l *sol = NULL;
	int size = 0;
/*
	if(argc != 2) {
		printf("USAGE: %s <size>\n", argv[0]);
		exit(EXIT_FAILURE);
	}  */
	
	printf("congruence-free NxN-size queens problem solver (recursive backtracking)\n");
	size = 12;
	sol = solve_queensproblem(size);
sleep(10);

	sol_unique(&sol, size);
//sleep(60);

	return(0);
}
