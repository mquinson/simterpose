#ifndef __PEEK_DATA_H 
#define __PEEK_DATA_H

#include "sysdep.h"


void ptrace_cpy(pid_t child, void * dst, void * src, size_t len, char *syscall);


#endif

