#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#define __USE_GNU

#include <dlfcn.h>


typedef struct {
    void *arg;
    void *(*fn)(void *);
} real_args;


/*
 * PTHREAD_CREATE
 */
int pthread_create(pthread_t  *thread, __const pthread_attr_t *attr, void * (*start_routine)(void *), void * arg)
{
  fprintf(stdout, "Intercepted pthread_create\n");

  real_args args;
#if 0
  static void *handle = NULL;
#endif
  static int (*real_pthread_create)(pthread_t  *, __const pthread_attr_t *, void * (*)(void *), void *) = NULL;

  args.arg = arg;
  args.fn = start_routine;

  if (real_pthread_create == NULL) {
#if 0
    handle = dlopen("/usr/lib/libpthread.so", RTLD_LAZY);
    if (handle == NULL) {
      fprintf(stderr, "dlopen(%s) failed\n", "/usr/lib/libpthread.so");
      exit(1);
    }
#endif
    real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
    if (real_pthread_create == NULL) {
      fprintf(stderr, "dlsym(%s) failed\n", "pthread_create");
      exit(1);
    }
  }
  return (real_pthread_create(thread, attr, args.fn, args.arg));
}


/*
 * PTHREAD_MUTEX_DESTROY
 */
int pthread_mutex_destroy (pthread_mutex_t * mutex)
{
  fprintf(stdout, "Intercepted pthread_mutex_destroy\n");

#if 0
  static void *handle = NULL;
#endif
  static int (*real_pthread_mutex_destroy)(pthread_mutex_t * mutex ) = NULL;

  if (real_pthread_mutex_destroy == NULL) {
#if 0
    handle = dlopen("/usr/lib/libpthread.so", RTLD_LAZY);
    if (handle == NULL) {
      fprintf(stderr, "dlopen(%s) failed\n", "/usr/lib/libpthread.so");
      exit(1);
    }
#endif
    real_pthread_mutex_destroy = dlsym(RTLD_NEXT, "pthread_mutex_destroy");
    if (real_pthread_mutex_destroy == NULL) {
      fprintf(stderr,"dlsym(%s) failed\n","pthread_mutex_destroy");
      exit(1);
    }
  }
  return (real_pthread_mutex_destroy(mutex));
}


/*
 * PTHREAD_MUTEX_LOCK
 */
int pthread_mutex_lock (pthread_mutex_t * mutex )
{
  fprintf(stdout, "Intercepted pthread_mutex_lock\n");

#if 0
  static void *handle = NULL;
#endif
  static int (*real_pthread_mutex_lock)(pthread_mutex_t * mutex ) = NULL;

  if (real_pthread_mutex_lock == NULL) {
#if 0
    handle = dlopen("/usr/lib/libpthread.so",RTLD_LAZY);
    if (handle == NULL) {
      fprintf(stderr,"dlopen(%s) failed\n","/usr/lib/libpthread.so");
      exit(1);
    }
#endif
    real_pthread_mutex_lock = dlsym(RTLD_NEXT, "pthread_mutex_lock");
    if (real_pthread_mutex_lock == NULL) {
      fprintf(stderr, "dlsym(%s) failed\n", "pthread_mutex_lock");
      exit(1);
    }
  }
  return (real_pthread_mutex_lock(mutex));
}


/*
 * PTHREAD_MUTEX_TRYLOCK
 */
int pthread_mutex_trylock (pthread_mutex_t * mutex )
{
  fprintf(stdout, "Intercepted pthread_mutex_trylock\n");

#if 0
  static void *handle = NULL;
#endif
  static int (*real_pthread_mutex_trylock)(pthread_mutex_t * mutex ) = NULL;

  if (real_pthread_mutex_trylock == NULL) {
#if 0
    handle = dlopen("/usr/lib/libpthread.so", RTLD_LAZY);
    if (handle == NULL) {
      fprintf(stderr, "dlopen(%s) failed\n", "/usr/lib/libpthread.so");
      exit(1);
    }
#endif
    real_pthread_mutex_trylock = dlsym(RTLD_NEXT, "pthread_mutex_trylock");
    if (real_pthread_mutex_trylock == NULL) {
      fprintf(stderr, "dlsym(%s) failed\n", "pthread_mutex_trylock");
      exit(1);
    }
  }
  return (real_pthread_mutex_trylock(mutex));
}


/*
 * PTHREAD_MUTEX_UNLOCK
 */
int pthread_mutex_unlock (pthread_mutex_t * mutex )
{
  fprintf(stdout, "Intercepted pthread_mutex_unlock\n");

#if 0
  static void *handle = NULL;
#endif
  static int (*real_pthread_mutex_unlock)(pthread_mutex_t * mutex ) = NULL;

  if (real_pthread_mutex_unlock == NULL) {
#if 0
    handle = dlopen("/usr/lib/libpthread.so", RTLD_LAZY);
    if (handle == NULL) {
      fprintf(stderr, "dlopen(%s) failed\n", "/usr/lib/libpthread.so");
      exit(1);
    }
#endif
    real_pthread_mutex_unlock = dlsym(RTLD_NEXT, "pthread_mutex_unlock");
    if (real_pthread_mutex_unlock == NULL) {
      fprintf(stderr, "dlsym(%s) failed\n", "pthread_mutex_unlock");
      exit(1);
    }
  }
  return (real_pthread_mutex_unlock(mutex));
}


/*
 * PTHREAD_MUTEX_INIT
 */
int pthread_mutex_init (pthread_mutex_t * mutex , const pthread_mutexattr_t * attr )
{
  fprintf(stdout, "Intercepted pthread_mutex_init\n");

#if 0
  static void *handle = NULL;
#endif
  static int (*real_pthread_mutex_init)(pthread_mutex_t * mutex , const pthread_mutexattr_t * attr ) = NULL;

  if (real_pthread_mutex_init == NULL) {
#if 0
    handle = dlopen("/usr/lib/libpthread.so", RTLD_LAZY);
    if (handle == NULL) {
      fprintf(stderr, "dlopen(%s) failed\n", "/usr/lib/libpthread.so");
      exit(1);
    }
#endif
    real_pthread_mutex_init = dlsym(RTLD_NEXT, "pthread_mutex_init");
    if (real_pthread_mutex_init == NULL) {
      fprintf(stderr,"dlsym(%s) failed\n","pthread_mutex_init");
      exit(1);
    }
  }
  return (real_pthread_mutex_init(mutex, attr));
}

