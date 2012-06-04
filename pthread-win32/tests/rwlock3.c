/*
 * rwlock3.c
 *
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 * --------------------------------------------------------------------------
 *
 * Declare a static rwlock object, wrlock it, trywrlock it,
 * and then unlock it again.
 *
 * Depends on API functions:
 *	pthread_create()
 *	pthread_join()
 *	pthread_rwlock_wrlock()
 *	pthread_rwlock_trywrlock()
 *	pthread_rwlock_unlock()
 */

#include "test.h"

static pthread_rwlock_t rwlock1 = PTHREAD_RWLOCK_INITIALIZER;

static int washere = 0;

static void * func(void * arg)
{
  assert(pthread_rwlock_trywrlock(&rwlock1) == EBUSY);

  washere = 1;

  return 0;
}

#ifndef MONOLITHIC_PTHREAD_TESTS
int
main()
#else
int
test_rwlock3(void)
#endif
{
  pthread_t t;

  assert(pthread_rwlock_wrlock(&rwlock1) == 0);

  assert(pthread_create(&t, NULL, func, NULL) == 0);

  assert(pthread_join(t, NULL) == 0);

  assert(pthread_rwlock_unlock(&rwlock1) == 0);

  assert(washere == 1);

  return 0;
}
