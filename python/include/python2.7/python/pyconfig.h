#ifndef __WIN32__
#include <bits/wordsize.h>
#endif	/* !__WIN32__ */

#ifdef __WIN32__
#include "pyconfig-mingw.h"
#else
#if __WORDSIZE == 32
#include "pyconfig-32.h"
#elif __WORDSIZE == 64
#include "pyconfig-64.h"
#else
#error "Unknown word size"
#endif
#endif	/* !__WIN32__ */
