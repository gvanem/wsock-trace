#ifndef MAXMINDDB_CONFIG_H
#define MAXMINDDB_CONFIG_H

/* Using or building the MaxMindDB library using
 * MSVC or clang-cl in '_DEBUG'-mode.
 */
#if defined(_MSC_VER) && defined(_DEBUG)
  #include <stdlib.h>
  #include <memory.h>
  #include <malloc.h>

  #undef  _CRTDBG_MAP_ALLOC
  #define _CRTDBG_MAP_ALLOC
  #undef _malloca       /* Avoid MSVC-9 <malloc.h>/<crtdbg.h> name-clash */

  #include <crtdbg.h>
#endif

/* Define as 1 if we do not have an 'unsigned __int128' type
 */
#define MMDB_UINT128_IS_BYTE_ARRAY 1

/* Define to 1 if we use 'unsigned int __attribute__ ((__mode__(TI)))'
 * for 'uint128' values.
 */
#if defined(__MINGW32__)
  #define MMDB_UINT128_USING_MODE 0
#else
  #define MMDB_UINT128_USING_MODE 1
#endif

#endif  /* MAXMINDDB_CONFIG_H */
