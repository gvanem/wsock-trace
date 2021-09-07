#if defined(__GNUC__)
  #include_next <unistd.h>
#else
  #include <io.h>
  #define dup(fd) _dup(fd)
#endif
