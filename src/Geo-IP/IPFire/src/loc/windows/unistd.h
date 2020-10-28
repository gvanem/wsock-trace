#if defined(__GNUC__)
  #include_next <unistd.h>
#else
  #include <io.h>
#endif
