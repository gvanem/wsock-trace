#include <stdio.h>

#if !defined(__CYGWIN__)
  #error "For Cygwin only"
#else
  #include <cygwin/version.h>
#endif

int main (void)
{
  printf ("CYGWIN_VERSION_DLL_COMBINED = %d\n", CYGWIN_VERSION_DLL_COMBINED);
  return (0);
}

