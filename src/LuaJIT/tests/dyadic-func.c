#include <stdio.h>
#include <string.h>

// '-fp:precise' has no effect.

void check_num (long double num, const char *format, const char *expected)
{
  char buf [500];
  snprintf (buf, sizeof(buf), format, num);

  if (!_stricmp(buf, expected))
       printf ("Okay\n");
  else printf ("expected:\n  %s\nbut got:\n  %s\n", expected, buf);
}

int main (void)
{
  check_num (2^-1074, "%.99e",
             "4.940656458412465441765687928682213723650598026143247644255856825006755072702087518652998363616359924e-324");
  return (0);
}

