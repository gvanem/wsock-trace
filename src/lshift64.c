#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

int main (void)
{
  int      shift;
  uint64_t a, b;

  for (shift = 0; shift <= 64; shift++)
  {
    a = 1ULL << shift;
    b = 1 << shift;
    printf ("shift = %2d, a = %016" PRIx64 ", b = %016" PRIx64 "\n",
            shift, a, b);
  }
  return 0;
}