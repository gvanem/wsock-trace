/*
 * This is just a dummy stub file to enable linking geoip.exe
 * for the first time.
 * I.e. before 'geoip-gen4.c' and 'geoip-gen6.c' gets generated.
 */
#include "geoip.h"

smartlist_t *geoip_smartlist_fixed_ipv4 (void)
{
  return (NULL);
}

smartlist_t *geoip_smartlist_fixed_ipv6 (void)
{
  return (NULL);
}
