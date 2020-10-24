/*
 * Fake OpenSSL for libloc.
 *
 * This file gets included from 'libloc.c' only, so
 * we can fake 'WSAStartup()' too (since it could interfere
 * when used from Wsock-trace.
 */
#ifdef WSAStartup
#error "What? ' WSAStartup()' already fakely defined"
#endif

#define OpenSSL_add_all_algorithms()  ((void) 0)
#define WSAStartup(ver, wsa)          ((void) 0)

