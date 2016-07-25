
#if 0
  #define UNICODE
  #define _UNICODE

  #define FD_SETSIZE 256
#endif

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <tchar.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "getopt.h"

#if defined(__GNUC__)
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
  #pragma GCC diagnostic ignored "-Wpointer-to-int-cast"

  /* Because of warning:
   *   test.c:46:14: warning: 'inet_pton' redeclared without dllimport attribute:
   *                          previous dllimport ignored [-Wattributes]
   */
  #pragma GCC diagnostic ignored "-Wattributes"
#endif

/* Because of:
 *   warning C4007: 'main': must be '__cdecl'
 * whe using 'cl -Gr'.
 */
#if defined(_MSC_VER)
  #define MS_CDECL __cdecl
#else
  #define MS_CDECL
#endif

/* Prevent MinGW globbing the cmd-line if we do 'test *'.
 */
int _CRT_glob = 0;

#define DIM(x)      (sizeof(x) / sizeof((x)[0]))
#define TOUPPER(c)  toupper ((int)(c))

#if defined(__MINGW32__) || defined(__CYGWIN__) || defined(__WATCOMC__)
  int WSAAPI inet_pton (int Family, PCSTR pszAddrString, void *pAddrBuf);
#endif

#if defined(__WATCOMC__) && !defined(IN6ADDR_LOOPBACK_INIT)
  #define IN6ADDR_LOOPBACK_INIT   { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }
#endif

typedef void (*test_func) (void);

struct test_struct {
       const char *name;
       test_func   func;
     };

static int chatty = 0;
static int last_result = 0;

#define TEST_STRING(expect, func)   test_string (expect, func, #func)
#define TEST_CONDITION(cond, func)  do {                                        \
                                      last_result = (int) func;                 \
                                      test_condition (last_result cond, #func); \
                                    } while (0)

static void test_condition (int okay, const char *function);
static void test_string (const char *expect, const char *result, const char *function);

static void test_ptr_or_error32 (void);
static void test_ptr_or_error32b (void);
static void test_ptr_or_error64 (void);
static void test_WSAStartup (void);
static void test_WSACleanup (void);
static void test_gethostbyaddr (void);
static void test_gethostbyname (void);
static void test_getprotobyname (void);
static void test_getprotobynumber (void);
static void test_getservbyname (void);
static void test_getservbyport (void);
static void test_getnameinfo (void);
static void test_getaddrinfo (void);
static void test_socket (void);
static void test_ioctlsocket (void);
static void test_connect (void);
static void test_select (void);
static void test_send (void);
static void test_WSAFDIsSet (void);
static void test_WSAAddressToStringA (void);
static void test_WSAAddressToStringW (void);

/*
 * fmatch() is copyright djgpp. Now simplified and renamed to
 * name_match().
 */
static int name_match (const char *wildcard, const char *string);

#define NAME_MATCH   1
#define NAME_NOMATCH 0

#define ADD_TEST(func)  { #func, test_ ## func }

static const struct test_struct tests[] = {
                    ADD_TEST (ptr_or_error32),
                    ADD_TEST (ptr_or_error32b),
                    ADD_TEST (ptr_or_error64),
                    ADD_TEST (WSAStartup),
                    ADD_TEST (gethostbyaddr),
                    ADD_TEST (gethostbyname),
                    ADD_TEST (getprotobyname),
                    ADD_TEST (getprotobynumber),
                    ADD_TEST (getservbyname),
                    ADD_TEST (getservbyport),
                    ADD_TEST (getnameinfo),
                    ADD_TEST (getaddrinfo),
                    ADD_TEST (socket),
                    ADD_TEST (ioctlsocket),
                    ADD_TEST (connect),
                    ADD_TEST (select),
                    ADD_TEST (send),
                    ADD_TEST (WSAFDIsSet),
                    ADD_TEST (WSAAddressToStringA),
                    ADD_TEST (WSAAddressToStringW),
                    ADD_TEST (WSACleanup)
                  };

static int run_test (const char *wildcard)
{
  const struct test_struct *t = tests;
  int   rc = 0, i = DIM(tests) - 1;

  assert ((t+i)->func == test_WSACleanup);

  for (i = 0; i < DIM(tests); i++, t++)
  {
    if (name_match(wildcard, t->name) != NAME_MATCH)
    {
      if (chatty > 2)
         printf ("Skipping test %s().\n", t->name);
      continue;
    }
    rc++;
    if (chatty > 0)
       printf ("\nTesting %s().\n", t->name);
    (*t->func)();
  }
  return (rc);
}

static void test_WSAStartup (void)
{
  WORD    version = MAKEWORD (2,2);
  WSADATA wsaData;
  TEST_CONDITION (== 0, WSAStartup (version, &wsaData));
}

static void test_WSACleanup (void)
{
  TEST_CONDITION (== 0, WSACleanup());
}

static void test_gethostbyaddr (void)
{
  struct in_addr  ia4;
  struct in6_addr ia6 = {{ IN6ADDR_LOOPBACK_INIT }};
  const char     *ia;

  ia4.s_addr = htonl (INADDR_LOOPBACK);
  ia = (const char*) &ia4;
  TEST_CONDITION (!= 0, gethostbyaddr (ia, sizeof(ia4), AF_INET));

  ia4.s_addr = htonl (INADDR_ANY); /* 0.0.0.0 -> hostname of this machine */
  TEST_CONDITION (!= 0, gethostbyaddr (ia, sizeof(ia4), AF_INET));

  ia = (const char*) &ia6;
  TEST_CONDITION (!= 0, gethostbyaddr (ia, sizeof(ia6), AF_INET6));

  /* Some www.google.com IPv6 addresses:
   */
  TEST_CONDITION (== 1, inet_pton (AF_INET6, "2A00:1450:400F:805::1011", &ia6.s6_addr));
  TEST_CONDITION (!= 0, gethostbyaddr (ia, sizeof(ia6), AF_INET6));

  TEST_CONDITION (== 1, inet_pton (AF_INET6, "2A00:1450:4010:C07::63", &ia6.s6_addr));
  TEST_CONDITION (== 0, gethostbyaddr (ia, sizeof(ia6), AF_INET6)); /* No reverse */
}

static void test_gethostbyname (void)
{
  TEST_CONDITION (!= 0, gethostbyname ("localhost"));
  TEST_CONDITION (!= 0, gethostbyname ("google-public-dns-a.google.com"));
}

/*
 * Test returns from the %SystemRoot\system32\drivers\etc\protocol file
 */
static void test_getprotobyname (void)
{
  TEST_CONDITION (!= 0, getprotobyname ("icmp"));   /* == 1 */
  TEST_CONDITION (== 0, getprotobyname ("xxx"));
}

static void test_getprotobynumber (void)
{
  TEST_CONDITION (!= 0, getprotobynumber (1));      /* == icmp */
  TEST_CONDITION (== 0, getprotobynumber (9999));
}

/*
 * Test returns from the %SystemRoot\system32\drivers\etc\services file
 */
static void test_getservbyname (void)
{
  TEST_CONDITION (!= 0, getservbyname ("http", "tcp"));
}

static void test_getservbyport (void)
{
  TEST_CONDITION (!= 0, getservbyport (htons(80), "tcp"));
}

static void test_getnameinfo (void)
{
  struct sockaddr_in sa4;
  const struct sockaddr *sa;
  char  host[80], serv[80];
  int   flags;

  memset (&sa4, 0, sizeof(sa4));
  sa4.sin_family = AF_INET;
  sa4.sin_addr.s_addr = inet_addr ("10.0.0.10");
  sa4.sin_port = htons (80);
  sa = (const struct sockaddr*)&sa4;
  flags = NI_NUMERICSERV | NI_NOFQDN;

  TEST_CONDITION (== 0, getnameinfo (sa, sizeof(sa4), host, sizeof(host), serv, sizeof(serv), 0));
  TEST_CONDITION (== 0, getnameinfo (sa, sizeof(sa4), host, sizeof(host), serv, sizeof(serv), flags));

  sa4.sin_addr.s_addr = inet_addr ("127.0.0.1"); // inet_addr ("12.34.56.78");
  sa4.sin_port = 0;
  flags = NI_DGRAM;
  TEST_CONDITION (== 0, getnameinfo (sa, sizeof(sa4), host, sizeof(host), NULL, 0, flags));
  TEST_CONDITION (== 0, getnameinfo (sa, sizeof(sa4), host, sizeof(host), NULL, 0, 0));

  sa4.sin_addr.s_addr = inet_addr ("8.8.8.8");  /* Google's DNS */
  sa4.sin_port = 0;
  flags = NI_DGRAM;
  TEST_CONDITION (== 0, getnameinfo (sa, sizeof(sa4), host, sizeof(host), NULL, 0, flags));
}

static void test_getaddrinfo (void)
{
  if (chatty >= 2)
    TEST_CONDITION (== 0, puts ("  Not finished yet."));
}

static SOCKET s1, s2;

static void test_socket (void)
{
  s1 = socket (AF_INET, SOCK_STREAM, 0);
  s2 = socket (AF_INET, SOCK_DGRAM, 0);

  TEST_CONDITION (!= INVALID_SOCKET, s1);
  TEST_CONDITION (!= INVALID_SOCKET, s2);
  TEST_CONDITION (== 0, WSAGetLastError());
}

static void test_ioctlsocket (void)
{
  DWORD on = 1;

  TEST_CONDITION (== 0, ioctlsocket (s1, FIONBIO, &on));
  TEST_CONDITION (== 0, WSAGetLastError());
}

static void test_connect (void)
{
  struct sockaddr_in sa4;
  const struct sockaddr *sa = (const struct sockaddr*) &sa4;

  memset (&sa4, 0, sizeof(sa4));
  sa4.sin_family = AF_INET;
  sa4.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  sa4.sin_port = htons (1234);
  TEST_CONDITION (== -1, connect (s1, sa, sizeof(sa4)));
  TEST_CONDITION (== WSAEWOULDBLOCK, WSAGetLastError());
}

static fd_set fd1, fd2;

static void test_select (void)
{
  struct timeval  tv = { 1, 1 };
  int    i;

  FD_ZERO (&fd1);
  FD_ZERO (&fd2);

  FD_SET (s1, &fd1);
  FD_SET (s2, &fd2);

  for (i = 0; i < 30; i++)
     FD_SET (i, &fd2);

  TEST_CONDITION (== -1, select (0, &fd1, &fd2, &fd2, &tv));
}

static void test_send (void)
{
  char data[256];
  int  i;

  for (i = 0; i < DIM(data); i++)
     data[i] = i;

  TEST_CONDITION (== -1, send (s1, (const char*)&data, sizeof(data), 0));
}

static void test_WSAFDIsSet (void)
{
  TEST_CONDITION (== 1, FD_ISSET (s1, &fd1));
  TEST_CONDITION (== 0, FD_ISSET (s2, &fd1));  /* Because it is SOCK_DGRAM */
}

static void test_WSAAddressToStringA (void)
{
  struct sockaddr_in sa4;
  char   data[256];
  DWORD  size = DIM (data);

  memset (&sa4, 0, sizeof(sa4));
  sa4.sin_family = AF_INET;
  sa4.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  WSAAddressToStringA ((SOCKADDR*)&sa4, sizeof(sa4), NULL, (LPTSTR)&data, &size);

  TEST_CONDITION (== 0, strcmp(data,"127.0.0.1"));
  TEST_CONDITION (== 1, (size == 10));
}

static void test_WSAAddressToStringW (void)
{
  struct sockaddr_in sa4;
  GUID               guid;
  WSAPROTOCOL_INFOW  p_info;
  wchar_t            data[256];
  DWORD              size = DIM (data);

  /* Just to test dump_wsaprotocol_info(). I assume the GUID:
   * {E70F1AA0-AB8B-11CF-8CA3-00805F48A192} is unique on all versions of Win-XP.
   * This is the "MSAFD Tcpip [TCP/IP]" provider.
   */
  memset (&guid, 0, sizeof(guid));
  memset (&p_info, 0, sizeof(p_info));
  guid.Data1 = 0xE70F1AA0;
  guid.Data2 = 0xAB8B;
  guid.Data3 = 0x11CF;
  *(WORD*)&guid.Data4[0] = htons (0x8CA3);
  *(WORD*)&guid.Data4[2] = htons (0x0080);
  *(WORD*)&guid.Data4[4] = htons (0x5F48);
  *(WORD*)&guid.Data4[6] = htons (0xA192);

  p_info.dwServiceFlags1 = XP1_CONNECTIONLESS | XP1_PSEUDO_STREAM | XP1_DISCONNECT_DATA;
  p_info.dwProviderFlags = PFL_RECOMMENDED_PROTO_ENTRY;
  memcpy (&p_info.ProviderId, &guid, sizeof(p_info.ProviderId));

  memset (&sa4, 0, sizeof(sa4));
  sa4.sin_family = AF_INET;
  sa4.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  WSAAddressToStringW ((SOCKADDR*)&sa4, sizeof(sa4), &p_info, (wchar_t*)&data, &size);
  TEST_CONDITION (== 0, wcscmp(data,L"127.0.0.1"));
  TEST_CONDITION (== 1, (size == 20));
}

static int show_help (void)
{
  puts ("Usage: test [-h] [-d] [-l] [test-wildcard]  (default = '*')");
  puts ("       -h:  this help.");
  puts ("       -d:  increase verbosity.");
  puts ("       -l:  list tests and exit.");
  return (0);
}

static int list_tests (void)
{
  const struct test_struct *t = tests;
  int   i;

  puts ("List of tests:");
  for (i = 0; i < DIM(tests); i++, t++)
     printf ("  %s()\n", t->name);
  return (0);
}

int MS_CDECL main (int argc, char **argv)
{
  int i, c, num = 0;

  while ((c = getopt (argc, argv, "h?dl")) != EOF)
    switch (c)
    {
      case '?':
      case 'h':
           exit (show_help());
           break;
      case 'l':
           exit (list_tests());
           break;
      case 'd':
           chatty++;
           break;
    }

  argc -= optind;
  argv += optind;

#ifndef __CYGWIN__
  setvbuf (stdout, NULL, _IONBF, 0);
#endif

  if (argc >= 1)
  {
    for (i = 0; i < argc; i++)
       num += run_test (argv[i]);
    if (num == 0)
       printf ("  No tests matched '%s'\n", argv[0]);
  }
  else
    run_test ("*");
  return (0);
}

/*
   If test.exe was linked correctly and you have "trace_level=1" in wsock_trace,
   the running trace should look something like this:

   * 22.383 msec: test.c(130) (test_WSAStartup+50):
     WSAStartup (2.2) --> No error.
   * 31.389 msec: test.c(146) (test_gethostbyaddr+113):
     gethostbyaddr (127.0.0.1, 4, AF_INET) --> 0x009F9088.
     name: localhost, addrtype: AF_INET, addr_list: 127.0.0.1
     aliases: ...
   * 37.813 msec: test.c(149) (test_gethostbyaddr+171):
     gethostbyaddr (0.0.0.0, 4, AF_INET) --> 0x009F9088.
     name: null, addrtype: AF_INET, addr_list: 0.0.0.0
     aliases: <none>
   * 42.091 msec: test.c(152) (test_gethostbyaddr+224):
     gethostbyaddr (::1, 16, AF_INET6) --> 0x009F9088.
     name: localhost, addrtype: AF_INET6, addr_list: ::1
     aliases: <none>
   * 47.725 msec: test.c(157) (test_gethostbyname+14):
     gethostbyname (localhost) --> 0x009F9088.
     name: SNURRE.dev.null, addrtype: AF_INET, addr_list: 127.0.0.1
     aliases: <none>

   ...
*/

static const char *ptr_or_error32 (ULONG x)
{
  static char buf [30];
  int    i, j;

  memset (&buf, '\0', sizeof(buf));
  buf[0] = '0';
  buf[1] = 'x';

  for (i = 0, j = 1+2*sizeof(x); i < 4*sizeof(x); i += 2, j--)
  {
    static const char hex_chars[] = "0123456789ABCDEF";
    unsigned idx = x % 16;

    x >>= 4;
    buf[j] = hex_chars [idx];
  }
  return (buf);
}

static const char *ptr_or_error64 (ULONG64 x)
{
  static char buf [30];
  int    i, j;

  memset (&buf, '\0', sizeof(buf));
  buf[0] = '0';
  buf[1] = 'x';

  for (i = 0, j = 1+2*sizeof(x); i < 4*sizeof(x); i += 2, j--)
  {
    static const char hex_chars[] = "0123456789ABCDEF";
    unsigned idx = x % 16;

    x >>= 4;
    buf[j] = hex_chars [idx];
  }
  return (buf);
}

static void test_ptr_or_error32 (void)
{
  TEST_STRING ("0x11223344", ptr_or_error32(0x11223344));
}

static void test_ptr_or_error32b (void)
{
  TEST_STRING ("0x11223345", ptr_or_error32(0x11223345));
}

static void test_ptr_or_error64 (void)
{
  TEST_STRING ("0x11223344AABBCCDD", ptr_or_error64(0x11223344AABBCCDD));
}

/*
 * to-do: Also test if the output of the tracing is sensible.
 * to-do: print in color (OKAY=green, FAIL=red).
 */
static void test_condition (int okay, const char *function)
{
 if (chatty < 2)
    return;

  printf ("  %-50s: ", function);
  if (okay)
       puts ("OKAY");
  else printf ("FAILED. result %d\n", last_result);
}

static void test_string (const char *expect, const char *result, const char *function)
{
 if (chatty < 2)
    return;

  printf ("  %-50s: ", function);
  if (!strcmp(expect,result))
       puts ("OKAY");
  else printf ("FAILED. expected: %s\n", expect);
}

static int name_match (const char *wildcard, const char *string)
{
  while (1)
  {
    char test, c = *wildcard++;

    switch (c)
    {
      case 0:
           return (*string == 0 ? NAME_MATCH : NAME_NOMATCH);

      case '*':
           c = *wildcard;
           /* collapse multiple stars */
           while (c == '*')
               c = *(++wildcard);

           /* optimize for wildcard with '*' at end */
           if (c == 0)
              return (NAME_MATCH);

           /* general case, use recursion */
           while ((test = *string) != '\0')
           {
             if (name_match(wildcard, string) == NAME_MATCH)
                return (NAME_MATCH);
             ++string;
           }
           return (NAME_NOMATCH);

      default:
           if (TOUPPER(c) != TOUPPER(*string++))
              return (NAME_NOMATCH);
           break;
    }
  }
}
