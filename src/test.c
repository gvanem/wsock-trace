/*
 * test.c - test the printout of some of the hooked functions in Wsock_trace.
 * Make sure 'trace_level = 1' (or higher) in your '%APPDATA%/wsock_trace'.
 */
#if 0
  #define UNICODE
  #define _UNICODE
#endif

#undef  _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <signal.h>
#include <tchar.h>

#include "wsock_defs.h"
#include "getopt.h"

#if !defined(s6_bytes)  /* mingw.org */
  #define s6_bytes _s6_bytes
#endif

#if defined(__MINGW32__) && !defined(__MINGW64_VERSION_MAJOR)
  #define USE_WSAPoll 0
#elif defined(__CYGWIN__) && defined(__i386__)
  #define USE_WSAPoll 0
#elif defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0600)
  #define USE_WSAPoll 1
#else
  #define USE_WSAPoll 0
#endif

GCC_PRAGMA (GCC diagnostic ignored "-Wstrict-aliasing")
GCC_PRAGMA (GCC diagnostic ignored "-Wpointer-to-int-cast")

#if (GCC_VERSION >= 50100)
  GCC_PRAGMA (GCC diagnostic ignored "-Wincompatible-pointer-types")
#endif

/* Because of warning:
 *   test.c:46:14: warning: 'inet_pton' redeclared without dllimport attribute:
 *                          previous dllimport ignored [-Wattributes]
 */
GCC_PRAGMA (GCC diagnostic ignored "-Wattributes")

#if defined(_MSC_VER) && defined(_WIN64)
  /*
   * Ignore warnings like:
   *   'type cast': pointer truncation from 'hostent *' to 'int'
   */
  #pragma warning (disable: 4311)
#endif

/* Prevent MinGW globbing the cmd-line if we do 'test *'.
 */
int _CRT_glob = 0;

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

#define TEST_STRING(expect, func)                  test_string (expect, func, #func)
#define TEST_WSTRING(expect, func_res, func_name)  test_wstring (expect, func_res, func_name)
#define TEST_CONDITION(cond, func)                 do {                                        \
                                                     last_result = (int) func;                 \
                                                     test_condition (last_result cond, #func); \
                                                   } while (0)

static void test_condition (int okay, const char *function);
static void test_string (const char *expect, const char *result, const char *function);
static void test_wstring (const wchar_t *expect, const wchar_t *result, const char *function);

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
static void test_gai_strerror (void);
static void test_socket (void);
static void test_ioctlsocket (void);
static void test_connect (void);
static void test_select (void);
static void test_select2 (void);
static void test_send (void);
static void test_WSAPoll (void);
static void test_WSAFDIsSet (void);
static void test_WSAAddressToStringA (void);
static void test_WSAAddressToStringW (void);
static void test_WSAAddressToStringWP (void);
static void test_WSAStringToAddressA (void);
static void test_WSAStringToAddressW (void);
static void test_WSAEnumProtocols (void);
static void test_IDNA_functions (void);

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
                    ADD_TEST (IDNA_functions),
                    ADD_TEST (getprotobyname),
                    ADD_TEST (getprotobynumber),
                    ADD_TEST (getservbyname),
                    ADD_TEST (getservbyport),
                    ADD_TEST (getnameinfo),
                    ADD_TEST (getaddrinfo),
                    ADD_TEST (gai_strerror),
                    ADD_TEST (socket),
                    ADD_TEST (ioctlsocket),
                    ADD_TEST (connect),
                    ADD_TEST (select),
                    ADD_TEST (select2),
                    ADD_TEST (send),
                    ADD_TEST (WSAPoll),
                    ADD_TEST (WSAFDIsSet),
                    ADD_TEST (WSAAddressToStringA),
                    ADD_TEST (WSAAddressToStringW),
                    ADD_TEST (WSAAddressToStringWP),
                    ADD_TEST (WSAStringToAddressA),
                    ADD_TEST (WSAStringToAddressW),
                    ADD_TEST (WSAEnumProtocols),
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
      if (chatty >= 2)
         printf ("Skipping test %s().\n", t->name);
      continue;
    }
    rc++;
    if (chatty >= 1)
       printf ("\nTesting %s():\n", t->name);
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
  struct in6_addr ia6 = IN6ADDR_LOOPBACK_INIT;
  const char     *ia;

  ia4.s_addr = htonl (INADDR_LOOPBACK);
  ia = (const char*) &ia4;
  TEST_CONDITION (!= 0, gethostbyaddr (ia, sizeof(ia4), AF_INET));

  ia4.s_addr = htonl (INADDR_ANY); /* 0.0.0.0 -> hostname of this machine */
  TEST_CONDITION (!= 0, gethostbyaddr (ia, sizeof(ia4), AF_INET));

  ia = (const char*) &ia6;         /* '::' -> hostname of this machine */
  TEST_CONDITION (!= 0, gethostbyaddr (ia, sizeof(ia6), AF_INET6));

  /* Some www.google.com IPv6 addresses: Should be in Ireland.
   */
  TEST_CONDITION (== 1, inet_pton (AF_INET6, "2A00:1450:400F:805::1011", &ia6.s6_addr));
  TEST_CONDITION (!= 0, gethostbyaddr (ia, sizeof(ia6), AF_INET6));

  /* Should be in Finland.
   */
  TEST_CONDITION (== 1, inet_pton (AF_INET6, "2A00:1450:4010:C07::63", &ia6.s6_addr));
  TEST_CONDITION (!= 0, gethostbyaddr (ia, sizeof(ia6), AF_INET6)); /* Has a reverse */
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

/* Test idna.c functions
 */
static void test_IDNA_functions (void)
{
  TEST_CONDITION (!= 0, gethostbyname ("www.seoghør.no"));  /* ACE: www.xn--seoghr-fya.no (www.lookhere.no) */
  TEST_CONDITION (!= 0, gethostbyname ("www.Bücher.ch"));   /* ACE: www.xn--bcher-kva.ch (www.books.ch) */
  TEST_CONDITION (!= 0, gethostbyname ("öbb.at"));          /* From: http://unicode.org/faq/idn.html */
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
  struct sockaddr_in  sa4;
  struct sockaddr_in6 sa6;

  const struct sockaddr *sa;
  char  host[80], serv[80];
  int   flags;

  memset (&sa4, 0, sizeof(sa4));
  memset (&sa6, 0, sizeof(sa6));

  sa4.sin_family = AF_INET;
  sa4.sin_addr.s_addr = inet_addr ("10.0.0.10");
  sa4.sin_port = htons (80);
  sa = (const struct sockaddr*) &sa4;
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

#if !defined(__CYGWIN__) /* Doesn't like the '.s6_bytes' */
  sa6.sin6_family = AF_INET6;
  sa6.sin6_addr.s6_bytes[0] = 0x2C; /* Should return 'geo-IP: KE - Kenya'. */
  sa6.sin6_addr.s6_bytes[1] = 0x0F;
  sa6.sin6_addr.s6_bytes[2] = 0xF4;
  sa6.sin6_addr.s6_bytes[3] = 0x08;
  sa6.sin6_port = htons (80);
  sa = (const struct sockaddr*) &sa6;
  TEST_CONDITION (== 0, getnameinfo (sa, sizeof(sa6), host, sizeof(host), NULL, 0, flags));
#endif
}

static void test_getaddrinfo (void)
{
  struct addrinfo hints;
  struct addrinfo *res = NULL;

  memset (&hints, 0, sizeof(hints));
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  TEST_CONDITION (== 0, getaddrinfo ("www.ssllabs.com", "443", &hints, &res));
  TEST_CONDITION (== 0, getaddrinfo ("localhost", NULL, &hints, &res));
}

static void test_gai_strerror (void)
{
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  char    err_buf1 [200];
  wchar_t err_buf2 [200];
  int     rc;

  /* Use the same flags as in non-export.c
   */
  #define FORMAT_FLAGS (FORMAT_MESSAGE_FROM_SYSTEM    | \
                        FORMAT_MESSAGE_IGNORE_INSERTS | \
                        FORMAT_MESSAGE_MAX_WIDTH_MASK)

  FormatMessageA (FORMAT_FLAGS, NULL, WSAHOST_NOT_FOUND,
                  LANG_NEUTRAL, err_buf1, sizeof(err_buf1)-1, NULL);

  FormatMessageW (FORMAT_FLAGS, NULL, WSAHOST_NOT_FOUND,
                  LANG_NEUTRAL, err_buf2, sizeof(err_buf2)/2-1, NULL);

  memset (&hints, 0, sizeof(hints));
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  rc = getaddrinfo ("www.no-such-host.com", NULL, &hints, &res);

  /* For non-MinGW, the 'gai_strerror[A|W]()' return-strings comes from inline
   * functions in <ws2tcpip.h>. So these should always pass (a test that
   * 'test_string()' + 'test_wstring()' works okay)
   */
  TEST_STRING  (err_buf1, gai_strerrorA(rc));
  TEST_WSTRING (err_buf2, gai_strerrorW(rc), "gai_strerrorW");
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

/*
 * Test if 'select()' dumps huge fd_sets okay.
 */
#undef  FD_SET
#define FD_SET(s,fd) ((fd_set*)(fd))->fd_array [((fd_set*)(fd))->fd_count++] = s
#undef  FD_SETSIZE
#define FD_SETSIZE   512

static void test_select2 (void)
{
  int i;
  struct {
         u_int  fd_count;
         SOCKET fd_array [FD_SETSIZE];
       } fd;

  FD_ZERO (&fd);
  for (i = 0; i < FD_SETSIZE; i++)
      FD_SET (i, &fd);

  TEST_CONDITION (== -1, select (0, (fd_set*)&fd, NULL, NULL, NULL));
}

static void test_send (void)
{
  char data[256];
  int  i;

  for (i = 0; i < DIM(data); i++)
     data[i] = i;

  TEST_CONDITION (== -1, send (s1, (const char*)&data, sizeof(data), 0));
}

static void test_WSAPoll (void)
{
#if USE_WSAPoll
  struct pollfd poll[2];

  poll[0].fd      = s1;
  poll[0].events  = POLLOUT;
  poll[0].revents = 0;

  poll[1].fd      = s2;
  poll[1].events  = POLLOUT;
  poll[1].revents = 0;

  TEST_CONDITION (== 1, WSAPoll ((LPWSAPOLLFD)&poll, 2, 10));
#else
  if (chatty >= 1)
     puts ("  disabled.");
#endif
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
  TEST_CONDITION (== 1, (size == sizeof("127.0.0.1")));
}

static void test_WSAAddressToStringW_common (WSAPROTOCOL_INFOW *p_info)
{
  struct sockaddr_in sa4;
  wchar_t            data[256];
  DWORD              size = DIM (data);

  memset (&sa4, 0, sizeof(sa4));
  sa4.sin_family = AF_INET;
  sa4.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  WSAAddressToStringW ((SOCKADDR*)&sa4, sizeof(sa4), p_info, (wchar_t*)&data, &size);

  TEST_CONDITION (== 0, wcscmp(data,L"127.0.0.1"));
  TEST_CONDITION (== 1, (size == sizeof(L"127.0.0.1")/2));
}

static void test_WSAAddressToStringW (void)
{
  test_WSAAddressToStringW_common (NULL);
}

/*
 * As above, but with the 'WSAPROTOCOL_INFOW' parameter.
 */
static void test_WSAAddressToStringWP (void)
{
  WSAPROTOCOL_INFOW p_info;
  GUID              guid;

  /* Just to test dump_wsaprotocol_info(). I assume the GUID:
   * {E70F1AA0-AB8B-11CF-8CA3-00805F48A192} is unique on all versions of Windows.
   * (seems the case from Win_XP to Win-10).
   * This GUID is the "MSAFD Tcpip [TCP/IP]" provider.
   */
  memset (&p_info, 0, sizeof(p_info));
  memset (&guid, 0, sizeof(guid));
  guid.Data1 = 0xE70F1AA0;
  guid.Data2 = 0xAB8B;
  guid.Data3 = 0x11CF;
  *(WORD*)&guid.Data4[0] = htons (0x8CA3);
  *(WORD*)&guid.Data4[2] = htons (0x0080);
  *(WORD*)&guid.Data4[4] = htons (0x5F48);
  *(WORD*)&guid.Data4[6] = htons (0xA192);

  p_info.dwServiceFlags1 = XP1_CONNECTIONLESS | XP1_PSEUDO_STREAM | XP1_DISCONNECT_DATA;
  p_info.dwProviderFlags = PFL_RECOMMENDED_PROTO_ENTRY;
  p_info.iAddressFamily  = AF_INET;
  p_info.iSocketType     = SOCK_STREAM;
  p_info.iProtocol       = IPPROTO_TCP;

  memcpy (&p_info.ProviderId, &guid, sizeof(p_info.ProviderId));

  test_WSAAddressToStringW_common (&p_info);
}

static void test_WSAStringToAddressA (void)
{
  SOCKADDR sa;
  int      len = sizeof(sa);
  int      rc = WSAStringToAddressA ("127.0.0.1", AF_INET, NULL, &sa, &len);

  TEST_CONDITION (== 0, rc);
}

static void test_WSAStringToAddressW (void)
{
  SOCKADDR sa;
  int      len = sizeof(sa);
  int      rc = WSAStringToAddressW (L"127.0.0.1", AF_INET, NULL, &sa, &len);

  TEST_CONDITION (== 0, rc);
}

static void test_WSAEnumProtocols (void)
{
  WSAPROTOCOL_INFO *p_info = NULL;
  DWORD             len = 0;
  DWORD             num = WSAEnumProtocols (NULL, p_info, &len);

  if (num == SOCKET_ERROR && WSAGetLastError() == WSAENOBUFS)
     p_info = alloca (len);

  TEST_CONDITION ( > 0, WSAEnumProtocols (NULL, p_info, &len));
}

/*
 * per-thread data given to 'thread_worker()' in it's 'arg' parameter.
 */
struct thr_data {
       char              t_name[20];
       DWORD             t_id;
       HANDLE            t_hnd;
       int               t_err;   /* per-thread error-code */
       CRITICAL_SECTION *t_crit;  /* the same for all threads */
     };

/*
 * This sub-routine checks if tracing of 'callee_level > 1' works.
 * Like:
 *  * 0.038 sec: test.c(523) (thread_sub_func+35)
 *               test.c(538) (thread_worker+44):
 *    WSASetLastError (0=No error).
 */
static void thread_sub_func (const struct thr_data *td)
{
  EnterCriticalSection (td->t_crit);

  /* This should demonstate that Winsock preserves 1 error-code per thread.
   * Ref. the 'TEST_CONDITION()' below.
   */
  WSASetLastError (td->t_err);

  printf ("In %s thread (%lu)\n", td->t_name, DWORD_CAST(td->t_id));

  TEST_CONDITION (== td->t_err, WSAGetLastError());
  fflush (stdout);

  LeaveCriticalSection (td->t_crit);
  Sleep (300);
}

static DWORD WINAPI thread_worker (void *arg)
{
  const struct thr_data *td = (const struct thr_data*) arg;
  int   i;

  for (i = 0; i < 5; i++)
      thread_sub_func (td);
  return (0);
}

/*
 * Create and start 'num_threads-1' sub-threads.
 * Thread 0 is the main-thread.
 */
static int thread_test (int num_threads)
{
  CRITICAL_SECTION crit_sect;
  struct thr_data *td = calloc (1, num_threads * sizeof(*td));
  int    i;

  InitializeCriticalSection (&crit_sect);

  strcpy (td[0].t_name, "main");
  td[0].t_id  = GetCurrentThreadId();
  td[0].t_err = 0;
  td[0].t_crit = &crit_sect;
  TEST_CONDITION (!= 0, td[0].t_id);

  for (i = 1; i < num_threads; i++)
  {
    snprintf (td[i].t_name, sizeof(td[i].t_name), "sub%d", i-1);

    /* Start at 'WSABASEERR + 40' which is a range with no holes.
     */
    td[i].t_err  = WSABASEERR + 39 + i;
    td[i].t_crit = &crit_sect;
    td[i].t_hnd  = CreateThread (NULL, 0, thread_worker, td+i, 0, &td[i].t_id);
    TEST_CONDITION (!= 0, td[i].t_id);
  }

  thread_worker (td + 0);

  for (i = 1; i < num_threads; i++)
  {
    printf ("Waiting for %s thread.\n", td[i].t_name);
    WaitForSingleObject (td[i].t_hnd, INFINITE);
    CloseHandle (td[i].t_hnd);
  }

  DeleteCriticalSection (&crit_sect);
  free (td);
  return (0);
}

static int show_help (void)
{
  puts ("Usage: test [-h] [-d] [-l] [-t] [test-wildcard]  (default = '*')");
  puts ("       -h:     this help.");
  puts ("       -d:     increase verbosity.");
  puts ("       -l:     list tests and exit.");
  puts ("       -t [N]: only do a thread test with <N> running threads.");
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

static void quit (int sig)
{
  fputs ("Got ^C.\n", stderr);
  fflush (stderr);
  exit (1);
}

int MS_CDECL main (int argc, char **argv)
{
  int i, c, num = 0;

  signal (SIGINT, quit);

  while ((c = getopt (argc, argv, "h?dlt::")) != EOF)
    switch (c)
    {
      case '?':
      case 'h':
           exit (show_help());
           break;
      case 'l':
           exit (list_tests());
           break;

      /* The above "t::" means 'optarg' is optional.
       * A limitation in getopt.c shows that if 4 threads is wanted, start this
       * programs as 'test.exe -t4' and not 'test.exe -t 4'.
       */
      case 't':
           if (optarg)
                num = atoi (optarg);
           else num = 1;
           exit (thread_test(num));
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
     geo-IP: Not global.
   * 37.813 msec: test.c(149) (test_gethostbyaddr+171):
     gethostbyaddr (0.0.0.0, 4, AF_INET) --> 0x009F9088.
     name: null, addrtype: AF_INET, addr_list: 0.0.0.0
     aliases: <none>
     geo-IP: Not global.
   * 42.091 msec: test.c(152) (test_gethostbyaddr+224):
     gethostbyaddr (::1, 16, AF_INET6) --> 0x009F9088.
     name: localhost, addrtype: AF_INET6, addr_list: ::1
     aliases: <none>
     geo-IP: Not global.
   * 47.725 msec: test.c(157) (test_gethostbyname+14):
     gethostbyname (localhost) --> 0x009F9088.
     name: SNURRE.dev.null, addrtype: AF_INET, addr_list: 127.0.0.1
     aliases: <none>
     geo-IP: Not global.

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
 * \todo: Also test if the output of the tracing is sensible.
 * \todo: print in color (OKAY=green, FAIL=red).
 */
static void test_condition (int okay, const char *function)
{
  if (chatty >= 1)
  {
    printf ("  %-50s: ", function);
    if (okay)
         puts ("OKAY");
    else printf ("FAILED. result %d\n", last_result);
  }
}

static void test_string (const char *expect, const char *result, const char *function)
{
  if (chatty >= 1)
  {
    printf ("  %-50s: ", function);
    if (!strcmp(expect,result))
         puts ("OKAY");
    else printf ("FAILED. expected: '%s', got: '%s'\n", expect, result);
  }
}

static void test_wstring (const wchar_t *expect, const wchar_t *result, const char *function)
{
  if (chatty >= 1)
  {
    printf ("  %-50s: ", function);
    if (!wcscmp(expect,result))
         puts ("OKAY");
    else printf ("FAILED. expected: '%S', got: '%S'\n", expect, result);
  }
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

